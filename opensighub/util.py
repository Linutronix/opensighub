# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import re
import shutil
import subprocess
import tempfile
from collections.abc import MutableMapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import ClassVar
from urllib.parse import parse_qsl, urlparse, urlunparse


class OpensighubError(Exception):
    """Expected failure that aborts opensighub with a plain error message instead
    of a traceback; translated into one at the CLI entry point."""


def missing_tools(*tools: str) -> list[str]:
    return [tool for tool in tools if shutil.which(tool) is None]


def raise_if_tool_missing(*tools: str) -> None:
    if missing := missing_tools(*tools):
        raise OpensighubError(f"{', '.join(missing)} not installed in PATH")


@dataclass
class Pkcs11UriQattr:
    pin_source: str | None = None
    pin_value: str | None = None
    module_name: str | None = None
    module_path: str | None = None


@dataclass
class Pkcs11Uri:
    pk11_path_res_avail: ClassVar[re.Pattern] = re.compile(r"^[a-zA-Z0-9:\[\]@!$'()*+,=&.~_-]+$")
    pk11_query_res_avail: ClassVar[re.Pattern] = re.compile(
        r"^[a-zA-Z0-9:\[\]@!$'()*+,=&/?|.~_-]+$"
    )

    token: str | None = None
    manufacturer: str | None = None
    serial: str | None = None
    model: str | None = None
    library_manufacturer: str | None = None
    library_description: str | None = None
    library_version: str | None = None
    object: str | None = None  # CKA_LABEL in PKCS #11 API
    type: str | None = None
    id: str | None = None  # CKA_ID in PKCS #11 API
    slot_description: str | None = None
    slot_manufacturer: str | None = None
    slot_id: str | None = None
    qattr: Pkcs11UriQattr | None = None

    @staticmethod
    def matched(pattern: re.Pattern, value: str):
        if not pattern.match(value):
            raise ValueError("invalid characters in PKCS#11 URI")
        return value

    @classmethod
    def try_parse(cls, uri: str) -> "Pkcs11Uri":
        """Decompose a PKCS#11 URI string into a structured Python type.

        See also
        https://www.rfc-editor.org/rfc/rfc3986
        https://www.rfc-editor.org/rfc/rfc7512.html
        """
        result = urlparse(uri)
        if result.scheme != "pkcs11":
            raise ValueError("Not a PKCS #11 URI")
        path_attrs = result.path.split(";")
        attr_dict = {}
        qattr_dict = {}
        for attr in path_attrs:
            k, v = attr.split("=")
            k = k.replace("-", "_")
            attr_dict[k] = cls.matched(cls.pk11_path_res_avail, v)
        if result.query:
            qattr_dict = {
                k.replace("-", "_"): cls.matched(cls.pk11_query_res_avail, v)
                for k, v in parse_qsl(result.query)
            }
        return cls(**attr_dict, qattr=Pkcs11UriQattr(**qattr_dict) if qattr_dict else None)

    def to_private_cert_pair(self):
        return replace(self, type="private"), replace(self, type="cert")

    def to_private_pubkey(self):
        return replace(self, type="private"), replace(self, type="public")

    def __str__(self):
        path = [
            f"{field.name.replace('_', '-')}={getattr(self, field.name)}"
            for field in filter(lambda f: f.name != "qattr", fields(self.__class__))
            if getattr(self, field.name) is not None
        ]
        if self.qattr:
            query = [
                f"{field.name.replace('_', '-')}={getattr(self.qattr, field.name)}"
                for field in fields(self.qattr.__class__)
                if getattr(self.qattr, field.name) is not None
            ]
        else:
            query = []
        return urlunparse(("pkcs11", "", ";".join(path), "", "&".join(query), ""))


class CertCache:
    """Pass-through certs in filesystem and temporarily export public key
    certificates from PKCS#11 to filesystem"""

    def __init__(
        self, cert_dict: MutableMapping[tuple[str | None, str | None], Path] | None = None
    ):
        self.cert_pool: tempfile.TemporaryDirectory | None = None
        self.by_pkcs11_id_label = {} if cert_dict is None else cert_dict

    def __enter__(self):
        self.cert_pool = tempfile.TemporaryDirectory()
        return self

    def __getitem__(self, uri: str | Pkcs11Uri) -> Path:
        assert self.cert_pool
        if isinstance(uri, Pkcs11Uri):
            return self.exported_from_pkcs11(uri)
        try:
            pkcs11uri = Pkcs11Uri.try_parse(uri)
            return self.exported_from_pkcs11(pkcs11uri)
        except ValueError:
            # treat as file
            return Path(uri)

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        if self.cert_pool:
            self.cert_pool.cleanup()

    def exported_from_pkcs11(self, pkcs11uri: Pkcs11Uri) -> Path:
        assert self.cert_pool
        pkcs11uri_id = (pkcs11uri.id, pkcs11uri.object)
        if pkcs11uri_id not in self.by_pkcs11_id_label:
            raise_if_tool_missing("p11tool")
            with tempfile.NamedTemporaryFile(
                delete=False, dir=self.cert_pool.name, suffix=".pem"
            ) as tmp_file:
                tmp_path = tmp_file.name
            subprocess.check_call(["p11tool", "--export", str(pkcs11uri), "--outfile", tmp_path])
            self.by_pkcs11_id_label[pkcs11uri_id] = Path(tmp_path)
        return self.by_pkcs11_id_label[pkcs11uri_id]


class MultiprocessingCertCache(CertCache):
    """A synchronized CertCache where many processes export certificates concurrently."""

    def __init__(
        self,
        shared_cert_dict: MutableMapping[tuple[str | None, str | None], Path],
        lock: AbstractContextManager,
    ):
        super().__init__(shared_cert_dict)
        self.shared_cert_dict_lock = lock

    def exported_from_pkcs11(self, pkcs11uri: Pkcs11Uri) -> Path:
        with self.shared_cert_dict_lock:
            return super().exported_from_pkcs11(pkcs11uri)
