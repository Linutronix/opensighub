# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import hashlib
import logging
import re
import shutil
import string
import subprocess
import tempfile
from collections.abc import Iterator, MutableMapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field, fields, replace
from enum import Enum, StrEnum, auto
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import quote, unquote, unquote_to_bytes

logger = logging.getLogger("opensighub")


class OpensighubError(Exception):
    """Expected failure that aborts opensighub with a plain error message instead
    of a traceback; translated into one at the CLI entry point."""


def missing_tools(*tools: str) -> list[str]:
    return [tool for tool in tools if shutil.which(tool) is None]


def raise_if_tool_missing(*tools: str) -> None:
    if missing := missing_tools(*tools):
        raise OpensighubError(f"{', '.join(missing)} not installed in PATH")


class Pkcs11AttrCodec(Enum):
    """Value syntax of a PKCS#11 URI attribute, following the RFC 7512 ABNF."""

    TEXT = auto()
    BINARY = auto()
    DECIMAL = auto()
    VERSION = auto()
    OBJECT_TYPE = auto()

    @property
    def grammar(self) -> str | None:
        match self:
            case Pkcs11AttrCodec.DECIMAL:
                return r"[0-9]+"
            case Pkcs11AttrCodec.VERSION:
                return r"[0-9]+(?:\.[0-9]+)?"
            case Pkcs11AttrCodec.OBJECT_TYPE:
                return r"public|private|cert|secret-key|data"
            case _:
                return None

    def decode(self, value: str) -> Any:
        match self:
            case Pkcs11AttrCodec.BINARY:
                return unquote_to_bytes(value)
            case Pkcs11AttrCodec.DECIMAL:
                return int(value)
            case _:
                return unquote(value, errors="strict")

    def encode(self, value: Any, unencoded_chars: str) -> str:
        match self:
            case Pkcs11AttrCodec.BINARY:
                return "".join(f"%{b:02X}" for b in value)
            case Pkcs11AttrCodec.DECIMAL:
                return str(value)
            case _:
                return quote(value, safe=unencoded_chars)

    def attr(self) -> Any:
        return field(default=None, metadata={"codec": self})


@dataclass
class Pkcs11UriAttrs:
    """Attributes of a PKCS#11 URI path or query, joined by separator."""

    # all characters except unencoded_chars are percent-encoded in a value
    unreserved_chars: ClassVar[str] = string.ascii_letters + string.digits + "-._~"
    separator: ClassVar[str]
    unencoded_chars: ClassVar[str]
    value_pattern: ClassVar[re.Pattern]

    @classmethod
    def _parse_attrs(cls, part: str) -> dict[str, Any]:
        attr_fields = {f.name.replace("_", "-"): f for f in fields(cls) if "codec" in f.metadata}
        attrs: dict[str, Any] = {}
        if not part:
            return attrs
        for attr in part.split(cls.separator):
            name, eq, value = attr.partition("=")
            if not eq:
                raise ValueError(f"PKCS#11 URI attribute '{attr}' has no value")
            attr_field = attr_fields.get(name)
            if attr_field is None:
                raise ValueError(f"unsupported PKCS#11 URI attribute '{name}'")
            if attr_field.name in attrs:
                raise ValueError(f"duplicate PKCS#11 URI attribute '{name}'")
            codec: Pkcs11AttrCodec = attr_field.metadata["codec"]
            if not cls.value_pattern.fullmatch(value) or (
                codec.grammar is not None and not re.fullmatch(codec.grammar, value)
            ):
                raise ValueError(f"invalid value for PKCS#11 URI attribute '{name}'")
            try:
                attrs[attr_field.name] = codec.decode(value)
            except UnicodeDecodeError as e:
                raise ValueError(f"PKCS#11 URI attribute '{name}' is not valid UTF-8") from e
        return attrs

    def _format_attrs(self) -> list[str]:
        return [
            f"{f.name.replace('_', '-')}={f.metadata['codec'].encode(value, self.unencoded_chars)}"
            for f in fields(self)
            if "codec" in f.metadata and (value := getattr(self, f.name)) is not None
        ]


@dataclass
class Pkcs11UriQattr(Pkcs11UriAttrs):
    separator = "&"
    unencoded_chars = Pkcs11UriAttrs.unreserved_chars + ":[]@!$'()*+,=/?|"
    value_pattern = re.compile(rf"(?:[{re.escape(unencoded_chars)}]|%[0-9a-fA-F]{{2}})*")

    pin_source: str | None = Pkcs11AttrCodec.TEXT.attr()
    pin_value: str | None = Pkcs11AttrCodec.TEXT.attr()
    module_name: str | None = Pkcs11AttrCodec.TEXT.attr()
    module_path: str | None = Pkcs11AttrCodec.TEXT.attr()


@dataclass
class Pkcs11Uri(Pkcs11UriAttrs):
    """PKCS#11 URI with attribute values in their decoded Python representation.

    Values are percent-decoded by try_parse() and percent-encoded by __str__().

    See also
    https://www.rfc-editor.org/rfc/rfc3986
    https://www.rfc-editor.org/rfc/rfc7512.html
    """

    separator = ";"
    unencoded_chars = Pkcs11UriAttrs.unreserved_chars + ":[]@!$'()*+,=&"
    value_pattern = re.compile(rf"(?:[{re.escape(unencoded_chars)}]|%[0-9a-fA-F]{{2}})*")

    token: str | None = Pkcs11AttrCodec.TEXT.attr()
    manufacturer: str | None = Pkcs11AttrCodec.TEXT.attr()
    serial: str | None = Pkcs11AttrCodec.TEXT.attr()
    model: str | None = Pkcs11AttrCodec.TEXT.attr()
    library_manufacturer: str | None = Pkcs11AttrCodec.TEXT.attr()
    library_description: str | None = Pkcs11AttrCodec.TEXT.attr()
    library_version: str | None = Pkcs11AttrCodec.VERSION.attr()
    object: str | None = Pkcs11AttrCodec.TEXT.attr()  # CKA_LABEL in PKCS #11 API
    type: str | None = Pkcs11AttrCodec.OBJECT_TYPE.attr()
    id: bytes | None = Pkcs11AttrCodec.BINARY.attr()  # CKA_ID in PKCS #11 API
    slot_description: str | None = Pkcs11AttrCodec.TEXT.attr()
    slot_manufacturer: str | None = Pkcs11AttrCodec.TEXT.attr()
    slot_id: int | None = Pkcs11AttrCodec.DECIMAL.attr()
    qattr: Pkcs11UriQattr | None = None

    @classmethod
    def try_parse(cls, uri: str) -> "Pkcs11Uri":
        """Decompose a PKCS#11 URI string into a structured Python type."""
        scheme, colon, rest = uri.partition(":")
        if not colon or scheme.lower() != "pkcs11":
            raise ValueError("Not a PKCS #11 URI")
        if "#" in rest:
            raise ValueError("PKCS#11 URI must not contain a fragment")
        path, _, query = rest.partition("?")
        path_vals = cls._parse_attrs(path)
        query_vals = Pkcs11UriQattr._parse_attrs(query)
        return cls(**path_vals, qattr=Pkcs11UriQattr(**query_vals) if query_vals else None)

    def to_private_cert_pair(self):
        return replace(self, type="private"), replace(self, type="cert")

    def to_private_pubkey(self):
        return replace(self, type="private"), replace(self, type="public")

    def pin_source_content(self) -> bytes:
        if self.qattr is not None and self.qattr.pin_source is not None:
            return (Path(self.qattr.pin_source).read_text() + "\n").encode()
        return b""

    def __str__(self):
        path = self._format_attrs()
        query = self.qattr._format_attrs() if self.qattr else []
        return f"pkcs11:{';'.join(path)}" + (f"?{'&'.join(query)}" if query else "")


class CertCache:
    """Pass-through certs in filesystem and temporarily export public key
    certificates from PKCS#11 to filesystem"""

    def __init__(
        self, cert_dict: MutableMapping[tuple[bytes | None, str | None], Path] | None = None
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
        shared_cert_dict: MutableMapping[tuple[bytes | None, str | None], Path],
        lock: AbstractContextManager,
    ):
        super().__init__(shared_cert_dict)
        self.shared_cert_dict_lock = lock

    def exported_from_pkcs11(self, pkcs11uri: Pkcs11Uri) -> Path:
        with self.shared_cert_dict_lock:
            return super().exported_from_pkcs11(pkcs11uri)


@dataclass
class Pkcs11Object:
    uri: str
    objclass: str
    label: str
    id: str
    key_type: str | None = None


@dataclass
class Subject:
    country: str | None = None
    state_or_province: str | None = None
    locality: str | None = None
    organization: str | None = None
    organizational_unit: str | None = None
    common_name: str | None = None
    email_address: str | None = None


class KeyType(StrEnum):
    RSA = "rsa"
    ECDSA = "ecdsa"


@dataclass
class KeyProperties:
    key_type: KeyType = KeyType.RSA
    bits: int | None = 4096
    curve: str | None = None


class KeyStatus(StrEnum):
    INVALID = "invalid"
    OFFLINE = "offline"
    AVAILABLE = "available"
    LOGIN_REQUIRED = "loginrequired"


def _subprocess_error_detail(e: subprocess.CalledProcessError) -> str:
    return e.stderr.decode().strip() if e.stderr else str(e)


def pkcs11_list_objects(token_uri: Pkcs11Uri) -> Iterator[Pkcs11Object]:
    try:
        objects = subprocess.check_output(
            ["p11-kit", "list-objects", str(token_uri)], stderr=subprocess.PIPE
        ).decode()
    except subprocess.CalledProcessError as e:
        raise OpensighubError(
            f"Failed to list objects on '{token_uri}': {_subprocess_error_detail(e)}"
        ) from e
    attrs: dict[str, str] = {}

    def flush() -> Iterator[Pkcs11Object]:
        if attrs:
            attrs["objclass"] = attrs.pop("class")
            yield Pkcs11Object(**attrs)
            attrs.clear()

    for line in objects.splitlines():
        k, sep, v = line.partition(": ")
        if not sep:
            continue
        k = k.strip()
        v = v.strip()
        if k == "Object":
            yield from flush()
        elif k in ("uri", "class", "key-type", "label", "id"):
            attrs[k.replace("-", "_")] = v
    yield from flush()


def pkcs11_object_exists(uri: Pkcs11Uri) -> bool:
    assert uri.object is not None
    key_id_hex = uri.object.encode().hex()
    scope_uri = replace(uri, object=None, id=None)
    return any(
        obj.label == uri.object or obj.id == key_id_hex for obj in pkcs11_list_objects(scope_uri)
    )


def pkcs11_generate_keypair(token_uri: Pkcs11Uri, key_id: str, key_properties: KeyProperties):
    try:
        result = subprocess.run(
            [
                "p11-kit",
                "generate-keypair",
                "--label",
                key_id,
                "--id",
                key_id.encode().hex(),
                "--type",
                key_properties.key_type,
                *(
                    ["--bits", str(key_properties.bits)]
                    if key_properties.key_type == KeyType.RSA
                    else ["--curve", str(key_properties.curve)]
                ),
                "--login",
                str(token_uri),
            ],
            input=token_uri.pin_source_content(),
            capture_output=True,
            start_new_session=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise OpensighubError(
            f"Failed to generate keypair '{key_id}' on '{token_uri}': {_subprocess_error_detail(e)}"
        ) from e
    log_subprocess_output(result)


def pkcs11_import_object(token_uri: Pkcs11Uri, pem_file: Path, key_id: str):
    try:
        result = subprocess.run(
            [
                "p11-kit",
                "import-object",
                f"--file={pem_file}",
                "--label",
                key_id,
                "--login",
                str(token_uri),
            ],
            input=token_uri.pin_source_content(),
            capture_output=True,
            start_new_session=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise OpensighubError(
            f"Failed to import object '{key_id}' on '{token_uri}': {_subprocess_error_detail(e)}"
        ) from e
    log_subprocess_output(result)


def pkcs11_delete_object(uri: Pkcs11Uri) -> None:
    result = subprocess.run(
        ["p11-kit", "delete-object", "--login", str(uri)],
        input=uri.pin_source_content(),
        capture_output=True,
        check=False,
        start_new_session=True,
    )
    if result.returncode != 0:
        raise OpensighubError(f"Failed to delete object '{uri}': {result.stderr.decode().strip()}")


def pkcs11_delete_key(key_uri: Pkcs11Uri):
    found = False
    for obj_type in ("private", "public", "cert"):
        obj_uri = replace(key_uri, type=obj_type)
        if pkcs11_object_exists(obj_uri):
            found = True
            pkcs11_delete_object(obj_uri)
    if not found:
        raise OpensighubError(f"No objects for key '{key_uri}' found on token")


def x509_generate_self_signed_cert(
    token: str, pkcs11_key_id: str, pin_source: str | None, cert_pem: Path
):
    try:
        result = subprocess.run(
            [
                "openssl",
                "req",
                "-provider",
                "pkcs11",
                "-new",
                "-batch",
                "-x509",
                "-days",
                "3650",
                "-subj",
                csr_openssl_subject(Subject(common_name="opensighub")),
                "-key",
                str(
                    Pkcs11Uri(
                        token=token,
                        object=pkcs11_key_id,
                        qattr=Pkcs11UriQattr(pin_source=pin_source) if pin_source else None,
                    )
                ),
                "-out",
                str(cert_pem),
            ],
            capture_output=True,
            start_new_session=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise OpensighubError(
            f"Failed to generate self-signed certificate for '{pkcs11_key_id}' on token "
            f"'{token}': {_subprocess_error_detail(e)}"
        ) from e
    log_subprocess_output(result)


def x509_generate_csr(
    key_uri: str, subject: Subject, csr_path: Path, purpose: Sequence[str] | None = None
):
    try:
        result = subprocess.run(
            [
                "openssl",
                "req",
                "-provider",
                "pkcs11",
                "-new",
                "-batch",
                "-subj",
                csr_openssl_subject(subject),
                *(["-addext", f"extendedKeyUsage={','.join(purpose)}"] if purpose else []),
                "-key",
                key_uri,
                "-out",
                str(csr_path),
            ],
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise OpensighubError(
            f"Failed to generate CSR for '{key_uri}': {_subprocess_error_detail(e)}"
        ) from e
    log_subprocess_output(result)


def key_status(pkcs11_uri: str | None) -> KeyStatus:
    if pkcs11_uri is None:
        return KeyStatus.INVALID
    try:
        Pkcs11Uri.try_parse(pkcs11_uri)
        provider = "pkcs11"
    except ValueError:
        return KeyStatus.INVALID
    try:
        result = subprocess.run(
            ["openssl", "storeutl", "-provider", provider, pkcs11_uri],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            start_new_session=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return KeyStatus.OFFLINE
    match = re.search(r"Total found:\s+(\d+)", result.stdout)
    if match and int(match.group(1)) > 0:
        return KeyStatus.AVAILABLE
    if "pass phrase" in result.stderr or "PIN" in result.stderr:
        return KeyStatus.LOGIN_REQUIRED
    return KeyStatus.OFFLINE


def pkcs11_pubkey_hash(uri: Pkcs11Uri) -> str:
    pubkey_uri = replace(uri, type="public")
    try:
        result = subprocess.run(
            [
                "openssl",
                "pkey",
                "-provider",
                "pkcs11",
                "-pubin",
                "-in",
                str(pubkey_uri),
                "-pubout",
                "-outform",
                "DER",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=True,
            start_new_session=True,
        )
    except subprocess.CalledProcessError as e:
        raise OpensighubError(
            f"Failed to read public key for '{pubkey_uri}': {_subprocess_error_detail(e)}"
        ) from e
    except (OSError, subprocess.TimeoutExpired) as e:
        raise OpensighubError(f"Failed to read public key for '{pubkey_uri}': {e}") from e
    return hashlib.sha256(result.stdout).hexdigest()


def x509_cert_pubkey_hash(cert_path: Path) -> str:
    try:
        pem = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"],
            capture_output=True,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        raise OpensighubError(
            f"Failed to read certificate '{cert_path}': {_subprocess_error_detail(e)}"
        ) from e
    der = base64.b64decode(b"".join(pem.splitlines()[1:-1]))
    return hashlib.sha256(der).hexdigest()


def csr_openssl_subject(subject: Subject) -> str:
    fields = [
        ("C", subject.country),
        ("ST", subject.state_or_province),
        ("L", subject.locality),
        ("O", subject.organization),
        ("OU", subject.organizational_unit),
        ("CN", subject.common_name),
        ("emailAddress", subject.email_address),
    ]
    escaped = [(name, value.replace("/", "\\/")) for name, value in fields if value]
    return "/" + "/".join(f"{name}={value}" for name, value in escaped)


def log_subprocess_output(result: subprocess.CompletedProcess[bytes]) -> None:
    if result.stdout:
        logger.debug(result.stdout.decode().strip())
    if result.stderr:
        logger.debug(result.stderr.decode().strip())
