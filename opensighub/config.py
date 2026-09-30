# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from collections.abc import Sequence
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import ClassVar

import yaml

from opensighub.util import OpensighubError

logger = logging.getLogger("opensighub")

# See also
# https://salsa.debian.org/ftp-team/code-signing/-/blob/master/etc/debian-prod.yaml


@dataclass
class PublicKeyCertificate:
    pkcs11_uri: str
    cfg_id_init: InitVar[str] = ""
    _id: str = field(default="", compare=False, repr=False, init=False)

    def __post_init__(self, cfg_id_init: str):
        self._id = cfg_id_init

    @classmethod
    def from_dict(cls, cfg_id: str, data: dict):
        return cls(pkcs11_uri=data["pkcs11_uri"], cfg_id_init=cfg_id)

    def to_dict(self) -> dict:
        return {"pkcs11_uri": self.pkcs11_uri}

    @property
    def cfg_id(self):
        return self._id


@dataclass
class SigningKey:
    """
    Access to private objects require a PIN. To specify a PIN, the  PKCS#11 URI
    may contain
    - pin-source=/some/text/file (recommended):
      Understood by libp11 nad pkcs11-provider. PIN value will be read
      from given text file. The file must not contain a trailing newline.
    - pin-value=plaintextpin
    """

    pkcs11_uri: str | None = None
    cfg_id_init: InitVar[str] = ""
    _id: str = field(default="", compare=False, repr=False, init=False)

    def __post_init__(self, cfg_id_init: str):
        self._id = cfg_id_init

    @classmethod
    def from_dict(cls, cfg_id: str, data: dict):
        return cls(pkcs11_uri=data["pkcs11_uri"], cfg_id_init=cfg_id)

    def to_dict(self) -> dict:
        return {"pkcs11_uri": self.pkcs11_uri}

    @property
    def cfg_id(self):
        return self._id


@dataclass
class DebArchiveEntry:
    url: str
    prefix: str | None = None
    suffix: str | None = None
    trusted: bool = False

    def to_dict(self) -> dict:
        data: dict = {"url": self.url}
        if self.prefix is not None:
            data["prefix"] = self.prefix
        if self.suffix is not None:
            data["suffix"] = self.suffix
        if self.trusted:
            data["trusted"] = self.trusted
        return data


@dataclass
class Archive:
    deb: list[DebArchiveEntry]

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            deb=[
                DebArchiveEntry(
                    deb_dict["url"],
                    deb_dict.get("prefix"),
                    deb_dict.get("suffix"),
                    deb_dict.get("trusted", False),
                )
                for deb_dict in data["deb"]
            ]
        )

    def to_dict(self) -> dict:
        return {"deb": [entry.to_dict() for entry in self.deb]}


@dataclass
class UefiVariableCfg:
    key: SigningKey
    attributes: list[str] | None = None
    guid: str | None = None

    def to_dict(self) -> dict:
        data: dict = {"key": self.key.cfg_id}
        if self.attributes:
            data["attributes"] = self.attributes
        if self.guid is not None:
            data["guid"] = self.guid
        return data


class SwuCfg:
    key: SigningKey
    attributes: list[str] | None = None


@dataclass
class SwuSigningCfg:
    key: SigningKey

    @classmethod
    def from_dict(cls, data: dict, keys: dict[str, SigningKey]):
        return cls(key=keys[data["key"]])

    def to_dict(self) -> dict:
        return {"key": self.key.cfg_id}


@dataclass
class UefiSigningCfg:
    key: SigningKey
    variables: dict[str, UefiVariableCfg] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict, keys: dict[str, SigningKey]):
        variables = {
            k: UefiVariableCfg(keys[v["key"]], v.get("attributes"), v.get("guid"))
            for k, v in data.get("variables", {}).items()
        }
        return cls(key=keys[data["key"]], variables=variables)

    def to_dict(self) -> dict:
        data: dict = {"key": self.key.cfg_id}
        if self.variables:
            data["variables"] = {k: v.to_dict() for k, v in self.variables.items()}
        return data


@dataclass
class LinuxModuleSigningCfg:
    key: SigningKey

    @classmethod
    def from_dict(cls, data: dict, keys: dict[str, SigningKey]):
        return cls(key=keys[data["key"]])

    def to_dict(self) -> dict:
        return {"key": self.key.cfg_id}


@dataclass
class Hab4SigningCfg:
    img_key: SigningKey | None = None
    csf_key: SigningKey | None = None
    srk_certificates: list[PublicKeyCertificate] = field(default_factory=list)
    srk_index: int | None = None

    @classmethod
    def from_dict(
        cls,
        data: dict,
        keys: dict[str, SigningKey],
        certs: dict[str, PublicKeyCertificate],
    ):
        return cls(
            img_key=keys[data["img_key"]] if "img_key" in data else None,
            csf_key=keys[data["csf_key"]] if "csf_key" in data else None,
            srk_certificates=[certs[cert] for cert in data.get("srk_certificates", [])],
            srk_index=int(data["srk_index"]) if "srk_index" in data else None,
        )

    def to_dict(self) -> dict:
        data: dict = {}
        if self.srk_index is not None:
            data["srk_index"] = self.srk_index
        if self.img_key is not None:
            data["img_key"] = self.img_key.cfg_id
        if self.csf_key is not None:
            data["csf_key"] = self.csf_key.cfg_id
        if self.srk_certificates:
            data["srk_certificates"] = [cert.cfg_id for cert in self.srk_certificates]
        return data


@dataclass
class RawSigningCfg:
    key: SigningKey
    alg_hash: str | None = None
    padding: str = "pkcs1"
    salt_len: str | None = None
    mgf1_md: str | None = None

    @classmethod
    def from_dict(cls, data: dict, keys: dict[str, "SigningKey"]):
        key = keys[data["key"]]
        alg_hash = data.get("hash")

        padding = data.get("padding", "pkcs1").lower()

        salt_len = data.get("saltlen")
        mgf1_md = data.get("mgf1_md")

        if padding == "pss":
            if salt_len is None:
                salt_len = "digest"
        else:
            salt_len = None
            mgf1_md = None

        return cls(
            key=key,
            alg_hash=alg_hash,
            padding=padding,
            salt_len=str(salt_len) if salt_len is not None else None,
            mgf1_md=mgf1_md,
        )

    def to_dict(self) -> dict:
        data: dict = {"key": self.key.cfg_id, "padding": self.padding}
        if self.alg_hash is not None:
            data["hash"] = self.alg_hash
        if self.salt_len is not None:
            data["saltlen"] = self.salt_len
        if self.mgf1_md is not None:
            data["mgf1_md"] = self.mgf1_md
        return data


@dataclass
class Config:
    _signer_path_length: ClassVar[dict[str, int]] = {
        "hab4": 2,
        "optee_ta": 1,
        "rpi": 1,
        "uefi": 1,
        "swu": 1,
        "kernel_modules": 1,
    }

    archives: dict[str, Archive]
    archive_keyring: Path | None
    log_level: int
    signing_keys: dict[str, SigningKey]
    trusted_certificates: dict[str, PublicKeyCertificate]
    uefi: UefiSigningCfg | None
    swu: SwuSigningCfg | None
    kernel_modules: LinuxModuleSigningCfg | None
    hab4: Hab4SigningCfg | None
    optee_ta: RawSigningCfg | None
    rpi: RawSigningCfg | None
    _source: Path | None = field(default=None, compare=False, repr=False)

    @classmethod
    def from_dict(cls, data: dict, source: Path | None = None):
        if (log_level_str := data.get("log-level")) is not None:
            log_level = logging.getLevelNamesMapping().get(log_level_str)
            if not log_level:
                logger.warning("unknown log level in config, setting to INFO")
                log_level = logging.INFO
        else:
            log_level = logging.INFO
        archives = {k: Archive.from_dict(v) for k, v in data.get("archives", {}).items()}
        signing_keys = {sk: SigningKey.from_dict(sk, sv) for sk, sv in data["signing-keys"].items()}
        trusted_certificates = (
            {
                k: PublicKeyCertificate.from_dict(k, v)
                for k, v in data["trusted-certificates"].items()
            }
            if "trusted-certificates" in data
            else {}
        )
        uefi_cfg = UefiSigningCfg.from_dict(data["uefi"], signing_keys) if "uefi" in data else None
        swu_cfg = SwuSigningCfg.from_dict(data["swu"], signing_keys) if "swu" in data else None
        kernel_modules_cfg = (
            LinuxModuleSigningCfg.from_dict(data["kernel_modules"], signing_keys)
            if "kernel_modules" in data
            else None
        )
        hab4_cfg = (
            Hab4SigningCfg.from_dict(data["hab4"], signing_keys, trusted_certificates)
            if "hab4" in data
            else None
        )
        optee_ta_cfg = (
            RawSigningCfg.from_dict(data["optee_ta"], signing_keys) if "optee_ta" in data else None
        )
        rpi_cfg = RawSigningCfg.from_dict(data["rpi"], signing_keys) if "rpi" in data else None
        return cls(
            archives=archives,
            archive_keyring=Path(data["archive-keyring"]) if "archive-keyring" in data else None,
            log_level=log_level,
            signing_keys=signing_keys,
            trusted_certificates=trusted_certificates,
            uefi=uefi_cfg,
            swu=swu_cfg,
            kernel_modules=kernel_modules_cfg,
            hab4=hab4_cfg,
            optee_ta=optee_ta_cfg,
            rpi=rpi_cfg,
            _source=source,
        )

    def to_dict(self) -> dict:
        data: dict = {
            "log-level": logging.getLevelName(self.log_level),
            "signing-keys": {kid: key.to_dict() for kid, key in self.signing_keys.items()},
        }
        if self.archives:
            data["archives"] = {name: a.to_dict() for name, a in self.archives.items()}
        if self.archive_keyring is not None:
            data["archive-keyring"] = str(self.archive_keyring)
        if self.trusted_certificates:
            data["trusted-certificates"] = {
                cid: cert.to_dict() for cid, cert in self.trusted_certificates.items()
            }
        if self.uefi:
            data["uefi"] = self.uefi.to_dict()
        if self.swu:
            data["swu"] = self.swu.to_dict()
        if self.kernel_modules:
            data["kernel_modules"] = self.kernel_modules.to_dict()
        if self.hab4:
            data["hab4"] = self.hab4.to_dict()
        if self.optee_ta:
            data["optee_ta"] = self.optee_ta.to_dict()
        if self.rpi:
            data["rpi"] = self.rpi.to_dict()
        return data

    def save(self) -> None:
        if self._source is None:
            raise OpensighubError("Config has no source path to save to")
        self._source.write_text(yaml.safe_dump(self.to_dict(), sort_keys=False))

    def add_signing_key(self, key_id: str, pkcs11_uri: str) -> None:
        self.signing_keys[key_id] = SigningKey(pkcs11_uri=pkcs11_uri, cfg_id_init=key_id)

    def set_key_for_signer(self, signer_path: Sequence[str], key_id: str) -> None:
        if key_id not in self.signing_keys:
            raise OpensighubError(f"Unknown signing key '{key_id}'")
        key = self.signing_keys[key_id]
        if not signer_path or self._signer_path_length.get(signer_path[0]) != len(signer_path):
            raise OpensighubError(f"Unknown signer purpose '{':'.join(signer_path)}'")
        signer = signer_path[0]
        if signer == "hab4":
            if signer_path[1] not in ("img_key", "csf_key"):
                raise OpensighubError(
                    "hab4 needs a sub-path, e.g. 'hab4:img_key' or 'hab4:csf_key'"
                )
            if self.hab4 is None:
                self.hab4 = Hab4SigningCfg()
            if signer_path[1] == "img_key":
                self.hab4.img_key = key
            else:
                self.hab4.csf_key = key
        elif signer == "optee_ta":
            if self.optee_ta is None:
                self.optee_ta = RawSigningCfg(key=key)
            else:
                self.optee_ta.key = key
        elif signer == "rpi":
            if self.rpi is None:
                self.rpi = RawSigningCfg(key=key)
            else:
                self.rpi.key = key
        elif signer == "uefi":
            if self.uefi is None:
                self.uefi = UefiSigningCfg(key=key)
            else:
                self.uefi.key = key
        elif signer == "swu":
            if self.swu is None:
                self.swu = SwuSigningCfg(key=key)
            else:
                self.swu.key = key
        elif signer == "kernel_modules":
            if self.kernel_modules is None:
                self.kernel_modules = LinuxModuleSigningCfg(key=key)
            else:
                self.kernel_modules.key = key
