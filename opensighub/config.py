# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("opensighub")

# See also
# https://salsa.debian.org/ftp-team/code-signing/-/blob/master/etc/debian-prod.yaml


@dataclass
class PublicKeyCertificate:
    pkcs11_uri: str

    @classmethod
    def from_dict(cls, data: dict):
        return cls(pkcs11_uri=data["pkcs11_uri"])


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

    pkcs11_uri: str

    @classmethod
    def from_dict(cls, data: dict):
        return cls(pkcs11_uri=data["pkcs11_uri"])


@dataclass
class DebArchiveEntry:
    url: str
    prefix: str | None = None
    suffix: str | None = None


@dataclass
class Archive:
    deb: list[DebArchiveEntry]

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            deb=[
                DebArchiveEntry(deb_dict["url"], deb_dict.get("prefix"), deb_dict.get("suffix"))
                for deb_dict in data["deb"]
            ]
        )


@dataclass
class UefiVariableCfg:
    key: SigningKey
    attributes: list[str] | None = None
    guid: str | None = None


class SwuCfg:
    key: SigningKey
    attributes: list[str] | None = None


@dataclass
class SwuSigningCfg:
    key: SigningKey

    @classmethod
    def from_dict(cls, data: dict, keys: dict[str, SigningKey]):
        return cls(key=keys[data["key"]])


@dataclass
class UefiSigningCfg:
    key: SigningKey
    variables: dict[str, UefiVariableCfg]

    @classmethod
    def from_dict(cls, data: dict, keys: dict[str, SigningKey]):
        variables = {
            k: UefiVariableCfg(keys[v["key"]], v.get("attributes"), v.get("guid"))
            for k, v in data.get("variables", {}).items()
        }
        return cls(key=keys[data["key"]], variables=variables)


@dataclass
class LinuxModuleSigningCfg:
    key: SigningKey

    @classmethod
    def from_dict(cls, data: dict, keys: dict[str, SigningKey]):
        return cls(key=keys[data["key"]])


@dataclass
class Hab4SigningCfg:
    img_key: SigningKey
    csf_key: SigningKey
    srk_certificates: list[PublicKeyCertificate]
    srk_index: int

    @classmethod
    def from_dict(
        cls,
        data: dict,
        keys: dict[str, SigningKey],
        certs: dict[str, PublicKeyCertificate],
    ):
        return cls(
            img_key=keys[data["img_key"]],
            csf_key=keys[data["csf_key"]],
            srk_certificates=[certs[cert] for cert in data["srk_certificates"]],
            srk_index=int(data["srk_index"]),
        )


@dataclass
class RawSigningCfg:
    key: SigningKey
    alg_hash: str
    padding: str
    salt_len: str | None
    mgf1_md: str | None = None

    @classmethod
    def from_dict(cls, data: dict, keys: dict[str, "SigningKey"]):
        key = keys[data["key"]]
        alg_hash = data["hash"]

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


@dataclass
class Config:
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

    @classmethod
    def from_dict(cls, data: dict):
        if (log_level_str := data.get("log-level")) is not None:
            log_level = logging.getLevelNamesMapping().get(log_level_str)
            if not log_level:
                logger.warning("unknown log level in config, setting to INFO")
                log_level = logging.INFO
        else:
            log_level = logging.INFO
        archives = {k: Archive.from_dict(v) for k, v in data["archives"].items()}
        signing_keys = {sk: SigningKey.from_dict(sv) for sk, sv in data["signing-keys"].items()}
        trusted_certificates = (
            {k: PublicKeyCertificate(**v) for k, v in data["trusted-certificates"].items()}
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
        )
