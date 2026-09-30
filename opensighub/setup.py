# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from enum import StrEnum
from pathlib import Path

import yaml
from platformdirs import user_data_path

from opensighub.config import Config, SigningKey
from opensighub.signers import confirm_overwrite
from opensighub.util import (
    KeyProperties,
    KeyType,
    OpensighubError,
    Pkcs11Uri,
    Pkcs11UriQattr,
    Subject,
    key_status,
    pkcs11_generate_keypair,
    pkcs11_import_object,
    pkcs11_object_exists,
    raise_if_tool_missing,
    x509_generate_csr,
    x509_generate_self_signed_cert,
)

logger = logging.getLogger("opensighub")

SOFTHSM_LOCAL_TOKEN_LABEL = "opensighub-local"
SOFTHSM_LOCAL_PIN = "1234"
SOFTHSM_LOCAL_SO_PIN = "5678"
SOFTHSM_TEST_UEFI_KEY_LABEL = "opensighub-test"


def _opensighub_paths(config_path: Path) -> tuple[Path, Path, Path, Path]:
    data_dir = user_data_path("opensighub")
    return (
        data_dir,
        config_path.parent / "softhsm2.conf",
        data_dir / "softhsm2-tokens",
        data_dir / "pin",
    )


DEBIAN_ARCHIVE_KEYRING = Path("/usr/share/keyrings/debian-archive-keyring.gpg")


def enable_local_softhsm2(config_path: Path) -> None:
    _, softhsm2_conf, _, _ = _opensighub_paths(config_path)
    if softhsm2_conf.exists():
        os.environ["SOFTHSM2_CONF"] = str(softhsm2_conf)


def setup_local_token(config_path: Path) -> None:
    raise_if_tool_missing("softhsm2-util")
    data_dir, softhsm2_conf, token_dir, pin_file = _opensighub_paths(config_path)
    data_dir.mkdir(parents=True, exist_ok=True)
    token_dir.mkdir(exist_ok=True)
    softhsm2_conf.parent.mkdir(parents=True, exist_ok=True)
    if not softhsm2_conf.exists():
        logger.info(f"Writing opensighub-specific local SoftHSM configuration to {softhsm2_conf}")
        softhsm2_conf.write_text(
            f"directories.tokendir = {token_dir}\nobjectstore.backend = file\nlog.level = INFO\n"
        )
    else:
        logger.warning(f"{softhsm2_conf} already exists, leaving it untouched")

    if not pin_file.exists():
        pin_file.write_text(SOFTHSM_LOCAL_PIN)
    else:
        logger.warning(f"{pin_file} already exists, leaving it untouched")

    enable_local_softhsm2(config_path)
    slots = subprocess.check_output(["softhsm2-util", "--show-slots"]).decode()
    if not SOFTHSM_LOCAL_TOKEN_LABEL in slots:
        logger.info(f"Setting up local SoftHSM token in {token_dir}")
        subprocess.check_call(
            [
                "softhsm2-util",
                "--init-token",
                "--free",
                "--label",
                SOFTHSM_LOCAL_TOKEN_LABEL,
                "--pin",
                SOFTHSM_LOCAL_PIN,
                "--so-pin",
                SOFTHSM_LOCAL_SO_PIN,
            ],
        )
    else:
        logger.warning(f"Token '{SOFTHSM_LOCAL_TOKEN_LABEL}' already exists, skipping init")

    if not config_path.exists():
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config = {
            "archives": {
                "debian-trixie": {
                    "deb": [
                        {"url": "http://deb.debian.org/debian"},
                        {
                            "url": "http://security.debian.org/debian-security",
                            "suffix": "-security",
                        },
                    ]
                }
            },
            "archive-keyring": str(DEBIAN_ARCHIVE_KEYRING),
            "signing-keys": {},
        }
        config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    else:
        logger.warning(f"{config_path} already exists, leaving it untouched")

    logger.info(
        f"Done. SOFTHSM2_CONF={softhsm2_conf} will be automatically loaded when running opensighub."
    )


class GenKeyUseFor(StrEnum):
    UEFI = "uefi"
    SWU = "swu"
    KERNEL_MODULES = "kernel_modules"
    HAB4_IMG_KEY = "hab4:img_key"
    HAB4_CSF_KEY = "hab4:csf_key"
    OPTEE_TA = "optee_ta"
    RPI = "rpi"


def setup_genkey(
    config: Config,
    key_id: str,
    key_properties: KeyProperties,
    token: str = SOFTHSM_LOCAL_TOKEN_LABEL,
    pin_source: str | None = None,
    use_for: Sequence[GenKeyUseFor] = (),
) -> None:
    raise_if_tool_missing("p11-kit", "openssl")
    if config._source is None:
        raise OpensighubError("Config has no source path to save to")
    if key_properties.key_type == KeyType.RSA and not key_properties.bits:
        raise OpensighubError("Key length missing for RSA key")
    if key_properties.key_type == KeyType.ECDSA and not key_properties.curve:
        raise OpensighubError("Curve missing for EC key")
    is_local = token == SOFTHSM_LOCAL_TOKEN_LABEL
    _data_dir, _softhsm2_conf, _softhsm2_token, local_pin_file = _opensighub_paths(config._source)
    if is_local and pin_source is None:
        if not local_pin_file.exists():
            raise OpensighubError("Run 'opensighub setup softhsm' first.")
        pin_source = str(local_pin_file)
    token_uri = Pkcs11Uri(
        token=token, qattr=Pkcs11UriQattr(pin_source=pin_source) if pin_source else None
    )
    key_uri = replace(token_uri, object=key_id)

    try:
        if pkcs11_object_exists(key_uri):
            logger.warning(f"Key '{key_id}' already exists, skipping generation")
        else:
            logger.info(f"Generating key on {token_uri}")
            pkcs11_generate_keypair(token_uri, key_id, key_properties)
            config.add_signing_key(key_id, str(key_uri))

            with tempfile.TemporaryDirectory() as tmp_cert_dir:
                cert_pem = Path(tmp_cert_dir) / f"{key_id}.pem"
                logger.info(f"Generating certificate for {key_id}")
                x509_generate_self_signed_cert(token, key_id, pin_source, cert_pem)
                logger.info(f"Import certificate to {token_uri}")
                pkcs11_import_object(token_uri, cert_pem, key_id)

        config.add_signing_key(key_id, str(key_uri))
        for use in use_for:
            config.set_key_for_signer(use.split(":"), key_id)
    finally:
        config.save()
    logger.info(f"Key '{key_id}' generated and entered in {config._source}.")


class KeyInfoColumn(StrEnum):
    KEYID = "keyid"
    URI = "uri"
    STATUS = "status"


class ExtendedKeyUsage(StrEnum):
    """RFC 5280 §4.2.1.12 (OID 2.5.29.37) well-known purposes; openssl's symbolic names."""

    SERVER_AUTH = "serverAuth"
    CLIENT_AUTH = "clientAuth"
    CODE_SIGNING = "codeSigning"
    EMAIL_PROTECTION = "emailProtection"
    TIME_STAMPING = "timeStamping"
    OCSP_SIGNING = "OCSPSigning"


def generate_csr(
    config: Config,
    key_id: str,
    output_dir: Path,
    subject: Subject,
    force_overwrite: bool = False,
    purpose: Sequence[ExtendedKeyUsage] | None = None,
) -> None:
    raise_if_tool_missing("openssl")
    signing_key = config.signing_keys.get(key_id)
    if signing_key is None or signing_key.pkcs11_uri is None:
        raise OpensighubError(f"No signing key '{key_id}'")
    if purpose and (unknown := [p for p in purpose if p not in list(ExtendedKeyUsage)]):
        raise OpensighubError(
            f"Unsupported purpose(s): {', '.join(unknown)}. "
            f"Available: {', '.join(ExtendedKeyUsage)}"
        )

    csr_path = output_dir / f"{key_id}.csr"
    if csr_path.exists():
        confirm_overwrite(csr_path, force_overwrite)
    csr_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"Generating CSR for key '{key_id}' at {csr_path}")
    x509_generate_csr(signing_key.pkcs11_uri, subject, csr_path, purpose)


def _key_uri(key: SigningKey) -> str:
    return key.pkcs11_uri or ""


KEY_INFO_COLUMNS: dict[str, Callable[[str, SigningKey], str]] = {
    KeyInfoColumn.KEYID: lambda key_id, _: key_id,
    KeyInfoColumn.URI: lambda _, key: _key_uri(key),
    KeyInfoColumn.STATUS: lambda _, key: key_status(key.pkcs11_uri),
}


def get_key_info(
    config: Config, columns: Sequence[KeyInfoColumn], key_id: str | None = None
) -> list[list[str]]:
    if KeyInfoColumn.STATUS in columns:
        raise_if_tool_missing("openssl")

    key_ids = [key_id] if key_id is not None else list(config.signing_keys.keys())
    for k in key_ids:
        if k not in config.signing_keys:
            raise OpensighubError(f"Key '{key_id}' is not configured")

    def row(k: str) -> list[str]:
        return [KEY_INFO_COLUMNS[column](k, config.signing_keys[k]) for column in columns]

    if KeyInfoColumn.STATUS in columns and len(key_ids) > 1:
        with ThreadPoolExecutor(max_workers=len(key_ids)) as pool:
            return list(pool.map(row, key_ids))
    return [row(k) for k in key_ids]
