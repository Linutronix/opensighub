# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import replace
from enum import StrEnum
from pathlib import Path

import yaml
from platformdirs import user_data_path

from opensighub.config import Config, SigningKey
from opensighub.signers import confirm_overwrite
from opensighub.util import OpensighubError, Pkcs11Uri, Pkcs11UriQattr, raise_if_tool_missing

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

    env = os.environ | {"SOFTHSM2_CONF": str(softhsm2_conf)}
    slots = subprocess.check_output(["softhsm2-util", "--show-slots"], env=env).decode()
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
            env=env,
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


def _login_uri(token_uri: Pkcs11Uri, pin_file: Path) -> str:
    # p11-kit's CLI only reads the PIN from a URI's pin-value attribute or the
    # terminal, never from stdin or pin-source; see p11-kit(8) under --login.
    return str(replace(token_uri, qattr=Pkcs11UriQattr(pin_value=pin_file.read_text())))


def setup_testenv_keys(config_path: Path) -> None:
    raise_if_tool_missing("p11-kit", "openssl")
    data_dir, softhsm2_conf, _, pin_file = _opensighub_paths(config_path)
    if not pin_file.exists() or not config_path.exists():
        raise OpensighubError("Run 'opensighub setup softhsm' first.")
    env = os.environ | {"SOFTHSM2_CONF": str(softhsm2_conf)}
    token_uri = Pkcs11Uri(token=SOFTHSM_LOCAL_TOKEN_LABEL)

    objects = subprocess.check_output(["p11-kit", "list-objects", str(token_uri)], env=env).decode()
    if not SOFTHSM_TEST_UEFI_KEY_LABEL in objects:
        logger.info(f"Generating test key on {token_uri}")
        subprocess.check_call(
            [
                "p11-kit",
                "generate-keypair",
                "--label",
                SOFTHSM_TEST_UEFI_KEY_LABEL,
                "--type",
                "rsa",
                "--bits",
                "4096",
                "--login",
                _login_uri(token_uri, pin_file),
            ],
            env=env,
        )
        cert_pem = data_dir / f"{SOFTHSM_TEST_UEFI_KEY_LABEL}.pem"
        logger.info(f"Generating certificate for {SOFTHSM_TEST_UEFI_KEY_LABEL}")
        subprocess.check_call(
            [
                "openssl",
                "req",
                "-engine",
                "pkcs11",
                "-keyform",
                "engine",
                "-new",
                "-batch",
                "-x509",
                "-days",
                "3650",
                "-subj",
                "/CN=opensighub test key/",
                "-key",
                str(Pkcs11Uri(token=SOFTHSM_LOCAL_TOKEN_LABEL, object=SOFTHSM_TEST_UEFI_KEY_LABEL)),
                "-passin",
                f"file:{pin_file}",
                "-out",
                str(cert_pem),
            ],
            env=env,
        )
        logger.info(f"Import certificate to {token_uri}")
        subprocess.check_call(
            [
                "p11-kit",
                "import-object",
                f"--file={cert_pem}",
                "--label",
                SOFTHSM_TEST_UEFI_KEY_LABEL,
                "--login",
                _login_uri(token_uri, pin_file),
            ],
            env=env,
        )
    else:
        logger.warning(f"Key '{SOFTHSM_TEST_UEFI_KEY_LABEL}' already exists, skipping generation")

    config = yaml.safe_load(config_path.read_text()) or {}
    config.setdefault("signing-keys", {})[SOFTHSM_TEST_UEFI_KEY_LABEL] = {
        "pkcs11_uri": str(
            Pkcs11Uri(
                token=SOFTHSM_LOCAL_TOKEN_LABEL,
                object=SOFTHSM_TEST_UEFI_KEY_LABEL,
                qattr=Pkcs11UriQattr(pin_source=str(pin_file)),
            )
        )
    }
    config.setdefault("uefi", {"key": SOFTHSM_TEST_UEFI_KEY_LABEL})
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    logger.info(f"Done. Test key entered in {config_path}.")


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


def _csr_openssl_subject(
    country: str | None,
    state_or_province: str | None,
    locality: str | None,
    organization: str | None,
    organizational_unit: str | None,
    common_name: str | None,
    email_address: str | None,
) -> str:
    fields = [
        ("C", country),
        ("ST", state_or_province),
        ("L", locality),
        ("O", organization),
        ("OU", organizational_unit),
        ("CN", common_name),
        ("emailAddress", email_address),
    ]
    escaped = [(name, value.replace("/", "\\/")) for name, value in fields if value]
    return "/" + "/".join(f"{name}={value}" for name, value in escaped)


def generate_csr(
    config: Config,
    key_id: str,
    output_dir: Path,
    force_overwrite: bool = False,
    country: str | None = None,
    state_or_province: str | None = None,
    locality: str | None = None,
    organization: str | None = None,
    organizational_unit: str | None = None,
    common_name: str | None = None,
    email_address: str | None = None,
    purpose: Sequence[ExtendedKeyUsage] | None = None,
) -> None:
    raise_if_tool_missing("openssl")
    if key_id not in config.signing_keys:
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
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-provider",
            "pkcs11",
            "-new",
            "-batch",
            "-subj",
            _csr_openssl_subject(
                country,
                state_or_province,
                locality,
                organization,
                organizational_unit,
                common_name,
                email_address,
            ),
            *(["-addext", f"extendedKeyUsage={','.join(purpose)}"] if purpose else []),
            "-key",
            config.signing_keys[key_id].pkcs11_uri,
            "-out",
            str(csr_path),
        ]
    )


def _key_status(key: SigningKey) -> str:
    try:
        Pkcs11Uri.try_parse(key.pkcs11_uri)
        provider = "pkcs11"
    except ValueError:
        return "invalid"
    try:
        result = subprocess.run(
            ["openssl", "storeutl", "-provider", provider, key.pkcs11_uri],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            start_new_session=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "offline"
    match = re.search(r"Total found:\s+(\d+)", result.stdout)
    if match and int(match.group(1)) > 0:
        return "available"
    if "pass phrase" in result.stderr or "PIN" in result.stderr:
        return "loginrequired"
    return "offline"


KEY_INFO_COLUMNS: dict[str, Callable[[str, SigningKey], str]] = {
    KeyInfoColumn.KEYID: lambda key_id, _: key_id,
    KeyInfoColumn.URI: lambda _, key: key.pkcs11_uri,
    KeyInfoColumn.STATUS: lambda _, key: _key_status(key),
}


def get_key_info(
    config: Config, columns: Sequence[KeyInfoColumn], key_id: str | None = None
) -> list[list[str]]:
    if unknown := [c for c in columns if c not in KEY_INFO_COLUMNS]:
        raise OpensighubError(
            f"Unsupported column(s): {', '.join(unknown)}. Available: {', '.join(KEY_INFO_COLUMNS)}"
        )
    if "status" in columns:
        raise_if_tool_missing("openssl")

    key_ids = [key_id] if key_id is not None else config.signing_keys.keys()
    result = []
    for k in key_ids:
        if k not in config.signing_keys:
            raise OpensighubError(f"Key '{key_id}' is not configured")
        result.append([KEY_INFO_COLUMNS[column](k, config.signing_keys[k]) for column in columns])
    return result
