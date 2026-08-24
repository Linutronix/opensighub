# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import yaml
from platformdirs import user_data_path

from opensighub.util import OpensighubError, Pkcs11Uri, Pkcs11UriQattr, raise_if_tool_missing

logger = logging.getLogger("opensighub")

SOFTHSM_LOCAL_TOKEN_LABEL = "opensighub-local"
SOFTHSM_LOCAL_PIN = "1234"
SOFTHSM_LOCAL_SO_PIN = "5678"
SOFTHSM_TEST_UEFI_KEY_LABEL = "opensighub-test"


def _osh_paths(config_path: Path) -> tuple[Path, Path, Path, Path]:
    data_dir = user_data_path("opensighub")
    return (
        data_dir,
        config_path.parent / "softhsm2.conf",
        data_dir / "softhsm2-tokens",
        data_dir / "pin",
    )


DEBIAN_ARCHIVE_KEYRING = Path("/usr/share/keyrings/debian-archive-keyring.gpg")


def enable_local_softhsm2(config_path: Path) -> None:
    _, softhsm2_conf, _, _ = _osh_paths(config_path)
    if softhsm2_conf.exists():
        os.environ["SOFTHSM2_CONF"] = str(softhsm2_conf)


def setup_local_token(config_path: Path) -> None:
    raise_if_tool_missing("softhsm2-util")
    data_dir, softhsm2_conf, token_dir, pin_file = _osh_paths(config_path)
    data_dir.mkdir(parents=True, exist_ok=True)
    token_dir.mkdir(exist_ok=True)
    softhsm2_conf.parent.mkdir(parents=True, exist_ok=True)
    if not softhsm2_conf.exists():
        logger.info(f"Writing osh-specific local SoftHSM configuration to {softhsm2_conf}")
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
        f"Done. SOFTHSM2_CONF={softhsm2_conf} will be automatically loaded when running osh."
    )


def _login_uri(token_uri: Pkcs11Uri, pin_file: Path) -> str:
    # p11-kit's CLI only reads the PIN from a URI's pin-value attribute or the
    # terminal, never from stdin or pin-source; see p11-kit(8) under --login.
    return str(replace(token_uri, qattr=Pkcs11UriQattr(pin_value=pin_file.read_text())))


def setup_testenv_keys(config_path: Path) -> None:
    raise_if_tool_missing("p11-kit", "openssl")
    data_dir, softhsm2_conf, _, pin_file = _osh_paths(config_path)
    if not pin_file.exists() or not config_path.exists():
        raise OpensighubError("Run 'osh setup softhsm' first.")
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
