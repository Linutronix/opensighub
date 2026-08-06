# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import yaml

from opensighub.config import (
    Archive,
    Config,
    DebArchiveEntry,
    Hab4SigningCfg,
    LinuxModuleSigningCfg,
    PublicKeyCertificate,
    RawSigningCfg,
    SigningKey,
    SwuSigningCfg,
    UefiSigningCfg,
    UefiVariableCfg,
)


def test_config(sample_config_yaml, sample_pin_file, repo_pubkey_file):
    cfg_dict = yaml.safe_load(sample_config_yaml)
    cfg = Config.from_dict(cfg_dict)
    assert cfg == Config(
        {
            "debian_org": Archive(
                deb=[
                    DebArchiveEntry(
                        url="http://ftp.de.debian.org/debian", prefix=None, suffix=None
                    ),
                    DebArchiveEntry(
                        url="http://security.debian.org/debian-security",
                        prefix=None,
                        suffix="-security",
                    ),
                ]
            )
        },
        archive_keyring=repo_pubkey_file,
        log_level=10,
        signing_keys={
            "acme-2025-uefi": SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=habIMG11?pin-source={sample_pin_file}"
            ),
            "acme-2025-kernelmodules": SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=habIMG11?pin-source={sample_pin_file}"
            ),
            "acme-2025-hab4-img": SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=habIMG11?pin-source={sample_pin_file}"
            ),
            "acme-2025-hab4-csf": SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=habCSF11?pin-source={sample_pin_file}"
            ),
            "acme-2025-ta-root": SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=ta-root-key?pin-source={sample_pin_file}"
            ),
            "acme-2025-rpi-boot": SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=rpi-boot-key?pin-source={sample_pin_file}"
            ),
            "acme-2025-swu": SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=SWU?pin-source={sample_pin_file}"
            ),
        },
        trusted_certificates={
            "acme-2025-hab4-srk1": PublicKeyCertificate(
                pkcs11_uri="pkcs11:token=SoftHSM;object=habSRK1CA;type=cert"
            ),
            "acme-2025-hab4-srk2": PublicKeyCertificate(
                pkcs11_uri="pkcs11:token=SoftHSM;object=habSRK2CA;type=cert"
            ),
        },
        uefi=UefiSigningCfg(
            key=SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=habIMG11?pin-source={sample_pin_file}"
            ),
            variables={
                "myvar": UefiVariableCfg(
                    key=SigningKey(
                        pkcs11_uri=f"pkcs11:token=SoftHSM;object=habIMG11?pin-source={sample_pin_file}"
                    ),
                    attributes=["BOOTSERVICE_ACCESS", "NON_VOLATILE"],
                    guid="5feb76ef-8320-47b1-ba80-1e23b8a25286",
                )
            },
        ),
        kernel_modules=LinuxModuleSigningCfg(
            key=SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=habIMG11?pin-source={sample_pin_file}"
            ),
        ),
        hab4=Hab4SigningCfg(
            img_key=SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=habIMG11?pin-source={sample_pin_file}"
            ),
            csf_key=SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=habCSF11?pin-source={sample_pin_file}"
            ),
            srk_certificates=[
                PublicKeyCertificate(pkcs11_uri="pkcs11:token=SoftHSM;object=habSRK1CA;type=cert"),
                PublicKeyCertificate(pkcs11_uri="pkcs11:token=SoftHSM;object=habSRK2CA;type=cert"),
            ],
            srk_index=1,
        ),
        optee_ta=RawSigningCfg(
            key=SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=ta-root-key?pin-source={sample_pin_file}"
            ),
            alg_hash="sha256",
            padding="pss",
            salt_len="digest",
        ),
        rpi=RawSigningCfg(
            key=SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=rpi-boot-key?pin-source={sample_pin_file}"
            ),
            alg_hash="sha256",
            padding="pkcs1",
            salt_len=None,
        ),
        swu=SwuSigningCfg(
            key=SigningKey(
                pkcs11_uri=f"pkcs11:token=SoftHSM;object=SWU?pin-source={sample_pin_file}"
            )
        ),
    )


def test_deb_archive_entry_trusted_default_false():
    archive = Archive.from_dict({"deb": [{"url": "http://localhost:8123"}]})
    assert archive.deb[0].trusted is False


def test_deb_archive_entry_trusted_true():
    archive = Archive.from_dict({"deb": [{"url": "http://localhost:8123", "trusted": True}]})
    assert archive.deb[0].trusted is True
