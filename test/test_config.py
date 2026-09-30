# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import pytest
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
from opensighub.util import OpensighubError


def test_config(unit_config_yaml, sample_pin_file, repo_pubkey_file):
    cfg_dict = yaml.safe_load(unit_config_yaml)
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


def test_config_to_dict_round_trip(unit_config_yaml):
    cfg_dict = yaml.safe_load(unit_config_yaml)
    cfg = Config.from_dict(cfg_dict)
    assert Config.from_dict(cfg.to_dict()) == cfg


def test_config_save_writes_to_source(unit_config_yaml, tmp_path):
    cfg_dict = yaml.safe_load(unit_config_yaml)
    cfg = Config.from_dict(cfg_dict, source=tmp_path / "config.yaml")
    cfg.save()
    assert Config.from_dict(yaml.safe_load((tmp_path / "config.yaml").read_text())) == cfg


def test_config_save_without_source_raises(unit_config_yaml):
    cfg_dict = yaml.safe_load(unit_config_yaml)
    cfg = Config.from_dict(cfg_dict)
    with pytest.raises(OpensighubError, match="no source path"):
        cfg.save()


def test_deb_archive_entry_trusted_default_false():
    archive = Archive.from_dict({"deb": [{"url": "http://localhost:8123"}]})
    assert archive.deb[0].trusted is False


def test_deb_archive_entry_trusted_true():
    archive = Archive.from_dict({"deb": [{"url": "http://localhost:8123", "trusted": True}]})
    assert archive.deb[0].trusted is True


def test_register_signing_key(unit_config):
    unit_config.add_signing_key("new-key", "pkcs11:token=SoftHSM;object=new-key")
    assert unit_config.signing_keys["new-key"] == SigningKey(
        pkcs11_uri="pkcs11:token=SoftHSM;object=new-key"
    )


def test_register_key_for_signer_uefi_keeps_variables(unit_config):
    unit_config.add_signing_key("new-key", "pkcs11:token=SoftHSM;object=new-key")
    unit_config.set_key_for_signer(["uefi"], "new-key")
    assert unit_config.uefi.key == unit_config.signing_keys["new-key"]
    assert "myvar" in unit_config.uefi.variables


def test_register_key_for_signer_hab4_creates_section():
    config = Config(
        archives={},
        archive_keyring=None,
        log_level=10,
        signing_keys={"new-key": SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=new-key")},
        trusted_certificates={},
        uefi=None,
        swu=None,
        kernel_modules=None,
        hab4=None,
        optee_ta=None,
        rpi=None,
    )
    config.set_key_for_signer(["hab4", "img_key"], "new-key")
    assert config.hab4.img_key == config.signing_keys["new-key"]
    assert config.hab4.csf_key is None


def test_register_key_for_signer_hab4_needs_role(unit_config):
    with pytest.raises(OpensighubError):
        unit_config.set_key_for_signer(["hab4"], "acme-2025-hab4-img")


def test_register_key_for_signer_unknown_purpose_raises(unit_config):
    with pytest.raises(OpensighubError):
        unit_config.set_key_for_signer(["foobar"], "acme-2025-hab4-img")


def test_register_key_for_signer_unknown_key_raises(unit_config):
    with pytest.raises(OpensighubError):
        unit_config.set_key_for_signer(["uefi"], "does-not-exist")


def test_remove_signing_key_unknown_key_raises(unit_config):
    with pytest.raises(OpensighubError):
        unit_config.remove_signing_key("does-not-exist")


def test_remove_signing_key_drops_from_signing_keys(unit_config):
    unit_config.remove_signing_key("acme-2025-ta-root")
    assert "acme-2025-ta-root" not in unit_config.signing_keys


def test_remove_signing_key_clears_whole_section_swu(unit_config):
    unit_config.remove_signing_key("acme-2025-swu")
    assert unit_config.swu is None


def test_remove_signing_key_clears_whole_section_uefi(unit_config):
    unit_config.remove_signing_key("acme-2025-uefi")
    assert unit_config.uefi is None


def test_remove_signing_key_clears_uefi_variable_without_dropping_section():
    key = SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=main", cfg_id_init="main-key")
    var_key = SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=var", cfg_id_init="var-key")
    config = Config(
        archives={},
        archive_keyring=None,
        log_level=10,
        signing_keys={"main-key": key, "var-key": var_key},
        trusted_certificates={},
        uefi=UefiSigningCfg(
            key=key,
            variables={"myvar": UefiVariableCfg(key=var_key)},
        ),
        swu=None,
        kernel_modules=None,
        hab4=None,
        optee_ta=None,
        rpi=None,
    )
    config.remove_signing_key("var-key")
    assert config.uefi is not None
    assert "myvar" not in config.uefi.variables


def test_remove_signing_key_clears_only_matching_hab4_role(unit_config):
    unit_config.remove_signing_key("acme-2025-hab4-img")
    assert unit_config.hab4 is not None
    assert unit_config.hab4.img_key is None
    assert unit_config.hab4.csf_key is not None


def test_config_to_dict_omits_none_sections():
    config = Config(
        archives={},
        archive_keyring=None,
        log_level=20,
        signing_keys={},
        trusted_certificates={},
        uefi=None,
        swu=None,
        kernel_modules=None,
        hab4=None,
        optee_ta=None,
        rpi=None,
    )
    result = config.to_dict()
    for absent in (
        "archives",
        "archive-keyring",
        "trusted-certificates",
        "uefi",
        "swu",
        "kernel_modules",
        "hab4",
        "optee_ta",
        "rpi",
    ):
        assert absent not in result


def test_hab4_to_dict_partial_img_key_only():
    hab4 = Hab4SigningCfg(
        img_key=SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=img", cfg_id_init="my-img-key")
    )
    assert hab4.to_dict() == {"img_key": "my-img-key"}


def test_hab4_to_dict_partial_csf_key_only():
    hab4 = Hab4SigningCfg(
        csf_key=SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=csf", cfg_id_init="my-csf-key")
    )
    assert hab4.to_dict() == {"csf_key": "my-csf-key"}


def test_uefi_to_dict_with_variables():
    key = SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=habIMG11", cfg_id_init="my-key")
    uefi = UefiSigningCfg(
        key=key,
        variables={"myvar": UefiVariableCfg(key=key, attributes=["A", "B"], guid="1234")},
    )
    assert uefi.to_dict() == {
        "key": "my-key",
        "variables": {"myvar": {"key": "my-key", "attributes": ["A", "B"], "guid": "1234"}},
    }


def test_raw_signing_cfg_to_dict_pkcs1_omits_saltlen():
    key = SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=root", cfg_id_init="my-key")
    cfg = RawSigningCfg(key=key, alg_hash="sha256", padding="pkcs1", salt_len=None)
    assert cfg.to_dict() == {"key": "my-key", "padding": "pkcs1", "hash": "sha256"}


def test_raw_signing_cfg_to_dict_pss_includes_saltlen():
    key = SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=root", cfg_id_init="my-key")
    cfg = RawSigningCfg(key=key, alg_hash="sha256", padding="pss", salt_len="digest")
    assert cfg.to_dict() == {
        "key": "my-key",
        "padding": "pss",
        "hash": "sha256",
        "saltlen": "digest",
    }


def test_debarchiveentry_to_dict_omits_defaults():
    entry = DebArchiveEntry(url="http://example.com")
    assert entry.to_dict() == {"url": "http://example.com"}


def test_signing_key_to_dict_excludes_ref():
    key = SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=x", cfg_id_init="foo")
    assert key.to_dict() == {"pkcs11_uri": "pkcs11:token=SoftHSM;object=x"}
