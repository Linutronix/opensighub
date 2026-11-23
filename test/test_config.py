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
    QualifiedSignerPath,
    RawSigningCfg,
    SignerPath,
    SignerProfile,
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
        default_profile=SignerProfile(
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
                    PublicKeyCertificate(
                        pkcs11_uri="pkcs11:token=SoftHSM;object=habSRK1CA;type=cert"
                    ),
                    PublicKeyCertificate(
                        pkcs11_uri="pkcs11:token=SoftHSM;object=habSRK2CA;type=cert"
                    ),
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


def test_config_save_creates_parent_directory(tmp_path):
    cfg = Config.from_dict({}, source=tmp_path / "new" / "config.yaml")
    cfg.save()
    assert (tmp_path / "new" / "config.yaml").exists()


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
    unit_config.set_key_for_signer(QualifiedSignerPath(SignerPath.UEFI), "new-key")
    assert unit_config.uefi.key == unit_config.signing_keys["new-key"]
    assert "myvar" in unit_config.uefi.variables


def test_register_key_for_signer_hab4_creates_section():
    config = Config(
        archives={},
        archive_keyring=None,
        log_level=10,
        signing_keys={"new-key": SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=new-key")},
        trusted_certificates={},
    )
    config.set_key_for_signer(QualifiedSignerPath(SignerPath.HAB4_IMG_KEY), "new-key")
    assert config.hab4.img_key == config.signing_keys["new-key"]
    assert config.hab4.csf_key is None


def test_register_key_for_signer_unknown_key_raises(unit_config):
    with pytest.raises(OpensighubError):
        unit_config.set_key_for_signer(QualifiedSignerPath(SignerPath.UEFI), "does-not-exist")


def test_remove_signing_key_unknown_key_raises(unit_config):
    with pytest.raises(OpensighubError):
        unit_config.remove_signing_key("does-not-exist")


def test_remove_signing_key_drops_from_signing_keys(unit_config):
    unit_config.remove_signing_key("acme-2025-ta-root")
    assert "acme-2025-ta-root" not in unit_config.signing_keys


def test_remove_signing_key_keeps_sections(unit_config):
    for key_id in ("acme-2025-swu", "acme-2025-uefi", "acme-2025-ta-root"):
        unit_config.remove_signing_key(key_id)
    assert unit_config.swu == SwuSigningCfg(key=None)
    assert unit_config.uefi.key is None
    assert unit_config.uefi.variables["myvar"].key is None
    assert unit_config.uefi.variables["myvar"].guid == "5feb76ef-8320-47b1-ba80-1e23b8a25286"
    assert unit_config.kernel_modules.key is None
    assert unit_config.optee_ta.key is None
    assert unit_config.optee_ta.padding == "pss"


def test_remove_signing_key_clears_only_uefi_variable_key():
    key = SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=main", cfg_id_init="main-key")
    var_key = SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=var", cfg_id_init="var-key")
    config = Config(
        archives={},
        archive_keyring=None,
        log_level=10,
        signing_keys={"main-key": key, "var-key": var_key},
        trusted_certificates={},
        default_profile=SignerProfile(
            uefi=UefiSigningCfg(key=key, variables={"myvar": UefiVariableCfg(key=var_key)})
        ),
    )
    config.remove_signing_key("var-key")
    assert config.uefi.key is key
    assert config.uefi.variables["myvar"] == UefiVariableCfg()


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
        img_key=SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=img", cfg_id_init="my-img-key"),
        csf_key=None,
    )
    assert hab4.to_dict() == {"img_key": "my-img-key"}


def test_hab4_to_dict_partial_csf_key_only():
    hab4 = Hab4SigningCfg(
        img_key=None,
        csf_key=SigningKey(pkcs11_uri="pkcs11:token=SoftHSM;object=csf", cfg_id_init="my-csf-key"),
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


@pytest.mark.parametrize("data", [{}, {"signing-keys": None}])
def test_config_create_missing_top_level_fields(data):
    cfg = Config.from_dict(data)
    assert cfg.signing_keys == {}
    assert cfg.to_dict()["signing-keys"] == {}


def test_config_missing_key():
    with pytest.raises(OpensighubError, match="'acme-unknown' missing or unknown"):
        Config.from_dict({"signing-keys": {}, "swu": {"key": "acme-unknown"}})


@pytest.fixture
def profiles_config_dict():
    return {
        "signing-keys": {
            "default-key": {"pkcs11_uri": "pkcs11:token=t;object=default-key"},
            "product1-key": {"pkcs11_uri": "pkcs11:token=t;object=product1-key"},
        },
        "uefi": {"key": "default-key"},
        "profiles": {
            "product1": {"uefi": {"key": "product1-key"}, "swu": {"key": "product1-key"}},
            "empty": None,
        },
    }


def test_config_default_profile_is_top_level(profiles_config_dict):
    cfg = Config.from_dict(profiles_config_dict)
    assert cfg.uefi.key.cfg_id == "default-key"
    assert cfg.swu is None


def test_config_selects_profile(profiles_config_dict):
    cfg = Config.from_dict(profiles_config_dict)
    cfg.select_profile("product1")
    assert cfg.uefi.key.cfg_id == "product1-key"
    assert cfg.swu.key.cfg_id == "product1-key"


def test_config_unknown_profile_raises(profiles_config_dict):
    with pytest.raises(OpensighubError, match="Profile 'nope' not defined"):
        Config.from_dict(profiles_config_dict).select_profile("nope")


def test_config_profiles_round_trip(profiles_config_dict):
    cfg = Config.from_dict(profiles_config_dict)
    assert Config.from_dict(cfg.to_dict()) == cfg
    assert cfg.to_dict()["profiles"]["empty"] == {}


def test_set_key_for_signer_writes_given_profile(profiles_config_dict):
    cfg = Config.from_dict(profiles_config_dict)
    cfg.set_key_for_signer(QualifiedSignerPath(SignerPath.RPI, "empty"), "product1-key")
    assert cfg.profiles["empty"].rpi.key.cfg_id == "product1-key"
    assert cfg.default_profile.rpi is None
    cfg.set_key_for_signer(QualifiedSignerPath(SignerPath.RPI), "default-key")
    assert cfg.default_profile.rpi.key.cfg_id == "default-key"
    assert cfg.profiles["empty"].rpi.key.cfg_id == "product1-key"


def test_set_key_for_signer_unknown_profile_raises(profiles_config_dict):
    cfg = Config.from_dict(profiles_config_dict)
    with pytest.raises(OpensighubError, match="Profile 'nope' not defined"):
        cfg.set_key_for_signer(QualifiedSignerPath(SignerPath.RPI, "nope"), "product1-key")


@pytest.mark.parametrize("name", ["a/b", "a,b", "a b", ""])
def test_config_invalid_profile_name_raises(profiles_config_dict, name):
    profiles_config_dict["profiles"][name] = None
    with pytest.raises(OpensighubError, match="profile name"):
        Config.from_dict(profiles_config_dict)


def test_remove_signing_key_clears_all_profiles(profiles_config_dict):
    cfg = Config.from_dict(profiles_config_dict)
    cfg.remove_signing_key("product1-key")
    assert cfg.profiles["product1"].uefi == UefiSigningCfg(key=None)
    assert cfg.profiles["product1"].swu == SwuSigningCfg(key=None)
    assert cfg.uefi.key.cfg_id == "default-key"


def test_config_signer_sections_without_key_round_trip():
    data = {
        "signing-keys": {"k": {"pkcs11_uri": "pkcs11:token=t;object=k"}},
        "uefi": {"variables": {"db": {"guid": "d719b2cb-3d3a-4596-a3bc-dad00e67656f"}}},
        "swu": {},
        "kernel_modules": None,
        "rpi": {"hash": "sha256"},
        "profiles": {"product1": {"uefi": {"key": "k"}}},
    }
    cfg = Config.from_dict(data)
    assert cfg.uefi.key is None
    assert cfg.uefi.variables["db"].key is None
    assert cfg.swu.key is None
    assert cfg.kernel_modules.key is None
    assert cfg.rpi.key is None
    out = cfg.to_dict()
    assert out["uefi"] == {"variables": {"db": {"guid": "d719b2cb-3d3a-4596-a3bc-dad00e67656f"}}}
    assert out["swu"] == {}
    assert out["kernel_modules"] == {}
    assert out["rpi"] == {"hash": "sha256", "padding": "pkcs1"}
    assert out["profiles"]["product1"] == {"uefi": {"key": "k"}}


def test_verified():
    key = SigningKey(pkcs11_uri="pkcs11:token=t;object=k", cfg_id_init="k")
    assert SwuSigningCfg(key=None).verified() is None
    swu = SwuSigningCfg(key=key)
    assert swu.verified() is swu
    assert Hab4SigningCfg(img_key=key, csf_key=None).verified() is None
    verified_hab4 = Hab4SigningCfg(img_key=key, csf_key=key).verified()
    assert verified_hab4.img_key is key and verified_hab4.csf_key is key


def test_profile_name(profiles_config_dict):
    cfg = Config.from_dict(profiles_config_dict)
    assert cfg.profile_name == "default"
    cfg.select_profile("product1")
    assert cfg.profile_name == "product1"
