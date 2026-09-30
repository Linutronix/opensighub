# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import subprocess

import pytest

from opensighub.config import SigningKey
from opensighub.setup import (
    ExtendedKeyUsage,
    KeyInfoColumn,
    generate_csr,
    get_key_info,
    setup_testenv_keys,
)
from opensighub.util import OpensighubError


def test_setup_testenv_keys_requires_softhsm_setup_first(tmp_path, monkeypatch):
    monkeypatch.setattr("opensighub.setup.user_data_path", lambda name: tmp_path / "data")
    with pytest.raises(OpensighubError, match="opensighub setup softhsm"):
        setup_testenv_keys(tmp_path / "config.yaml")


@pytest.mark.integration
def test_setup_csr(softhsm_shared, integration_config, tmp_path):
    generate_csr(
        integration_config,
        "acme-2025-swu",
        tmp_path,
        False,
        country="DE",
        organization="opensighub test suite",
        common_name="opensighub test signer",
    )
    assert (tmp_path / "acme-2025-swu.csr").exists()


@pytest.mark.integration
def test_setup_csr_purpose_requests_extended_key_usage(
    softhsm_shared, integration_config, tmp_path
):
    generate_csr(
        integration_config,
        "acme-2025-swu",
        tmp_path,
        common_name="opensighub test signer",
        purpose=[ExtendedKeyUsage.CODE_SIGNING, ExtendedKeyUsage.TIME_STAMPING],
    )
    csr_text = subprocess.check_output(
        ["openssl", "req", "-in", str(tmp_path / "acme-2025-swu.csr"), "-noout", "-text"]
    ).decode()
    assert "X509v3 Extended Key Usage" in csr_text
    assert "Code Signing" in csr_text
    assert "Time Stamping" in csr_text


@pytest.mark.integration
def test_setup_csr_without_purpose_omits_extended_key_usage(
    softhsm_shared, integration_config, tmp_path
):
    generate_csr(
        integration_config,
        "acme-2025-swu",
        tmp_path,
        common_name="opensighub test signer",
    )
    csr_text = subprocess.check_output(
        ["openssl", "req", "-in", str(tmp_path / "acme-2025-swu.csr"), "-noout", "-text"]
    ).decode()
    assert "Extended Key Usage" not in csr_text


def test_setup_csr_unknown_purpose_raises(unit_config, tmp_path):
    with pytest.raises(OpensighubError, match="Unsupported purpose"):
        generate_csr(
            unit_config,
            "acme-2025-swu",
            tmp_path,
            common_name="opensighub test signer",
            purpose=["bogus"],
        )


def test_setup_csr_key_without_pkcs11_uri_raises(unit_config, tmp_path):
    unit_config.signing_keys["broken-key"] = SigningKey(pkcs11_uri=None, cfg_id_init="broken-key")
    with pytest.raises(OpensighubError, match="No signing key"):
        generate_csr(
            unit_config,
            "broken-key",
            tmp_path,
            common_name="opensighub test signer",
        )


def test_setup_get_key_info_name_uri(unit_config):
    key_info = get_key_info(
        unit_config, [KeyInfoColumn.KEYID, KeyInfoColumn.URI], key_id="acme-2025-uefi"
    )
    assert len(key_info) == 1
    assert key_info[0][0] == "acme-2025-uefi"
    assert key_info[0][1].startswith("pkcs11:token=SoftHSM;object=habIMG11?pin-source=")


def test_setup_get_key_info_all_name_uri(unit_config):
    key_info = get_key_info(unit_config, [KeyInfoColumn.KEYID, KeyInfoColumn.URI])
    assert len(key_info) == 7
    for columns in key_info:
        assert len(columns) == 2


@pytest.mark.integration
def test_setup_get_key_info_status(softhsm_shared, integration_config):
    key_info = get_key_info(integration_config, [KeyInfoColumn.STATUS], "acme-2025-uefi")
    assert len(key_info) == 1
    assert key_info[0][0] == "available"


@pytest.mark.integration
def test_setup_get_key_info_status_multiple_keys_preserves_order(
    softhsm_shared, integration_config
):
    key_info = get_key_info(integration_config, [KeyInfoColumn.KEYID, KeyInfoColumn.STATUS])
    assert [row[0] for row in key_info] == list(integration_config.signing_keys.keys())
    for row in key_info:
        assert row[1] in ("available", "loginrequired", "offline", "invalid")
    uefi_row = next(row for row in key_info if row[0] == "acme-2025-uefi")
    assert uefi_row[1] == "available"
