# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import pytest

from opensighub.setup import KeyInfoColumn, get_key_info, setup_testenv_keys
from opensighub.util import OpensighubError


def test_setup_testenv_keys_requires_softhsm_setup_first(tmp_path, monkeypatch):
    monkeypatch.setattr("opensighub.setup.user_data_path", lambda name: tmp_path / "data")
    with pytest.raises(OpensighubError, match="opensighub setup softhsm"):
        setup_testenv_keys(tmp_path / "config.yaml")


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
def test_setup_get_key_info_status(softhsm, integration_config):
    key_info = get_key_info(integration_config, [KeyInfoColumn.STATUS], "acme-2025-uefi")
    assert len(key_info) == 1
    assert key_info[0][0] == "available"


@pytest.mark.integration
def test_setup_get_key_info_status_multiple_keys_preserves_order(softhsm, integration_config):
    key_info = get_key_info(integration_config, [KeyInfoColumn.KEYID, KeyInfoColumn.STATUS])
    assert [row[0] for row in key_info] == list(integration_config.signing_keys.keys())
    for row in key_info:
        assert row[1] in ("available", "loginrequired", "offline", "invalid")
    uefi_row = next(row for row in key_info if row[0] == "acme-2025-uefi")
    assert uefi_row[1] == "available"
