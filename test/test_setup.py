# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import pytest

from opensighub.setup import setup_testenv_keys
from opensighub.util import OpensighubError


def test_setup_testenv_keys_requires_softhsm_setup_first(tmp_path, monkeypatch):
    monkeypatch.setattr("opensighub.setup.user_data_path", lambda name: tmp_path / "data")
    with pytest.raises(OpensighubError, match="osh setup softhsm"):
        setup_testenv_keys(tmp_path / "config.yaml")
