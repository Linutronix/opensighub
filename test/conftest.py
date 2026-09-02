# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import os
import platform
import subprocess
from pathlib import Path

import pytest
import yaml

from opensighub.config import Config


def pytest_collection_modifyitems(items):
    for item in items:
        if not any(m.name in ("integration", "live") for m in item.iter_markers()):
            item.add_marker(pytest.mark.unit)


def pytest_addoption(parser):
    parser.addoption(
        "--sign-file-path",
        action="store",
        help="Path to sign-file",
    )
    parser.addoption(
        "--optee-scripts-path",
        action="store",
        help="Path to optee scripts",
    )
    parser.addoption(
        "--rpi-eeprom-tool-path",
        action="store",
        help="Path to rpi-eeprom-digest tool",
    )
    parser.addoption(
        "--build-dir",
        action="store",
        help="Directory where test artifacts where built. Defaults to test/build/.",
    )


def pytest_generate_tests(metafunc):
    sign_file_path_opt = metafunc.config.getoption("sign_file_path")
    if sign_file_path_opt:
        sign_file_path = sign_file_path_opt
    else:
        uname_no_arch = platform.uname().release.rsplit("-", maxsplit=1)[0]
        sign_file_path = f"/usr/lib/linux-kbuild-{uname_no_arch}/scripts"

    optee_scripts_path = metafunc.config.getoption("optee_scripts_path")
    rpi_eeprom_tool_path = metafunc.config.getoption("rpi_eeprom_tool_path")

    # assemble PATH
    path_parts = [os.environ.get("PATH", "")]
    path_parts.append(sign_file_path)
    if optee_scripts_path:
        path_parts.append(optee_scripts_path)

    if rpi_eeprom_tool_path:
        path_parts.append(rpi_eeprom_tool_path)

    os.environ["PATH"] = ":".join(path_parts)


@pytest.fixture(scope="session")
def project_root_path(request):
    return request.config.rootpath


@pytest.fixture(scope="session")
def build_dir(request, project_root_path):
    build_dir_opt = request.config.getoption("build_dir")
    if build_dir_opt:
        return Path(build_dir_opt)
    return project_root_path / "test" / "build"


@pytest.fixture
def softhsm2_conf(tmp_path, monkeypatch):
    token_dir = tmp_path / "softhsm2-tokens"
    token_dir.mkdir()
    conf_file = tmp_path / "softhsm2.conf"
    conf_file.write_text(
        f"directories.tokendir = {token_dir}\nobjectstore.backend = file\nlog.level = INFO\n"
    )
    monkeypatch.setenv("SOFTHSM2_CONF", str(conf_file))

    openssl_conf = tmp_path / "openssl.cnf"
    openssl_conf.write_text("""\
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
activate = 1
pkcs11-module-block-operations = digest
""")
    monkeypatch.setenv("OPENSSL_CONF", str(openssl_conf))

    return conf_file


@pytest.fixture
def softhsm(softhsm2_conf, project_root_path):
    cmd = [
        "softhsm2-util",
        "--init-token",
        "--free",
        "--label",
        "SoftHSM",
        "--pin",
        "1234",
        "--so-pin",
        "5678",
    ]
    subprocess.check_call(cmd)
    subprocess.check_call([project_root_path / "test" / "scripts" / "enroll_test_pki.sh"])


@pytest.fixture
def sample_pin_file(tmp_path):
    pin_file = tmp_path / "pin.txt"
    with open(pin_file, "w") as f:
        f.write("1234")
    return pin_file


def _assert_build(path):
    assert path.exists(), f"{path} missing, run 'invoke build-signables' first"
    return path


@pytest.fixture
def sample_blob(build_dir):
    return _assert_build(build_dir / "hab4" / "minimal_hab4.bin")


@pytest.fixture
def sample_efi_file(build_dir):
    return _assert_build(build_dir / "efi" / "minimal.efi")


@pytest.fixture
def sample_ko_file(build_dir):
    return _assert_build(build_dir / "ko" / "minimal.ko")


@pytest.fixture
def sample_hab4csf_file(project_root_path):
    return project_root_path / "test" / "signables" / "hab4" / "minimal_hab4_csf.txt"


@pytest.fixture
def sample_ta_file(build_dir):
    uuid_file = _assert_build(build_dir / "elf" / ".uuid")
    ta_dir = build_dir / "elf"

    uuid_str = uuid_file.read_text(encoding="utf-8").strip()
    if not uuid_str:
        raise RuntimeError(f"UUID file is empty: {uuid_file}")

    return ta_dir / f"{uuid_str}.stripped.elf"


@pytest.fixture
def sample_rpi_boot_file(build_dir):
    return _assert_build(build_dir / "rpi-boot-container" / "boot.img")


@pytest.fixture
def repo_pubkey_file(project_root_path):
    return project_root_path / "test" / "trusted.d" / "debian-archive-trixie-stable.asc"


@pytest.fixture
def swu_file(project_root_path):
    return project_root_path / "test" / "signables" / "swu" / "out.swu"


@pytest.fixture
def signing_config_yaml_block(sample_pin_file):
    return f"""trusted-certificates:
  acme-2025-hab4-srk1:
    pkcs11_uri: "pkcs11:token=SoftHSM;object=habSRK1CA;type=cert"
  acme-2025-hab4-srk2:
    pkcs11_uri: "pkcs11:token=SoftHSM;object=habSRK2CA;type=cert"

signing-keys:
  acme-2025-uefi:
    pkcs11_uri: "pkcs11:token=SoftHSM;object=habIMG11?pin-source={sample_pin_file}"
  acme-2025-kernelmodules:
    pkcs11_uri: "pkcs11:token=SoftHSM;object=habIMG11?pin-source={sample_pin_file}"
  acme-2025-hab4-img:
    pkcs11_uri: "pkcs11:token=SoftHSM;object=habIMG11?pin-source={sample_pin_file}"
  acme-2025-hab4-csf:
    pkcs11_uri: "pkcs11:token=SoftHSM;object=habCSF11?pin-source={sample_pin_file}"
  acme-2025-ta-root:
    pkcs11_uri: "pkcs11:token=SoftHSM;object=ta-root-key?pin-source={sample_pin_file}"
  acme-2025-rpi-boot:
    pkcs11_uri: "pkcs11:token=SoftHSM;object=rpi-boot-key?pin-source={sample_pin_file}"
  acme-2025-swu:
    pkcs11_uri: "pkcs11:token=SoftHSM;object=SWU?pin-source={sample_pin_file}"

uefi:
  key: acme-2025-uefi
  variables:
    myvar:
      attributes: ["BOOTSERVICE_ACCESS", "NON_VOLATILE"]
      guid: 5feb76ef-8320-47b1-ba80-1e23b8a25286
      key: acme-2025-uefi

kernel_modules:
  key: acme-2025-uefi

optee_ta:
  key: acme-2025-ta-root
  hash: sha256
  padding: pss
  saltlen: digest

hab4:
  img_key: acme-2025-hab4-img
  csf_key: acme-2025-hab4-csf
  srk_certificates:
  - acme-2025-hab4-srk1
  - acme-2025-hab4-srk2
  srk_index: 1

rpi:
  key: acme-2025-rpi-boot
  hash: sha256
  padding: pkcs1

swu:
  key: acme-2025-swu
"""


@pytest.fixture
def unit_config_yaml(repo_pubkey_file, signing_config_yaml_block):
    return f"""---
log-level: DEBUG

archives:
  debian_org:
    deb:
      - url: http://ftp.de.debian.org/debian
      - url: http://security.debian.org/debian-security
        suffix: "-security"

archive-keyring: {repo_pubkey_file}

{signing_config_yaml_block}"""


@pytest.fixture
def apt_signing_archive(build_dir):
    archive_dir = build_dir / "apt-signing-archive"
    _assert_build(archive_dir / "Packages")
    return archive_dir


@pytest.fixture
def integration_config_yaml(repo_pubkey_file, apt_signing_archive, signing_config_yaml_block):
    return f"""---
log-level: DEBUG

archives:
  debian_org:
    deb:
      - url: http://ftp.de.debian.org/debian
      - url: http://security.debian.org/debian-security
        suffix: "-security"
  local:
    deb:
      - url: file://{apt_signing_archive}
        trusted: true

archive-keyring: {repo_pubkey_file}

{signing_config_yaml_block}"""


@pytest.fixture
def integration_config_yaml_file(tmp_path, integration_config_yaml):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(integration_config_yaml)
    return cfg_file


@pytest.fixture
def integration_config(integration_config_yaml):
    cfg_dict = yaml.safe_load(integration_config_yaml)
    return Config.from_dict(cfg_dict)
