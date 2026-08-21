# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from opensighub.cli import DebianRun, sign_main
from opensighub.config import Config
from opensighub.debian import DebianSigningJob, FileEntry, FilesJson, LocalPackagePool, Package


@pytest.fixture
def files_json():
    """Sample files.json as included in Debian's grub package."""
    return """{
    "version": "2",
    "packages": {
        "pkg:deb/debian/grub-efi-amd64-bin@2.06-13+deb12u1?arch=amd64&distro=bookworm": {
            "trusted_certs": [],
            "files": [
                {"sig_type": "efi", "file": "usr/lib/grub/x86_64-efi/monolithic/gcdx64.efi"},
                {"sig_type": "efi", "file": "usr/lib/grub/x86_64-efi/monolithic/grubnetx64.efi"},
                {"sig_type": "efi", "file": "usr/lib/grub/x86_64-efi/monolithic/grubnetx64-installer.efi"},
                {"sig_type": "efi", "file": "usr/lib/grub/x86_64-efi/monolithic/grubx64.efi"}
            ]
        }
    }
}"""


@pytest.mark.integration
def test_debian_org_sign_shim(tmp_path, softhsm, sample_config_yaml_file):
    """Sign shim from internet debian.org archive."""
    sign_main(
        DebianRun(
            config=sample_config_yaml_file,
            output=tmp_path,
            jobs=[
                DebianSigningJob(
                    signing_template="shim-helpers-amd64-signed-template",
                    version="15.8-1",
                    architecture="amd64",
                    suite_codename="trixie",
                    archive_id="debian_org",
                ),
                DebianSigningJob(
                    signing_template="shim-helpers-arm64-signed-template",
                    version="15.8-1",
                    architecture="arm64",
                    suite_codename="trixie",
                    archive_id="debian_org",
                ),
            ],
            parallel=5,
        )
    )
    for pkg in ["shim-helpers-amd64-signed", "shim-helpers-arm64-signed"]:
        assert (tmp_path / pkg).is_dir()
        assert (tmp_path / pkg / "debian").is_dir()
        assert (tmp_path / pkg / "debian" / "control").is_file()
        assert (tmp_path / pkg / "debian" / "rules").is_file()
        assert (tmp_path / pkg / "debian" / "signatures").is_dir()
        assert len(list((tmp_path / pkg / "debian" / "signatures").glob("**/*.efi.sig"))) == 2


def test_files_json(files_json):
    json_obj = json.loads(files_json)
    files = FilesJson.from_dict(json_obj)
    assert files == FilesJson(
        version=2,
        packages={
            "pkg:deb/debian/grub-efi-amd64-bin@2.06-13+deb12u1?arch=amd64&distro=bookworm": Package(
                trusted_certs=[],
                files=[
                    FileEntry(
                        sig_type="efi",
                        file=Path("usr/lib/grub/x86_64-efi/monolithic/gcdx64.efi"),
                    ),
                    FileEntry(
                        sig_type="efi",
                        file=Path("usr/lib/grub/x86_64-efi/monolithic/grubnetx64.efi"),
                    ),
                    FileEntry(
                        sig_type="efi",
                        file=Path("usr/lib/grub/x86_64-efi/monolithic/grubnetx64-installer.efi"),
                    ),
                    FileEntry(
                        sig_type="efi",
                        file=Path("usr/lib/grub/x86_64-efi/monolithic/grubx64.efi"),
                    ),
                ],
            )
        },
    )


def test_build_chdist_name_regular_suite():
    assert LocalPackagePool.build_chdist_name("trixie", "local_test") == "local_test-trixie"


def test_build_chdist_name_flat_suite_strips_trailing_slash():
    assert LocalPackagePool.build_chdist_name("./", "local_test") == "local_test-."


def test_pool_skips_download_if_available():
    cfg = Config(
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
    pool = LocalPackagePool(cfg)
    pool.download_pkg = MagicMock()
    pool.extract_pkg = MagicMock(return_value=Path("/fake/extract/dir"))
    job = DebianSigningJob(
        archive_id="local",
        suite_codename="./",
        signing_template="foo-signed-template",
        architecture="amd64",
        version="1.0",
    )
    pool.download_and_extract_debian(job, ["foo-unsigned"])
    pool.download_and_extract_debian(job, ["foo-unsigned"])
    pool.download_pkg.assert_called_once()
    pool.extract_pkg.assert_called_once()
