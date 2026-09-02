# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensighub.cli import DebianRun, sign_main
from opensighub.config import Config
from opensighub.debian import (
    DebianSigningJob,
    DebianSigningProcessor,
    FileEntry,
    FilesJson,
    LocalPackagePool,
    Package,
)
from opensighub.util import OpensighubError


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
def test_debsign(tmp_path, softhsm, debian_config_yaml_file):
    sign_main(
        DebianRun(
            config=debian_config_yaml_file,
            output=tmp_path,
            jobs=[
                DebianSigningJob(
                    signing_template="opensighub-test-package-signed-template",
                    version="1.0-1",
                    architecture="amd64",
                    suite_codename="./",
                    archive_id="local_test",
                ),
            ],
            parallel=5,
            force_overwrite=False,
        )
    )
    pkg = "opensighub-test-package-signed"
    assert (tmp_path / pkg).is_dir()
    assert (tmp_path / pkg / "debian").is_dir()
    assert (tmp_path / pkg / "debian" / "control").is_file()
    assert (tmp_path / pkg / "debian" / "rules").is_file()
    signatures_dir = tmp_path / pkg / "debian" / "signatures"
    assert signatures_dir.is_dir()
    signed = {p.name for p in signatures_dir.glob("**/*.sig")}
    assert signed == {"minimal.efi.sig", "minimal_hab4_csf.txt.sig", "minimal.ko.sig"}


@pytest.mark.integration
@pytest.mark.external
def test_debian_org_sign_and_build_shim(tmp_path, softhsm, debian_config_yaml_file):
    sign_main(
        DebianRun(
            config=debian_config_yaml_file,
            output=tmp_path,
            jobs=[
                DebianSigningJob(
                    signing_template="shim-helpers-amd64-signed-template",
                    version="16.1-2~deb13u1",
                    architecture="amd64",
                    suite_codename="trixie",
                    archive_id="debian_org",
                ),
            ],
            parallel=5,
            force_overwrite=False,
            run_sbuild=True,
            sbuild_args=["--no-clean-source"],
        )
    )
    debs = list(tmp_path.glob("shim-helpers-amd64-signed_*.deb"))
    assert debs, f"no built .deb found in {tmp_path}"


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


def test_pool_skips_download_if_available(empty_config):
    pool = LocalPackagePool(empty_config)
    pool.download_pkg = MagicMock()
    pool.extract_pkg = MagicMock(return_value=Path("/fake/extract/dir"))
    job = DebianSigningJob(
        archive_id="local",
        suite_codename="./",
        signing_template="foo-signed-template",
        architecture="amd64",
        version="1.0",
    )
    packages = {"foo-unsigned": Package(trusted_certs=[], files=[])}
    pool.download_and_extract_debian(job, packages)
    pool.download_and_extract_debian(job, packages)
    pool.download_pkg.assert_called_once()
    pool.extract_pkg.assert_called_once()


def test_pool_uses_per_package_version_override(empty_config):
    pool = LocalPackagePool(empty_config)
    pool.download_pkg = MagicMock()
    pool.extract_pkg = MagicMock(return_value=Path("/fake/extract/dir"))
    job = DebianSigningJob(
        archive_id="local",
        suite_codename="./",
        signing_template="foo-signed-template",
        architecture="amd64",
        version="257.13+acme1",
    )
    packages = {"systemd-boot-efi": Package(trusted_certs=[], files=[], version="257.13-1~deb13u1")}
    pool.download_and_extract_debian(job, packages)
    pool.download_pkg.assert_called_once_with(
        "systemd-boot-efi", "257.13-1~deb13u1", "./", "amd64", "local"
    )
    pool.extract_pkg.assert_called_once_with("systemd-boot-efi", "257.13-1~deb13u1", "amd64")


def test_processor_resolves_relative_spkg_out_dir(empty_config, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    processor = DebianSigningProcessor(empty_config, Path("signed"))
    assert processor.spkg_out_dir == tmp_path / "signed"


@pytest.fixture
def empty_config():
    return Config(
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


def test_prepare_dest_dir_overwrite_requires_confirmation(tmp_path, empty_config):
    dest_dir = tmp_path / "existing"
    dest_dir.mkdir()
    (dest_dir / "leftover.txt").touch()
    processor = DebianSigningProcessor(empty_config, tmp_path, force_overwrite=False)

    with pytest.raises(OpensighubError):
        processor._prepare_dest_dir(dest_dir)
    assert dest_dir.exists()

    processor.force_overwrite = True
    processor._prepare_dest_dir(dest_dir)
    assert not dest_dir.exists()


@pytest.fixture
def debsign_sbuild_processor(tmp_path, empty_config):
    return DebianSigningProcessor(empty_config, tmp_path, run_sbuild=True)


@pytest.fixture
def debsign_sbuild_job(debsign_sbuild_processor):
    job = DebianSigningJob(
        archive_id="debian_org",
        suite_codename="trixie",
        signing_template="foo-signed-template",
        architecture="amd64",
        version="1.0",
    )
    dist = debsign_sbuild_processor.repo.build_chdist_name(job.suite_codename, job.archive_id)
    apt_dir = debsign_sbuild_processor.repo.chdist_dir / dist / "etc" / "apt"
    apt_dir.mkdir(parents=True)
    (apt_dir / "sources.list").write_text(
        "deb [arch=amd64,arm64,armhf,i386] http://deb.debian.org/debian trixie main\n"
        "deb [arch=amd64,arm64,armhf,i386] http://security.debian.org/debian-security"
        " trixie-security main\n"
    )
    return job


def test_run_sbuild_omits_key_flag_without_archive_keyring(
    tmp_path, debsign_sbuild_processor, debsign_sbuild_job
):
    with patch("subprocess.check_call") as mock_call:
        debsign_sbuild_processor._run_sbuild(debsign_sbuild_job, tmp_path / "signed-pkg")
    cmd = mock_call.call_args[0][0]
    assert not any(arg.startswith("--extra-repository-key=") for arg in cmd)


def test_run_sbuild_passes_through_extra_args_before_source_dir(
    tmp_path, debsign_sbuild_processor, debsign_sbuild_job
):
    debsign_sbuild_processor.sbuild_args = ["--no-clean-source", "--verbose"]
    source_dir = tmp_path / "signed-pkg"
    with patch("subprocess.check_call") as mock_call:
        debsign_sbuild_processor._run_sbuild(debsign_sbuild_job, source_dir)
    cmd = mock_call.call_args[0][0]
    assert cmd[-3:] == ["--no-clean-source", "--verbose", str(source_dir)]
