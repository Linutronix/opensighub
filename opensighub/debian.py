# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from opensighub.config import Config
from opensighub.signers import (
    Hab4SignJob,
    LinuxModuleSignJob,
    OpteeTaSignJob,
    RpiSignJob,
    SigningPool,
    UefiSignJob,
    confirm_overwrite,
)

logger = logging.getLogger("opensighub")


@dataclass
class DebianSigningJob:
    archive_id: str
    suite_codename: str
    signing_template: str
    architecture: str
    version: str


@dataclass
class FileEntry:
    sig_type: str
    file: Path
    version: int | None = None


@dataclass
class Package:
    trusted_certs: list[str]
    files: list[FileEntry]

    @classmethod
    def from_dict(cls, data):
        return cls(
            trusted_certs=list(data.get("trusted_certs")),
            files=[
                FileEntry(
                    sig_type=f["sig_type"],
                    file=Path(f["file"]),
                    version=int(f["version"]) if "version" in f else None,
                )
                for f in data.get("files")
            ],
        )


@dataclass
class FilesJson:
    """Represent Debian files.json scheme as python class."""

    version: int
    packages: dict[str, Package]

    @classmethod
    def from_dict(cls, data):
        return cls(
            version=int(data.get("version", 2)),
            packages={
                purl: Package.from_dict(package) for purl, package in data.get("packages").items()
            },
        )


@dataclass
class PkgInfo:
    extract_dir: Path
    bin_pkg: str


class LocalPackagePool:
    def __init__(self, config: Config):
        self.config = config
        self.tmp_dir = TemporaryDirectory()
        self.download_dir = Path(self.tmp_dir.name)
        self.extracted_dir = self.download_dir / "extracted"
        self.chdist_dir = self.download_dir / "chdist"
        self.dirs_by_pkgname: dict[str, PkgInfo] = {}

    def download_and_extract_debian(self, job: DebianSigningJob, job_bin_packages: Iterable[str]):
        for package_name in job_bin_packages:
            if package_name in self.dirs_by_pkgname:
                continue
            self.download_pkg(
                package_name,
                job.version,
                job.suite_codename,
                job.architecture,
                job.archive_id,
            )
            extracted_dir = self.extract_pkg(package_name, job.version, job.architecture)
            self.dirs_by_pkgname[package_name] = PkgInfo(extracted_dir, package_name)

    def download_pkg(self, pkg: str, version: str, suite: str, architecture: str, archive: str):
        """Run apt download in a chdist environment."""
        cmd = [
            "chdist",
            "-d",
            str(self.chdist_dir),
            "-a",
            architecture,
            "apt-get",
            self.build_chdist_name(suite, archive),
            "download",
            f"{pkg}={version}",
        ]
        logger.info("Downloading %s", pkg)
        logger.debug("%s", " ".join([str(arg) for arg in cmd]))
        subprocess.check_call(cmd, cwd=self.download_dir)

    def extract_pkg(self, pkg: str, version: str, arch: str) -> Path:
        pkg_full_name = self.build_pkg_full_name(pkg, version, arch)
        pkg_file_name = self.build_pkg_deb_name(pkg, version, arch)
        unpack_dir = self.extracted_dir / pkg_full_name
        os.makedirs(unpack_dir)
        cmd = ["dpkg", "-x", pkg_file_name, unpack_dir]
        logger.info("Extracting %s", pkg)
        logger.debug("%s", " ".join([str(arg) for arg in cmd]))
        subprocess.check_call(cmd, cwd=self.download_dir)
        return unpack_dir

    def update_or_create_chdist(self, suite_codename: str, archive: str):
        dist = self.build_chdist_name(suite_codename, archive)
        sources_list_d = self.chdist_dir / dist / "etc" / "apt" / "sources.list"
        if (
            not os.path.isdir(self.chdist_dir)
            or dist
            not in subprocess.check_output(["chdist", "-d", str(self.chdist_dir), "list"])
            .decode("ascii")
            .strip()
        ):
            logger.info(f"Creating new dist {dist}")
            cmd = [
                "chdist",
                "-d",
                str(self.chdist_dir),
                "create",
                dist,
                self.config.archives[archive].deb[0].url,
                suite_codename,
                "main",
            ]
            logger.debug("%s", " ".join([str(arg) for arg in cmd]))
            subprocess.check_call(cmd)
            with open(sources_list_d, "w") as sourceslist:
                for target in self.config.archives[archive].deb:
                    codename = target.prefix if target.prefix else ""
                    codename += suite_codename
                    if target.suffix:
                        codename += target.suffix
                    options = "arch=amd64,arm64,armhf,i386"
                    if target.trusted:
                        options += " trusted=yes"
                    # a codename ending in "/" denotes a flat (dists-less) repository,
                    # whose sources.list entry must not carry a component
                    component = "" if codename.endswith("/") else " main"
                    sourceslist.write(f"deb [{options}] {target.url} {codename}{component}\n")

            if self.config.archive_keyring:
                keyring_name = "archive" + self.config.archive_keyring.suffix
                os.symlink(
                    self.config.archive_keyring.absolute(),
                    self.chdist_dir / dist / "etc" / "apt" / "trusted.gpg.d" / keyring_name,
                )

        subprocess.check_call(["chdist", "-d", str(self.chdist_dir), "apt-get", dist, "update"])

    @staticmethod
    def build_chdist_name(suite_codename: str, archive: str) -> str:
        return f"{archive}-{suite_codename.rstrip('/')}"

    @staticmethod
    def build_pkg_full_name(pkg: str, version: str, arch: str):
        # omit epoch from version
        version = version.rsplit(":")[-1]
        return f"{pkg}_{version}_{arch}"

    @staticmethod
    def build_pkg_deb_name(pkg: str, version: str, arch: str):
        version = version.replace(":", "%3a")
        return f"{pkg}_{version}_{arch}.deb"


class DebianSigningProcessor:
    def __init__(
        self,
        config: Config,
        spkg_out_dir: Path,
        force_overwrite: bool = False,
    ):
        self.config: Config = config
        self.repo = LocalPackagePool(config)
        self.spkg_out_dir: Path = spkg_out_dir
        self.force_overwrite = force_overwrite
        self.files_json_path: Path | None = None
        self.template_source_dir: Path | None = None

    def process(self, job: DebianSigningJob, pool: SigningPool):
        self.repo.update_or_create_chdist(job.suite_codename, job.archive_id)
        self._install_signing_template(
            job.signing_template, job.version, job.architecture, job.suite_codename, job.archive_id
        )
        self._fetch_and_sign(job, pool)
        assert self.template_source_dir is not None
        source_name = (
            subprocess.check_output(
                ["dpkg-parsechangelog", "-S", "Source"], cwd=self.template_source_dir
            )
            .decode(sys.stdout.encoding)
            .strip()
        )
        dest_dir = self.spkg_out_dir / Path(source_name)
        self._prepare_dest_dir(dest_dir)
        logger.info("Move extracted and signed source package to %s", dest_dir)
        shutil.move(self.template_source_dir, dest_dir)

    def _prepare_dest_dir(self, dest_dir: Path) -> None:
        if dest_dir.exists():
            confirm_overwrite(dest_dir, self.force_overwrite)
            shutil.rmtree(dest_dir)

    def _install_signing_template(
        self,
        signing_template: str,
        version: str,
        architecture: str,
        suite_codename: str,
        archive_id: str,
    ):
        self.repo.download_pkg(
            signing_template,
            version,
            suite_codename,
            architecture,
            archive_id,
        )
        template_unpack_dir = self.repo.extract_pkg(signing_template, version, architecture)
        signing_template_dir = (
            template_unpack_dir / "usr" / "share" / "code-signing" / signing_template
        )
        self.template_source_dir = signing_template_dir / "source-template"
        self.files_json_path = signing_template_dir / "files.json"

    def _fetch_and_sign(self, job: DebianSigningJob, pool: SigningPool):
        assert self.files_json_path is not None
        jobs = []
        with open(self.files_json_path, "r") as f:
            files = FilesJson.from_dict(json.load(f))
            self.repo.download_and_extract_debian(job, files.packages.keys())
            for pkg_name, pkg_data in files.packages.items():
                for file in pkg_data.files:
                    jobs.append(self._make_job(pkg_name, file))
        pool.sign(jobs)

    def _make_job(
        self, pkg_name: str, file: FileEntry
    ) -> Hab4SignJob | LinuxModuleSignJob | UefiSignJob | OpteeTaSignJob | RpiSignJob:
        assert self.template_source_dir is not None
        pkg_dir = self.repo.dirs_by_pkgname[pkg_name].extract_dir
        rel_file = file.file.relative_to("/") if file.file.is_absolute() else file.file
        unsigned_file = pkg_dir / rel_file
        detached_sig_path = (
            self.template_source_dir
            / "debian"
            / "signatures"
            / self.repo.dirs_by_pkgname[pkg_name].bin_pkg
            / rel_file.with_suffix(rel_file.suffix + ".sig")
        )
        detached_sig_path.parent.mkdir(parents=True, exist_ok=True)
        if file.sig_type == "efi" and self.config.uefi:
            return UefiSignJob(unsigned_file, detached_sig_path)
        elif file.sig_type == "hab4" and self.config.hab4:
            return Hab4SignJob(unsigned_file, detached_sig_path, pkg_dir)
        elif file.sig_type == "linux-module" and self.config.kernel_modules:
            return LinuxModuleSignJob(unsigned_file, detached_sig_path)
        elif (file.sig_type == "optee-ta-core") and self.config.optee_ta:
            return OpteeTaSignJob(unsigned_file, detached_sig_path, file.sig_type, file.version)
        elif (file.sig_type == "rpi-boot") and self.config.rpi:
            return RpiSignJob(unsigned_file, detached_sig_path)

        raise ValueError(
            f"files.json lists signature type {file.sig_type}, but no such signer is configured"
        )

    def cleanup(self):
        self.repo.tmp_dir.cleanup()
