# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from multiprocessing import Pool
from pathlib import Path
from typing import IO

from opensighub.config import (
    Hab4SigningCfg,
    LinuxModuleSigningCfg,
    RawSigningCfg,
    SwuSigningCfg,
    UefiSigningCfg,
)
from opensighub.util import CertCache, Pkcs11Uri

logger = logging.getLogger("opensighub")


@dataclass
class SwuSignJob:
    artifact: Path
    signed_artifact: Path

    def sign(self, registry: "SignerRegistry") -> None:
        registry.get_swu_signer().sign(self.artifact, self.signed_artifact)


@dataclass
class UefiSignJob:
    artifact: Path
    signed_artifact: Path
    detached: bool = True

    def sign(self, registry: "SignerRegistry") -> None:
        registry.get_uefi_signer().sign(self.artifact, self.signed_artifact, self.detached)


@dataclass
class UefiVariableSignJob:
    variable_name: str
    artifact: Path
    signed_artifact: Path

    def sign(self, registry: "SignerRegistry") -> None:
        registry.get_uefi_variable_signer().sign(
            self.artifact, self.signed_artifact, self.variable_name
        )


@dataclass
class LinuxModuleSignJob:
    artifact: Path
    signed_artifact: Path
    detached: bool = True

    def sign(self, registry: "SignerRegistry") -> None:
        registry.get_linux_module_signer().sign(self.artifact, self.signed_artifact, self.detached)


@dataclass
class Hab4SignJob:
    csf_txt_in_path: Path
    csf_bin_out_path: Path
    auth_data_prefix: Path

    def sign(self, registry: "SignerRegistry") -> None:
        registry.get_hab4_signer().sign(
            self.csf_txt_in_path, self.csf_bin_out_path, self.auth_data_prefix
        )


@dataclass
class RawSignJob:
    artifact: Path
    signed_artifact: Path


@dataclass
class OpteeTaSignJob(RawSignJob):
    ta_type: str
    ta_ver: int | None

    def sign(self, registry: "SignerRegistry") -> None:
        registry.get_optee_ta_signer().sign(self.artifact, self.signed_artifact, self.ta_ver)


@dataclass
class RpiSignJob(RawSignJob):
    artifact: Path
    signed_artifact: Path

    def sign(self, registry: "SignerRegistry") -> None:
        registry.get_rpi_signer().sign(self.artifact, self.signed_artifact)


Job = (
    UefiSignJob
    | UefiVariableSignJob
    | LinuxModuleSignJob
    | Hab4SignJob
    | RpiSignJob
    | OpteeTaSignJob
    | SwuSignJob
)


class UefiSign:
    def __init__(self, cert_cache: CertCache, config: UefiSigningCfg):
        self.cert_cache: CertCache = cert_cache
        self.config = config

    def sign(self, artifact: Path, signed_artifact: Path, detached: bool = True):
        """Sign (U)EFI PE/Coff binaries with sbsign."""
        artifact = Path(artifact).resolve()
        signed_artifact = Path(signed_artifact).resolve()
        key_uri = Pkcs11Uri.try_parse(self.config.key.pkcs11_uri)
        key_uri, cert_uri = key_uri.to_private_cert_pair()
        certificate_file = self.cert_cache[cert_uri]
        cmd = ["sbsign"]
        if detached:
            cmd.append("--detached")
        cmd.extend(
            [
                "--engine",
                "pkcs11",
                "--key",
                str(key_uri),
                "--cert",
                str(certificate_file),
                "--output",
                str(signed_artifact),
                str(artifact),
            ]
        )
        logger.info("Sign UEFI binary %s", artifact)
        logger.debug("%s", " ".join([str(arg) for arg in cmd]))
        with tempfile.TemporaryDirectory() as tmp_working_dir:
            subprocess.check_call(cmd, cwd=tmp_working_dir)


class SwuSign:
    def __init__(self, cert_cache: CertCache, config: SwuSigningCfg):
        self.cert_cache: CertCache = cert_cache
        self.config = config

    def sign(self, artifact: Path, signed_artifact: Path, detached: bool = True):
        """Sign swu file"""
        signed_artifact.parent.mkdir(parents=True, exist_ok=True)
        key_uri = Pkcs11Uri.try_parse(self.config.key.pkcs11_uri)
        key_uri, cert_uri = key_uri.to_private_cert_pair()
        certificate_file = self.cert_cache[cert_uri]
        cmd = [
            "swugenerator",
            "-g",
            "pkcs11",
            "-f",
            "engine",
            "-k",
            "CMS," + str(key_uri) + "," + str(certificate_file),
            "-o",
            str(signed_artifact.resolve()),
            "sign",
            "-i",
            str(artifact.resolve()),
        ]
        logger.info("Signing swu file %s", artifact)
        logger.debug("%s", " ".join([str(arg) for arg in cmd]))
        with tempfile.TemporaryDirectory() as tmp_working_dir:
            subprocess.check_call(cmd, cwd=tmp_working_dir)


class UefiVariableSign:
    def __init__(self, cert_cache: CertCache, config: UefiSigningCfg):
        self.cert_cache: CertCache = cert_cache
        self.config = config

    def sign(self, artifact: Path, signed_artifact: Path, variable_name: str):
        """Sign arbitrary data blob as UEFI authenticated variable with sbvarsign.

        UEFI standardizes flexible key/value storage by means of EFI variables, where
        - the key is a simple string name, optionally scoped with a 16 byte GUID, and
        - the value can be an arbitrary blob.

        config may define a GUID. If no GUID is provided by config, the default GUID for "db" and "dbx" is
        EFI_IMAGE_SECURITY_DATABASE_GUID. For other variables, the default GUID is EFI_GLOBAL_VARIABLE as guid.

        config may define attributes for access and storage policy of the variable.

        Output of the signing process is a file consisting of attributes, authentication descriptor with signature
        and the data itself.
        """
        key_uri = Pkcs11Uri.try_parse(self.config.key.pkcs11_uri)
        key_uri, cert_uri = key_uri.to_private_cert_pair()
        certificate_file = self.cert_cache[cert_uri]

        cmd = ["sbvarsign"]
        attr_cmd_arg = []
        guid_cmd_arg = []
        if variable_name in self.config.variables:
            if (attributes := self.config.variables[variable_name].attributes) is not None:
                attr_cmd_arg = ["--attr", ",".join(attributes)]
            if (guid := self.config.variables[variable_name].guid) is not None:
                guid_cmd_arg = ["--guid", guid]
        cmd.extend(
            [
                "--engine",
                "pkcs11",
                "--key",
                str(key_uri),
                "--cert",
                str(certificate_file),
                *attr_cmd_arg,
                *guid_cmd_arg,
                "--output",
                str(signed_artifact),
                variable_name,
                str(artifact),
            ]
        )
        logger.info("Sign data blob %s to UEFI authenticated variable %s", artifact, variable_name)
        logger.debug("%s", " ".join([str(arg) for arg in cmd]))
        subprocess.check_call(cmd)


class LinuxModuleSign:
    def __init__(self, cert_cache: CertCache, config: LinuxModuleSigningCfg):
        self.cert_cache: CertCache = cert_cache
        self.config = config

    def sign(self, artifact: Path, signed_artifact: Path, detached: bool = True):
        """Sign a Linux Kernel module (*.ko) with sign-file.

        artifact: Linux kernel loadable module (.ko)
        signed_artifact: Detached signature file if detached is True, otherwise signed .ko file.
        detached: If True, don't append signature to .ko file but store separately

        For further information see
        https://docs.kernel.org/admin-guide/module-signing.html
        """
        key_uri = Pkcs11Uri.try_parse(self.config.key.pkcs11_uri)
        key_uri, cert_uri = key_uri.to_private_cert_pair()
        certificate_file = self.cert_cache[cert_uri]
        with tempfile.TemporaryDirectory() as tmp_dir_name:
            artifact_copy = Path(tmp_dir_name) / "module.ko"
            move_detached_signature = None
            shutil.copyfile(artifact, artifact_copy)
            cmd = ["sign-file"]
            if detached:
                cmd.append("-d")
            cmd.extend(["sha512", str(key_uri), str(certificate_file), str(artifact_copy)])
            if not detached:
                # custom destination is only supported for non-detached
                cmd.append(str(signed_artifact))
            else:
                move_detached_signature = Path(tmp_dir_name) / "module.ko.p7s"
            logger.info("Sign Linux Kernel Module %s", artifact)
            logger.debug("%s", " ".join([str(arg) for arg in cmd]))
            subprocess.check_call(cmd, cwd=tmp_dir_name)
            if move_detached_signature:
                shutil.move(move_detached_signature, signed_artifact)


class Hab4Sign:
    def __init__(self, cert_cache: CertCache, config: Hab4SigningCfg):
        self.cert_cache: CertCache = cert_cache
        self.config = config

    def make_srktable(self, output_dir: Path) -> Path:
        """Create a temporary SRK table blob from public key certificates.

        Requires srktool from NXP imx code signing tools.
        """
        srk_certs = [str(self.cert_cache[cert.pkcs11_uri]) for cert in self.config.srk_certificates]
        env = os.environ.copy()
        table_bin_outfile = output_dir / "table.bin"
        efuses_outfile = output_dir / "efuses.bin"
        cmd = [
            "srktool",
            "--hab_ver",
            "4",
            "--table",
            str(table_bin_outfile),
            "--efuses",
            str(efuses_outfile),
            "--digest",
            "sha256",
            "--certs",
            ",".join(srk_certs),
        ]
        logger.info("Generate HAB4 SRK table from certificates")
        logger.debug("%s", " ".join([str(arg) for arg in cmd]))
        subprocess.check_call(cmd, env=env)
        return table_bin_outfile

    @staticmethod
    def csf_substitute(
        csf_in_file: IO[str],
        csf_out_file: IO[str],
        srk_table: Path,
        srk_src_idx: int,
        csf_uri: str,
        img_uri: str,
        auth_data_prefix: Path = Path("/"),
    ):
        """Replace certificate paths in sequence file with real locations.

        For a specification of the CSF text format see NXP UG10106 6.1.
        """
        section_pattern = re.compile(r"\[(.*)]")
        key_pattern = re.compile(r"^\s*(.*?)\s*=(.*)$")
        section = None
        key = None
        value = None
        prev_line = None
        for line in csf_in_file:
            if line.endswith("\\\n"):
                line = line.rstrip("\\\n")
                prev_line = line if not prev_line else f"{prev_line} {line}"
                continue
            elif prev_line is not None:
                line = f"{prev_line} {line}"
                prev_line = None
            if matches := re.findall(section_pattern, line):
                section = matches[0].lower()
                key = None
            elif matches := re.findall(key_pattern, line):
                key = matches[0][0].lower()
                value = matches[0][1]
            elif not line.strip() or line.strip().startswith("#"):
                key = None
            if section == "install srk" and key == "file":
                csf_out_file.write(f'  File = "{srk_table}"\n')
            elif section == "install srk" and key == "source index":
                csf_out_file.write(f"  Source Index = {srk_src_idx}\n")
            elif section == "install csfk" and key == "file":
                csf_out_file.write(f'  File = "{csf_uri}"\n')
            elif section == "install key" and key == "file":
                csf_out_file.write(f'  File = "{img_uri}"\n')
            elif section == "authenticate data" and key == "blocks" and value:
                blocks = value.split(",")
                block_lines: list[str] = []
                for block in blocks:
                    block_args = block.strip().split(maxsplit=3)
                    prefixed_file = Path(auth_data_prefix) / Path(
                        block_args[3].lstrip(" \"'").rstrip(" \"'")
                    ).relative_to("/")
                    block_args[3] = f'"{prefixed_file}"'
                    if not block_lines:
                        block_lines.append("  Blocks = " + " ".join(block_args))
                    else:
                        block_lines.append("           " + " ".join(block_args))
                csf_out_file.write(", \\\n".join(block_lines) + "\n")
            else:
                csf_out_file.write(line)
        csf_out_file.flush()

    def sign(
        self, csf_txt_in_path: Path, csf_bin_out_path: Path, auth_data_prefix: Path = Path("/")
    ):
        """Create a CSF binary including signatures to verify a HAB4 binary.

        The signing process is as follows:
        1. Temporarily export public key certificates from PKCS#11 provider.
        2. Create temporary SRK table from the public key certificates.
        3. Set File in [Install SRK], [Install CSFK], [Install Key]
           CSF file sections to PKCS#11 URIs as given by Hab4SigningCfg.
        4. Sign using NXP cst 4.0 and keys from PKCS#11 provider.

        Note: File URIs refer to public key certificates. Corresponding
        private keys will be looked up by cst automatically by convention.
        """
        with (
            open(csf_txt_in_path, "r") as csf_in,
            tempfile.NamedTemporaryFile("w") as csf_tmp_out,
            tempfile.TemporaryDirectory() as tmp_working_dir,
        ):
            tmp_working_dir_path = Path(tmp_working_dir)
            srk_table = self.make_srktable(tmp_working_dir_path)
            self.csf_substitute(
                csf_in,
                csf_tmp_out,
                srk_table,
                self.config.srk_index,
                self.config.csf_key.pkcs11_uri,
                self.config.img_key.pkcs11_uri,
                auth_data_prefix,
            )
            cmd = ["cst", "-i", csf_tmp_out.name, "-o", str(csf_bin_out_path), "-b", "pkcs11"]
            logger.info("Sign HAB4 command sequence file %s", csf_txt_in_path)
            logger.debug("%s", " ".join([str(arg) for arg in cmd]))
            subprocess.check_call(cmd, cwd=tmp_working_dir_path)


class RawSign:
    def __init__(self, cert_cache: CertCache, config: RawSigningCfg):
        self.cert_cache: CertCache = cert_cache
        self.config = config

    def pkeyopt_args(self) -> list[str]:
        cfg = self.config
        args = [
            "-pkeyopt",
            "digest:" + cfg.alg_hash,
            "-pkeyopt",
            "rsa_padding_mode:" + cfg.padding,
        ]
        if cfg.padding == "pss":
            assert cfg.salt_len is not None
            mgf1 = cfg.mgf1_md or cfg.alg_hash
            args += [
                "-pkeyopt",
                "rsa_pss_saltlen:" + cfg.salt_len,
                "-pkeyopt",
                "rsa_mgf1_md:" + mgf1,
            ]
        return args

    def sign_digest(self, digest: Path, signed_digest: Path) -> None:
        """
        Basic raw-signature: digest (raw bytes) -> signed_digest
        using openssl pkeyutl + pkcs11.
        """
        key_uri = Pkcs11Uri.try_parse(self.config.key.pkcs11_uri)

        cmd = (
            [
                "openssl",
                "pkeyutl",
                "-engine",
                "pkcs11",
                "-keyform",
                "engine",
                "-sign",
                "-inkey",
                str(key_uri),
            ]
            + self.pkeyopt_args()
            + [
                "-in",
                str(digest),
                "-out",
                str(signed_digest),
            ]
        )
        logger.info("sign raw digest %s", digest)
        logger.debug("%s", " ".join([str(arg) for arg in cmd]))
        subprocess.run(cmd, check=True)

    def digest(self, artifact: Path, digest: Path):
        """
        Basic digest calculation: artifact (raw bytes) -> digest
        using openssl dgst.
        """
        cmd = [
            "openssl",
            "dgst",
            "-" + self.config.alg_hash,
            "-binary",
            "-out",
            str(digest),
            str(artifact),
        ]
        logger.info("Digest raw binary %s", artifact)
        logger.debug("%s", " ".join([str(arg) for arg in cmd]))
        subprocess.check_call(cmd)


class OpteeTaSign(RawSign):
    def sign(self, artifact: Path, signed_artifact: Path, ta_ver: int | None) -> None:
        """
        Creates optee-specific digest signature for trusted application.

        artifact          - .stripped.elf file
        signed_artifact   - file with detached signature (base64)
        """
        ta_uuid = artifact.name.removesuffix(".stripped.elf")

        key_uri = Pkcs11Uri.try_parse(self.config.key.pkcs11_uri)
        key_uri, pubkey_uri = key_uri.to_private_pubkey()
        pubkey_path = self.cert_cache[pubkey_uri]

        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            dig_file = tmpdir / (ta_uuid + ".dig")
            digest_bin = tmpdir / "digest.bin"
            sig_bin = tmpdir / "sig.bin"

            tool = shutil.which("sign_encrypt.py")
            if not tool:
                raise FileNotFoundError("sign_encrypt.py not found in PATH")

            # 1) Create optee specific digest
            cmd_digest = [
                "/usr/bin/python3",
                tool,
                "digest",
                "--key",
                str(pubkey_path),
                "--uuid",
                ta_uuid,
                "--in",
                str(artifact),
                "--dig",
                str(dig_file),
            ]
            if ta_ver is not None:
                cmd_digest += ["--ta-version", str(ta_ver)]
            subprocess.check_call(cmd_digest)

            # 2) Decode base64 payload
            dig_b64 = dig_file.read_bytes()
            dig_raw = base64.b64decode(dig_b64)
            digest_bin.write_bytes(dig_raw)

            # 3) Sign digest
            super().sign_digest(digest_bin, sig_bin)

            # 4) Encode back with base64
            sig_raw = sig_bin.read_bytes()
            sig_b64 = base64.b64encode(sig_raw)
            signed_artifact.write_bytes(sig_b64)

            # 5) Save ta rollback version (sign_encrypt.py defaults to 0 when
            # --ta-version is omitted)
            ver_path = signed_artifact.with_suffix(".ver")
            ver_path.write_text(str(ta_ver if ta_ver is not None else 0))


class RpiSign(RawSign):
    def sign(self, artifact: Path, signature: Path) -> None:
        """
        Sign a Raspberry boot container
        """
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            digest_bin = tmpdir / "tmp.dig"
            sig_bin = tmpdir / "sig.bin"

            super().digest(artifact, digest_bin)

            # Create signature
            super().sign_digest(digest_bin, sig_bin)

            # Create the format needed by rpi
            digest_hex = digest_bin.read_bytes().hex()
            sig_hex = sig_bin.read_bytes().hex()
            ts = int(time.time())
            signature.write_text(f"{digest_hex}\nts: {ts}\nrsa2048: {sig_hex}\n")


class SignerRegistry:
    """Gives each job typed access to exactly the signer it needs. Each job's
    sign() takes the registry and calls its own get_xxx_signer(), so no lookup
    anywhere needs to narrow or cast a signer's type."""

    def __init__(
        self,
        uefi_signer: UefiSign | None,
        uefi_variable_signer: UefiVariableSign | None,
        swu_signer: SwuSign | None,
        linux_module_signer: LinuxModuleSign | None,
        hab4_signer: Hab4Sign | None,
        optee_ta_signer: OpteeTaSign | None,
        rpi_signer: RpiSign | None,
    ):
        self._uefi_signer = uefi_signer
        self._uefi_variable_signer = uefi_variable_signer
        self._swu_signer = swu_signer
        self._linux_module_signer = linux_module_signer
        self._hab4_signer = hab4_signer
        self._optee_ta_signer = optee_ta_signer
        self._rpi_signer = rpi_signer

    def get_uefi_signer(self) -> UefiSign:
        if self._uefi_signer is None:
            raise ValueError("UEFI signer not configured")
        return self._uefi_signer

    def get_uefi_variable_signer(self) -> UefiVariableSign:
        if self._uefi_variable_signer is None:
            raise ValueError("UEFI signer not configured")
        return self._uefi_variable_signer

    def get_swu_signer(self) -> SwuSign:
        if self._swu_signer is None:
            raise ValueError("SWU signer not configured")
        return self._swu_signer

    def get_linux_module_signer(self) -> LinuxModuleSign:
        if self._linux_module_signer is None:
            raise ValueError("Linux module signer not configured")
        return self._linux_module_signer

    def get_hab4_signer(self) -> Hab4Sign:
        if self._hab4_signer is None:
            raise ValueError("HAB4 signer not configured")
        return self._hab4_signer

    def get_optee_ta_signer(self) -> OpteeTaSign:
        if self._optee_ta_signer is None:
            raise ValueError("OPTEE TA signer not configured")
        return self._optee_ta_signer

    def get_rpi_signer(self) -> RpiSign:
        if self._rpi_signer is None:
            raise ValueError("RPI signer not configured")
        return self._rpi_signer

    def sign(self, job: Job) -> None:
        job.sign(self)


class SigningPool:
    def __init__(
        self,
        uefi_signer: UefiSign | None,
        uefi_variable_signer: UefiVariableSign | None,
        swu_signer: SwuSign | None,
        linux_module_signer: LinuxModuleSign | None,
        hab4_signer: Hab4Sign | None,
        optee_ta_signer: OpteeTaSign | None,
        rpi_signer: RpiSign | None,
        parallel: int,
    ):
        self.registry = SignerRegistry(
            uefi_signer,
            uefi_variable_signer,
            swu_signer,
            linux_module_signer,
            hab4_signer,
            optee_ta_signer,
            rpi_signer,
        )
        self.parallel = parallel

    def sign(self, jobs: Sequence[Job]):
        with Pool(processes=self.parallel) as p:
            p.map(self.registry.sign, jobs)
