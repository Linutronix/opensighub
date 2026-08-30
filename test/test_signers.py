# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import shutil
import subprocess

import pytest

from opensighub.cli import UefiVariableRun, sign_main
from opensighub.signers import (
    Hab4Sign,
    LinuxModuleSign,
    OpteeTaSign,
    RpiSign,
    SwuSign,
    UefiSign,
    UefiVariableSign,
    UefiVariableSignJob,
)
from opensighub.util import CertCache, Pkcs11Uri


@pytest.mark.integration
def test_uefi_sign(softhsm, sample_config, sample_efi_file, tmp_path):
    signature_dest = tmp_path / "signature.pk7"
    with CertCache() as cc:
        uefi_signer = UefiSign(cc, sample_config.uefi)
        uefi_signer.sign(sample_efi_file, signature_dest)
        assert signature_dest.is_file()
        subprocess.check_call(
            [
                "sbverify",
                "--cert",
                cc[Pkcs11Uri.try_parse(sample_config.uefi.key.pkcs11_uri)],
                "--detached",
                signature_dest,
                sample_efi_file,
            ]
        )


@pytest.mark.integration
def test_uefi_variable_sign(softhsm, sample_config, sample_blob, tmp_path):
    signature_dest = tmp_path / "myvar.auth"
    with CertCache() as cc:
        uefi_variable_signer = UefiVariableSign(cc, sample_config.uefi)
        uefi_variable_signer.sign(sample_blob, signature_dest, "myvar")
        assert signature_dest.is_file()


@pytest.mark.integration
def test_kernel_module_sign(softhsm, sample_config, sample_ko_file, tmp_path):
    signature_dest = tmp_path / "signature.pk7"
    with CertCache() as cc:
        kernel_module_signer = LinuxModuleSign(cc, sample_config.kernel_modules)
        kernel_module_signer.sign(sample_ko_file, signature_dest)
        assert signature_dest.is_file()
        subprocess.check_call(
            [
                "openssl",
                "smime",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                signature_dest,
                "-content",
                sample_ko_file,
                "-certfile",
                cc[Pkcs11Uri.try_parse(sample_config.kernel_modules.key.pkcs11_uri)],
                "-nointern",
                "-noverify",
            ]
        )


@pytest.mark.integration
def test_hab4_sign(softhsm, sample_config, sample_hab4csf_file, tmp_path):
    path_to_minimal_hab4_bin = sample_hab4csf_file.parent
    signed_csf_dest = tmp_path / "csf.bin"
    with CertCache() as cc:
        hab4_signer = Hab4Sign(cc, sample_config.hab4)
        hab4_signer.sign(sample_hab4csf_file, signed_csf_dest, path_to_minimal_hab4_bin)
    assert signed_csf_dest.is_file()
    parser_stdout = subprocess.check_output(["hab_csf_parser", "-c", signed_csf_dest])
    assert any(
        check_ok in parser_stdout.decode("ascii")
        for check_ok in [
            "SRK Table file created",
            "CSF Certificate Detected",
            "IMG Certificate Detected",
            "Certificate file created",
            "Certificate file created",
            "Signature file created",
            "Signature file created",
        ]
    )


@pytest.mark.integration
def test_uefi_variable_sign_cli(softhsm, sample_config_yaml_file, sample_blob, tmp_path):
    signed_artifact = tmp_path / "myvar.auth"
    sign_main(
        UefiVariableRun(
            config=sample_config_yaml_file,
            output=tmp_path,
            jobs=[
                UefiVariableSignJob(
                    variable_name="myvar", artifact=sample_blob, signed_artifact=signed_artifact
                ),
            ],
            parallel=5,
            force_overwrite=False,
        )
    )
    assert signed_artifact.is_file()


@pytest.mark.integration
def test_optee_ta_sign(softhsm, sample_config, sample_ta_file, tmp_path):
    signature_dest = tmp_path / "signature.bin"
    with CertCache() as cc:
        ver = 1
        optee_ta_signer = OpteeTaSign(cc, sample_config.optee_ta)
        optee_ta_signer.sign(sample_ta_file, signature_dest, ver)
        assert signature_dest.is_file()
        out_ta = tmp_path / "test.ta"
        ta_uuid = sample_ta_file.name.split(".")[0]

        key_uri = Pkcs11Uri.try_parse(optee_ta_signer.config.key.pkcs11_uri)
        key_uri, pubkey_uri = key_uri.to_private_pubkey()
        pubkey_path = optee_ta_signer.cert_cache[pubkey_uri]

        tool = shutil.which("sign_encrypt.py")
        assert tool

        cmd = [
            "/usr/bin/python3",
            tool,
            "stitch",
            "--uuid",
            ta_uuid,
            "--in",
            str(sample_ta_file),
            "--key",
            str(pubkey_path),
            "--out",
            str(out_ta),
            "--sig",
            str(signature_dest),
            "--ta-version",
            str(ver),
        ]
        subprocess.check_call(cmd)
        assert out_ta.is_file()


@pytest.mark.integration
def test_rpi_boot_sign(softhsm, sample_config, sample_rpi_boot_file, tmp_path):
    signature_dest = tmp_path / "signature.bin"
    with CertCache() as cc:
        rpi_signer = RpiSign(cc, sample_config.rpi)
        rpi_signer.sign(sample_rpi_boot_file, signature_dest)
        assert signature_dest.is_file()

        key_uri = Pkcs11Uri.try_parse(sample_config.rpi.key.pkcs11_uri)
        key_uri, pubkey_uri = key_uri.to_private_pubkey()

        # Verify signature with rpi-eeprom-digest tool
        subprocess.check_call(
            [
                "rpi-eeprom-digest",
                "-k",
                cc[pubkey_uri],
                "-i",
                sample_rpi_boot_file,
                "-v",
                signature_dest,
            ]
        )


@pytest.mark.integration
def test_swu_sign(softhsm, sample_config, swu_file, tmp_path):
    sig_dest = tmp_path / "sign.swu"
    with CertCache() as cc:
        swu_signer = SwuSign(cc, sample_config.swu)
        swu_signer.sign(swu_file, sig_dest)
        assert sig_dest.is_file()
