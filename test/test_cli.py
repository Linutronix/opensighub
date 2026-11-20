# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import os
import shutil
import signal
import subprocess
from pathlib import Path

import pytest
from helpers import wait_for

from opensighub.cli import (
    DebSignCmd,
    EfiBinarySignCmd,
    GenKeyCmd,
    UefiVarSignCmd,
    parse_args,
    sign_main,
)
from opensighub.debian import DebianSigningJob
from opensighub.signers import UefiSignJob, UefiVariableSignJob
from opensighub.util import OpensighubError


def test_cli():
    argv = [
        "--config",
        "config.yaml",
        "--output",
        "/test/dir",
        "uefivarsign",
        "my_var_1:myvar1.bin",
        "my_var_2:myvar2.bin",
    ]
    run_config = parse_args(argv)
    assert run_config == UefiVarSignCmd(
        config_path=Path("config.yaml"),
        jobs=[
            UefiVariableSignJob("my_var_1", Path("myvar1.bin"), Path("/test/dir/my_var_1.auth")),
            UefiVariableSignJob("my_var_2", Path("myvar2.bin"), Path("/test/dir/my_var_2.auth")),
        ],
        output=Path("/test/dir"),
        parallel=5,
    )


def test_cli_efibinarysign_attached_default():
    argv = [
        "--config",
        "config.yaml",
        "--output",
        "/test/dir",
        "efibinarysign",
        "uki.efi",
        "vmlinuz",
    ]
    run_config = parse_args(argv)
    assert run_config == EfiBinarySignCmd(
        config_path=Path("config.yaml"),
        jobs=[
            UefiSignJob(Path("uki.efi"), Path("/test/dir/uki.efi"), detached=False),
            UefiSignJob(Path("vmlinuz"), Path("/test/dir/vmlinuz"), detached=False),
        ],
        output=Path("/test/dir"),
        parallel=5,
    )


def test_sign_main_missing_config_raises_opensighub_error(tmp_path):
    run_config = EfiBinarySignCmd(
        config_path=tmp_path / "nonexistent-config.yaml",
        output=tmp_path,
        jobs=[],
        parallel=5,
    )
    with pytest.raises(OpensighubError, match="does not exist"):
        sign_main(run_config)


def test_cli_with_empty_config(tmp_path):
    # some commands support auto generation of config
    run_config = parse_args(["--config", str(tmp_path / "new.yaml"), "-y", "setup", "genkey"])
    assert isinstance(run_config, GenKeyCmd)
    assert run_config.config.signing_keys == {}

    # auto config generation must be explicitely allowed
    run_config = parse_args(["--config", str(tmp_path / "new.yaml"), "setup", "genkey"])
    with pytest.raises(OpensighubError, match="Not creating config file"):
        _ = run_config.config


def test_cli_debsign_build_passes_through_sbuild_args():
    argv = [
        "--config",
        "config.yaml",
        "--output",
        "/test/dir",
        "debsign",
        "--archive",
        "debian_org",
        "--suite",
        "trixie",
        "--version",
        "1.0",
        "--architecture",
        "amd64",
        "--build",
        "foo-signed-template",
        "--",
        "--no-clean-source",
    ]
    run_config = parse_args(argv)
    assert run_config == DebSignCmd(
        config_path=Path("config.yaml"),
        jobs=[
            DebianSigningJob(
                signing_template="foo-signed-template",
                version="1.0",
                architecture="amd64",
                suite_codename="trixie",
                archive_id="debian_org",
            ),
        ],
        output=Path("/test/dir"),
        parallel=5,
        run_sbuild=True,
        sbuild_args=["--no-clean-source"],
    )


def test_cli_debsign_sbuild_args_require_build():
    argv = [
        "--config",
        "config.yaml",
        "--output",
        "/test/dir",
        "debsign",
        "--archive",
        "debian_org",
        "--suite",
        "trixie",
        "--version",
        "1.0",
        "--architecture",
        "amd64",
        "foo-signed-template",
        "--",
        "--no-clean-source",
    ]
    with pytest.raises(SystemExit):
        parse_args(argv)


def test_cli_efibinarysign_detached():
    argv = [
        "--config",
        "config.yaml",
        "--output",
        "/test/dir",
        "efibinarysign",
        "--detached",
        "vmlinuz",
    ]
    run_config = parse_args(argv)
    assert run_config == EfiBinarySignCmd(
        config_path=Path("config.yaml"),
        jobs=[
            UefiSignJob(Path("vmlinuz"), Path("/test/dir/vmlinuz.sig"), detached=True),
        ],
        output=Path("/test/dir"),
        parallel=5,
    )


@pytest.mark.integration
def test_main_terminates_workers_on_interrupt(
    softhsm_shared,
    integration_config_yaml_file,
    sample_efi_file,
    hanging_sbsign,
    opensighub_cli,
    tmp_path,
):
    def process_group_exists(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        return True

    binaries = [shutil.copy(sample_efi_file, tmp_path / f"{name}.efi") for name in ("a", "b")]
    proc = opensighub_cli(
        *("-c", integration_config_yaml_file, "-o", tmp_path / "out", "-p", "2"),
        *("efibinarysign", *binaries),
        stderr=subprocess.PIPE,
    )
    wait_for(lambda: hanging_sbsign.exists() and len(hanging_sbsign.read_text().split()) == 2)

    os.killpg(proc.pid, signal.SIGINT)
    _, stderr = proc.communicate(timeout=5)

    assert proc.returncode == 128 + signal.SIGINT
    assert stderr.endswith("opensighub: interrupted\n")
    assert "Traceback" not in stderr
    wait_for(lambda: not process_group_exists(proc.pid), timeout=2)
