# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

from pathlib import Path

import pytest

from opensighub.cli import DebianRun, EfiBinaryRun, UefiVariableRun, parse_args, sign_main
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
    assert run_config == UefiVariableRun(
        config=Path("config.yaml"),
        jobs=[
            UefiVariableSignJob("my_var_1", Path("myvar1.bin"), Path("/test/dir/my_var_1.auth")),
            UefiVariableSignJob("my_var_2", Path("myvar2.bin"), Path("/test/dir/my_var_2.auth")),
        ],
        output=Path("/test/dir"),
        parallel=5,
        force_overwrite=False,
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
    assert run_config == EfiBinaryRun(
        config=Path("config.yaml"),
        jobs=[
            UefiSignJob(Path("uki.efi"), Path("/test/dir/uki.efi"), detached=False),
            UefiSignJob(Path("vmlinuz"), Path("/test/dir/vmlinuz"), detached=False),
        ],
        output=Path("/test/dir"),
        parallel=5,
        force_overwrite=False,
    )


def test_sign_main_missing_config_raises_opensighub_error(tmp_path):
    run_config = EfiBinaryRun(
        config=tmp_path / "nonexistent-config.yaml",
        output=tmp_path,
        jobs=[],
        parallel=5,
        force_overwrite=False,
    )
    with pytest.raises(OpensighubError, match="Could not read config file"):
        sign_main(run_config)


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
    assert run_config == DebianRun(
        config=Path("config.yaml"),
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
        force_overwrite=False,
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
    assert run_config == EfiBinaryRun(
        config=Path("config.yaml"),
        jobs=[
            UefiSignJob(Path("vmlinuz"), Path("/test/dir/vmlinuz.sig"), detached=True),
        ],
        output=Path("/test/dir"),
        parallel=5,
        force_overwrite=False,
    )
