# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

from pathlib import Path

from opensighub.cli import EfiBinaryRun, UefiVariableRun, parse_args
from opensighub.signers import UefiSignJob, UefiVariableSignJob


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
