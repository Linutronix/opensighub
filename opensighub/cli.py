# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import logging
import multiprocessing
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cached_property
from importlib.metadata import version
from pathlib import Path

import yaml
from platformdirs import user_config_path

from opensighub import setup
from opensighub.config import Config
from opensighub.debian import DebianSigningJob, DebianSigningProcessor
from opensighub.signers import (
    Hab4Sign,
    LinuxModuleSign,
    OpteeTaSign,
    RpiEepromSign,
    RpiSign,
    SigningPool,
    SwuSign,
    SwuSignJob,
    UefiSign,
    UefiSignJob,
    UefiVariableSign,
    UefiVariableSignJob,
)
from opensighub.util import MultiprocessingCertCache, OpensighubError

DEFAULT_CONFIG_PATH = user_config_path("opensighub") / "config.yaml"


@dataclass
class BaseCmd:
    config_path: Path
    output: Path

    @cached_property
    def config(self) -> Config:
        try:
            cfg_dict = yaml.safe_load(self.config_path.read_text()) or {}
        except OSError as e:
            raise OpensighubError(f"Could not read config file: {e}") from e
        return Config.from_dict(cfg_dict)


@dataclass
class SigningBaseCmd(BaseCmd):
    parallel: int
    force_overwrite: bool

    def processor_factory(
        self, config: Config, cert_cache: MultiprocessingCertCache
    ) -> Callable[[], None]:
        raise NotImplementedError


@dataclass
class DebSignCmd(SigningBaseCmd):
    jobs: list[DebianSigningJob]
    run_sbuild: bool = False
    sbuild_args: list[str] = field(default_factory=list)

    def processor_factory(
        self, config: Config, cert_cache: MultiprocessingCertCache
    ) -> Callable[[], None]:
        debian_processor = DebianSigningProcessor(
            config,
            Path(self.output),
            self.run_sbuild,
            self.sbuild_args,
            self.force_overwrite,
        )
        worker = SigningPool(
            UefiSign(cert_cache, config.uefi, self.force_overwrite) if config.uefi else None,
            None,  # UefiVariableSign
            None,  # SwuSign
            LinuxModuleSign(cert_cache, config.kernel_modules) if config.kernel_modules else None,
            Hab4Sign(cert_cache, config.hab4) if config.hab4 else None,
            OpteeTaSign(cert_cache, config.optee_ta) if config.optee_ta else None,
            RpiSign(cert_cache, config.rpi) if config.rpi else None,
            RpiEepromSign(cert_cache, config.rpi) if config.rpi else None,
            parallel=self.parallel,
        )

        def process():
            for job in self.jobs:
                debian_processor.process(job, worker)
            debian_processor.cleanup()

        return process


@dataclass
class UefiVarSignCmd(SigningBaseCmd):
    jobs: list[UefiVariableSignJob]

    def processor_factory(
        self, config: Config, cert_cache: MultiprocessingCertCache
    ) -> Callable[[], None]:
        pool = SigningPool(
            None,  # uefi_signer
            UefiVariableSign(cert_cache, config.uefi) if config.uefi else None,
            None,  # swu_signer
            None,  # linux_module_signer
            None,  # hab4_signer
            None,  # optee_ta_signer
            None,  # rpi_signer
            None,  # rpi_eeprom_signer
            parallel=self.parallel,
        )

        def process():
            pool.sign(self.jobs)

        return process


@dataclass
class SwuSignCmd(SigningBaseCmd):
    jobs: list[SwuSignJob]

    def processor_factory(
        self, config: Config, cert_cache: MultiprocessingCertCache
    ) -> Callable[[], None]:
        pool = SigningPool(
            None,  # uefi_signer
            None,  # UefiVariableSign
            SwuSign(cert_cache, config.swu) if config.swu else None,
            None,  # linux_module_signer
            None,  # hab4_signer
            None,  # optee_ta_signer
            None,  # rpi_signer
            None,  # rpi_eeprom_signer
            parallel=self.parallel,
        )

        def process():
            pool.sign(self.jobs)

        return process


@dataclass
class EfiBinarySignCmd(SigningBaseCmd):
    jobs: list[UefiSignJob]

    def processor_factory(
        self, config: Config, cert_cache: MultiprocessingCertCache
    ) -> Callable[[], None]:
        pool = SigningPool(
            UefiSign(cert_cache, config.uefi, self.force_overwrite) if config.uefi else None,
            None,  # uefi_variable_signer
            None,  # swu_signer
            None,  # linux_module_signer
            None,  # hab4_signer
            None,  # optee_ta_signer
            None,  # rpi_signer
            None,  # rpi_eeprom_signer
            parallel=self.parallel,
        )

        def process():
            pool.sign(self.jobs)

        return process


@dataclass
class SoftHsmCmd(BaseCmd):
    pass


@dataclass
class TestKeysCmd(BaseCmd):
    pass


SetupCmd = SoftHsmCmd | TestKeysCmd
SigningCmd = DebSignCmd | UefiVarSignCmd | SwuSignCmd | EfiBinarySignCmd


debian_example = """examples:

To read configuration from /etc/opensighub/config.yaml from, download and sign the
architecture specific (amd64) signed-template Debian package
linux-image-amd64-signed-template version 6.12.41-1, and output a source package
tree with detached signatures under /tmp/signed:

    opensighub --config /etc/opensighub/config.yaml --output /tmp/signed debsign \\
         --archive debian_org --suite trixie --version 6.12.41-1 \\
         --architecture amd64 \\
         --build \\
         linux-image-amd64-signed-template -- --no-clean-source

The exact type of signatures (EFI in case of the linux kernel) and to-be-signed
files (boot/vmlinuz in case of the linux kernel) is determined by a files.json
included in signed-template. A final sbuild run will attach the signatures and
create the signed /boot/vmlinuz. Extra arguments after a literal '--' are passed
through to that sbuild call verbatim.
"""


uefivarsign_example = """examples:

To read configuration from /etc/opensighub/config.yaml and sign the data blob mydata.bin
as UEFI variable named mydata

    opensighub --config /etc/opensighub/config.yaml --output /tmp/signed uefivarsign \\
         mydata1:mydata1.bin mydata2:mydata2.bin

Optional details for the signing process (like attributes to attach to mydata variable
or which GUID to assign) will be looked up in config.yaml.
"""

swusign_example = """examples:

To read configuration from /etc/opensighub/config.yaml and sign the swu file my.swu

    opensighub --config /etc/opensighub/config.yaml --output /tmp/signed swusign \\
         my.swu
"""

efibinarysign_example = """examples:

To read configuration from /etc/opensighub/config.yaml and sign the (U)EFI PE/COFF
binaries uki.efi and vmlinuz, writing signed binaries /tmp/signed/uki.efi and
/tmp/signed/vmlinuz that can be booted or verified directly, e.g. with
'sbverify --cert cert.pem /tmp/signed/uki.efi':

    opensighub --config /etc/opensighub/config.yaml --output /tmp/signed efibinarysign \\
         uki.efi vmlinuz

To instead produce detached signatures (e.g. /tmp/signed/vmlinuz.sig), as used
by the Debian signing flow where the signature is attached later during the
package build, pass --detached:

    opensighub --config /etc/opensighub/config.yaml --output /tmp/signed efibinarysign \\
         --detached vmlinuz
"""


class PassthroughParser(argparse.ArgumentParser):
    def __init__(self, *args, passthrough: bool = False, **kwargs):
        self._passthrough = passthrough
        super().__init__(*args, **kwargs)

    def parse_known_args(self, args=None, namespace=None):
        passthrough_args: list[str] = []
        if self._passthrough and args and "--" in args:
            sep = args.index("--")
            args, passthrough_args = args[:sep], args[sep + 1 :]
        namespace, extras = super().parse_known_args(args, namespace)
        if self._passthrough:
            namespace.passthrough_args = passthrough_args
        return namespace, extras


def get_parser(generate_completion: bool = False) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sign artifacts or packages according to various schemes."
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {version('opensighub')}"
    )
    config_arg = parser.add_argument(
        "-c",
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"Config file to load. Defaults to {DEFAULT_CONFIG_PATH}.",
    )
    parser.add_argument(
        "-p", "--parallel", help="Number of concurrent signing operations.", type=int, default=5
    )
    output_arg = parser.add_argument(
        "-o",
        "--output",
        default=".",
        help="Directory where to place signed files. Defaults to current working directory.",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Answer y/n confirmation prompts with 'y' instead of asking or aborting.",
    )
    sub_parsers = parser.add_subparsers(dest="command", parser_class=PassthroughParser)
    debsign_parser = sub_parsers.add_parser(
        "debsign",
        help="Sign a package from an apt archive.",
        description="Sign a package from an apt archive.",
        epilog=debian_example,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        passthrough=True,
    )
    debsign_parser.add_argument(
        "--archive",
        required=True,
        help="Refers to archive mapping from config file. opensighub uses it to build "
        "sources.list entries to download signed-template and dependencies.",
    )
    debsign_parser.add_argument(
        "--suite",
        required=True,
        help="The apt archive may have multiple suites. This options selects "
        "the codename of a suite, e.g. bookworm or trixie, "
        "where to download the signed-template and dependencies.",
    )
    debsign_parser.add_argument(
        "--version",
        required=True,
        help="The apt archive may contain multiple versions of a "
        "signed-template. This options specifies the version to download.",
    )
    architecture_arg = debsign_parser.add_argument(
        "--architecture",
        required=True,
        help="The apt archive may contain a signed-template (and dependencies) "
        "for multiple architectures side by side. This selects the architecture "
        "to download. Values are the same as for sbuild (1) --host=archtiecture.",
    )
    templates_arg = debsign_parser.add_argument(
        "templates",
        nargs="+",
        help="One or more Debian signed-template binary packages. For each, a "
        "sub directory with the name of the new signed source package name "
        "as per debian/changelog will be created under the output directory.",
    )
    debsign_parser.add_argument(
        "--build",
        action="store_true",
        help="Build the signed source package using sbuild to final deb. Default: False. "
        "Extra arguments after a literal '--' are passed through to sbuild.",
    )
    uefi_parser = sub_parsers.add_parser(
        "uefivarsign",
        help="Sign a data blob as a UEFI authenticated variable.",
        description="Sign arbitrary data blob as UEFI authenticated variable. "
        "The signed output file name is calculated by appending '.auth' to the variable name. "
        "Optional details for signing a variable can be configured in the config file.",
        epilog=uefivarsign_example,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    uefi_parser.add_argument(
        "variables",
        nargs="+",
        help="One or more variable:blob pairs. Well known variable names are db, dbx, pk, kek, "
        "but custom names are also supported. Blob paths are absolut, or relative to the "
        "current working directory.",
    )
    swu_parser = sub_parsers.add_parser(
        "swusign",
        help="Sign or resign an existing SW-Update (.swu) file.",
        description="Sign or resign an existing SW-Update file generated for swupdate. "
        "The signed output file name is stored in the output directory using the given input file name. ",
        epilog=swusign_example,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    swu_arg = swu_parser.add_argument("swu", help="The swu file to sign")
    efibinary_parser = sub_parsers.add_parser(
        "efibinarysign",
        help="Sign one or more (U)EFI PE/COFF binaries with sbsign.",
        description="Sign one or more (U)EFI PE/COFF binaries (e.g. uki.efi, "
        "vmlinuz) with sbsign. By default the signature is embedded into the "
        "binary (matching sbsign's default), producing a binary that can be "
        "booted or verified directly; it is written using the input file name "
        "in the output directory. With --detached a detached signature is "
        "produced instead, named by appending '.sig' to the input file name.",
        epilog=efibinarysign_example,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    efibinary_parser.add_argument(
        "--detached",
        action="store_true",
        help="Produce a detached '.sig' signature file instead of embedding the "
        "signature into the binary. Useful for the Debian signing flow where the "
        "signature is attached later during the package build.",
    )
    binaries_arg = efibinary_parser.add_argument(
        "binaries",
        nargs="+",
        help="One or more (U)EFI binaries to sign. Paths are absolute, or "
        "relative to the current working directory.",
    )
    setup_parser = sub_parsers.add_parser(
        "setup",
        help="Set up user-local environment for opensighub to help getting started.",
        description="Set up user-local environment for opensighub to help getting started.",
    )
    setup_sub_parsers = setup_parser.add_subparsers(dest="setup_command")
    setup_sub_parsers.add_parser(
        "softhsm",
        help="Set up an isolated, user-local SoftHSM token for test purpose.",
        description="Set up an isolated, user-local SoftHSM token for test purpose.",
    )
    setup_sub_parsers.add_parser(
        "testkeys",
        help="Generate a self-signed test key and suitable configuration file for test purpose.",
        description="Generate a self-signed test key in the local SoftHSM token for test purpose"
        " and suitable configuration file.",
    )

    if generate_completion:
        import shtab

        config_arg.complete = shtab.FILE  # type: ignore[attr-defined]
        output_arg.complete = shtab.DIR  # type: ignore[attr-defined]
        architecture_arg.complete = shtab.cmd(  # type: ignore[attr-defined]
            "dpkg-architecture -L 2>/dev/null"
        )
        templates_arg.complete = shtab.cmd(  # type: ignore[attr-defined]
            'apt-cache pkgnames "$1" 2>/dev/null | grep -- signed-template'
        )
        swu_arg.complete = shtab.FILE  # type: ignore[attr-defined]
        binaries_arg.complete = shtab.FILE  # type: ignore[attr-defined]

    return parser


def get_shtab_parser() -> argparse.ArgumentParser:
    return get_parser(generate_completion=True)


def parse_args(arg_list: list[str] | None = None) -> SigningCmd | SetupCmd:
    parser = get_parser()
    args = parser.parse_args(arg_list)
    if args.command is None:
        parser.print_help()
        parser.exit()
    if args.command == "setup" and args.setup_command == "softhsm":
        return SoftHsmCmd(config_path=Path(args.config), output=Path(args.output))
    if args.command == "setup" and args.setup_command == "testkeys":
        return TestKeysCmd(config_path=Path(args.config), output=Path(args.output))
    if args.command == "debsign" and args.passthrough_args and not args.build:
        parser.error("arguments after '--' require debsign --build")
    if args.command == "swusign":
        outfile = Path(args.output) / Path(args.swu).name
        return SwuSignCmd(
            config_path=Path(args.config),
            output=outfile,
            jobs=[SwuSignJob(Path(args.swu), outfile)],
            parallel=args.parallel,
            force_overwrite=args.yes,
        )
    if args.command == "efibinarysign":
        detached = args.detached
        return EfiBinarySignCmd(
            config_path=Path(args.config),
            output=Path(args.output),
            jobs=[
                UefiSignJob(
                    artifact=Path(binary),
                    signed_artifact=Path(args.output)
                    / (Path(binary).name + ".sig" if detached else Path(binary).name),
                    detached=detached,
                )
                for binary in args.binaries
            ],
            parallel=args.parallel,
            force_overwrite=args.yes,
        )
    if args.command == "uefivarsign":
        return UefiVarSignCmd(
            config_path=Path(args.config),
            output=Path(args.output),
            jobs=[
                UefiVariableSignJob(
                    name, Path(blob), (Path(args.output) / name).with_suffix(".auth")
                )
                for name, blob in (v.split(":") for v in args.variables)
            ],
            parallel=args.parallel,
            force_overwrite=args.yes,
        )
    elif args.command == "debsign":
        return DebSignCmd(
            config_path=Path(args.config),
            output=Path(args.output),
            jobs=[
                DebianSigningJob(
                    signing_template=template,
                    version=args.version,
                    architecture=args.architecture,
                    suite_codename=args.suite,
                    archive_id=args.archive,
                )
                for template in args.templates
            ],
            parallel=args.parallel,
            force_overwrite=args.yes,
            run_sbuild=args.build,
            sbuild_args=args.passthrough_args,
        )
    raise NotImplementedError


def sign_main(run_config: SigningCmd):
    logger = logging.getLogger("opensighub")

    if not run_config or run_config is NotImplementedError:
        return

    logger.setLevel(run_config.config.log_level)

    with multiprocessing.Manager() as manager:
        shared_data = manager.dict()
        shared_data_lock = manager.Lock()
        with MultiprocessingCertCache(shared_data, shared_data_lock) as cert_cache:
            process = run_config.processor_factory(run_config.config, cert_cache)
            process()


def run_setup(run_config: SetupCmd) -> None:
    if isinstance(run_config, SoftHsmCmd):
        setup.setup_local_token(run_config.config_path)
    elif isinstance(run_config, TestKeysCmd):
        setup.setup_testenv_keys(run_config.config_path)
    else:
        raise NotImplementedError


def main():
    logging.basicConfig(format="%(message)s")
    logging.getLogger("opensighub").setLevel(logging.INFO)

    run_config = parse_args()
    setup.enable_local_softhsm2(run_config.config_path)

    try:
        if isinstance(run_config, SetupCmd):
            run_setup(run_config)
        elif isinstance(run_config, SigningCmd):
            sign_main(run_config)
    except OpensighubError as e:
        print(f"opensighub: error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
