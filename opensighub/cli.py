# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import logging
import multiprocessing
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
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
class SigningRunBase:
    config: Path
    output: Path
    parallel: int
    force_overwrite: bool

    def processor_factory(
        self, config: Config, cert_cache: MultiprocessingCertCache
    ) -> Callable[[], None]:
        raise NotImplementedError


@dataclass
class DebianRun(SigningRunBase):
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
            parallel=self.parallel,
        )

        def process():
            for job in self.jobs:
                debian_processor.process(job, worker)
            debian_processor.cleanup()

        return process


@dataclass
class UefiVariableRun(SigningRunBase):
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
            parallel=self.parallel,
        )

        def process():
            pool.sign(self.jobs)

        return process


@dataclass
class SwuRun(SigningRunBase):
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
            parallel=self.parallel,
        )

        def process():
            pool.sign(self.jobs)

        return process


@dataclass
class EfiBinaryRun(SigningRunBase):
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
            parallel=self.parallel,
        )

        def process():
            pool.sign(self.jobs)

        return process


@dataclass
class SetupRun:
    config: Path
    setup_command: str | None


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


def parse_args(arg_list: list[str] | None = None) -> SigningRunBase | SetupRun:
    parser = argparse.ArgumentParser(
        description="Sign artifacts or packages according to various schemes."
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {version('opensighub')}"
    )
    parser.add_argument(
        "-c",
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"Config file to load. Defaults to {DEFAULT_CONFIG_PATH}.",
    )
    parser.add_argument(
        "-p", "--parallel", help="Number of concurrent signing operations.", type=int, default=5
    )
    parser.add_argument(
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
        description="Sign a package from an apt archive.",
        epilog=debian_example,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        passthrough=True,
    )
    debsign_parser.add_argument(
        "--archive",
        help="Refers to archive mapping from config file. opensighub uses it to build "
        "sources.list entries to download signed-template and dependencies.",
    )
    debsign_parser.add_argument(
        "--suite",
        help="The apt archive may have multiple suites. This options selects "
        "the codename of a suite, e.g. bookworm or trixie, "
        "where to download the signed-template and dependencies.",
    )
    debsign_parser.add_argument(
        "--version",
        help="The apt archive may contain multiple versions of a "
        "signed-template. This options specifies the version to download.",
    )
    debsign_parser.add_argument(
        "--architecture",
        help="The apt archive may contain a signed-template (and dependencies) "
        "for multiple architectures side by side. This selects the architecture "
        "to download. Values are the same as for sbuild (1) --host=archtiecture.",
    )
    debsign_parser.add_argument(
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
        description="Sign or resign an existing SW-Update file generated for swupdate. "
        "The signed output file name is stored in the output directory using the given input file name. ",
        epilog=swusign_example,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    swu_parser.add_argument("swu", help="The swu file to sign")
    efibinary_parser = sub_parsers.add_parser(
        "efibinarysign",
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
    efibinary_parser.add_argument(
        "binaries",
        nargs="+",
        help="One or more (U)EFI binaries to sign. Paths are absolute, or "
        "relative to the current working directory.",
    )
    setup_parser = sub_parsers.add_parser(
        "setup",
        description="Set up user-local environment for opensighub to help getting started.",
    )
    setup_sub_parsers = setup_parser.add_subparsers(dest="setup_command")
    setup_sub_parsers.add_parser(
        "softhsm",
        description="Set up an isolated, user-local SoftHSM token for test purpose.",
    )
    setup_sub_parsers.add_parser(
        "testkeys",
        description="Generate a self-signed test key in the local SoftHSM token for test purpose"
        " and suitable configuration file.",
    )
    args = parser.parse_args(arg_list)
    if args.command == "setup":
        return SetupRun(config=Path(args.config), setup_command=args.setup_command)
    if args.command == "debsign" and args.passthrough_args and not args.build:
        parser.error("arguments after '--' require debsign --build")
    if args.command == "swusign":
        outfile = Path(args.output) / Path(args.swu).name
        return SwuRun(
            config=Path(args.config),
            output=outfile,
            jobs=[SwuSignJob(Path(args.swu), outfile)],
            parallel=args.parallel,
            force_overwrite=args.yes,
        )
    if args.command == "efibinarysign":
        detached = args.detached
        return EfiBinaryRun(
            config=Path(args.config),
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
        return UefiVariableRun(
            config=Path(args.config),
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
        return DebianRun(
            config=Path(args.config),
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


def sign_main(run_config: SigningRunBase):
    logger = logging.getLogger("opensighub")

    if not run_config or run_config is NotImplementedError:
        return

    try:
        with open(run_config.config) as fp:
            cfg_dict = yaml.safe_load(fp)
    except OSError as e:
        raise OpensighubError(f"Could not read config file: {e}") from e
    config = Config.from_dict(cfg_dict)

    logger.setLevel(config.log_level)

    with multiprocessing.Manager() as manager:
        shared_data = manager.dict()
        shared_data_lock = manager.Lock()
        with MultiprocessingCertCache(shared_data, shared_data_lock) as cert_cache:
            process = run_config.processor_factory(config, cert_cache)
            process()


def run_setup(run_config: SetupRun):
    if run_config.setup_command == "softhsm":
        setup.setup_local_token(run_config.config)
    elif run_config.setup_command == "testkeys":
        setup.setup_testenv_keys(run_config.config)
    else:
        raise NotImplementedError


def main():
    logging.basicConfig(format="%(message)s")
    logging.getLogger("opensighub").setLevel(logging.INFO)

    run_config = parse_args()
    setup.enable_local_softhsm2(run_config.config)

    try:
        if isinstance(run_config, SetupRun):
            run_setup(run_config)
            return
        sign_main(run_config)
    except OpensighubError as e:
        print(f"opensighub: error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
