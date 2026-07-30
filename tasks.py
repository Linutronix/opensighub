# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

from invoke import Context, task


@task
def install_debian_dev(c: Context):
    print("Installing native development dependencies on a Debian system")
    packages = [
        "clang",
        "devscripts",
        "imx-code-signing-tool",
        "libengine-pkcs11-openssl",
        "linux-headers-generic",
        "make",
        "lld",
        "p11-kit-modules",
        "pkcs11-provider",
        "sbsigntool",
        "softhsm2",
        "uuidgen-runtime",
    ]
    c.run(f"apt install {' '.join(packages)}")


@task(aliases=("bs",))
def build_signables(c: Context):
    print("Building minimal signable binaries for test")
    c.run("make -C test/signables")


@task(build_signables, aliases=("ti",))
def test_integration(c: Context):
    print("Executing integration tests")
    c.run("coverage run -m pytest test/")
