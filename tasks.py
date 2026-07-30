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


@task(aliases=("tu",))
def test_unit(c: Context):
    print("Executing unit tests")
    c.run('pdm run coverage run -m pytest -m "not integration" test/')


@task(build_signables, aliases=("ti",))
def test_integration(c: Context):
    print("Executing integration tests")
    c.run("pdm run coverage run -m pytest -m integration test/")


@task(test_unit, test_integration, aliases=("t",))
def test(c: Context):
    pass


@task(aliases=("lr",))
def lint_ruff(c: Context):
    print("Checking for common coding errors")
    c.run("pdm run ruff check")


@task(aliases=("lf",))
def lint_ruff_format(c: Context):
    print("Checking code formatting")
    c.run("pdm run ruff format --check")


@task(aliases=("lm",))
def lint_mypy(c: Context):
    print("Running static type checks")
    c.run("pdm run mypy opensighub")


@task(aliases=("lreuse",))
def lint_reuse(c: Context):
    print("Checking license/copyright compliance")
    c.run("pdm run reuse lint")


@task(lint_ruff, lint_ruff_format, lint_mypy, lint_reuse, aliases=("l",))
def lint(c: Context):
    pass


@task(lint, test, aliases=("c",))
def check(c: Context):
    pass
