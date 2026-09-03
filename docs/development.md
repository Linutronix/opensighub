<!--
SPDX-FileCopyrightText: 2026 Linutronix GmbH

SPDX-License-Identifier: 0BSD
-->

# Development

## Setup

```
pdm install
pdm run opensighub --help
```

`pdm install` also installs the `dev` dependency group (ruff, mypy, pytest,
invoke, bandit, reuse) by default, so nothing further is required to run the
project's own lint/test tooling below. Signing backends and other native
tools used by tests are not available on pypi.org and must be installed
separately (Debian/Ubuntu):

```
apt install python3-invoke
invoke install-debian-dev
invoke build-signables
```

`invoke install-debian-dev` installs the native signing tools and libraries
listed in the [User Manual's System Dependency
table](user-manual.md#system-dependencies), plus a few build tools test
signables need. `invoke build-signables` then builds the minimal test
binaries under `test/signables/` used by the test suite.

Note that `opensighub`'s own quickstart (`opensighub setup softhsm`/`opensighub setup testkeys`,
see the [Quick Start](../README.md#quick-start)) is unrelated to this
`invoke` tooling: it's a shipped subcommand available to any `pip`/`pipx`
install, whereas `tasks.py` (and `invoke` itself) is a dev-only dependency
never packaged with `opensighub`.

## Tasks

Tasks are defined in `tasks.py` and run as `invoke <task>` (or its alias,
shown in parentheses):

| Task | Alias | Description |
|---|---|---|
| `install-debian-dev` | | Install native dev/test dependencies via apt. |
| `build-signables` | `bs` | Build minimal signable binaries under `test/signables/`. |
| `record-quickstart` | `rq` | Render `docs/quickstart.tape` to `docs/quickstart.gif` via VHS. |
| `test-unit` | `tu` | Run unit tests (`pytest -m "not integration"`). |
| `test-integration` | `ti` | Run integration tests (`pytest -m integration`); builds signables first. |
| `test` | `t` | Run both unit and integration tests. |
| `lint-ruff` | `lr` | `ruff check` — common coding errors. |
| `lint-ruff-format` | `lf` | `ruff format --check` — formatting. |
| `lint-mypy` | `lm` | `mypy opensighub` — static type checks. |
| `lint-reuse` | `lreuse` | `reuse lint` — SPDX license/copyright compliance. |
| `lint` | `l` | All of the above lint tasks. |
| `check` | `c` | `lint` + `test`. |

Before pushing, `invoke check` (or `invoke c`) is the single command to run
everything CI runs.

## Tests

Unit tests (`test/test_*.py`, excluding integration-marked ones) don't need
native signing tools and run fast; they're what `invoke test-unit` runs.
Integration tests are marked with `@pytest.mark.integration` (declared in
`pyproject.toml`) and exercise the real signing backends, a SoftHSM token,
and/or network access to external repositories — they need
`invoke build-signables` to have run first, which `invoke test-integration`
does automatically.

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs `invoke lint` and
`invoke test-unit` on push and pull request (integration tests, needing more
native tooling, aren't run there). GitLab CI (`.gitlab-ci.yml`) separately
runs `ruff check`, `ruff format --check`, and `reuse lint`.

## Conventions

- Every source file carries SPDX `FileCopyrightText`/`License-Identifier`
  headers (checked by `reuse lint`). Code is usually GPL-3.0-or-later,
  documentation and other prose is 0BSD. See `REUSE.toml` for path-based exceptions
  (e.g. `test/signables/**`).
- Commits require sign-off.
- Inline `#...` should only document non-obvious *why*. Otherwise try to
  write speaking code.
