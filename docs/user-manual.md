<!--
SPDX-FileCopyrightText: 2026 Linutronix GmbH

SPDX-License-Identifier: 0BSD
-->

# User Manual

See the [Quick Start](../README.md#quick-start) for a self-contained
walkthrough against a local SoftHSM test key. This document covers the
subcommands, `config.yaml` in full, and what to install for real use.

## Subcommands

Every subcommand shares `-c/--config` (default:
`$XDG_CONFIG_HOME/opensighub/config.yaml`, usually
`~/.config/opensighub/config.yaml`), `-p/--parallel`, and `-o/--output`
(default: current directory). Run `osh <command> --help` for the full option
list and examples of each; only a summary is given here.

- `osh debsign TEMPLATE...` — the high-level Debian workflow described below:
  download one or more `*-signed-template` packages plus their dependencies,
  sign the files they list, and write out a signed source package tree per
  template.
- `osh efibinarysign BINARY...` — sign (U)EFI PE/COFF binaries with sbsign.
  By default the signature is embedded (a directly bootable/verifiable
  binary); with `--detached` a `.sig` file is produced instead.
- `osh uefivarsign NAME:BLOB...` — sign an arbitrary data blob as a UEFI
  authenticated variable with sbvarsign, e.g. for `db`/`dbx`/`KEK`/`PK`
  updates.
- `osh swusign FILE` — sign or resign a swupdate `.swu` file.
- `osh setup softhsm` / `osh setup testkeys` — set up an isolated, user-local
  SoftHSM token and a self-signed test key in it, for the quickstart. Not
  meant for production keys.

### Signing in place and `--output`

`--output` defaults to the current directory, so a signed file can end up
overwriting its own input if `--output` isn't set explicitly (e.g. running
`osh efibinarysign` in the same directory as the input, or with
`--output .`). `osh` reacts differently depending on what that actually does:

- `swusign`: signing in place is not possible (the underlying tool truncates
  the output before reading the input), so `osh` always refuses with an
  error.
- `efibinarysign` without `--detached`: signing in place works and produces a
  valid signed replacement, but silently discards the unsigned original, so
  `osh` asks for interactive confirmation (in the style of `cp -i`/`rm -i`).
  Outside a terminal (e.g. in a pipeline) it refuses instead of guessing.
- `efibinarysign --detached`: the output would contain only the detached
  signature, not the binary, so signing in place would destroy the artifact
  for no usable result; `osh` always refuses.
- `uefivarsign`, kernel module, HAB4, OPTEE TA, and RPi boot container
  signing have no realistic in-place collision and are unaffected.

## Configuration (`config.yaml`)

```yaml
# Apt archive(s) where to download signed-templates and packages listed in
# files.json. Key is a freely chosen identifier, passed to --archive.
archives:
  debian_org:
    deb:
      - url: http://ftp.de.debian.org/debian
      - url: http://security.debian.org/debian-security
        suffix: "-security"   # appended to the suite codename in sources.list
      - url: http://localhost:8123   # e.g. a local test repo without a signed Release file
        trusted: true                # apt's [trusted=yes], skips Release signature checks
        prefix: ""                   # optional prefix before the suite codename

# Key(s) that signed the archive's Release files, used to verify downloads.
# Any keyring format apt's trusted.gpg.d accepts (binary .gpg/.pgp or
# ASCII-armored .asc) works; the extension is preserved when osh links it in.
archive-keyring: /usr/share/keyrings/debian-archive-keyring.gpg

# Available signing keys, referenced by name from the sections below.
signing-keys:
  acme-2025-uefi:
    pkcs11_uri: "pkcs11:token=SoftHSM;object=acme2025uefi?pin-source=/tmp/pinfile"

# Certificates referenced by name, currently only used by hab4's
# srk_certificates below.
trusted-certificates:
  acme-srk-0:
    pkcs11_uri: "pkcs11:token=SoftHSM;object=srk0;type=cert"

log-level: INFO   # DEBUG, INFO, WARNING, ERROR, ...

# Files listed as type "efi" in files.json, and "osh efibinarysign", are
# signed with this key. The public key certificate's PKCS#11 URI is derived
# automatically by replacing type=cert in the key's URI.
uefi:
  key: acme-2025-uefi
  variables:            # optional, for "osh uefivarsign"
    db:
      key: acme-2025-uefi
      attributes: ["NON_VOLATILE", "BOOTSERVICE_ACCESS", "RUNTIME_ACCESS", "TIME_BASED_AUTHENTICATED_WRITE_ACCESS"]
      guid: "d719b2cb-3d3a-4596-a3bc-dad00e67656f"

# Files listed as type "linux-module" are signed with sign-file.
kernel_modules:
  key: acme-2025-uefi

# Files listed as type "hab4" are signed with NXP's cst.
hab4:
  img_key: acme-2025-uefi
  csf_key: acme-2025-uefi
  srk_certificates: [acme-srk-0]   # names from trusted-certificates above
  srk_index: 0

# Files listed as type "optee-ta-core" are signed via sign_encrypt.py.
optee_ta:
  key: acme-2025-uefi
  hash: sha256
  padding: pkcs1   # or pss
  # saltlen: digest   # only used when padding: pss
  # mgf1_md: sha256   # only used when padding: pss, defaults to hash

# Files listed as type "rpi-boot" (Raspberry Pi boot container) are signed
# with a raw RSA signature via OpenSSL. Same fields as optee_ta above.
rpi:
  key: acme-2025-uefi
  hash: sha256
  padding: pkcs1

# osh swusign uses this key.
swu:
  key: acme-2025-uefi
```

A signing key's PKCS#11 URI needs to carry its PIN somehow. Two forms are
understood, both by libp11/pkcs11-provider and by osh itself:

- `pin-source=/path/to/file` (recommended): PIN is read from a text file
  (must not contain a trailing newline).
- `pin-value=plaintext`: PIN embedded directly in the URI.

Note that `p11-kit`'s own CLI (used by `osh setup testkeys` to generate the
quickstart test key) only understands `pin-value` or an interactive terminal
prompt for `--login`, not `pin-source` — this only matters if you use
`p11-kit` yourself to provision keys.

A `--suite` value ending in `/` (e.g. `osh debsign --suite trixie/ ...`)
addresses a flat, `dists`-less repository instead, as produced by a plain
`dpkg-scanpackages . > Packages` served from that same directory.

## The `debsign` workflow

`osh debsign` downloads and extracts one or more `*-signed-template` Debian
binary packages. By convention, a `-signed-template` package provides a
`debian/` skeleton for the final signed source package, plus a
`files.json` that lists the binary packages providing the actual
to-be-signed content (also downloaded and extracted automatically) and, per
package, which files to sign and how.

`files.json`'s `sig_type` values map to a config.yaml section and a signer:

| `sig_type`       | config.yaml section | Signer            |
|------------------|----------------------|--------------------|
| `efi`            | `uefi`               | UefiSign (sbsign)  |
| `linux-module`   | `kernel_modules`      | LinuxModuleSign (sign-file) |
| `hab4`           | `hab4`                | Hab4Sign (cst)     |
| `optee-ta-core`  | `optee_ta`            | OpteeTaSign (sign_encrypt.py) |
| `rpi-boot`       | `rpi`                 | RpiSign (raw RSA via OpenSSL) |

If `files.json` lists a `sig_type` whose section isn't configured, `osh
debsign` fails with an error naming the missing section.

The result of `osh debsign` is an extracted source package tree under
`--output`. For example, signing `linux-image-amd64-signed-template` from
the official Debian archive produces (tree redacted to files relevant to
signing):

```
/tmp/signed/linux-signed-amd64/
└── debian/
    ├── control          # depends on the matching linux-image-*-unsigned
    │                     # packages, which provide unsigned boot/vmlinuz-*
    ├── rules
    ├── rules.real        # runs sbattach --attach during the binary build
    └── signatures/
        ├── linux-image-6.12.94+deb13-amd64-unsigned/
        │   └── boot/vmlinuz-6.12.94+deb13-amd64.sig
        ├── linux-image-6.12.94+deb13-cloud-amd64-unsigned/
        │   └── boot/vmlinuz-6.12.94+deb13-cloud-amd64.sig
        └── linux-image-6.12.94+deb13-rt-amd64-unsigned/
            └── boot/vmlinuz-6.12.94+deb13-rt-amd64.sig
```

The exact contents of the source package tree are up to the signed-template
package's author, but two principles hold generally:

- The `-signed` source package contains detached signatures, not the signed
  binaries themselves.
- `debian/rules` attaches those signatures (e.g. via `sbattach`) while
  building the final `-signed` binary package.

The source package tree can then be built with standard Debian tooling, e.g.:

```
sbuild /tmp/signed/linux-signed-amd64
```

## System Dependencies

`osh` shells out to native tools rather than reimplementing cryptographic
signing. OpenSSL must be able to load a PKCS#11 module; installing `libp11`
and `p11-kit` is normally enough, as most PKCS#11 modules register
themselves with p11-kit automatically. If not, see p11-kit's [manual
configuration
guide](https://p11-glue.github.io/p11-glue/p11-kit/manual/pkcs11-conf.html#config-locations).

| Component | Used for | Debian package |
|---|---|---|
| sbsigntool | `sbsign`/`sbvarsign`, backing UefiSign and UEFI variable signing. `sbverify` is used by integration tests. | sbsigntool |
| sign-file | Backs LinuxModuleSign (kernel module signing). | linux-kbuild |
| cst (IMX Code Signing Tool) | Backs Hab4Sign (HABv4/AHAB). `hab_csf_parser` is used by integration tests. | imx-code-signing-tool |
| OpenSSL | All backends eventually call into libssl; forwards to an HSM via the engine API (deprecated) or the newer provider API. | openssl, libssl3 |
| GnuTLS | `p11tool` downloads public key certificates from a PKCS#11 module for use during signing. | gnutls-bin |
| p11-kit | Default PKCS#11 module (`libp11-kit.so.0`) loaded by libp11 and pkcs11-provider; also used directly by `osh setup`. | libp11-kit0, p11-kit-modules |
| libp11 (OpenSC) | `libengine-pkcs11-openssl` provides the OpenSSL engine used for raw RSA signing (OPTEE TA, RPi) and, on older toolchains, for other backends. | libengine-pkcs11-openssl |
| pkcs11-provider | Newer sbsign/sign-file versions use OpenSSL's provider API instead of the engine API. | pkcs11-provider |
| SoftHSM v2 | Emulates an HSM, used by `osh setup` and for testing. | softhsm2 |
| swugenerator | Backs SwuSign (swupdate `.swu` files); version 0.6-1 or higher required. | swugenerator (trixie's main archive only has 0.4-1; use trixie-backports or pip) |
| sign_encrypt.py | Backs OpteeTaSign (OPTEE trusted applications); found under `optee_source/scripts/` in an OP-TEE checkout. | not packaged, ships with OP-TEE |
| rpi-eeprom | Used by integration tests to verify RPi boot containers. | not packaged, see [raspberrypi/rpi-eeprom](https://github.com/raspberrypi/rpi-eeprom) |
| Your HSM/Smart Card's PKCS#11 module | Each vendor ships their own `*.so` implementing the Cryptoki C API. | e.g. softhsm2, ykcs11, opensc |
