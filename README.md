<!--
SPDX-FileCopyrightText: 2026 Linutronix GmbH

SPDX-License-Identifier: 0BSD
-->

# OpenSigHub

OpenSigHub signs artifacts typically encountered in embedded systems
development, like UEFI Secure Boot, NXP HAB4 or swupdate files.

Signing operations are performed through PKCS#11 for generic HSM integration.

It supports two modes of operation:
- High-level mode to sign Debian packages following the
  [Debian packaging convention for Secure Boot signing](https://wiki.debian.org/SecureBoot/Discussion).
  These are recipes how to sign multiple files using different signers at once.
- Low-level mode, to sign a single artifact with a specific signer.

## Quick Start

```
pipx install opensighub
```

Install system dependencies (Debian/Ubuntu)

```
sudo apt install softhsm2 p11-kit p11-kit-modules libengine-pkcs11-openssl sbsigntool
```

Set up configuration for user-local SoftHSM token and keys test key in it

```
osh setup softhsm
osh setup testkeys
```

Sign systemd-boot from the Debian archive with your own key

```
osh --output ./signed debsign \
    --archive debian-trixie --suite trixie --version 257.13-1~deb13u1 \
    --architecture amd64 \
    systemd-boot-efi-amd64-signed-template
```

Build signed Debian package with sbuild

```
sbuild ./signed/systemd-boot-efi-amd64-signed
```

## Documentation

- [User Manual](docs/user-manual.md)
- [Development](docs/development.md)
