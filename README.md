<!--
SPDX-FileCopyrightText: 2026 Linutronix GmbH

SPDX-License-Identifier: 0BSD
-->

# OpenSigHub

This project is maintained by:

[![Linutronix](https://raw.githubusercontent.com/Linutronix/.github/master/images/lx_logo_padded.png)](https://www.linutronix.de)

# Overview

OpenSigHub signs boot and operating system artifacts like UEFI Secure Boot,
NXP HAB4 or swupdate files.

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
sudo apt install softhsm2 p11-kit libengine-pkcs11-openssl sbsigntool \
     devscripts dpkg-dev
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
    --build \
    systemd-boot-efi-amd64-signed-template
```

## Documentation

- [User Manual](https://github.com/Linutronix/opensighub/blob/main/docs/user-manual.md)
- [Development](https://github.com/Linutronix/opensighub/blob/main/docs/development.md)
