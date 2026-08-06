.. SPDX-FileCopyrightText: 2026 Linutronix GmbH
..
.. SPDX-License-Identifier: 0BSD

Quick Start
===========

.. code::

   pdm install
   pdm run osh --help

For test and development, you need additional system libraries and tools that
are not available on pypi.org. On a Debian system, you can simply run

.. code::

   apt install python3-invoke
   invoke install-debian-dev
   invoke build-signables


Debian Secure Boot Signing
==========================

OpenSigHub implements a high level mode to sign Debian packages following
`Debian packaging convention for Secure Boot signing`_. To use it, signing keys
must be provisioned in an HSM and apt archives must be configured in config.yaml.

The following example signs the Linux kernel from the original Debian archive to
demonstrate the workflow.

Prepare a soft HSM module for testing and generate keys. Use e.g. pkcs11-tool,
or your favorite PKI to generate signing keys on the HSM (not shown here).

.. code::
   softhsm2-util --init-token --free --label "SoftHSM" --pin 1234 --so-pin 5678
   echo -n 1234 > /tmp/pinfile

Write a configuration file

.. code::

   # /etc/osh/config.yaml

   # apt archive(s) where to download signed-templates and packages listed in files.json
   archives:
     debian_org:  # freely chosen identifier to be passed to --archive
       deb:
         - url: http://ftp.de.debian.org/debian
         - url: http://security.debian.org/debian-security
           suffix: "-security"  # appended to codename in generated sources.list
         - url: http://localhost:8123  # e.g. a local test repo without a signed Release file
           trusted: true  # adds apt's [trusted=yes] option, skipping Release signature checks

   # Key(s) that signed the Release files of the archive
   archive-keyring: /etc/apt/trusted.gpg.d/debian-archive-trixie-stable.asc

   # List of available keys with their PKCS#11 URI
   signing-keys:
     acme-2025-uefi:
       pkcs11_uri: "pkcs11:token=SoftHSM;object=acme2025uefi?pin-source=/tmp/pinfile"

   # Files listed as type 'efi' in files.json will be signed with
   uefi:
     key: acme-2025-uefi  # Refers to signing-keys mapping above. A URI for the
                          # related public key certificate is automatically
                          # constructed by replacing type=cert in the URI.

Then, to sign the Linux kernel:

.. code::

   pdm run osh --config /tmp/config.yaml --output /tmp/signed debsign \
        --archive debian_org --suite trixie --version 6.12.41-1 \
        --architecture amd64 \
        linux-image-amd64-signed-template

:code:`osh debsign` will download and extract \*-signed-template Debian binary
packages. By convention, the extracted \*-signed-template provide a debian/
skeleton for the final signed package and a file named :code:`files.json`. The
json file lists binary packages that provide actual to-be-signed content. These
are also downloaded and extracted.

files.json further describes how to sign files. The following types are supported:

- :code:`type: "efi"` uses UefiSign
- :code:`type: "linux-module"` uses LinuxModuleSign
- :code:`type: "hab4"` uses Hab4Sign

The result of :code:`osh debsign` is an extracted source package tree under
:code:`/tmp/signed`. It notably contains (tree redacted to only list files relevant
to signing):

.. code::

   cd /tmp/signed/linux-signed-amd64 && tree
   .
   └── debian
       ├── control                         # adep on linux-image-6.12.41+deb13{-,cloud-,rt-}amd64-unsigned,
       │                                   # providing unsigned boot/vmlinuz-6.12.41+deb13
       ├── rules
       ├── rules.real                      # contains sbattach --attach commands, executed during binary build
       └── signatures
           ├── linux-image-6.12.41+deb13-amd64-unsigned
           │   └── boot
           │       └── vmlinuz-6.12.sig    # detached EFI signature, will be attached
           │                               # to boot/vmlinuz-6.12.41+deb13-amd64
           ├── linux-image-6.12.41+deb13-cloud-amd64-unsigned
           │   └── boot
           │       └── vmlinuz-6.12.sig    # detached EFI signature, will be attached
           │                               # to boot/vmlinuz-6.12.41+deb13-cloud-amd64
           └── linux-image-6.12.41+deb13-rt-amd64-unsigned
               └── boot
                   └── vmlinuz-6.12.sig    # detached EFI signature, will be attached
                                           # boot/vmlinuz-6.12.41+deb13-rt-amd64

The exact contents of the source package tree are up to the author of the
signed-template package. Two principles should always be followed:

- The -signed source package contains detached signatures.
- debian/rules will attach signatures when building the final -signed binary
  package.

The source package tree can now be built to source (.dsc, .tgz) and binary (.deb)
packages with standard Debian tooling.

.. code::

   sbuild /tmp/signed/linux-signed-amd64


.. _Debian packaging convention for Secure Boot signing: https://wiki.debian.org/SecureBoot/Discussion

System Dependencies
===================

Following dependencies must be provided as native installation.

OpenSSL must be configured so that it loads your PKCS#11 module. The recommended
setup is to install libp11 and p11-kit. No further configuration should be required
then. Most PKCS#11 modules should be p11-kit aware and register themselves during
installation. If not, they can be `configured manually`_.

.. _configured manually: https://p11-glue.github.io/p11-glue/p11-kit/manual/pkcs11-conf.html#config-locations

.. list-table:: Dependencies
   :widths: 20 60 20
   :header-rows: 1

   * - Component
     - Description
     - Debian
   * - sbsigntool_
     - Signs EFI binaries. The :code:`sbsign` executable is required as backend
       for the :code:`UefiSign` signer. :code:`sbverify` is required for integration
       tests.
     - :code:`sbsign` provided by sbsigntool.
   * - sign-file_
     - Signs Linux Kernel Modules. The :code:`sign-file` executable is required
       as backend for the :code:`LinuxModuleSign` signer.
     - :code:`sign-file` provided by linux-kbuild.
   * - IMX_CST_TOOL_NEW_
     - Signs HABv4 and AHAB binaries. The :code:`cst` executable is required as
       backend for the :code:`Hab4Sign`
       signer. :code:`hab_csf_parser` is required for integration tests.
     - :code:`cst` is provided by imx-code-signing-tool.
   * - OpenSSL
     - All supported signing backends eventually call into libssl to do the actual
       signing. OpenSSL can transparently forward to HSM through its engine API
       (deprecated) or provider API. The engine plugin is by default searched
       at libpkcs11.so.
     - openssl, libssl3
   * - GnuTLS
     - The :code:`p11tool` executable is required to download public key certificates
       from a PKCS#11 module into the file system for use during signing.
     - :code:`p11tool` is provided by gnutls-bin.
   * - OpenSC
     - :code:`pkcs11-tool` is required to enroll certificates on the SoftHSM
       for testing.
     - :code:`pkcs11-tool` is provided by opensc.
   * - libp11 by OpenSC
     - :code:`libengine-pkcs11-openssl` provides an OpenSSL engine that forwards
       to PKCS#11 modules. It uses p11-kit proxy module as default module. It is
       required for NXP CST which doesn't support the newer provider API yet.
       Note that libp11 recently gained a provider library, which is somewhat
       redundant to pkcs11-provider.
     - libengine-pkcs11-openssl provides pkcs11.so and links it to the default
       OpenSSL engine search path.
   * - pkcs11-provider_
     - Newer versions of sbsign and sign-file use the OpenSSL provider API rather
       than the engine API. By default, pkcs11-provider will load the p11-kit proxy
       module.
     - pkcs11-provider
   * - p11-kit
     - By default, libp11 and pkcs11-provider load :code:`libp11-kit.so.0` PKCS#11
       module.
     - libp11-kit0 p11-kit-modules
   * - `SoftHSM version 2`_
     - Required to emulate an HSM for testing.
     - softhsm2.
   * - PKCS#11 module for your HSM or Smart Card.
     - Each HSM vendor provides their own PKCS#11 module. They come as :code:`*.so`
       files implementing the Cryptoki C API.
     - Examples: softhsm2, ykcs11, opensc.
   * - sign_encrypt.py_
     - Signs OPTEE trusted applications. The :code:`sign-encrypt.py` script is required
       as a dependency for the :code:`OpteeTaSign` signer.
     - :code:`sign-encrypt.py` could be found under :code:`optee_source/scripts/` path
   * - `rpi-eeprom`_
     - Required for integration tests to verify boot container.
     - Available through https://archive.raspberrypi.org
   * - `swu_generator`_
     - Required for signing sw-upate files (swu).
     - swugenerator version 0.6-1 or higher


.. _sbsigntool: https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git/
.. _sign-file: https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html#configuring-module-signing
.. _IMX_CST_TOOL_NEW: https://www.nxp.com/webapp/sps/download/license.jsp?colCode=IMX_CST_TOOL_NEW
.. _pkcs11-provider: https://github.com/latchset/pkcs11-provider
.. _SoftHSM version 2: https://github.com/softhsm/SoftHSMv2
.. _rpi-eeprom: https://github.com/raspberrypi/rpi-eeprom
.. _swu_generator: https://github.com/sbabic/swugenerator
