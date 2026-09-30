<!--
SPDX-FileCopyrightText: 2026 Linutronix GmbH

SPDX-License-Identifier: 0BSD
-->

# Key management workflow with external CA

This walkthrough generates a production signing key, requests a certificate
from an external CA, imports the issued certificate, and retires the key
after use.

The walkthrough uses the local SoftHSM token as an example. Any PKCS#11
token works the same way. For a real token, skip "Preparation". Pass
`--token`/`--pin-source` to `opensighub setup genkey` instead.

## Preparation

Enroll a PKCS#11 token. Reference it in `config.yaml`. For testing, use the
local SoftHSM token:

```
opensighub setup softhsm
```

## 1. Generate a key

`opensighub setup genkey` generates a key on the token and a self-signed
placeholder certificate, then registers both in `config.yaml`.

`--use-for` assigns the key to one or more purposes. This example uses one
key for both swupdate and UEFI signing:

```
opensighub setup genkey --key-id myos1 --type rsa --use-for swu,uefi
Generating key on pkcs11:token=opensighub-local?pin-source=/home/user/.local/share/opensighub/pin
Generating certificate for myos1
Import certificate to pkcs11:token=opensighub-local?pin-source=/home/user/.local/share/opensighub/pin
Key 'myos1' generated and entered in /home/user/.config/opensighub/config.yaml.
```

## 2. Generate a certificate signing request

```
opensighub setup csr --purpose codeSigning --common-name "myos" myos1
Generating CSR for key 'myos1' at myos1.csr
```

## 3. Get the CSR signed

Submit `myos1.csr` to the CA. To test the workflow without a real CA,
create an ad-hoc one with OpenSSL:

```
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -days 3650 -subj "/CN=Test CA/" -out ca.crt
openssl x509 -req -in myos1.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days 3650 -out myos1.pem
```

## 4. Import the issued certificate

`opensighub setup importcert` matches the certificate to its key
automatically, by comparing public key hashes. `--key-id` is only needed to
override that lookup.

The imported certificate replaces the self-signed placeholder from step 1.
Confirm the overwrite:

```
opensighub setup importcert myos1.pem
opensighub: overwrite 'certificate for key 'myos1' on token 'opensighub-local'' (y/n)? y
Importing certificate for key 'myos1'
Certificate imported for key 'myos1'.
```

## 5. Sign

opensighub selects a signer key by use-case association. Since we said
`--use-for uefi` in step 1, our new key and certificate will automatically be
used for `opensighub efibinarysign`.

```
opensighub efibinarysign bootx64.efi
opensighub: overwrite '/home/user/bootx64.efi' (y/n)? y
Sign UEFI binary /home/user/bootx64.efi
```

## 6. Retire the key

Delete the key and its certificate from the token once it expires or is no
longer needed:

```
opensighub setup delkey myos1
Key 'myos1' deleted from token and removed from /home/user/.config/opensighub/config.yaml.
```
