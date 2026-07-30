#!/bin/bash

# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export TOKEN=SoftHSM

function cleanup {
  rm -rf "$tmpdir"
}

trap cleanup EXIT

tmpdir=`mktemp -d`
mkdir -p "${tmpdir}/crts"
cd "$tmpdir"

touch ./index.txt
echo "12345678" > ./serial

# Generating CA key and certificate

pkcs11-tool --module $PKCS11_MODULE -l --pin 1234 --keypairgen --key-type rsa:4096 --label "habCA1"
openssl req -engine pkcs11 -new -batch -subj /CN=CA1_sha256_4096_65537_v3_ca/ -key "pkcs11:token=${TOKEN};object=habCA1" -keyform engine -out "${tmpdir}/crts/CA1_sha256_4096_65537_v3_ca_crt.pem" -text -x509 -extensions v3_ca -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
openssl x509 -outform DER -in "${tmpdir}/crts/CA1_sha256_4096_65537_v3_ca_crt.pem" -out "${tmpdir}/crts/CA1_sha256_4096_65537_v3_ca_crt.der"

# Generating SRK key and certificate 1

pkcs11-tool --module $PKCS11_MODULE -l --pin 1234 --keypairgen --key-type rsa:4096 --label "habSRK1CA"
openssl req -engine pkcs11 -new -batch -subj /CN=SRK1_sha256_4096_65537_v3_ca/ -keyform engine -key "pkcs11:token=${TOKEN};object=habSRK1CA" -out temp_srk_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_srk_req.pem -cert "${tmpdir}/crts/CA1_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habCA1" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_ca.cnf -out "${tmpdir}/crts/SRK1_sha256_4096_65537_v3_ca_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
openssl x509 -outform DER -in "${tmpdir}/crts/SRK1_sha256_4096_65537_v3_ca_crt.pem" -out "${tmpdir}/crts/SRK1_sha256_4096_65537_v3_ca_crt.der"
pkcs11-tool --module $PKCS11_MODULE -l --write-object "${tmpdir}/crts/SRK1_sha256_4096_65537_v3_ca_crt.der" --type cert --label "habSRK1CA" --pin 1234

# Generating CSF key and certificate 1

pkcs11-tool --module $PKCS11_MODULE -l --pin 1234 --keypairgen --key-type rsa:4096 --label "habCSF11"
openssl req -engine pkcs11 -new -batch -subj /CN=CSF1_1_sha256_4096_65537_v3_usr/ -keyform engine -key "pkcs11:token=${TOKEN};object=habCSF11" -out temp_csf_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_csf_req.pem -cert "${tmpdir}/crts/SRK1_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habSRK1CA" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_usr.cnf -out "${tmpdir}/crts/CSF1_1_sha256_4096_65537_v3_usr_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
openssl x509 -outform DER -in "${tmpdir}/crts/CSF1_1_sha256_4096_65537_v3_usr_crt.pem" -out "${tmpdir}/crts/CSF1_1_sha256_4096_65537_v3_usr_crt.der"
pkcs11-tool --module $PKCS11_MODULE -l --write-object "${tmpdir}/crts/CSF1_1_sha256_4096_65537_v3_usr_crt.der" --type cert --label "habCSF11" --pin 1234

# Generating IMG key and certificate 1

pkcs11-tool --module $PKCS11_MODULE -l --pin 1234 --keypairgen --key-type rsa:4096 --label "habIMG11"
openssl req -engine pkcs11 -new -batch -subj /CN=IMG1_1_sha256_4096_65537_v3_usr/ -keyform engine -key "pkcs11:token=${TOKEN};object=habIMG11" -out temp_img_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_img_req.pem -cert "${tmpdir}/crts/SRK1_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habSRK1CA" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_usr.cnf -out "${tmpdir}/crts/IMG1_1_sha256_4096_65537_v3_usr_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
openssl x509 -outform DER -in "${tmpdir}/crts/IMG1_1_sha256_4096_65537_v3_usr_crt.pem" -out "${tmpdir}/crts/IMG1_1_sha256_4096_65537_v3_usr_crt.der"
pkcs11-tool --module $PKCS11_MODULE -l --write-object "${tmpdir}/crts/IMG1_1_sha256_4096_65537_v3_usr_crt.der" --type cert --label "habIMG11" --pin 1234

# Generating SRK key and certificate 2

pkcs11-tool --module $PKCS11_MODULE -l --pin 1234 --keypairgen --key-type rsa:4096 --label "habSRK2CA"
openssl req -engine pkcs11 -new -batch -subj /CN=SRK2_sha256_4096_65537_v3_ca/ -keyform engine -key "pkcs11:token=${TOKEN};object=habSRK2CA" -out temp_srk_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_srk_req.pem -cert "${tmpdir}/crts/CA1_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habCA1" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_ca.cnf -out "${tmpdir}/crts/SRK2_sha256_4096_65537_v3_ca_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
openssl x509 -outform DER -in "${tmpdir}/crts/SRK2_sha256_4096_65537_v3_ca_crt.pem" -out "${tmpdir}/crts/SRK2_sha256_4096_65537_v3_ca_crt.der"
pkcs11-tool --module $PKCS11_MODULE -l --write-object "${tmpdir}/crts/SRK2_sha256_4096_65537_v3_ca_crt.der" --type cert --label "habSRK2CA" --pin 1234

# Generating CSF key and certificate 2

pkcs11-tool --module $PKCS11_MODULE -l --pin 1234 --keypairgen --key-type rsa:4096 --label "habCSF21"
openssl req -engine pkcs11 -new -batch -subj /CN=CSF2_1_sha256_4096_65537_v3_usr/ -keyform engine -key "pkcs11:token=${TOKEN};object=habCSF21" -out temp_csf_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_csf_req.pem -cert "${tmpdir}/crts/SRK2_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habSRK2CA" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_usr.cnf -out "${tmpdir}/crts/CSF2_1_sha256_4096_65537_v3_usr_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
openssl x509 -outform DER -in "${tmpdir}/crts/CSF2_1_sha256_4096_65537_v3_usr_crt.pem" -out "${tmpdir}/crts/CSF2_1_sha256_4096_65537_v3_usr_crt.der"
pkcs11-tool --module $PKCS11_MODULE -l --write-object "${tmpdir}/crts/CSF2_1_sha256_4096_65537_v3_usr_crt.der" --type cert --label "habCSF21" --pin 1234

# Generating IMG key and certificate 2

pkcs11-tool --module $PKCS11_MODULE -l --pin 1234 --keypairgen --key-type rsa:4096 --label "habIMG21"
openssl req -engine pkcs11 -new -batch -subj /CN=IMG2_1_sha256_4096_65537_v3_usr/ -keyform engine -key "pkcs11:token=${TOKEN};object=habIMG21" -out temp_img_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_img_req.pem -cert "${tmpdir}/crts/SRK2_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habSRK2CA" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_usr.cnf -out "${tmpdir}/crts/IMG2_1_sha256_4096_65537_v3_usr_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
openssl x509 -outform DER -in "${tmpdir}/crts/IMG2_1_sha256_4096_65537_v3_usr_crt.pem" -out "${tmpdir}/crts/IMG2_1_sha256_4096_65537_v3_usr_crt.der"
pkcs11-tool --module $PKCS11_MODULE -l --write-object "${tmpdir}/crts/IMG2_1_sha256_4096_65537_v3_usr_crt.der" --type cert --label "habIMG21" --pin 1234

# Generating TA root key / public key
pkcs11-tool --module $PKCS11_MODULE -l --pin 1234 --keypairgen --key-type rsa:4096 --label "ta-root-key"

# Generating Rpi root key / public key
pkcs11-tool --module $PKCS11_MODULE -l --pin 1234 --keypairgen --key-type rsa:4096 --label "rpi-boot-key"

# Generating SWU key and certificate
pkcs11-tool --module $PKCS11_MODULE -l --pin 1234 --keypairgen --key-type rsa:4096 --label "SWU"
openssl req -engine pkcs11 -new -batch -subj /CN=CA1_sha256_4096_65537_v3_ca/ -key "pkcs11:token=${TOKEN};object=SWU" -keyform engine -out "${tmpdir}/crts/swu_crt.pem" -text -x509 -extensions v3_ca -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
openssl x509 -outform DER -in "${tmpdir}/crts/swu_crt.pem" -out "${tmpdir}/crts/swu_crt.pem.der"
pkcs11-tool --module $PKCS11_MODULE -l --write-object "${tmpdir}/crts/swu_crt.pem.der" --type cert --label "SWU" --pin 1234
