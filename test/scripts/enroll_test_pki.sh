#!/bin/bash

# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

export TOKEN=SoftHSM
export GNUTLS_PIN=1234

function cleanup {
  rm -rf "$tmpdir"
}

trap cleanup EXIT

tmpdir=`mktemp -d`
mkdir -p "${tmpdir}/crts"
cd "$tmpdir"

touch ./index.txt
echo "12345678" > ./serial

function keygen {
  p11tool --login --generate-rsa --bits 4096 --label "$1" --outfile /dev/null "pkcs11:token=${TOKEN}"
}

function write_cert {
  p11tool --login --write --load-certificate "$1" --label "$2" "pkcs11:token=${TOKEN}"
}

# Generating CA key and certificate

keygen "habCA1"
openssl req -engine pkcs11 -new -batch -subj /CN=CA1_sha256_4096_65537_v3_ca/ -key "pkcs11:token=${TOKEN};object=habCA1" -keyform engine -out "${tmpdir}/crts/CA1_sha256_4096_65537_v3_ca_crt.pem" -text -x509 -extensions v3_ca -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234

# Generating SRK key and certificate 1

keygen "habSRK1CA"
openssl req -engine pkcs11 -new -batch -subj /CN=SRK1_sha256_4096_65537_v3_ca/ -keyform engine -key "pkcs11:token=${TOKEN};object=habSRK1CA" -out temp_srk_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_srk_req.pem -cert "${tmpdir}/crts/CA1_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habCA1" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_ca.cnf -out "${tmpdir}/crts/SRK1_sha256_4096_65537_v3_ca_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
write_cert "${tmpdir}/crts/SRK1_sha256_4096_65537_v3_ca_crt.pem" "habSRK1CA"

# Generating CSF key and certificate 1

keygen "habCSF11"
openssl req -engine pkcs11 -new -batch -subj /CN=CSF1_1_sha256_4096_65537_v3_usr/ -keyform engine -key "pkcs11:token=${TOKEN};object=habCSF11" -out temp_csf_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_csf_req.pem -cert "${tmpdir}/crts/SRK1_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habSRK1CA" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_usr.cnf -out "${tmpdir}/crts/CSF1_1_sha256_4096_65537_v3_usr_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
write_cert "${tmpdir}/crts/CSF1_1_sha256_4096_65537_v3_usr_crt.pem" "habCSF11"

# Generating IMG key and certificate 1

keygen "habIMG11"
openssl req -engine pkcs11 -new -batch -subj /CN=IMG1_1_sha256_4096_65537_v3_usr/ -keyform engine -key "pkcs11:token=${TOKEN};object=habIMG11" -out temp_img_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_img_req.pem -cert "${tmpdir}/crts/SRK1_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habSRK1CA" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_usr.cnf -out "${tmpdir}/crts/IMG1_1_sha256_4096_65537_v3_usr_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
write_cert "${tmpdir}/crts/IMG1_1_sha256_4096_65537_v3_usr_crt.pem" "habIMG11"

# Generating SRK key and certificate 2

keygen "habSRK2CA"
openssl req -engine pkcs11 -new -batch -subj /CN=SRK2_sha256_4096_65537_v3_ca/ -keyform engine -key "pkcs11:token=${TOKEN};object=habSRK2CA" -out temp_srk_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_srk_req.pem -cert "${tmpdir}/crts/CA1_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habCA1" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_ca.cnf -out "${tmpdir}/crts/SRK2_sha256_4096_65537_v3_ca_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
write_cert "${tmpdir}/crts/SRK2_sha256_4096_65537_v3_ca_crt.pem" "habSRK2CA"

# Generating CSF key and certificate 2

keygen "habCSF21"
openssl req -engine pkcs11 -new -batch -subj /CN=CSF2_1_sha256_4096_65537_v3_usr/ -keyform engine -key "pkcs11:token=${TOKEN};object=habCSF21" -out temp_csf_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_csf_req.pem -cert "${tmpdir}/crts/SRK2_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habSRK2CA" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_usr.cnf -out "${tmpdir}/crts/CSF2_1_sha256_4096_65537_v3_usr_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
write_cert "${tmpdir}/crts/CSF2_1_sha256_4096_65537_v3_usr_crt.pem" "habCSF21"

# Generating IMG key and certificate 2

keygen "habIMG21"
openssl req -engine pkcs11 -new -batch -subj /CN=IMG2_1_sha256_4096_65537_v3_usr/ -keyform engine -key "pkcs11:token=${TOKEN};object=habIMG21" -out temp_img_req.pem -passin pass:1234
openssl ca -engine pkcs11 -batch -md sha256 -outdir ./ -in ./temp_img_req.pem -cert "${tmpdir}/crts/SRK2_sha256_4096_65537_v3_ca_crt.pem" -keyform engine -keyfile "pkcs11:token=${TOKEN};object=habSRK2CA" -extfile /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/v3_usr.cnf -out "${tmpdir}/crts/IMG2_1_sha256_4096_65537_v3_usr_crt.pem" -notext -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
write_cert "${tmpdir}/crts/IMG2_1_sha256_4096_65537_v3_usr_crt.pem" "habIMG21"

# Generating TA root key / public key
keygen "ta-root-key"

# Generating Rpi root key / public key
keygen "rpi-boot-key"

# Generating SWU key and certificate
keygen "SWU"
openssl req -engine pkcs11 -new -batch -subj /CN=CA1_sha256_4096_65537_v3_ca/ -key "pkcs11:token=${TOKEN};object=SWU" -keyform engine -out "${tmpdir}/crts/swu_crt.pem" -text -x509 -extensions v3_ca -days 1825 -config /usr/share/doc/imx-code-signing-tool/pki_scripts/ca/openssl.cnf -passin pass:1234
write_cert "${tmpdir}/crts/swu_crt.pem" "SWU"
