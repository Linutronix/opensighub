# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

from dataclasses import replace

import pytest

from opensighub.util import CertCache, Pkcs11Uri, Pkcs11UriQattr


def test_pkcs11uri_parse():
    p = Pkcs11Uri.try_parse(
        "pkcs11:token=MyHSM;object=habCA1?pin-source=/run/password.txt&module-name=libpkcs11.so"
    )
    assert p.token == "MyHSM"
    assert p.object == "habCA1"
    assert p.qattr.pin_source == "/run/password.txt"
    assert p.qattr.module_name == "libpkcs11.so"


def test_pkcs11uri_parse_invalid():
    with pytest.raises(ValueError):
        Pkcs11Uri.try_parse("pkcs11:token=My|HSM")
    with pytest.raises(ValueError):
        Pkcs11Uri.try_parse("invalid:foo")
    with pytest.raises(TypeError):
        Pkcs11Uri.try_parse("pkcs11:invalid=foo")


def test_pkcs11_uri_unparse():
    p = Pkcs11Uri(
        token="MyHSM",
        object="habCA1",
        qattr=Pkcs11UriQattr(pin_source="/run/password.txt", module_name="libpkcs11.so"),
    )
    assert (
        str(p)
        == "pkcs11:token=MyHSM;object=habCA1?pin-source=/run/password.txt&module-name=libpkcs11.so"
    )


def test_pkcs11_to_private_cert_pair():
    prototype = Pkcs11Uri(
        token="MyHSM",
        object="habCA1",
        qattr=Pkcs11UriQattr(pin_source="/run/password.txt", module_name="libpkcs11.so"),
    )
    for pkcs11_type in ["private", "cert", None]:
        uri = replace(prototype, type=pkcs11_type)
        private, cert = uri.to_private_cert_pair()
        assert private.type == "private"
        assert cert.type == "cert"


@pytest.mark.integration
def test_cert_from_token(softhsm):
    with CertCache() as cc, open(cc["pkcs11:token=SoftHSM;object=habCA1;type=public"]) as f:
        assert len(f.read()) > 0


def test_cert_from_file():
    with CertCache() as cc, open(cc["/etc/ssl/certs/ca-certificates.crt"]) as f:
        assert len(f.read()) > 0
