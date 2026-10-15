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


@pytest.mark.parametrize(
    "uri",
    [
        "pkcs11:",
        "PKCS11:token=a",
        "pkcs11:token=",
        "pkcs11:object=a=b",
        "pkcs11:object=a&b",
        "pkcs11:serial=bddd8ca79d7bda1a;type=private;id=%02?pin-value=123456",
        "pkcs11:id=%aB%02",
        "pkcs11:token=a?pin-value=x/y?z|w",
        "pkcs11:token=a?",
        "pkcs11:slot-id=12;library-version=1.7",
        "pkcs11:type=secret-key",
    ],
)
def test_pkcs11uri_parse_valid(uri):
    Pkcs11Uri.try_parse(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "invalid:foo",
        "pkcs11",
        "pkcs11:token=My|HSM",
        "pkcs11:object=a/b",
        "pkcs11:object=a b",
        "pkcs11:id=%0g",
        "pkcs11:id=%2",
        "pkcs11:token=t?pin-value=%0g",
        "pkcs11:invalid=foo",
        "pkcs11:token=a;x-foo=b",
        "pkcs11:slot_id=1",
        "pkcs11:token",
        "pkcs11:token=a;",
        "pkcs11:;token=a",
        "pkcs11:token=a;token=b",
        "pkcs11:token=a?pin-value=1&pin-value=2",
        "pkcs11:token=a?pin-value=1&",
        "pkcs11:token=a?object=b",
        "pkcs11:pin-value=1",
        "pkcs11:object=a#b",
        "pkcs11:type=foo",
        "pkcs11:slot-id=x",
        "pkcs11:library-version=1.",
        "pkcs11:object=%FF",
    ],
)
def test_pkcs11uri_parse_invalid(uri):
    with pytest.raises(ValueError):
        Pkcs11Uri.try_parse(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "pkcs11:serial=bddd8ca79d7bda1a;type=private;id=%02?pin-value=123456",
        "pkcs11:object=my%20key?pin-value=a+b",
        "pkcs11:token=?pin-value=",
        "pkcs11:token=a;id=%FE%E5%00;slot-id=3",
        "pkcs11:object=a%3Bb%2Fc?pin-value=x%26y%23z",
    ],
)
def test_pkcs11uri_roundtrip(uri):
    assert str(Pkcs11Uri.try_parse(uri)) == uri


def test_pkcs11uri_parse_decodes():
    p = Pkcs11Uri.try_parse("pkcs11:object=my%20key;id=%FE%02;slot-id=7?pin-value=a%20b")
    assert p.object == "my key"
    assert p.id == b"\xfe\x02"
    assert p.slot_id == 7
    assert p.qattr.pin_value == "a b"


def test_pkcs11uri_unparse_encodes():
    p = Pkcs11Uri(
        object="a;b/c ä",
        id=b"\x00\xff",
        slot_id=3,
        qattr=Pkcs11UriQattr(pin_source="/my dir/pin", pin_value="x&y#z"),
    )
    assert (
        str(p) == "pkcs11:object=a%3Bb%2Fc%20%C3%A4;id=%00%FF;slot-id=3"
        "?pin-source=/my%20dir/pin&pin-value=x%26y%23z"
    )
    assert Pkcs11Uri.try_parse(str(p)) == p


def test_pkcs11uri_pin_source_pct_decoded(tmp_path):
    pin_file = tmp_path / "my pin"
    pin_file.write_text("1234")
    p = Pkcs11Uri.try_parse(f"pkcs11:token=t?pin-source={str(pin_file).replace(' ', '%20')}")
    assert p.qattr.pin_source == str(pin_file)
    assert p.pin_source_content() == b"1234\n"


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
def test_cert_from_token(softhsm_shared):
    with CertCache() as cc, open(cc["pkcs11:token=SoftHSM;object=habCA1;type=public"]) as f:
        assert len(f.read()) > 0


def test_cert_from_file(tmp_path):
    cert_file = tmp_path / "cert.pem"
    cert_file.write_text("dummy cert content")
    with CertCache() as cc, open(cc[str(cert_file)]) as f:
        assert len(f.read()) > 0
