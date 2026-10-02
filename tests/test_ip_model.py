import pytest

from app.models.ip import IPAddress


def test_ipv4_normalization():
    ip = IPAddress(
        address=" 192.0.2.10 ",
    )

    assert ip.address == "192.0.2.10"
    assert ip.version == 4


def test_ipv6_normalization():
    ip = IPAddress(
        address="2001:0db8:0000:0000:0000:0000:0000:0001",
    )

    assert ip.address == "2001:db8::1"
    assert ip.version == 6


def test_invalid_ip_is_rejected():
    with pytest.raises(ValueError):
        IPAddress(
            address="999.999.999.999",
        )


def test_ip_metadata_normalization():
    ip = IPAddress(
        address="192.0.2.10",
        asn=64500,
        organization="  Example Network  ",
        country=" BR ",
        network=" 192.0.2.0/24 ",
        hostnames=[
            "WWW.EXAMPLE.COM.",
            "api.example.com.",
            "www.example.com",
        ],
    )

    assert ip.asn == 64500
    assert ip.organization == "Example Network"
    assert ip.country == "BR"
    assert ip.network == "192.0.2.0/24"

    assert ip.hostnames == [
        "api.example.com",
        "www.example.com",
    ]


def test_add_hostname():
    ip = IPAddress(
        address="192.0.2.10",
    )

    ip.add_hostname("WWW.EXAMPLE.COM.")
    ip.add_hostname("www.example.com")

    assert ip.hostnames == [
        "www.example.com",
    ]