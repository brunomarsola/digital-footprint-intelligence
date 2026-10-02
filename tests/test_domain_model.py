from app.models.domain import Domain


def test_domain_normalization():
    domain = Domain(
        name="  Example.COM.  ",
    )

    assert domain.name == "example.com"


def test_domain_removes_duplicates():
    domain = Domain(
        name="example.com",
        ipv4=[
            "192.0.2.1",
            "192.0.2.1",
            "192.0.2.2",
        ],
        nameservers=[
            "NS1.EXAMPLE.COM.",
            "ns1.example.com.",
        ],
    )

    assert domain.ipv4 == [
        "192.0.2.1",
        "192.0.2.2",
    ]

    assert domain.nameservers == [
        "ns1.example.com",
    ]


def test_add_subdomain():
    domain = Domain(name="example.com")

    domain.add_subdomain("WWW.EXAMPLE.COM.")
    domain.add_subdomain("www.example.com")

    assert domain.discovered_subdomains == [
        "www.example.com",
    ]


def test_add_ip():
    domain = Domain(name="example.com")

    domain.add_ipv4("192.0.2.1")
    domain.add_ipv4("192.0.2.1")

    assert domain.ipv4 == [
        "192.0.2.1",
    ]