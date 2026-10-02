from app.models.certificate import Certificate


def test_certificate_normalization():
    certificate = Certificate(
        certificate_id="12345",
        issuer_name="  Example Certificate Authority  ",
        common_name="WWW.EXAMPLE.COM.",
        serial_number=" ABC123 ",
        domains=[
            "EXAMPLE.COM.",
            "*.example.com",
            "www.example.com.",
            "example.com",
        ],
    )

    assert certificate.certificate_id == "12345"
    assert certificate.issuer_name == "Example Certificate Authority"
    assert certificate.common_name == "www.example.com"
    assert certificate.serial_number == "abc123"

    assert certificate.domains == [
        "*.example.com",
        "example.com",
        "www.example.com",
    ]
def test_certificate_add_domain():
    certificate = Certificate(
        common_name="example.com",
    )

    certificate.add_domain("API.EXAMPLE.COM.")
    certificate.add_domain("api.example.com")
    certificate.add_domain("*.mail.example.com")

    assert certificate.domains == [
    "*.mail.example.com",
    "api.example.com",
]
def test_certificate_classification_defaults_to_none():
    certificate = Certificate(
        certificate_id="12345",
        common_name="example.com",
    )

    assert certificate.classification is None


def test_certificate_accepts_valid_domain_classification():
    certificate = Certificate(
        certificate_id="12345",
        common_name="example.com",
        classification="VALID_DOMAIN",
    )

    assert certificate.classification == "VALID_DOMAIN"


def test_certificate_accepts_wildcard_classification():
    certificate = Certificate(
        certificate_id="12345",
        common_name="*.example.com",
        classification="WILDCARD",
    )

    assert certificate.classification == "WILDCARD"


def test_certificate_accepts_external_domain_classification():
    certificate = Certificate(
        certificate_id="12345",
        common_name="www.example.org",
        classification="EXTERNAL_DOMAIN",
    )

    assert certificate.classification == "EXTERNAL_DOMAIN"


def test_certificate_accepts_non_domain_classification():
    certificate = Certificate(
        certificate_id="12345",
        common_name="as207960 test intermediate - example.com",
        classification="NON_DOMAIN",
    )

    assert certificate.classification == "NON_DOMAIN"


def test_certificate_classification_is_normalized():
    certificate = Certificate(
        certificate_id="12345",
        common_name="example.com",
        classification="valid_domain",
    )

    assert certificate.classification == "VALID_DOMAIN"

def test_certificate_preserves_wildcard_domain():
    certificate = Certificate(
        domains=["*.example.com"],
    )

    assert certificate.domains == ["*.example.com"]