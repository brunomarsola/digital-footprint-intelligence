from app.analysis.certificate import (
    CertificateClassifier,
)
from app.models.certificate import Certificate


def test_classify_exact_target_as_valid_domain():
    certificate = Certificate(
        common_name="example.com",
    )

    result = CertificateClassifier.classify(
        certificate,
        "example.com",
    )

    assert result == "VALID_DOMAIN"


def test_classify_subdomain_as_valid_domain():
    certificate = Certificate(
        common_name="www.example.com",
    )

    result = CertificateClassifier.classify(
        certificate,
        "example.com",
    )

    assert result == "VALID_DOMAIN"


def test_classify_nested_subdomain_as_valid_domain():
    certificate = Certificate(
        common_name="api.dev.example.com",
    )

    result = CertificateClassifier.classify(
        certificate,
        "example.com",
    )

    assert result == "VALID_DOMAIN"


def test_classify_wildcard_as_wildcard():
    certificate = Certificate(
        common_name="*.example.com",
    )

    result = CertificateClassifier.classify(
        certificate,
        "example.com",
    )

    assert result == "WILDCARD"


def test_classify_external_domain():
    certificate = Certificate(
        common_name="www.example.org",
    )

    result = CertificateClassifier.classify(
        certificate,
        "example.com",
    )

    assert result == "EXTERNAL_DOMAIN"


def test_classify_external_wildcard():
    certificate = Certificate(
        common_name="*.example.org",
    )

    result = CertificateClassifier.classify(
        certificate,
        "example.com",
    )

    assert result == "EXTERNAL_DOMAIN"


def test_classify_invalid_certificate_name():
    certificate = Certificate(
        common_name=(
            "as207960 test intermediate - example.com"
        ),
    )

    result = CertificateClassifier.classify(
        certificate,
        "example.com",
    )

    assert result == "NON_DOMAIN"


def test_classify_email_as_non_domain():
    certificate = Certificate(
        common_name="subjectname@example.com",
    )

    result = CertificateClassifier.classify(
        certificate,
        "example.com",
    )

    assert result == "NON_DOMAIN"


def test_classify_empty_common_name_as_non_domain():
    certificate = Certificate()

    result = CertificateClassifier.classify(
        certificate,
        "example.com",
    )

    assert result == "NON_DOMAIN"


def test_classify_normalizes_target_and_common_name():
    certificate = Certificate(
        common_name="WWW.EXAMPLE.COM.",
    )

    result = CertificateClassifier.classify(
        certificate,
        " EXAMPLE.COM. ",
    )

    assert result == "VALID_DOMAIN"

def test_classify_name_exact_target_as_valid_domain():
    result = CertificateClassifier.classify_name(
        "example.com",
        "example.com",
    )

    assert result == "VALID_DOMAIN"


def test_classify_name_subdomain_as_valid_domain():
    result = CertificateClassifier.classify_name(
        "api.example.com",
        "example.com",
    )

    assert result == "VALID_DOMAIN"


def test_classify_name_wildcard_as_wildcard():
    result = CertificateClassifier.classify_name(
        "*.example.com",
        "example.com",
    )

    assert result == "WILDCARD"


def test_classify_name_external_domain():
    result = CertificateClassifier.classify_name(
        "www.example.org",
        "example.com",
    )

    assert result == "EXTERNAL_DOMAIN"


def test_classify_name_email_as_non_domain():
    result = CertificateClassifier.classify_name(
        "user@example.com",
        "example.com",
    )

    assert result == "NON_DOMAIN"