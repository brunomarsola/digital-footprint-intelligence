from app.analysis.certificate_rules import (
    evaluate_certificate,
)
from app.models.certificate import Certificate


def test_wildcard_certificate_generates_finding():
    certificate = Certificate(
        certificate_id="12345",
        common_name="*.example.com",
        classification="WILDCARD",
    )

    findings = evaluate_certificate(
        certificate
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CERT-WILD-001"
    assert finding.severity == "LOW"
    assert (
        finding.title
        == "Wildcard certificate detected"
    )
    assert finding.confidence == "HIGH"

    assert (
        "12345 | *.example.com"
        in finding.evidence
    )


def test_external_domain_certificate_generates_finding():
    certificate = Certificate(
        certificate_id="67890",
        common_name="www.example.org",
        classification="EXTERNAL_DOMAIN",
    )

    findings = evaluate_certificate(
        certificate
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CERT-EXT-001"
    assert finding.severity == "MEDIUM"
    assert (
        finding.title
        == "External certificate domain detected"
    )
    assert finding.confidence == "MEDIUM"

    assert (
        "67890 | www.example.org"
        in finding.evidence
    )


def test_non_domain_certificate_generates_finding():
    certificate = Certificate(
        certificate_id="11111",
        common_name=(
            "as207960 test intermediate - example.com"
        ),
        classification="NON_DOMAIN",
    )

    findings = evaluate_certificate(
        certificate
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CERT-NONDNS-001"
    assert finding.severity == "INFO"
    assert (
        finding.title
        == "Non-DNS certificate name detected"
    )
    assert finding.confidence == "HIGH"

    assert (
        "11111 | as207960 test intermediate - example.com"
        in finding.evidence
    )


def test_valid_domain_certificate_generates_no_finding():
    certificate = Certificate(
        certificate_id="22222",
        common_name="www.example.com",
        classification="VALID_DOMAIN",
    )

    findings = evaluate_certificate(
        certificate
    )

    assert findings == []


def test_unclassified_certificate_generates_no_finding():
    certificate = Certificate(
        certificate_id="33333",
        common_name="example.com",
    )

    findings = evaluate_certificate(
        certificate
    )

    assert findings == []


def test_certificate_without_id_or_common_name_still_generates_finding():
    certificate = Certificate(
        classification="WILDCARD",
    )

    findings = evaluate_certificate(
        certificate
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CERT-WILD-001"
    assert "unknown | unknown" in finding.evidence