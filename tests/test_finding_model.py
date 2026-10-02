import pytest

from app.models.finding import Finding


def test_finding_creation():
    finding = Finding(
        rule_id="CERT-EXT-001",
        severity="MEDIUM",
        title="External certificate domain detected",
        description=(
            "The certificate references a valid DNS name "
            "outside the investigated target namespace."
        ),
        evidence=(
            "Certificate 16228519060 | www.example.org"
        ),
        confidence="MEDIUM",
    )

    assert finding.rule_id == "CERT-EXT-001"
    assert finding.severity == "MEDIUM"
    assert (
        finding.title
        == "External certificate domain detected"
    )
    assert (
        finding.description
        == (
            "The certificate references a valid DNS name "
            "outside the investigated target namespace."
        )
    )
    assert (
        finding.evidence
        == "Certificate 16228519060 | www.example.org"
    )
    assert finding.confidence == "MEDIUM"


def test_finding_normalizes_fields():
    finding = Finding(
        rule_id=" cert-ext-001 ",
        severity=" medium ",
        title=" External certificate domain detected ",
        description=" Example description ",
        evidence=" Certificate evidence ",
        confidence=" high ",
    )

    assert finding.rule_id == "CERT-EXT-001"
    assert finding.severity == "MEDIUM"
    assert (
        finding.title
        == "External certificate domain detected"
    )
    assert finding.description == "Example description"
    assert finding.evidence == "Certificate evidence"
    assert finding.confidence == "HIGH"


def test_finding_supports_info_severity():
    finding = Finding(
        rule_id="DOMAIN-ENUM-001",
        severity="INFO",
        title="Multiple domains discovered",
        description="Multiple DNS names were discovered.",
        evidence="7 domains",
        confidence="HIGH",
    )

    assert finding.severity == "INFO"


def test_finding_supports_critical_severity():
    finding = Finding(
        rule_id="TEST-CRITICAL-001",
        severity="CRITICAL",
        title="Critical finding",
        description="Critical test finding.",
        evidence="Test evidence",
        confidence="HIGH",
    )

    assert finding.severity == "CRITICAL"


def test_finding_supports_low_confidence():
    finding = Finding(
        rule_id="TEST-LOW-001",
        severity="LOW",
        title="Low confidence finding",
        description="Test finding.",
        evidence="Test evidence",
        confidence="LOW",
    )

    assert finding.confidence == "LOW"


def test_finding_rejects_invalid_severity():
    with pytest.raises(
        ValueError,
        match="Invalid finding severity",
    ):
        Finding(
            rule_id="TEST-001",
            severity="URGENT",
            title="Invalid severity",
            description="Test finding.",
            evidence="Test evidence",
            confidence="HIGH",
        )


def test_finding_rejects_invalid_confidence():
    with pytest.raises(
        ValueError,
        match="Invalid finding confidence",
    ):
        Finding(
            rule_id="TEST-002",
            severity="LOW",
            title="Invalid confidence",
            description="Test finding.",
            evidence="Test evidence",
            confidence="MAYBE",
        )


def test_finding_accepts_all_valid_severities():
    for severity in (
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ):
        finding = Finding(
            rule_id="TEST-SEVERITY",
            severity=severity,
            title="Test finding",
            description="Test description.",
            evidence="Test evidence",
            confidence="HIGH",
        )

        assert finding.severity == severity


def test_finding_accepts_all_valid_confidences():
    for confidence in (
        "LOW",
        "MEDIUM",
        "HIGH",
    ):
        finding = Finding(
            rule_id="TEST-CONFIDENCE",
            severity="INFO",
            title="Test finding",
            description="Test description.",
            evidence="Test evidence",
            confidence=confidence,
        )

        assert finding.confidence == confidence