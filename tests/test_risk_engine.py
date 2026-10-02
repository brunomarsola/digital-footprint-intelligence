from app.analysis.risk import RiskEngine
from app.models.certificate import Certificate
from app.models.collection import CollectionStatus
from app.models.domain import Domain
from app.models.infrastructure import Infrastructure
from app.models.ip import IPAddress


def test_risk_engine_returns_no_findings_for_empty_infrastructure():
    infrastructure = Infrastructure(
        target="example.com",
    )

    findings = RiskEngine().evaluate(
        infrastructure
    )

    assert findings == []


def test_risk_engine_evaluates_certificate_rules():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="12345",
            common_name="*.example.com",
            classification="WILDCARD",
        )
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="67890",
            common_name="www.example.org",
            classification="EXTERNAL_DOMAIN",
        )
    )

    findings = RiskEngine().evaluate(
        infrastructure
    )

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "CERT-WILD-001",
        "CERT-EXT-001",
    }


def test_risk_engine_evaluates_infrastructure_rules():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(name="example.com")
    )

    infrastructure.add_domain(
        Domain(name="api.example.com")
    )

    infrastructure.add_ip(
        IPAddress(
            address="192.0.2.10"
        )
    )

    infrastructure.add_ip(
        IPAddress(
            address="192.0.2.20"
        )
    )

    findings = RiskEngine().evaluate(
        infrastructure
    )

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "DOMAIN-ENUM-001",
        "INFRA-IP-001",
    }


def test_risk_engine_detects_collection_failure():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_collection_status(
        CollectionStatus(
            source="crt.sh",
            status="error",
            attempts=3,
            error="HTTP 502",
        )
    )

    findings = RiskEngine().evaluate(
        infrastructure
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "COLLECTION-001"
    assert finding.severity == "LOW"
    assert finding.confidence == "HIGH"
    assert finding.title == "Incomplete collection"

    assert "crt.sh" in finding.evidence


def test_risk_engine_combines_multiple_rule_sources():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_collection_status(
        CollectionStatus(
            source="crt.sh",
            status="error",
            attempts=3,
            error="HTTP 502",
        )
    )

    infrastructure.add_domain(
        Domain(name="example.com")
    )

    infrastructure.add_domain(
        Domain(name="api.example.com")
    )

    infrastructure.add_ip(
        IPAddress(
            address="192.0.2.10"
        )
    )

    infrastructure.add_ip(
        IPAddress(
            address="192.0.2.20"
        )
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="12345",
            common_name="*.example.com",
            classification="WILDCARD",
        )
    )

    findings = RiskEngine().evaluate(
        infrastructure
    )

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "COLLECTION-001",
        "CERT-WILD-001",
        "DOMAIN-ENUM-001",
        "INFRA-IP-001",
    }