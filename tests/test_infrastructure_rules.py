from app.analysis.infrastructure_rules import (
    evaluate_infrastructure,
)
from app.models.domain import Domain
from app.models.infrastructure import Infrastructure
from app.models.ip import IPAddress


def test_multiple_domains_generate_finding():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(name="example.com")
    )

    infrastructure.add_domain(
        Domain(name="www.example.com")
    )

    findings = evaluate_infrastructure(
        infrastructure
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "DOMAIN-ENUM-001"
    assert finding.severity == "INFO"
    assert finding.title == "Multiple domains discovered"
    assert finding.confidence == "HIGH"

    assert (
        "Domains discovered: 2"
        in finding.evidence
    )


def test_multiple_ips_generate_finding():
    infrastructure = Infrastructure(
        target="example.com",
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

    findings = evaluate_infrastructure(
        infrastructure
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "INFRA-IP-001"
    assert finding.severity == "INFO"
    assert finding.title == "Multiple IP addresses discovered"
    assert finding.confidence == "HIGH"

    assert (
        "IP addresses discovered: 2"
        in finding.evidence
    )


def test_single_domain_generates_no_domain_finding():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(name="example.com")
    )

    findings = evaluate_infrastructure(
        infrastructure
    )

    assert findings == []


def test_single_ip_generates_no_ip_finding():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_ip(
        IPAddress(
            address="192.0.2.10"
        )
    )

    findings = evaluate_infrastructure(
        infrastructure
    )

    assert findings == []


def test_multiple_domains_and_ips_generate_multiple_findings():
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

    findings = evaluate_infrastructure(
        infrastructure
    )

    assert len(findings) == 2

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "DOMAIN-ENUM-001",
        "INFRA-IP-001",
    }