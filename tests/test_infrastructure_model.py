from app.models.certificate import Certificate
from app.models.collection import CollectionStatus
from app.models.domain import Domain
from app.models.finding import Finding
from app.models.infrastructure import Infrastructure
from app.models.ip import IPAddress
from app.models.relationship import Relationship
from app.models.similarity import (
    SimilarityResult,
    SimilaritySignal,
)


def test_infrastructure_normalizes_target():
    infrastructure = Infrastructure(
        target="  EXAMPLE.COM.  ",
    )

    assert infrastructure.target == "example.com"


def test_add_domain():
    infrastructure = Infrastructure(
        target="example.com",
    )

    domain = Domain(
        name="api.example.com",
    )

    infrastructure.add_domain(domain)
    infrastructure.add_domain(domain)

    assert infrastructure.domain_count == 1
    assert (
        infrastructure.domains[0].name
        == "api.example.com"
    )


def test_add_ip():
    infrastructure = Infrastructure(
        target="example.com",
    )

    ip = IPAddress(
        address="192.0.2.10",
    )

    infrastructure.add_ip(ip)
    infrastructure.add_ip(ip)

    assert infrastructure.ip_count == 1
    assert (
        infrastructure.ip_addresses[0].address
        == "192.0.2.10"
    )


def test_add_certificate():
    infrastructure = Infrastructure(
        target="example.com",
    )

    certificate = Certificate(
        certificate_id="12345",
        common_name="example.com",
    )

    infrastructure.add_certificate(
        certificate
    )

    infrastructure.add_certificate(
        certificate
    )

    assert infrastructure.certificate_count == 1
    assert (
        infrastructure.certificates[0].certificate_id
        == "12345"
    )


def test_infrastructure_can_contain_multiple_entities():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com"
        )
    )

    infrastructure.add_domain(
        Domain(
            name="api.example.com"
        )
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
            certificate_id="cert-001",
            common_name="example.com",
        )
    )

    assert infrastructure.domain_count == 2
    assert infrastructure.ip_count == 2
    assert infrastructure.certificate_count == 1


def test_add_collection_status():
    infrastructure = Infrastructure(
        target="example.com",
    )

    status = CollectionStatus(
        source="crt.sh",
        status="error",
        attempts=3,
        error="HTTP 502",
    )

    infrastructure.add_collection_status(
        status
    )

    assert len(
        infrastructure.collection_status
    ) == 1

    assert (
        infrastructure.collection_status[0].source
        == "crt.sh"
    )

    assert (
        infrastructure.collection_status[0].status
        == "error"
    )

    assert (
        infrastructure.collection_status[0].attempts
        == 3
    )

    assert (
        infrastructure.collection_status[0].error
        == "HTTP 502"
    )


def test_add_finding():
    infrastructure = Infrastructure(
        target="example.com",
    )

    finding = Finding(
        rule_id="TEST-001",
        severity="INFO",
        title="Test finding",
        description="Test description",
        evidence="Test evidence",
        confidence="HIGH",
    )

    infrastructure.add_finding(
        finding
    )

    assert len(
        infrastructure.findings
    ) == 1

    assert (
        infrastructure.findings[0]
        == finding
    )


def test_add_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    relationship = Relationship(
        source="example.com",
        target="192.0.2.10",
        relation="RESOLVES_TO",
        confidence="HIGH",
        evidence="DNS A record",
    )

    infrastructure.add_relationship(
        relationship
    )

    assert len(
        infrastructure.relationships
    ) == 1

    assert (
        infrastructure.relationships[0]
        == relationship
    )


def test_add_relationship_ignores_duplicates():
    infrastructure = Infrastructure(
        target="example.com",
    )

    relationship = Relationship(
        source="example.com",
        target="192.0.2.10",
        relation="RESOLVES_TO",
        confidence="HIGH",
        evidence="DNS A record",
    )

    infrastructure.add_relationship(
        relationship
    )

    infrastructure.add_relationship(
        relationship
    )

    assert len(
        infrastructure.relationships
    ) == 1

def test_infrastructure_adds_similarity_result():
    infrastructure = Infrastructure(
        target="example.com",
    )

    signal = SimilaritySignal(
        source="example.com",
        target="api.example.com",
        similarity_type="SHARED_IP",
        evidence="Shared IP address(es): 192.0.2.10",
    )

    result = SimilarityResult(
        source="example.com",
        target="api.example.com",
        signals=[signal],
    )

    infrastructure.add_similarity_result(result)

    assert infrastructure.similarity_results == [result]

def test_infrastructure_deduplicates_similarity_results():
    infrastructure = Infrastructure(
        target="example.com",
    )

    signal = SimilaritySignal(
        source="example.com",
        target="api.example.com",
        similarity_type="SHARED_IP",
        evidence="Shared IP address(es): 192.0.2.10",
    )

    result = SimilarityResult(
        source="example.com",
        target="api.example.com",
        signals=[signal],
    )

    infrastructure.add_similarity_result(result)
    infrastructure.add_similarity_result(result)

    assert len(
        infrastructure.similarity_results
    ) == 1