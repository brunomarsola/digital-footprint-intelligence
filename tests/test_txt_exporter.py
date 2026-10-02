from app.exporters.txt import export_txt
from app.models.certificate import Certificate
from app.models.collection import CollectionStatus
from app.models.domain import Domain
from app.models.finding import Finding
from app.models.infrastructure import Infrastructure
from app.models.ip import IPAddress
from app.models.relationship import Relationship
from app.models.similarity import SimilarityResult, SimilaritySignal


def test_export_txt_contains_investigation_data():
    infrastructure = Infrastructure(
        target="example.com"
    )

    infrastructure.add_collection_status(
        CollectionStatus(
            source="DNS",
            status="success",
            attempts=1,
        )
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            ipv4=["192.0.2.10"],
            nameservers=["ns1.example.com"],
            mail_servers=["mail.example.com"],
        )
    )

    infrastructure.add_domain(
        Domain(
            name="api.example.com"
        )
    )

    infrastructure.add_ip(
        IPAddress(
            address="192.0.2.10",
            hostnames=["example.com"],
        )
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="12345",
            issuer_name="Example CA",
            common_name="example.com",
            serial_number="ABC123",
            not_before="2026-01-01",
            not_after="2027-01-01",
            domains=[
                "example.com",
                "api.example.com",
            ],
        )
    )

    infrastructure.add_finding(
        Finding(
            rule_id="TEST-001",
            severity="MEDIUM",
            title="Test finding",
            description="Test description",
            evidence="Test evidence",
            confidence="HIGH",
        )
    )

    infrastructure.add_relationship(
        Relationship(
            source="api.example.com",
            target="example.com",
            relation="SUBDOMAIN_OF",
            confidence="HIGH",
            evidence="Domain discovered within target namespace",
        )
    )

    infrastructure.add_similarity_result(
        SimilarityResult(
            source="api.example.com",
            target="example.com",
            signals=[
                SimilaritySignal(
                    source="api.example.com",
                    target="example.com",
                    similarity_type="SUBDOMAIN_RELATION",
                    evidence="Domain discovered within target namespace",
                )
            ],
        )
    )

    report = export_txt(
        infrastructure
    )

    assert "DIGITAL FOOTPRINT INTELLIGENCE" in report
    assert "Target: example.com" in report

    assert "example.com" in report
    assert "api.example.com" in report
    assert "192.0.2.10" in report

    assert "12345" in report
    assert "Example CA" in report

    assert "TEST-001" in report
    assert "Test finding" in report

    assert "SUBDOMAIN_OF" in report
    assert "SUBDOMAIN_RELATION" in report