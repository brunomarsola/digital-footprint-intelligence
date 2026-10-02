from app.exporters.csv import export_csv
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

def test_csv_exporter_preserves_empty_certificate_table_schema():
    infrastructure = Infrastructure(
        target="example.com"
    )

    tables = export_csv(
        infrastructure
    )

    assert tables["certificates"] == []

def test_export_csv_contains_investigation_data():
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

    infrastructure.add_collection_status(
        CollectionStatus(
            source="crt.sh",
            status="error",
            attempts=3,
            error="HTTP 502",
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

    result = export_csv(
        infrastructure
    )

    assert set(result.keys()) == {
        "collection_status",
        "domains",
        "ips",
        "certificates",
        "findings",
        "relationships",
        "similarity",
    }

    assert result["collection_status"][0] == {
        "source": "DNS",
        "status": "success",
        "attempts": 1,
        "error": "",
    }

    assert result["domains"] == [
        {
            "name": "example.com",
            "ipv4": "192.0.2.10",
            "ipv6": "",
            "nameservers": "ns1.example.com",
            "mail_servers": "mail.example.com",
            "txt_records": "",
            "cname_records": "",
            "discovered_subdomains": "",
        },
        {
            "name": "api.example.com",
            "ipv4": "",
            "ipv6": "",
            "nameservers": "",
            "mail_servers": "",
            "txt_records": "",
            "cname_records": "",
            "discovered_subdomains": "",
        },
    ]

    assert result["ips"] == [
        {
            "address": "192.0.2.10",
            "version": 4,
            "asn": "",
            "organization": "",
            "country": "",
            "network": "",
            "hostnames": "example.com",
        }
    ]

    assert result["certificates"] == [
        {
            "certificate_id": "12345",
            "issuer_name": "Example CA",
            "common_name": "example.com",
            "serial_number": "abc123",
            "not_before": "2026-01-01",
            "not_after": "2027-01-01",
            "classification": "",
            "domains": "api.example.com;example.com",
        }
    ]

    assert result["findings"] == [
        {
            "rule_id": "TEST-001",
            "severity": "MEDIUM",
            "title": "Test finding",
            "description": "Test description",
            "evidence": "Test evidence",
            "confidence": "HIGH",
        }
    ]

    assert result["relationships"] == [
        {
            "source": "api.example.com",
            "target": "example.com",
            "relation": "SUBDOMAIN_OF",
            "confidence": "HIGH",
            "evidence": "Domain discovered within target namespace",
        }
    ]

    assert result["similarity"] == [
        {
            "source": "api.example.com",
            "target": "example.com",
            "similarity_type": "SUBDOMAIN_RELATION",
            "evidence": "Domain discovered within target namespace",
        }
    ]