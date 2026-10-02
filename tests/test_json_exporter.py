import json

from app.exporters.json import export_json
from app.models.certificate import Certificate
from app.models.collection import CollectionStatus
from app.models.domain import Domain
from app.models.finding import Finding
from app.models.infrastructure import Infrastructure
from app.models.ip import IPAddress
from app.models.relationship import Relationship
from app.models.similarity import SimilarityResult, SimilaritySignal


def test_export_json_contains_investigation_data():
    infrastructure = Infrastructure(target="example.com")

    infrastructure.add_collection_status(
        CollectionStatus(
            source="dns",
            status="success",
            attempts=1,
        )
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            ipv4=["93.184.216.34"],
            discovered_subdomains=["api.example.com"],
        )
    )

    infrastructure.add_ip(
        IPAddress(
            address="93.184.216.34",
            asn=15133,
            organization="Example Org",
            country="US",
            network="93.184.216.0/24",
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
            domains=["example.com", "api.example.com"],
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
            source="example.com",
            target="93.184.216.34",
            relation="RESOLVES_TO",
            confidence="HIGH",
            evidence="DNS A record",
        )
    )

    infrastructure.add_similarity_result(
        SimilarityResult(
            source="example.com",
            target="api.example.com",
            signals=[
                SimilaritySignal(
                    source="example.com",
                    target="api.example.com",
                    similarity_type="SUBDOMAIN_RELATION",
                    evidence="Domain discovered within target namespace",
                )
            ],
        )
    )

    result = export_json(infrastructure)

    data = json.loads(result)

    assert data["target"] == "example.com"

    assert data["collection_status"] == [
        {
            "source": "dns",
            "status": "success",
            "attempts": 1,
            "error": None,
        }
    ]

    assert data["domains"] == [
        {
            "name": "example.com",
            "ipv4": ["93.184.216.34"],
            "ipv6": [],
            "nameservers": [],
            "mail_servers": [],
            "txt_records": [],
            "cname_records": [],
            "discovered_subdomains": ["api.example.com"],
        }
    ]

    assert data["ip_addresses"] == [
        {
            "address": "93.184.216.34",
            "version": 4,
            "asn": 15133,
            "organization": "Example Org",
            "country": "US",
            "network": "93.184.216.0/24",
            "hostnames": [],
        }
    ]

    assert data["certificates"] == [
        {
            "certificate_id": "12345",
            "issuer_name": "Example CA",
            "common_name": "example.com",
            "serial_number": "abc123",
            "not_before": "2026-01-01",
            "not_after": "2027-01-01",
            "classification": None,
            "domains": ["api.example.com", "example.com"],
        }
    ]

    assert data["findings"] == [
        {
            "rule_id": "TEST-001",
            "severity": "MEDIUM",
            "title": "Test finding",
            "description": "Test description",
            "evidence": "Test evidence",
            "confidence": "HIGH",
        }
    ]

    assert data["relationships"] == [
        {
            "source": "example.com",
            "target": "93.184.216.34",
            "relation": "RESOLVES_TO",
            "confidence": "HIGH",
            "evidence": "DNS A record",
        }
    ]

    assert data["similarity_results"] == [
        {
            "source": "example.com",
            "target": "api.example.com",
            "signals": [
                {
                    "source": "example.com",
                    "target": "api.example.com",
                    "similarity_type": "SUBDOMAIN_RELATION",
                    "evidence": "Domain discovered within target namespace",
                }
            ],
        }
    ]