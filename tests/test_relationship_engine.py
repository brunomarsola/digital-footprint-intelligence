from app.analysis.relationship import RelationshipEngine
from app.models.certificate import Certificate, CertificateClassification
from app.models.infrastructure import Infrastructure
from app.models.domain import Domain

def test_relationship_engine_builds_ipv4_resolution():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            ipv4=[
                "192.0.2.10",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    assert len(relationships) == 1

    relationship = relationships[0]

    assert relationship.source == "example.com"
    assert relationship.target == "192.0.2.10"
    assert relationship.relation == "RESOLVES_TO"
    assert relationship.confidence == "HIGH"
    assert relationship.evidence == "DNS A record"


def test_relationship_engine_builds_ipv6_resolution():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            ipv6=[
                "2001:db8::10",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    assert len(relationships) == 1

    relationship = relationships[0]

    assert relationship.source == "example.com"
    assert relationship.target == "2001:db8::10"
    assert relationship.relation == "RESOLVES_TO"
    assert relationship.confidence == "HIGH"
    assert relationship.evidence == "DNS AAAA record"


def test_relationship_engine_builds_subdomain_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
        )
    )

    infrastructure.add_domain(
        Domain(
            name="api.example.com",
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    assert len(relationships) == 1

    relationship = relationships[0]

    assert relationship.source == "api.example.com"
    assert relationship.target == "example.com"
    assert relationship.relation == "SUBDOMAIN_OF"
    assert relationship.confidence == "HIGH"


def test_relationship_engine_builds_certificate_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="cert-001",
            common_name="example.com",
            domains=[
                "example.com",
                "www.example.com",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    assert len(relationships) == 2

    assert any(
        relationship.source == "example.com"
        and relationship.target == "cert-001"
        and relationship.relation == "HAS_CERTIFICATE"
        for relationship in relationships
    )

    assert any(
        relationship.source == "www.example.com"
        and relationship.target == "cert-001"
        and relationship.relation == "HAS_CERTIFICATE"
        for relationship in relationships
    )


def test_relationship_engine_does_not_create_false_domain_ip_relationships():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            ipv4=[
                "192.0.2.10",
            ],
        )
    )

    infrastructure.add_domain(
        Domain(
            name="api.example.com",
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    resolution_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "RESOLVES_TO"
    ]

    assert len(
        resolution_relationships
    ) == 1

    assert (
        resolution_relationships[0].source
        == "example.com"
    )

    assert (
        resolution_relationships[0].target
        == "192.0.2.10"
    )


def test_relationship_engine_deduplicates_relationships():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            ipv4=[
                "192.0.2.10",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    assert len(relationships) == 1

def test_relationship_engine_builds_cname_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="www.example.com",
            cname_records=[
                "edge.example.net",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    cname_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "CNAME_TO"
    ]

    assert len(
        cname_relationships
    ) == 1

    relationship = cname_relationships[0]

    assert relationship.source == "www.example.com"
    assert relationship.target == "edge.example.net"
    assert relationship.relation == "CNAME_TO"
    assert relationship.confidence == "HIGH"
    assert relationship.evidence == "DNS CNAME record"


def test_relationship_engine_builds_nameserver_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            nameservers=[
                "ns1.example.net",
                "ns2.example.net",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    nameserver_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "USES_NAMESERVER"
    ]

    assert len(
        nameserver_relationships
    ) == 2

    assert any(
        relationship.source == "example.com"
        and relationship.target == "ns1.example.net"
        for relationship in nameserver_relationships
    )

    assert any(
        relationship.source == "example.com"
        and relationship.target == "ns2.example.net"
        for relationship in nameserver_relationships
    )


def test_relationship_engine_builds_mail_server_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            mail_servers=[
                "mail.example.net",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    mail_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "USES_MAIL_SERVER"
    ]

    assert len(
        mail_relationships
    ) == 1

    relationship = mail_relationships[0]

    assert relationship.source == "example.com"
    assert relationship.target == "mail.example.net"
    assert relationship.relation == "USES_MAIL_SERVER"
    assert relationship.confidence == "HIGH"
    assert relationship.evidence == "DNS MX record"

def test_relationship_engine_ignores_null_mail_server():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            mail_servers=[],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    mail_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "USES_MAIL_SERVER"
    ]

    assert mail_relationships == []

def test_relationship_engine_builds_shared_ip_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            ipv4=[
                "192.0.2.10",
            ],
        )
    )

    infrastructure.add_domain(
        Domain(
            name="other.example",
            ipv4=[
                "192.0.2.10",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    shared_ip_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_IP"
    ]

    assert len(
        shared_ip_relationships
    ) == 1

    relationship = (
        shared_ip_relationships[0]
    )

    assert relationship.source == "example.com"
    assert relationship.target == "other.example"
    assert relationship.relation == "SHARES_IP"
    assert relationship.confidence == "HIGH"
    assert (
        relationship.evidence
        == "Shared IP address(es): 192.0.2.10"
    )


def test_relationship_engine_builds_shared_ipv6_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            ipv6=[
                "2001:db8::10",
            ],
        )
    )

    infrastructure.add_domain(
        Domain(
            name="other.example",
            ipv6=[
                "2001:db8::10",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    shared_ip_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_IP"
    ]

    assert len(
        shared_ip_relationships
    ) == 1

    relationship = (
        shared_ip_relationships[0]
    )

    assert relationship.source == "example.com"
    assert relationship.target == "other.example"
    assert relationship.relation == "SHARES_IP"
    assert (
        relationship.evidence
        == "Shared IP address(es): 2001:db8::10"
    )


def test_relationship_engine_ignores_non_shared_ips():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            ipv4=[
                "192.0.2.10",
            ],
        )
    )

    infrastructure.add_domain(
        Domain(
            name="other.example",
            ipv4=[
                "192.0.2.20",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    shared_ip_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_IP"
    ]

    assert shared_ip_relationships == []


def test_relationship_engine_does_not_create_self_shared_ip():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            ipv4=[
                "192.0.2.10",
                "192.0.2.20",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    shared_ip_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_IP"
    ]

    assert shared_ip_relationships == []


def test_relationship_engine_aggregates_multiple_shared_ips():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_domain(
        Domain(
            name="example.com",
            ipv4=[
                "192.0.2.10",
                "192.0.2.20",
            ],
        )
    )

    infrastructure.add_domain(
        Domain(
            name="other.example",
            ipv4=[
                "192.0.2.10",
                "192.0.2.20",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    shared_ip_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_IP"
    ]

    assert len(
        shared_ip_relationships
    ) == 1

    relationship = (
        shared_ip_relationships[0]
    )

    assert (
        relationship.evidence
        == (
            "Shared IP address(es): "
            "192.0.2.10, 192.0.2.20"
        )
    )

def test_relationship_engine_builds_shared_certificate_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="cert-001",
            common_name="example.com",
            domains=[
                "example.com",
                "api.example.com",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    shared_certificate_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_CERTIFICATE"
    ]

    assert len(
        shared_certificate_relationships
    ) == 1

    relationship = (
        shared_certificate_relationships[0]
    )

    assert relationship.source == "api.example.com"
    assert relationship.target == "example.com"
    assert relationship.relation == "SHARES_CERTIFICATE"
    assert relationship.confidence == "HIGH"
    assert (
        relationship.evidence
        == "Shared certificate(s): cert-001"
    )


def test_relationship_engine_ignores_single_domain_certificate():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="cert-001",
            common_name="example.com",
            domains=[
                "example.com",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    shared_certificate_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_CERTIFICATE"
    ]

    assert shared_certificate_relationships == []


def test_relationship_engine_aggregates_multiple_shared_certificates():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="cert-001",
            common_name="example.com",
            domains=[
                "example.com",
                "api.example.com",
            ],
        )
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="cert-002",
            common_name="api.example.com",
            domains=[
                "example.com",
                "api.example.com",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    shared_certificate_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_CERTIFICATE"
    ]

    assert len(
        shared_certificate_relationships
    ) == 1

    relationship = (
        shared_certificate_relationships[0]
    )

    assert (
        relationship.source
        == "api.example.com"
    )

    assert (
        relationship.target
        == "example.com"
    )

    assert (
        relationship.evidence
        == (
            "Shared certificate(s): "
            "cert-001, cert-002"
        )
    )


def test_relationship_engine_ignores_certificate_without_id():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id=None,
            common_name="example.com",
            domains=[
                "example.com",
                "api.example.com",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    shared_certificate_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_CERTIFICATE"
    ]

    assert shared_certificate_relationships == []

def test_wildcard_certificate_name_does_not_create_shared_certificate_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="cert-001",
            common_name="example.com",
            domains=[
                "example.com",
                "*.example.com",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(infrastructure)

    shared_certificate_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_CERTIFICATE"
    ]

    assert shared_certificate_relationships == []

def test_external_certificate_name_does_not_create_shared_certificate_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="cert-001",
            common_name="example.com",
            domains=[
                "example.com",
                "www.example.org",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(infrastructure)

    shared_certificate_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_CERTIFICATE"
    ]

    assert shared_certificate_relationships == []

def test_non_domain_certificate_name_does_not_create_shared_certificate_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="cert-001",
            common_name="example.com",
            domains=[
                "example.com",
                "user@example.com",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(infrastructure)

    shared_certificate_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_CERTIFICATE"
    ]

    assert shared_certificate_relationships == []


def test_relationship_engine_builds_certificate_relationship():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="cert-001",
            common_name="example.com",
            domains=[
                "example.com",
                "www.example.com",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    assert len(relationships) == 3

    certificate_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "HAS_CERTIFICATE"
    ]

    assert len(certificate_relationships) == 2

    shared_certificate_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "SHARES_CERTIFICATE"
    ]

    assert len(shared_certificate_relationships) == 1

    relationship = shared_certificate_relationships[0]

    assert relationship.source == "example.com"
    assert relationship.target == "www.example.com"
    assert relationship.relation == "SHARES_CERTIFICATE"
    assert relationship.confidence == "HIGH"
    assert relationship.evidence == "Shared certificate(s): cert-001"

def test_relationship_engine_builds_certificate_relationships():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="cert-001",
            common_name="example.com",
            domains=[
                "example.com",
                "www.example.com",
            ],
        )
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(
        infrastructure
    )

    certificate_relationships = [
        relationship
        for relationship in relationships
        if relationship.relation == "HAS_CERTIFICATE"
    ]

    assert len(certificate_relationships) == 2

    pairs = {
        (
            relationship.source,
            relationship.target,
        )
        for relationship in certificate_relationships
    }

    assert pairs == {
        ("example.com", "cert-001"),
        ("www.example.com", "cert-001"),
    }

def test_non_domain_certificate_name_does_not_create_has_certificate():
    certificate = Certificate(
        certificate_id="123",
        issuer_name="Test CA",
        common_name="example.com",
        domains=[
            "example.com",
            "user@example.com",
        ],
    )

    infrastructure = Infrastructure(
        target="example.com",
        certificates=[certificate],
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(infrastructure)

    has_certificate = [
        relationship
        for relationship in relationships
        if relationship.relation == "HAS_CERTIFICATE"
    ]

    assert len(has_certificate) == 1
    assert has_certificate[0].source == "example.com"
    assert has_certificate[0].target == "123"

def test_external_domain_does_not_create_has_certificate():
    certificate = Certificate(
        certificate_id="456",
        issuer_name="Test CA",
        common_name="example.com",
        domains=[
            "example.com",
            "www.example.org",
        ],
    )

    infrastructure = Infrastructure(
        target="example.com",
        certificates=[certificate],
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(infrastructure)

    has_certificate = [
        relationship
        for relationship in relationships
        if relationship.relation == "HAS_CERTIFICATE"
    ]

    assert len(has_certificate) == 1
    assert has_certificate[0].source == "example.com"
    assert has_certificate[0].target == "456"

def test_wildcard_domain_does_not_create_has_certificate():
    certificate = Certificate(
        certificate_id="789",
        issuer_name="Test CA",
        common_name="*.example.com",
        domains=[
            "*.example.com",
            "example.com",
        ],
    )

    infrastructure = Infrastructure(
        target="example.com",
        certificates=[certificate],
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(infrastructure)

    has_certificate = [
        relationship
        for relationship in relationships
        if relationship.relation == "HAS_CERTIFICATE"
    ]

    assert len(has_certificate) == 1
    assert has_certificate[0].source == "example.com"
    assert has_certificate[0].target == "789"

def test_wildcard_domain_does_not_create_has_certificate():
    certificate = Certificate(
        certificate_id="789",
        issuer_name="Test CA",
        common_name="*.example.com",
        domains=[
            "*.example.com",
            "example.com",
        ],
    )

    infrastructure = Infrastructure(
        target="example.com",
        certificates=[certificate],
    )

    engine = RelationshipEngine()

    relationships = engine.evaluate(infrastructure)

    has_certificate = [
        relationship
        for relationship in relationships
        if relationship.relation == "HAS_CERTIFICATE"
    ]

    assert len(has_certificate) == 1
    assert has_certificate[0].source == "example.com"
    assert has_certificate[0].target == "789"