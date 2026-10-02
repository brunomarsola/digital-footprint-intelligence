from app.models.relationship import Relationship


def test_relationship_creation():
    relationship = Relationship(
        source="example.com",
        target="192.0.2.10",
        relation="RESOLVES_TO",
        confidence="HIGH",
        evidence="DNS A record",
    )

    assert relationship.source == "example.com"
    assert relationship.target == "192.0.2.10"
    assert relationship.relation == "RESOLVES_TO"
    assert relationship.confidence == "HIGH"
    assert relationship.evidence == "DNS A record"


def test_relationship_normalizes_fields():
    relationship = Relationship(
        source=" example.com ",
        target=" 192.0.2.10 ",
        relation=" resolves_to ",
        confidence=" high ",
        evidence=" DNS A record ",
    )

    assert relationship.source == "example.com"
    assert relationship.target == "192.0.2.10"
    assert relationship.relation == "RESOLVES_TO"
    assert relationship.confidence == "HIGH"
    assert relationship.evidence == "DNS A record"


def test_relationship_supports_subdomain_relation():
    relationship = Relationship(
        source="dev.example.com",
        target="example.com",
        relation="SUBDOMAIN_OF",
        confidence="HIGH",
        evidence="DNS / certificate discovery",
    )

    assert relationship.relation == "SUBDOMAIN_OF"


def test_relationship_supports_certificate_relation():
    relationship = Relationship(
        source="example.com",
        target="12345",
        relation="HAS_CERTIFICATE",
        confidence="HIGH",
        evidence="Certificate Transparency",
    )

    assert relationship.relation == "HAS_CERTIFICATE"


def test_relationship_supports_shared_ip_relation():
    relationship = Relationship(
        source="example.com",
        target="www.example.com",
        relation="SHARES_IP",
        confidence="MEDIUM",
        evidence="Both domains resolve to 192.0.2.10",
    )

    assert relationship.relation == "SHARES_IP"


def test_relationship_supports_shared_certificate_relation():
    relationship = Relationship(
        source="example.com",
        target="www.example.com",
        relation="SHARES_CERTIFICATE",
        confidence="HIGH",
        evidence="Both names appear in certificate SANs",
    )

    assert relationship.relation == "SHARES_CERTIFICATE"