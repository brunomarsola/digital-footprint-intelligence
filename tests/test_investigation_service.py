from unittest.mock import patch

from app.services.investigation import investigate

from app.analysis.similarity import SimilarityEngine

@patch(
    "app.services.investigation.collect_rdap"
)
@patch(
    "app.services.investigation.collect_certificates"
)
@patch(
    "app.services.investigation.collect_dns"
)
def test_investigation_builds_infrastructure(
    mock_dns,
    mock_certificates,
    mock_rdap,
):
    mock_dns.return_value = {
        "domain": "example.com",
        "records": {
            "A": [
                "192.0.2.10",
            ],
            "AAAA": [],
            "MX": [
                "mail.example.com.",
            ],
            "NS": [
                "ns1.example.com.",
            ],
            "TXT": [],
            "CNAME": [],
        },
    }

    mock_certificates.return_value = {
        "domain": "example.com",
        "domains": [
            "example.com",
            "api.example.com",
        ],
        "certificates": [
            {
                "id": 12345,
                "issuer_name": "Example CA",
                "common_name": "*.example.com",
                "serial_number": "ABC123",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2027-01-01T00:00:00",
                "name_value": (
                    "example.com\n"
                    "api.example.com"
                ),
            }
        ],
        "attempts": 1,
        "error": None,
    }

    mock_rdap.return_value = {
        "domain": "example.com",
        "handle": "EXAMPLE-123",
        "status": [
            "active",
        ],
        "nameservers": [
            "ns1.example.com",
        ],
        "events": [],
        "rdap_conformance": [],
        "attempts": 1,
        "error": None,
    }

    result = investigate(
        "EXAMPLE.COM."
    )

    assert result.target == "example.com"

    assert result.domain_count == 2
    assert result.ip_count == 1
    assert result.certificate_count == 1

    assert result.domains[0].name == "example.com"

    assert (
        result.ip_addresses[0].address
        == "192.0.2.10"
    )

    assert (
        result.certificates[0].certificate_id
        == "12345"
    )

    assert len(
        result.collection_status
    ) == 3

    statuses = {
        status.source: status
        for status in result.collection_status
    }

    assert statuses["DNS"].status == "success"
    assert statuses["crt.sh"].status == "success"
    assert statuses["RDAP"].status == "success"

    assert statuses["DNS"].attempts == 1
    assert statuses["crt.sh"].attempts == 1
    assert statuses["RDAP"].attempts == 1

    assert statuses["DNS"].error is None
    assert statuses["crt.sh"].error is None
    assert statuses["RDAP"].error is None

    mock_dns.assert_called_once_with(
        "example.com"
    )

    mock_certificates.assert_called_once_with(
        "example.com"
    )

    mock_rdap.assert_called_once_with(
        "example.com"
    )


@patch(
    "app.services.investigation.collect_rdap"
)
@patch(
    "app.services.investigation.collect_certificates"
)
@patch(
    "app.services.investigation.collect_dns"
)
def test_investigation_preserves_collection_failure(
    mock_dns,
    mock_certificates,
    mock_rdap,
):
    mock_dns.return_value = {
        "domain": "example.com",
        "records": {
            "A": [
                "192.0.2.10",
            ],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": [],
        },
        "error": None,
        "attempts": 1,
    }

    mock_certificates.return_value = {
        "domain": "example.com",
        "certificates": [],
        "domains": [],
        "attempts": 3,
        "error": (
            "HTTP 502: temporary upstream failure"
        ),
    }

    mock_rdap.return_value = {
        "domain": "example.com",
        "handle": "EXAMPLE-123",
        "status": [
            "active",
        ],
        "nameservers": [],
        "events": [],
        "rdap_conformance": [],
        "error": None,
        "attempts": 1,
    }

    result = investigate(
        "example.com"
    )

    crtsh_status = next(
        status
        for status in result.collection_status
        if status.source == "crt.sh"
    )

    assert crtsh_status.status == "error"

    assert crtsh_status.attempts == 3

    assert (
        crtsh_status.error
        == "HTTP 502: temporary upstream failure"
    )

    assert result.certificate_count == 0


def test_investigation_classifies_certificates():
    dns_data = {
        "records": {
            "A": [
                "192.0.2.10"
            ],
            "AAAA": [],
            "NS": [],
            "MX": [],
            "TXT": [],
            "CNAME": [],
        },
        "error": None,
        "attempts": 1,
    }

    certificate_data = {
        "certificates": [
            {
                "id": 1,
                "issuer_name": "Example CA",
                "common_name": "example.com",
                "serial_number": "ABC123",
                "not_before": "2026-01-01",
                "not_after": "2027-01-01",
                "name_value": "example.com",
            },
            {
                "id": 2,
                "issuer_name": "Example CA",
                "common_name": "*.example.com",
                "serial_number": "DEF456",
                "not_before": "2026-01-01",
                "not_after": "2027-01-01",
                "name_value": "*.example.com",
            },
            {
                "id": 3,
                "issuer_name": "Example CA",
                "common_name": "www.example.org",
                "serial_number": "GHI789",
                "not_before": "2026-01-01",
                "not_after": "2027-01-01",
                "name_value": "www.example.org",
            },
            {
                "id": 4,
                "issuer_name": "Example CA",
                "common_name": (
                    "as207960 test intermediate - example.com"
                ),
                "serial_number": "JKL012",
                "not_before": "2026-01-01",
                "not_after": "2027-01-01",
                "name_value": (
                    "as207960 test intermediate - example.com"
                ),
            },
        ],
        "domains": [
            "example.com",
        ],
        "error": None,
        "attempts": 1,
    }

    rdap_data = {
        "nameservers": [],
        "error": None,
        "attempts": 1,
    }

    with patch(
        "app.services.investigation.collect_dns",
        return_value=dns_data,
    ), patch(
        "app.services.investigation.collect_certificates",
        return_value=certificate_data,
    ), patch(
        "app.services.investigation.collect_rdap",
        return_value=rdap_data,
    ):
        infrastructure = investigate(
            "example.com"
        )

    classifications = {
        certificate.certificate_id:
        certificate.classification
        for certificate
        in infrastructure.certificates
    }

    assert classifications == {
        "1": "VALID_DOMAIN",
        "2": "WILDCARD",
        "3": "EXTERNAL_DOMAIN",
        "4": "NON_DOMAIN",
    }


def test_investigation_generates_findings():
    dns_data = {
        "records": {
            "A": [
                "192.0.2.10",
                "192.0.2.20",
            ],
            "AAAA": [],
            "NS": [],
            "MX": [],
            "TXT": [],
            "CNAME": [],
        },
        "error": None,
        "attempts": 1,
    }

    certificate_data = {
        "certificates": [
            {
                "id": 1,
                "issuer_name": "Example CA",
                "common_name": "*.example.com",
                "serial_number": "ABC123",
                "not_before": "2026-01-01",
                "not_after": "2027-01-01",
                "name_value": "*.example.com",
            },
        ],
        "domains": [
            "example.com",
            "www.example.com",
        ],
        "error": None,
        "attempts": 1,
    }

    rdap_data = {
        "nameservers": [],
        "error": None,
        "attempts": 1,
    }

    with patch(
        "app.services.investigation.collect_dns",
        return_value=dns_data,
    ), patch(
        "app.services.investigation.collect_certificates",
        return_value=certificate_data,
    ), patch(
        "app.services.investigation.collect_rdap",
        return_value=rdap_data,
    ):
        infrastructure = investigate(
            "example.com"
        )

    rule_ids = {
        finding.rule_id
        for finding
        in infrastructure.findings
    }

    assert "CERT-WILD-001" in rule_ids
    assert "DOMAIN-ENUM-001" in rule_ids
    assert "INFRA-IP-001" in rule_ids

def test_investigation_adds_similarity_results():
    dns_data = {
        "records": {
            "A": [
                "192.0.2.10",
            ],
            "AAAA": [],
            "NS": [],
            "MX": [],
            "TXT": [],
            "CNAME": [],
        },
        "error": None,
        "attempts": 1,
    }

    certificate_data = {
        "certificates": [
            {
                "id": 1,
                "issuer_name": "Example CA",
                "common_name": "example.com",
                "serial_number": "ABC123",
                "not_before": "2026-01-01",
                "not_after": "2027-01-01",
                "name_value": (
                    "example.com\n"
                    "api.example.com"
                ),
            },
        ],
        "domains": [
            "example.com",
            "api.example.com",
        ],
        "error": None,
        "attempts": 1,
    }

    rdap_data = {
        "nameservers": [],
        "error": None,
        "attempts": 1,
    }

    with patch(
        "app.services.investigation.collect_dns",
        return_value=dns_data,
    ), patch(
        "app.services.investigation.collect_certificates",
        return_value=certificate_data,
    ), patch(
        "app.services.investigation.collect_rdap",
        return_value=rdap_data,
    ):
        infrastructure = investigate(
            "example.com"
        )

    assert len(
        infrastructure.similarity_results
    ) == 1

    result = infrastructure.similarity_results[0]

    assert result.source == "api.example.com"
    assert result.target == "example.com"

    assert {
    signal.similarity_type
    for signal in result.signals
} == {
    "SUBDOMAIN_RELATION",
    "SHARED_CERTIFICATE",
}