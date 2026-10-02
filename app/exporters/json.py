from __future__ import annotations

import json

from app.models.infrastructure import Infrastructure


def export_json(infrastructure: Infrastructure) -> str:
    data = {
        "target": infrastructure.target,
        "collection_status": [
            {
                "source": status.source,
                "status": status.status,
                "attempts": status.attempts,
                "error": status.error,
            }
            for status in infrastructure.collection_status
        ],
        "domains": [
            {
                "name": domain.name,
                "ipv4": domain.ipv4,
                "ipv6": domain.ipv6,
                "nameservers": domain.nameservers,
                "mail_servers": domain.mail_servers,
                "txt_records": domain.txt_records,
                "cname_records": domain.cname_records,
                "discovered_subdomains": domain.discovered_subdomains,
            }
            for domain in infrastructure.domains
        ],
        "ip_addresses": [
            {
                "address": ip.address,
                "version": ip.version,
                "asn": ip.asn,
                "organization": ip.organization,
                "country": ip.country,
                "network": ip.network,
                "hostnames": ip.hostnames,
            }
            for ip in infrastructure.ip_addresses
        ],
        "certificates": [
            {
                "certificate_id": certificate.certificate_id,
                "issuer_name": certificate.issuer_name,
                "common_name": certificate.common_name,
                "serial_number": certificate.serial_number,
                "not_before": certificate.not_before,
                "not_after": certificate.not_after,
                "classification": certificate.classification,
                "domains": certificate.domains,
            }
            for certificate in infrastructure.certificates
        ],
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "title": finding.title,
                "description": finding.description,
                "evidence": finding.evidence,
                "confidence": finding.confidence,
            }
            for finding in infrastructure.findings
        ],
        "relationships": [
            {
                "source": relationship.source,
                "target": relationship.target,
                "relation": relationship.relation,
                "confidence": relationship.confidence,
                "evidence": relationship.evidence,
            }
            for relationship in infrastructure.relationships
        ],
        "similarity_results": [
            {
                "source": result.source,
                "target": result.target,
                "signals": [
                    {
                        "source": signal.source,
                        "target": signal.target,
                        "similarity_type": signal.similarity_type,
                        "evidence": signal.evidence,
                    }
                    for signal in result.signals
                ],
            }
            for result in infrastructure.similarity_results
        ],
    }

    return json.dumps(data, indent=2)