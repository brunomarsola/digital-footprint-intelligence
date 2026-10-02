"""
CSV exporter for Digital Footprint Intelligence.

Converts a normalized Infrastructure model into
CSV-friendly tabular data.
"""

from __future__ import annotations

from app.models.infrastructure import Infrastructure

CSV_FIELDS: dict[str, list[str]] = {
    "collection_status": [
        "source",
        "status",
        "attempts",
        "error",
    ],
    "domains": [
        "name",
        "ipv4",
        "ipv6",
        "nameservers",
        "mail_servers",
        "txt_records",
        "cname_records",
        "discovered_subdomains",
    ],
    "ips": [
        "address",
        "version",
        "asn",
        "organization",
        "country",
        "network",
        "hostnames",
    ],
    "certificates": [
        "certificate_id",
        "issuer_name",
        "common_name",
        "serial_number",
        "not_before",
        "not_after",
        "classification",
        "domains",
    ],
    "findings": [
        "rule_id",
        "severity",
        "title",
        "description",
        "evidence",
        "confidence",
    ],
    "relationships": [
        "source",
        "target",
        "relation",
        "confidence",
        "evidence",
    ],
    "similarity": [
        "source",
        "target",
        "similarity_type",
        "evidence",
    ],
}

def _join_values(
    values: list[str],
    separator: str = ";",
) -> str:
    """
    Convert a list of values into a CSV-friendly string.
    """

    return separator.join(
        str(value)
        for value in values
        if value
    )


def export_csv(
    infrastructure: Infrastructure,
) -> dict[str, list[dict[str, object]]]:
    """
    Convert an infrastructure investigation into
    CSV-friendly tables.

    The exporter does not write files. It only prepares
    normalized tabular data for the CLI or another consumer.
    """

    collection_status = []

    for status in infrastructure.collection_status:
        collection_status.append(
            {
                "source": status.source,
                "status": status.status,
                "attempts": status.attempts,
                "error": status.error or "",
            }
        )

    domains = []

    for domain in infrastructure.domains:
        domains.append(
            {
                "name": domain.name,
                "ipv4": _join_values(
                    domain.ipv4
                ),
                "ipv6": _join_values(
                    domain.ipv6
                ),
                "nameservers": _join_values(
                    domain.nameservers
                ),
                "mail_servers": _join_values(
                    domain.mail_servers
                ),
                "txt_records": _join_values(
                    domain.txt_records
                ),
                "cname_records": _join_values(
                    domain.cname_records
                ),
                "discovered_subdomains": _join_values(
                    domain.discovered_subdomains
                ),
            }
        )

    ips = []

    for ip in infrastructure.ip_addresses:
        ips.append(
            {
                "address": ip.address,
                "version": ip.version,
                "asn": (
                    ip.asn
                    if ip.asn is not None
                    else ""
                ),
                "organization": (
                    ip.organization
                    or ""
                ),
                "country": (
                    ip.country
                    or ""
                ),
                "network": (
                    ip.network
                    or ""
                ),
                "hostnames": _join_values(
                    ip.hostnames
                ),
            }
        )

    certificates = []

    for certificate in infrastructure.certificates:
        certificates.append(
            {
                "certificate_id": (
                    certificate.certificate_id
                    or ""
                ),
                "issuer_name": (
                    certificate.issuer_name
                    or ""
                ),
                "common_name": (
                    certificate.common_name
                    or ""
                ),
                "serial_number": (
                    certificate.serial_number
                    or ""
                ),
                "not_before": (
                    certificate.not_before
                    or ""
                ),
                "not_after": (
                    certificate.not_after
                    or ""
                ),
                "classification": (
                    certificate.classification
                    or ""
                ),
                "domains": _join_values(
                    certificate.domains
                ),
            }
        )

    findings = []

    for finding in infrastructure.findings:
        findings.append(
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "title": finding.title,
                "description": finding.description,
                "evidence": finding.evidence,
                "confidence": finding.confidence,
            }
        )

    relationships = []

    for relationship in infrastructure.relationships:
        relationships.append(
            {
                "source": relationship.source,
                "target": relationship.target,
                "relation": relationship.relation,
                "confidence": relationship.confidence,
                "evidence": relationship.evidence,
            }
        )

    similarity = []

    for result in infrastructure.similarity_results:
        for signal in result.signals:
            similarity.append(
                {
                    "source": result.source,
                    "target": result.target,
                    "similarity_type": (
                        signal.similarity_type
                    ),
                    "evidence": signal.evidence,
                }
            )

    return {
        "collection_status": collection_status,
        "domains": domains,
        "ips": ips,
        "certificates": certificates,
        "findings": findings,
        "relationships": relationships,
        "similarity": similarity,
    }