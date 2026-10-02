"""
TXT exporter for Digital Footprint Intelligence.

Converts a normalized Infrastructure model into
a human-readable plain-text report.
"""

from __future__ import annotations

from app.models.infrastructure import Infrastructure


def export_txt(
    infrastructure: Infrastructure,
) -> str:
    """
    Export an infrastructure investigation as plain text.
    """

    lines: list[str] = []

    lines.append(
        "DIGITAL FOOTPRINT INTELLIGENCE"
    )
    lines.append(
        "=" * 60
    )
    lines.append(
        f"Target: {infrastructure.target}"
    )
    lines.append("")

    # ---------------------------------------------------------
    # Collection status
    # ---------------------------------------------------------

    lines.append(
        "COLLECTION STATUS"
    )
    lines.append(
        "-" * 60
    )

    for status in infrastructure.collection_status:
        lines.append(
            f"{status.source}: "
            f"{status.status.upper()} "
            f"(attempts: {status.attempts})"
        )

        if status.error:
            lines.append(
                f"  Error: {status.error}"
            )

    lines.append("")

    # ---------------------------------------------------------
    # Infrastructure
    # ---------------------------------------------------------

    lines.append(
        "INFRASTRUCTURE"
    )
    lines.append(
        "-" * 60
    )

    lines.append(
        f"Domains: {infrastructure.domain_count}"
    )

    lines.append(
        f"IP addresses: {infrastructure.ip_count}"
    )

    lines.append(
        f"Certificates: {infrastructure.certificate_count}"
    )

    lines.append("")

    # ---------------------------------------------------------
    # Domains
    # ---------------------------------------------------------

    lines.append(
        "DOMAINS"
    )
    lines.append(
        "-" * 60
    )

    for domain in infrastructure.domains:
        lines.append(
            f"- {domain.name}"
        )

        for address in domain.ipv4:
            lines.append(
                f"  IPv4: {address}"
            )

        for address in domain.ipv6:
            lines.append(
                f"  IPv6: {address}"
            )

        for nameserver in domain.nameservers:
            lines.append(
                f"  Nameserver: {nameserver}"
            )

        for mail_server in domain.mail_servers:
            lines.append(
                f"  Mail server: {mail_server}"
            )

        for cname in domain.cname_records:
            lines.append(
                f"  CNAME: {cname}"
            )

    lines.append("")

    # ---------------------------------------------------------
    # IP addresses
    # ---------------------------------------------------------

    lines.append(
        "IP ADDRESSES"
    )
    lines.append(
        "-" * 60
    )

    for ip in infrastructure.ip_addresses:
        lines.append(
            f"- {ip.address}"
        )

        if ip.organization:
            lines.append(
                f"  Organization: {ip.organization}"
            )

        if ip.country:
            lines.append(
                f"  Country: {ip.country}"
            )

        if ip.network:
            lines.append(
                f"  Network: {ip.network}"
            )

        for hostname in ip.hostnames:
            lines.append(
                f"  Hostname: {hostname}"
            )

    lines.append("")

    # ---------------------------------------------------------
    # Certificates
    # ---------------------------------------------------------

    lines.append(
        "CERTIFICATES"
    )
    lines.append(
        "-" * 60
    )

    for certificate in infrastructure.certificates:
        lines.append(
            f"- ID: {certificate.certificate_id}"
        )

        if certificate.issuer_name:
            lines.append(
                f"  Issuer: {certificate.issuer_name}"
            )

        if certificate.common_name:
            lines.append(
                f"  Common Name: {certificate.common_name}"
            )

        if certificate.serial_number:
            lines.append(
                f"  Serial: {certificate.serial_number}"
            )

        if certificate.not_before:
            lines.append(
                f"  Not Before: {certificate.not_before}"
            )

        if certificate.not_after:
            lines.append(
                f"  Not After: {certificate.not_after}"
            )

        if certificate.classification:
            lines.append(
                f"  Classification: "
                f"{certificate.classification}"
            )

        for domain in certificate.domains:
            lines.append(
                f"  Domain: {domain}"
            )

    lines.append("")

    # ---------------------------------------------------------
    # Findings
    # ---------------------------------------------------------

    lines.append(
        "RISK FINDINGS"
    )
    lines.append(
        "-" * 60
    )

    for finding in infrastructure.findings:
        lines.append(
            f"- [{finding.severity}] "
            f"{finding.rule_id}: "
            f"{finding.title}"
        )

        lines.append(
            f"  Description: "
            f"{finding.description}"
        )

        lines.append(
            f"  Evidence: "
            f"{finding.evidence}"
        )

        lines.append(
            f"  Confidence: "
            f"{finding.confidence}"
        )

    lines.append("")

    # ---------------------------------------------------------
    # Relationships
    # ---------------------------------------------------------

    lines.append(
        "RELATIONSHIPS"
    )
    lines.append(
        "-" * 60
    )

    for relationship in infrastructure.relationships:
        lines.append(
            f"- {relationship.source} "
            f"--[{relationship.relation}]--> "
            f"{relationship.target}"
        )

        lines.append(
            f"  Confidence: "
            f"{relationship.confidence}"
        )

        lines.append(
            f"  Evidence: "
            f"{relationship.evidence}"
        )

    lines.append("")

    # ---------------------------------------------------------
    # Similarity
    # ---------------------------------------------------------

    lines.append(
        "SIMILARITY INTELLIGENCE"
    )
    lines.append(
        "-" * 60
    )

    for result in infrastructure.similarity_results:
        lines.append(
            f"- {result.source} "
            f"<-> "
            f"{result.target}"
        )

        for signal in result.signals:
            lines.append(
                f"  Signal: "
                f"{signal.similarity_type}"
            )

            lines.append(
                f"  Evidence: "
                f"{signal.evidence}"
            )

    lines.append("")

    return "\n".join(lines)