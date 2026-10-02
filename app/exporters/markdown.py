"""
Markdown exporter for Digital Footprint Intelligence.

Converts a normalized Infrastructure model into
a human-readable Markdown report.
"""

from __future__ import annotations

from app.models.infrastructure import Infrastructure


def export_markdown(
    infrastructure: Infrastructure,
) -> str:
    """
    Export an infrastructure investigation as Markdown.
    """

    lines: list[str] = []

    lines.append(
        "# Digital Footprint Intelligence"
    )
    lines.append("")

    # ---------------------------------------------------------
    # Target
    # ---------------------------------------------------------

    lines.append("## Target")
    lines.append("")
    lines.append(
        f"`{infrastructure.target}`"
    )
    lines.append("")

    # ---------------------------------------------------------
    # Collection Status
    # ---------------------------------------------------------

    lines.append(
        "## Collection Status"
    )
    lines.append("")

    lines.append(
        "| Source | Status | Attempts |"
    )
    lines.append(
        "|---|---|---:|"
    )

    for status in infrastructure.collection_status:
        lines.append(
            f"| {status.source} "
            f"| {status.status.upper()} "
            f"| {status.attempts} |"
        )

        if status.error:
            lines.append(
                f"> **{status.source} error:** "
                f"{status.error}"
            )
            lines.append("")

    lines.append("")

    # ---------------------------------------------------------
    # Infrastructure
    # ---------------------------------------------------------

    lines.append(
        "## Infrastructure"
    )
    lines.append("")

    lines.append(
        f"- Domains: {infrastructure.domain_count}"
    )

    lines.append(
        f"- IP addresses: {infrastructure.ip_count}"
    )

    lines.append(
        f"- Certificates: "
        f"{infrastructure.certificate_count}"
    )

    lines.append("")

    # ---------------------------------------------------------
    # Domains
    # ---------------------------------------------------------

    lines.append(
        "## Domains"
    )
    lines.append("")

    for domain in infrastructure.domains:
        lines.append(
            f"### {domain.name}"
        )
        lines.append("")

        for address in domain.ipv4:
            lines.append(
                f"- IPv4: `{address}`"
            )

        for address in domain.ipv6:
            lines.append(
                f"- IPv6: `{address}`"
            )

        for nameserver in domain.nameservers:
            lines.append(
                f"- Nameserver: `{nameserver}`"
            )

        for mail_server in domain.mail_servers:
            lines.append(
                f"- Mail server: `{mail_server}`"
            )

        for txt_record in domain.txt_records:
            lines.append(
                f"- TXT: `{txt_record}`"
            )

        for cname in domain.cname_records:
            lines.append(
                f"- CNAME: `{cname}`"
            )

        if domain.discovered_subdomains:
            lines.append(
                "- Discovered subdomains:"
            )

            for subdomain in domain.discovered_subdomains:
                lines.append(
                    f"  - `{subdomain}`"
                )

        lines.append("")

    # ---------------------------------------------------------
    # IP Addresses
    # ---------------------------------------------------------

    lines.append(
        "## IP Addresses"
    )
    lines.append("")

    for ip in infrastructure.ip_addresses:
        lines.append(
            f"### `{ip.address}`"
        )
        lines.append("")

        if ip.organization:
            lines.append(
                f"- Organization: `{ip.organization}`"
            )

        if ip.country:
            lines.append(
                f"- Country: `{ip.country}`"
            )

        if ip.network:
            lines.append(
                f"- Network: `{ip.network}`"
            )

        if ip.hostnames:
            lines.append(
                "- Hostnames:"
            )

            for hostname in ip.hostnames:
                lines.append(
                    f"  - `{hostname}`"
                )

        lines.append("")

    # ---------------------------------------------------------
    # Certificates
    # ---------------------------------------------------------

    lines.append(
        "## Certificates"
    )
    lines.append("")

    for certificate in infrastructure.certificates:
        certificate_id = (
            certificate.certificate_id
            or "unknown"
        )

        lines.append(
            f"### Certificate `{certificate_id}`"
        )
        lines.append("")

        if certificate.issuer_name:
            lines.append(
                f"- Issuer: "
                f"`{certificate.issuer_name}`"
            )

        if certificate.common_name:
            lines.append(
                f"- Common Name: "
                f"`{certificate.common_name}`"
            )

        if certificate.serial_number:
            lines.append(
                f"- Serial: "
                f"`{certificate.serial_number}`"
            )

        if certificate.not_before:
            lines.append(
                f"- Not Before: "
                f"`{certificate.not_before}`"
            )

        if certificate.not_after:
            lines.append(
                f"- Not After: "
                f"`{certificate.not_after}`"
            )

        if certificate.classification:
            lines.append(
                f"- Classification: "
                f"`{certificate.classification}`"
            )

        if certificate.domains:
            lines.append(
                "- Domains:"
            )

            for domain in certificate.domains:
                lines.append(
                    f"  - `{domain}`"
                )

        lines.append("")

    # ---------------------------------------------------------
    # Risk Findings
    # ---------------------------------------------------------

    lines.append(
        "## Risk Findings"
    )
    lines.append("")

    if not infrastructure.findings:
        lines.append(
            "No findings."
        )
        lines.append("")

    for finding in infrastructure.findings:
        lines.append(
            f"### `{finding.rule_id}` — "
            f"{finding.title}"
        )
        lines.append("")

        lines.append(
            f"- Severity: "
            f"`{finding.severity}`"
        )

        lines.append(
            f"- Confidence: "
            f"`{finding.confidence}`"
        )

        lines.append(
            f"- Description: "
            f"{finding.description}"
        )

        lines.append(
            f"- Evidence: "
            f"{finding.evidence}"
        )

        lines.append("")

    # ---------------------------------------------------------
    # Relationships
    # ---------------------------------------------------------

    lines.append(
        "## Relationships"
    )
    lines.append("")

    if not infrastructure.relationships:
        lines.append(
            "No relationships."
        )
        lines.append("")

    for relationship in infrastructure.relationships:
        lines.append(
            f"### `{relationship.source}` "
            f"→ `{relationship.target}`"
        )
        lines.append("")

        lines.append(
            f"- Relation: "
            f"`{relationship.relation}`"
        )

        lines.append(
            f"- Confidence: "
            f"`{relationship.confidence}`"
        )

        lines.append(
            f"- Evidence: "
            f"{relationship.evidence}"
        )

        lines.append("")

    # ---------------------------------------------------------
    # Similarity Intelligence
    # ---------------------------------------------------------

    lines.append(
        "## Similarity Intelligence"
    )
    lines.append("")

    if not infrastructure.similarity_results:
        lines.append(
            "No similarity results."
        )
        lines.append("")

    for result in infrastructure.similarity_results:
        lines.append(
            f"### `{result.source}` "
            f"↔ `{result.target}`"
        )
        lines.append("")

        for signal in result.signals:
            lines.append(
                f"- **{signal.similarity_type}**"
            )

            lines.append(
                f"  - Evidence: "
                f"{signal.evidence}"
            )

        lines.append("")

    return "\n".join(lines)