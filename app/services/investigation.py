"""
Investigation service for Digital Footprint Intelligence.

Orchestrates passive collectors and converts their results
into normalized infrastructure models.
"""

from __future__ import annotations

from app.analysis.similarity import SimilarityEngine
from app.analysis.certificate import CertificateClassifier
from app.analysis.relationship import RelationshipEngine
from app.analysis.risk import RiskEngine
from app.collectors.crtsh import collect_certificates
from app.collectors.dns import collect_dns
from app.collectors.rdap import collect_rdap
from app.models.certificate import Certificate
from app.models.collection import CollectionStatus
from app.models.domain import Domain
from app.models.infrastructure import Infrastructure
from app.models.ip import IPAddress


def _build_domain(
    target: str,
    dns_data: dict,
    rdap_data: dict,
    discovered_domains: list[str],
) -> Domain:
    """
    Build a normalized Domain model from collector results.
    """

    records = dns_data.get(
        "records",
        {},
    )

    domain = Domain(
        name=target,
        ipv4=records.get(
            "A",
            [],
        ),
        ipv6=records.get(
            "AAAA",
            [],
        ),
        nameservers=(
            records.get("NS", [])
            + rdap_data.get(
                "nameservers",
                [],
            )
        ),
        mail_servers=records.get(
            "MX",
            [],
        ),
        txt_records=records.get(
            "TXT",
            [],
        ),
        cname_records=records.get(
            "CNAME",
            [],
        ),
        discovered_subdomains=discovered_domains,
    )

    return domain


def _build_certificates(
    certificate_data: list[dict],
    target: str,
) -> list[Certificate]:
    """
    Convert raw crt.sh certificate records into
    normalized Certificate models and classify them.
    """

    certificates: list[Certificate] = []

    for entry in certificate_data:
        certificate = Certificate(
            certificate_id=(
                str(entry["id"])
                if entry.get("id") is not None
                else None
            ),
            issuer_name=entry.get(
                "issuer_name"
            ),
            common_name=entry.get(
                "common_name"
            ),
            serial_number=entry.get(
                "serial_number"
            ),
            not_before=entry.get(
                "not_before"
            ),
            not_after=entry.get(
                "not_after"
            ),
            domains=entry.get(
                "name_value",
                "",
            ).splitlines(),
        )

        certificate.classification = (
            CertificateClassifier.classify(
                certificate,
                target,
            )
        )

        certificates.append(
            certificate
        )

    return certificates


def _build_ips(
    domain: Domain,
) -> list[IPAddress]:
    """
    Build IP entities from addresses discovered through DNS.
    """

    ip_addresses: list[IPAddress] = []

    for address in domain.ipv4:
        ip = IPAddress(
            address=address,
            hostnames=[
                domain.name
            ],
        )

        ip_addresses.append(
            ip
        )

    for address in domain.ipv6:
        ip = IPAddress(
            address=address,
            hostnames=[
                domain.name
            ],
        )

        ip_addresses.append(
            ip
        )

    return ip_addresses


def investigate(
    target: str,
) -> Infrastructure:
    """
    Perform a passive digital footprint investigation.

    The investigation currently uses:
        - DNS
        - Certificate Transparency
        - RDAP

    Args:
        target: Domain to investigate.

    Returns:
        Normalized Infrastructure model.
    """

    # ---------------------------------------------------------
    # Target normalization
    # ---------------------------------------------------------

    target = (
        target
        .strip()
        .lower()
        .rstrip(".")
    )

    # ---------------------------------------------------------
    # Collection
    # ---------------------------------------------------------

    dns_data = collect_dns(
        target
    )

    certificate_data = collect_certificates(
        target
    )

    rdap_data = collect_rdap(
        target
    )

    # ---------------------------------------------------------
    # Collection status
    # ---------------------------------------------------------

    dns_status = CollectionStatus(
        source="DNS",
        status=(
            "error"
            if dns_data.get("error")
            else "success"
        ),
        attempts=dns_data.get(
            "attempts",
            1,
        ),
        error=dns_data.get(
            "error"
        ),
    )

    crtsh_status = CollectionStatus(
        source="crt.sh",
        status=(
            "error"
            if certificate_data.get("error")
            else "success"
        ),
        attempts=certificate_data.get(
            "attempts",
            1,
        ),
        error=certificate_data.get(
            "error"
        ),
    )

    rdap_status = CollectionStatus(
        source="RDAP",
        status=(
            "error"
            if rdap_data.get("error")
            else "success"
        ),
        attempts=rdap_data.get(
            "attempts",
            1,
        ),
        error=rdap_data.get(
            "error"
        ),
    )

    # ---------------------------------------------------------
    # Normalization
    # ---------------------------------------------------------

    discovered_domains = (
        certificate_data.get(
            "domains",
            [],
        )
    )

    domain = _build_domain(
        target=target,
        dns_data=dns_data,
        rdap_data=rdap_data,
        discovered_domains=discovered_domains,
    )

    certificates = _build_certificates(
        certificate_data.get(
            "certificates",
            [],
        ),
        target=target,
    )

    ip_addresses = _build_ips(
        domain
    )

    # ---------------------------------------------------------
    # Infrastructure
    # ---------------------------------------------------------

    infrastructure = Infrastructure(
        target=target,
    )

    infrastructure.add_collection_status(
        dns_status
    )

    infrastructure.add_collection_status(
        crtsh_status
    )

    infrastructure.add_collection_status(
        rdap_status
    )

    # ---------------------------------------------------------
    # Domains
    # ---------------------------------------------------------

    infrastructure.add_domain(
        domain
    )

    for discovered_domain in discovered_domains:
        if discovered_domain == target:
            continue

        infrastructure.add_domain(
            Domain(
                name=discovered_domain,
            )
        )

    # ---------------------------------------------------------
    # IP addresses
    # ---------------------------------------------------------

    for ip_address in ip_addresses:
        infrastructure.add_ip(
            ip_address
        )

    # ---------------------------------------------------------
    # Certificates
    # ---------------------------------------------------------

    for certificate in certificates:
        infrastructure.add_certificate(
            certificate
        )

    # ---------------------------------------------------------
    # Risk analysis
    # ---------------------------------------------------------

    risk_engine = RiskEngine()

    findings = risk_engine.evaluate(
        infrastructure
    )

    for finding in findings:
        infrastructure.add_finding(
            finding
        )

    # ---------------------------------------------------------
    # Relationship analysis
    # ---------------------------------------------------------

    relationship_engine = RelationshipEngine()

    relationships = relationship_engine.evaluate(
        infrastructure
    )

    for relationship in relationships:
        infrastructure.add_relationship(
            relationship
        )

    similarity_engine = SimilarityEngine()

    similarity_signals = similarity_engine.evaluate(
        relationships
    )

    similarity_results = similarity_engine.correlate(
        similarity_signals
    )

    for result in similarity_results:
        infrastructure.add_similarity_result(
            result
        )
    # ---------------------------------------------------------
    # Result
    # ---------------------------------------------------------

    return infrastructure