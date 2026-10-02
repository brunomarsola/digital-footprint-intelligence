"""
Relationship analysis engine for Digital Footprint Intelligence.

Builds deterministic relationships between infrastructure entities
based on collected and normalized passive evidence.
"""

from __future__ import annotations

from itertools import combinations

from app.models.infrastructure import Infrastructure
from app.models.relationship import Relationship
from app.analysis.certificate import CertificateClassifier

class RelationshipEngine:
    """
    Generates deterministic analytical relationships
    from normalized infrastructure data.
    """

    def evaluate(
        self,
        infrastructure: Infrastructure,
    ) -> list[Relationship]:
        """
        Evaluate the infrastructure and generate relationships.
        """

        relationships: list[Relationship] = []

        relationships.extend(
            self._build_domain_ip_relationships(
                infrastructure
            )
        )

        relationships.extend(
            self._build_subdomain_relationships(
                infrastructure
            )
        )

        relationships.extend(
            self._build_certificate_relationships(
                infrastructure
            )
        )

        relationships.extend(
            self._build_cname_relationships(
                infrastructure
            )
        )

        relationships.extend(
            self._build_nameserver_relationships(
                infrastructure
            )
        )

        relationships.extend(
            self._build_mail_server_relationships(
                infrastructure
            )
        )

        relationships.extend(
            self._build_shared_ip_relationships(
                infrastructure
            )
        )

        relationships.extend(
            self._build_shared_certificate_relationships(
                infrastructure
            )
        )

        return self._deduplicate(
            relationships
        )

    # ------------------------------------------------------------------
    # Domain -> IP
    # ------------------------------------------------------------------

    def _build_domain_ip_relationships(
        self,
        infrastructure: Infrastructure,
    ) -> list[Relationship]:
        """
        Build RESOLVES_TO relationships from DNS records.
        """

        relationships: list[Relationship] = []

        for domain in infrastructure.domains:

            for ipv4 in domain.ipv4:
                relationships.append(
                    Relationship(
                        source=domain.name,
                        target=ipv4,
                        relation="RESOLVES_TO",
                        confidence="HIGH",
                        evidence="DNS A record",
                    )
                )

            for ipv6 in domain.ipv6:
                relationships.append(
                    Relationship(
                        source=domain.name,
                        target=ipv6,
                        relation="RESOLVES_TO",
                        confidence="HIGH",
                        evidence="DNS AAAA record",
                    )
                )

        return relationships

    # ------------------------------------------------------------------
    # Subdomain relationships
    # ------------------------------------------------------------------

    def _build_subdomain_relationships(
        self,
        infrastructure: Infrastructure,
    ) -> list[Relationship]:
        """
        Build SUBDOMAIN_OF relationships.
        """

        relationships: list[Relationship] = []

        target = infrastructure.target

        for domain in infrastructure.domains:
            domain_name = domain.name

            if domain_name == target:
                continue

            if domain_name.endswith(
                "." + target
            ):
                relationships.append(
                    Relationship(
                        source=domain_name,
                        target=target,
                        relation="SUBDOMAIN_OF",
                        confidence="HIGH",
                        evidence=(
                            "Domain discovered within "
                            "target namespace"
                        ),
                    )
                )

        return relationships

    # ------------------------------------------------------------------
    # Domain -> Certificate
    # ------------------------------------------------------------------

    def _build_certificate_relationships(
        self,
        infrastructure: Infrastructure,
    ) -> list[Relationship]:
        """
        Build HAS_CERTIFICATE relationships.
        """

        relationships: list[Relationship] = []

        for certificate in infrastructure.certificates:

            if not certificate.certificate_id:
                continue

            for domain_name in certificate.domains:

                classification = (
                    CertificateClassifier.classify_name(
                        domain_name,
                        infrastructure.target,
                    )
                )

                if classification != "VALID_DOMAIN":
                    continue

                relationships.append(
                    Relationship(
                        source=domain_name,
                        target=certificate.certificate_id,
                        relation="HAS_CERTIFICATE",
                        confidence="HIGH",
                        evidence=(
                            "Certificate Transparency "
                            "domain entry"
                        ),
                    )
                )

        return relationships
    # ------------------------------------------------------------------
    # CNAME
    # ------------------------------------------------------------------

    def _build_cname_relationships(
        self,
        infrastructure: Infrastructure,
    ) -> list[Relationship]:
        """
        Build CNAME_TO relationships from DNS CNAME records.
        """

        relationships: list[Relationship] = []

        for domain in infrastructure.domains:

            for cname in domain.cname_records:

                relationships.append(
                    Relationship(
                        source=domain.name,
                        target=cname,
                        relation="CNAME_TO",
                        confidence="HIGH",
                        evidence="DNS CNAME record",
                    )
                )

        return relationships

    # ------------------------------------------------------------------
    # Nameservers
    # ------------------------------------------------------------------

    def _build_nameserver_relationships(
        self,
        infrastructure: Infrastructure,
    ) -> list[Relationship]:
        """
        Build USES_NAMESERVER relationships.
        """

        relationships: list[Relationship] = []

        for domain in infrastructure.domains:

            for nameserver in domain.nameservers:

                relationships.append(
                    Relationship(
                        source=domain.name,
                        target=nameserver,
                        relation="USES_NAMESERVER",
                        confidence="HIGH",
                        evidence="DNS NS record",
                    )
                )

        return relationships

    # ------------------------------------------------------------------
    # Mail servers
    # ------------------------------------------------------------------

    def _build_mail_server_relationships(
        self,
        infrastructure: Infrastructure,
    ) -> list[Relationship]:
        """
        Build USES_MAIL_SERVER relationships.
        """

        relationships: list[Relationship] = []

        for domain in infrastructure.domains:

            for mail_server in domain.mail_servers:

                relationships.append(
                    Relationship(
                        source=domain.name,
                        target=mail_server,
                        relation="USES_MAIL_SERVER",
                        confidence="HIGH",
                        evidence="DNS MX record",
                    )
                )

        return relationships

    # ------------------------------------------------------------------
    # Shared IP
    # ------------------------------------------------------------------

    def _build_shared_ip_relationships(
        self,
        infrastructure: Infrastructure,
    ) -> list[Relationship]:
        """
        Build SHARES_IP relationships between domains.

        A relationship is created when two different domains
        explicitly resolve to the same IP address.

        Multiple shared IPs between the same pair of domains
        are consolidated into a single relationship.
        """

        ip_to_domains: dict[
            str,
            set[str],
        ] = {}

        for domain in infrastructure.domains:

            addresses = (
                list(domain.ipv4)
                + list(domain.ipv6)
            )

            for address in addresses:
                ip_to_domains.setdefault(
                    address,
                    set(),
                ).add(
                    domain.name
                )

        shared_ips_by_pair: dict[
            tuple[str, str],
            set[str],
        ] = {}

        for ip_address, domains in ip_to_domains.items():

            if len(domains) < 2:
                continue

            for source, target in combinations(
                sorted(domains),
                2,
            ):
                pair = (
                    source,
                    target,
                )

                shared_ips_by_pair.setdefault(
                    pair,
                    set(),
                ).add(
                    ip_address
                )

        relationships: list[Relationship] = []

        for (
            source,
            target,
        ), shared_ips in sorted(
            shared_ips_by_pair.items()
        ):

            ordered_ips = sorted(
                shared_ips
            )

            evidence = (
                "Shared IP address(es): "
                + ", ".join(
                    ordered_ips
                )
            )

            relationships.append(
                Relationship(
                    source=source,
                    target=target,
                    relation="SHARES_IP",
                    confidence="HIGH",
                    evidence=evidence,
                )
            )

        return relationships

    # ------------------------------------------------------------------
    # Shared certificate
    # ------------------------------------------------------------------

    def _build_shared_certificate_relationships(
        self,
        infrastructure: Infrastructure,
    ) -> list[Relationship]:
        """
        Build SHARES_CERTIFICATE relationships between domains.

        A relationship is created when two different domain names
        appear in the same certificate.

        Multiple shared certificates between the same pair of
        domains are consolidated into a single relationship.
        """

        certificates_by_pair: dict[
            tuple[str, str],
            set[str],
        ] = {}

        for certificate in infrastructure.certificates:

            certificate_id = (
                certificate.certificate_id
            )

            if not certificate_id:
                continue

            valid_domains = []

            for domain_name in certificate.domains:
                classification = CertificateClassifier.classify_name(
                    domain_name,
                    infrastructure.target,
                )

                if classification == "VALID_DOMAIN":
                    valid_domains.append(domain_name)

            domains = sorted(set(valid_domains))

            if len(domains) < 2:
                continue

            for source, target in combinations(
                domains,
                2,
            ):
                pair = (
                    source,
                    target,
                )

                certificates_by_pair.setdefault(
                    pair,
                    set(),
                ).add(
                    certificate_id
                )

        relationships: list[Relationship] = []

        for (
            source,
            target,
        ), certificate_ids in sorted(
            certificates_by_pair.items()
        ):

            ordered_certificates = sorted(
                certificate_ids
            )

            evidence = (
                "Shared certificate(s): "
                + ", ".join(
                    ordered_certificates
                )
            )

            relationships.append(
                Relationship(
                    source=source,
                    target=target,
                    relation="SHARES_CERTIFICATE",
                    confidence="HIGH",
                    evidence=evidence,
                )
            )

        return relationships

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(
        relationships: list[Relationship],
    ) -> list[Relationship]:
        """
        Remove duplicate relationships while preserving order.
        """

        unique: list[Relationship] = []

        for relationship in relationships:

            if relationship not in unique:
                unique.append(
                    relationship
                )

        return unique