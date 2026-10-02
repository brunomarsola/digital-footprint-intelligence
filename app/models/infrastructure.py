"""
Infrastructure model for Digital Footprint Intelligence.

Represents the normalized infrastructure discovered during
a passive digital footprint investigation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.similarity import SimilarityResult

from app.models.certificate import Certificate
from app.models.collection import CollectionStatus
from app.models.domain import Domain
from app.models.finding import Finding
from app.models.ip import IPAddress
from app.models.relationship import Relationship


@dataclass
class Infrastructure:
    """
    Represents the infrastructure discovered for a target.

    The infrastructure acts as the central normalized container
    for domains, IP addresses, certificates, collection status,
    analytical findings, and relationships.
    """

    target: str

    domains: list[Domain] = field(
        default_factory=list
    )

    ip_addresses: list[IPAddress] = field(
        default_factory=list
    )

    certificates: list[Certificate] = field(
        default_factory=list
    )

    similarity_results: list[SimilarityResult] = field(
    default_factory=list
    )

    collection_status: list[CollectionStatus] = field(
        default_factory=list
    )

    findings: list[Finding] = field(
        default_factory=list
    )

    relationships: list[Relationship] = field(
        default_factory=list
    )

    def __post_init__(self) -> None:
        """
        Normalize the investigation target.
        """

        self.target = (
            self.target
            .strip()
            .lower()
            .rstrip(".")
        )

    # ------------------------------------------------------------------
    # Domains
    # ------------------------------------------------------------------

    def add_domain(
        self,
        domain: Domain,
    ) -> None:
        """
        Add a domain to the infrastructure.

        Duplicate domains are ignored.
        """

        if domain not in self.domains:
            self.domains.append(
                domain
            )

    @property
    def domain_count(self) -> int:
        """
        Return the number of discovered domains.
        """

        return len(
            self.domains
        )

    # ------------------------------------------------------------------
    # IP addresses
    # ------------------------------------------------------------------

    def add_ip(
        self,
        ip_address: IPAddress,
    ) -> None:
        """
        Add an IP address to the infrastructure.

        Duplicate IP addresses are ignored.
        """

        if ip_address not in self.ip_addresses:
            self.ip_addresses.append(
                ip_address
            )

    @property
    def ip_count(self) -> int:
        """
        Return the number of discovered IP addresses.
        """

        return len(
            self.ip_addresses
        )

    # ------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------

    def add_certificate(
        self,
        certificate: Certificate,
    ) -> None:
        """
        Add a certificate to the infrastructure.

        Duplicate certificates are ignored.
        """

        if certificate not in self.certificates:
            self.certificates.append(
                certificate
            )

    @property
    def certificate_count(self) -> int:
        """
        Return the number of discovered certificates.
        """

        return len(
            self.certificates
        )

    # ------------------------------------------------------------------
    # Collection status
    # ------------------------------------------------------------------

    def add_collection_status(
        self,
        status: CollectionStatus,
    ) -> None:
        """
        Add the result of a collection source.

        Collection statuses are kept as individual records because
        multiple collectors may participate in the same investigation.
        """

        self.collection_status.append(
            status
        )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(
        self,
        finding: Finding,
    ) -> None:
        """
        Add an analytical finding.

        Duplicate findings are ignored.
        """

        if finding not in self.findings:
            self.findings.append(
                finding
            )

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def add_relationship(
        self,
        relationship: Relationship,
    ) -> None:
        """
        Add an analytical relationship to the infrastructure.

        Duplicate relationships are ignored.
        """

        if relationship not in self.relationships:
            self.relationships.append(
                relationship
            )

    def add_similarity_result(
        self,
        result: SimilarityResult,
    ) -> None:
        """
        Add a similarity analysis result.

        Duplicate results are ignored.
        """

        if result not in self.similarity_results:
            self.similarity_results.append(result)