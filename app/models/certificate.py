"""
Certificate model for Digital Footprint Intelligence.

Represents a normalized TLS certificate discovered through
passive Certificate Transparency sources.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


CertificateClassification = Literal[
    "VALID_DOMAIN",
    "WILDCARD",
    "EXTERNAL_DOMAIN",
    "NON_DOMAIN",
]


@dataclass
class Certificate:
    """
    Normalized representation of a TLS certificate.

    Certificate data is intended to come from passive sources
    such as Certificate Transparency logs.
    """

    certificate_id: str | None = None
    issuer_name: str | None = None
    common_name: str | None = None
    serial_number: str | None = None

    not_before: str | None = None
    not_after: str | None = None

    domains: list[str] = field(default_factory=list)

    classification: CertificateClassification | None = None

    def __post_init__(self) -> None:
        """
        Normalize certificate fields after initialization.
        """
        if self.issuer_name:
            self.issuer_name = self.issuer_name.strip()

        if self.common_name:
            self.common_name = (
                self.common_name
                .strip()
                .lower()
                .rstrip(".")
            )

        if self.serial_number:
            self.serial_number = (
                self.serial_number
                .strip()
                .lower()
            )

        if self.classification:
            self.classification = (
                self.classification
                .strip()
                .upper()
            )

        self.domains = self._normalize_domains(
            self.domains
        )

    @staticmethod
    def _normalize_domains(
        domains: list[str],
    ) -> list[str]:
        """
        Normalize and deduplicate domain names.
        """
        normalized = {
            domain.strip()
            .lower()
            .rstrip(".")
            for domain in domains
            if domain and domain.strip()
        }

        return sorted(normalized)

    def add_domain(
        self,
        domain: str,
    ) -> None:
        """
        Add a domain associated with this certificate.
        """
        normalized = (
            domain
            .strip()
            .lower()
            .rstrip(".")
        )

        if normalized and normalized not in self.domains:
            self.domains.append(normalized)
            self.domains.sort()