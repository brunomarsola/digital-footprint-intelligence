"""
Relationship model for Digital Footprint Intelligence.

Represents an analytical relationship between two
infrastructure entities.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


RelationshipType = Literal[
    "RESOLVES_TO",
    "SUBDOMAIN_OF",
    "HAS_CERTIFICATE",
    "CERTIFICATE_FOR",
    "SHARES_IP",
    "SHARES_CERTIFICATE",
    "CNAME_TO",
    "USES_NAMESERVER",
    "USES_MAIL_SERVER",
    "RELATED_TO",
]


RelationshipConfidence = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
]


@dataclass
class Relationship:
    """
    Represents a normalized analytical relationship
    between two infrastructure entities.
    """

    source: str
    target: str
    relation: RelationshipType
    confidence: RelationshipConfidence
    evidence: str

    def __post_init__(self) -> None:
        """
        Normalize relationship fields.
        """

        self.source = (
            self.source
            .strip()
        )

        self.target = (
            self.target
            .strip()
        )

        self.relation = (
            self.relation
            .strip()
            .upper()
        )

        self.confidence = (
            self.confidence
            .strip()
            .upper()
        )

        self.evidence = (
            self.evidence
            .strip()
        )