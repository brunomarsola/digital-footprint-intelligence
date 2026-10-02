"""
Finding model for Digital Footprint Intelligence.

Represents an explainable analytical finding produced
by the risk and intelligence analysis engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


FindingSeverity = Literal[
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]

FindingConfidence = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
]


VALID_SEVERITIES: tuple[
    FindingSeverity,
    ...
] = (
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)


VALID_CONFIDENCES: tuple[
    FindingConfidence,
    ...
] = (
    "LOW",
    "MEDIUM",
    "HIGH",
)


@dataclass
class Finding:
    """
    Represents an explainable analytical finding.

    A finding describes an observation made during an
    investigation and preserves the evidence and reasoning
    behind that observation.
    """

    rule_id: str
    severity: FindingSeverity
    title: str
    description: str
    evidence: str
    confidence: FindingConfidence

    def __post_init__(self) -> None:
        """
        Normalize and validate finding fields.
        """
        self.rule_id = self.rule_id.strip().upper()

        self.severity = (
            self.severity
            .strip()
            .upper()
        )

        self.title = self.title.strip()

        self.description = (
            self.description.strip()
        )

        self.evidence = self.evidence.strip()

        self.confidence = (
            self.confidence
            .strip()
            .upper()
        )

        self._validate_severity()
        self._validate_confidence()

    def _validate_severity(self) -> None:
        """
        Validate the finding severity.
        """
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid finding severity: "
                f"{self.severity}"
            )

    def _validate_confidence(self) -> None:
        """
        Validate the finding confidence.
        """
        if self.confidence not in VALID_CONFIDENCES:
            raise ValueError(
                f"Invalid finding confidence: "
                f"{self.confidence}"
            )