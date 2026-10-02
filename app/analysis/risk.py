"""
Passive infrastructure risk analysis.

Generates explainable risk signals and findings from
infrastructure observed through passive intelligence sources.

This module does not perform active scanning or exploitation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.analysis.certificate_rules import (
    evaluate_certificate,
)
from app.analysis.infrastructure_rules import (
    evaluate_infrastructure,
)
from app.models.finding import Finding
from app.models.infrastructure import Infrastructure


RiskSeverity = Literal[
    "info",
    "low",
    "medium",
    "high",
]


@dataclass
class RiskSignal:
    """
    Represents an explainable risk observation.

    Legacy risk representation retained for compatibility
    with the original passive risk analysis implementation.
    """

    severity: RiskSeverity
    title: str
    description: str
    evidence: list[str]


def analyze_risk(
    infrastructure: Infrastructure,
) -> list[RiskSignal]:
    """
    Analyze an infrastructure model and generate
    explainable passive risk signals.

    This function is retained for compatibility with the
    original risk analysis implementation.

    Args:
        infrastructure:
            Normalized infrastructure collected through
            passive intelligence sources.

    Returns:
        List of risk signals.
    """
    signals: list[RiskSignal] = []

    # ---------------------------------------------------------
    # Collection integrity
    # ---------------------------------------------------------

    failed_sources = [
        status
        for status in infrastructure.collection_status
        if status.status == "error"
    ]

    if failed_sources:
        sources = [
            status.source
            for status in failed_sources
        ]

        signals.append(
            RiskSignal(
                severity="low",
                title="Incomplete collection",
                description=(
                    "One or more intelligence sources "
                    "failed during collection. The absence "
                    "of observed data should not be interpreted "
                    "as evidence that the infrastructure does "
                    "not exist."
                ),
                evidence=sources,
            )
        )

    # ---------------------------------------------------------
    # External infrastructure exposure
    # ---------------------------------------------------------

    if infrastructure.ip_count > 0:
        signals.append(
            RiskSignal(
                severity="info",
                title="Internet-facing infrastructure observed",
                description=(
                    "Publicly resolvable IP addresses were "
                    "observed through passive DNS collection."
                ),
                evidence=[
                    ip.address
                    for ip in infrastructure.ip_addresses
                ],
            )
        )

    # ---------------------------------------------------------
    # Domain surface
    # ---------------------------------------------------------

    if infrastructure.domain_count >= 5:
        signals.append(
            RiskSignal(
                severity="medium",
                title="Expanded domain footprint",
                description=(
                    "Five or more domains were observed "
                    "during passive collection."
                ),
                evidence=[
                    domain.name
                    for domain in infrastructure.domains
                ],
            )
        )

    # ---------------------------------------------------------
    # Certificate surface
    # ---------------------------------------------------------

    if infrastructure.certificate_count >= 10:
        signals.append(
            RiskSignal(
                severity="low",
                title="Large certificate footprint",
                description=(
                    "Multiple certificates were observed "
                    "through Certificate Transparency data."
                ),
                evidence=[
                    str(
                        certificate.certificate_id
                    )
                    for certificate
                    in infrastructure.certificates
                    if certificate.certificate_id
                ],
            )
        )

    return signals


class RiskEngine:
    """
    Orchestrates explainable intelligence rules.

    The RiskEngine does not calculate a global numerical
    risk score. Instead, it aggregates deterministic findings
    produced by specialized analysis rules.
    """

    def evaluate(
        self,
        infrastructure: Infrastructure,
    ) -> list[Finding]:
        """
        Evaluate normalized infrastructure and return
        explainable findings.

        Args:
            infrastructure:
                Normalized infrastructure produced by the
                investigation service.

        Returns:
            List of structured analytical findings.
        """
        findings: list[Finding] = []

        # -----------------------------------------------------
        # Collection integrity
        # -----------------------------------------------------

        findings.extend(
            self._evaluate_collection_status(
                infrastructure
            )
        )

        # -----------------------------------------------------
        # Certificate intelligence
        # -----------------------------------------------------

        for certificate in infrastructure.certificates:
            findings.extend(
                evaluate_certificate(
                    certificate
                )
            )

        # -----------------------------------------------------
        # Infrastructure intelligence
        # -----------------------------------------------------

        findings.extend(
            evaluate_infrastructure(
                infrastructure
            )
        )

        return findings

    @staticmethod
    def _evaluate_collection_status(
        infrastructure: Infrastructure,
    ) -> list[Finding]:
        """
        Generate findings for failed collection sources.

        Collection failure is treated as an integrity
        observation rather than evidence of absence.
        """
        failed_sources = [
            status
            for status in infrastructure.collection_status
            if status.status == "error"
        ]

        if not failed_sources:
            return []

        sources = [
            status.source
            for status in failed_sources
        ]

        return [
            Finding(
                rule_id="COLLECTION-001",
                severity="LOW",
                title="Incomplete collection",
                description=(
                    "One or more intelligence sources "
                    "failed during collection. The absence "
                    "of observed data should not be interpreted "
                    "as evidence that the infrastructure does "
                    "not exist."
                ),
                evidence=(
                    "Failed sources: "
                    + ", ".join(sources)
                ),
                confidence="HIGH",
            )
        ]