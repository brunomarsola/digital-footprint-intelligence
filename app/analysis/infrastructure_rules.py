"""
Domain and infrastructure intelligence rules.

Produces explainable findings from the normalized
infrastructure discovered during an investigation.
"""

from __future__ import annotations

from app.models.finding import Finding
from app.models.infrastructure import Infrastructure


def evaluate_infrastructure(
    infrastructure: Infrastructure,
) -> list[Finding]:
    """
    Evaluate normalized infrastructure and generate
    explainable analytical findings.

    These rules describe observable characteristics of
    the discovered infrastructure. They do not claim that
    an observation is inherently malicious or vulnerable.

    Returns:
        A list of findings generated from the infrastructure.
    """
    findings: list[Finding] = []

    if infrastructure.domain_count > 1:
        findings.append(
            Finding(
                rule_id="DOMAIN-ENUM-001",
                severity="INFO",
                title="Multiple domains discovered",
                description=(
                    "Multiple domain names were discovered "
                    "within the investigation footprint."
                ),
                evidence=(
                    f"Target: {infrastructure.target} | "
                    f"Domains discovered: "
                    f"{infrastructure.domain_count}"
                ),
                confidence="HIGH",
            )
        )

    if infrastructure.ip_count > 1:
        findings.append(
            Finding(
                rule_id="INFRA-IP-001",
                severity="INFO",
                title="Multiple IP addresses discovered",
                description=(
                    "Multiple IP addresses were associated "
                    "with the investigated infrastructure."
                ),
                evidence=(
                    f"Target: {infrastructure.target} | "
                    f"IP addresses discovered: "
                    f"{infrastructure.ip_count}"
                ),
                confidence="HIGH",
            )
        )

    return findings