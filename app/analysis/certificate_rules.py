"""
Certificate intelligence rules for Digital Footprint Intelligence.

Converts classified certificate observations into
explainable analytical findings.
"""

from __future__ import annotations

from app.models.certificate import Certificate
from app.models.finding import Finding


def evaluate_certificate(
    certificate: Certificate,
) -> list[Finding]:
    """
    Evaluate a certificate and generate analytical findings.

    The function is intentionally deterministic. It does not
    calculate a global risk score and does not treat every
    certificate observation as a security issue.

    Returns:
        A list of findings generated from the certificate.
    """
    findings: list[Finding] = []

    if certificate.classification == "WILDCARD":
        findings.append(
            Finding(
                rule_id="CERT-WILD-001",
                severity="LOW",
                title="Wildcard certificate detected",
                description=(
                    "The certificate uses a wildcard name "
                    "covering multiple hosts within the "
                    "target namespace."
                ),
                evidence=(
                    f"Certificate "
                    f"{certificate.certificate_id or 'unknown'}"
                    f" | "
                    f"{certificate.common_name or 'unknown'}"
                ),
                confidence="HIGH",
            )
        )

    elif certificate.classification == "EXTERNAL_DOMAIN":
        findings.append(
            Finding(
                rule_id="CERT-EXT-001",
                severity="MEDIUM",
                title="External certificate domain detected",
                description=(
                    "The certificate contains a valid DNS "
                    "name outside the investigated target "
                    "namespace."
                ),
                evidence=(
                    f"Certificate "
                    f"{certificate.certificate_id or 'unknown'}"
                    f" | "
                    f"{certificate.common_name or 'unknown'}"
                ),
                confidence="MEDIUM",
            )
        )

    elif certificate.classification == "NON_DOMAIN":
        findings.append(
            Finding(
                rule_id="CERT-NONDNS-001",
                severity="INFO",
                title="Non-DNS certificate name detected",
                description=(
                    "The certificate contains a common name "
                    "that does not conform to a valid DNS "
                    "hostname."
                ),
                evidence=(
                    f"Certificate "
                    f"{certificate.certificate_id or 'unknown'}"
                    f" | "
                    f"{certificate.common_name or 'unknown'}"
                ),
                confidence="HIGH",
            )
        )

    return findings