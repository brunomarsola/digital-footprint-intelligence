"""
Certificate intelligence and classification.

Provides deterministic classification of TLS certificate
common names discovered through passive sources.
"""

from __future__ import annotations

import re

from app.models.certificate import (
    Certificate,
    CertificateClassification,
)


_LABEL_PATTERN = re.compile(
    r"^[a-z0-9]"
    r"(?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def _normalize_target(target: str) -> str:
    """
    Normalize an investigation target.
    """
    return (
        target
        .strip()
        .lower()
        .rstrip(".")
    )


def _normalize_name(name: str) -> str:
    """
    Normalize a certificate common name.
    """
    return (
        name
        .strip()
        .lower()
        .rstrip(".")
    )


def _is_valid_dns_name(name: str) -> bool:
    """
    Validate a DNS hostname.

    Wildcard names are accepted when the wildcard is the
    left-most label, such as *.example.com.
    """
    name = _normalize_name(name)

    if not name:
        return False

    if "@" in name:
        return False

    if any(char.isspace() for char in name):
        return False

    if name.startswith("*."):
        name = name[2:]

    if "*" in name:
        return False

    if len(name) > 253:
        return False

    labels = name.split(".")

    if len(labels) < 2:
        return False

    return all(
        _LABEL_PATTERN.fullmatch(label)
        for label in labels
    )


def _is_subdomain(name: str, target: str) -> bool:
    """
    Determine whether a DNS name belongs to the target
    domain namespace.

    Example:

        name   = api.example.com
        target = example.com

        -> True
    """
    return (
        name.endswith(f".{target}")
        and name != target
    )


class CertificateClassifier:
    """
    Classify certificates according to their relationship
    with the investigation target.
    """

    @staticmethod
    def classify_name(
        name: str,
        target: str,
    ) -> CertificateClassification:
        """
        Classify an individual certificate name.

        Classification rules:

        - VALID_DOMAIN:
            Exact target or subdomain of target.

        - WILDCARD:
            Valid wildcard name associated with target.

        - EXTERNAL_DOMAIN:
            Valid DNS name outside the target namespace.

        - NON_DOMAIN:
            Invalid or non-DNS certificate value.
        """
        normalized_name = _normalize_name(
            name
        )

        normalized_target = _normalize_target(
            target
        )

        if not _is_valid_dns_name(
            normalized_name
        ):
            return "NON_DOMAIN"

        if normalized_name.startswith("*."):
            wildcard_domain = normalized_name[2:]

            if (
                wildcard_domain == normalized_target
                or _is_subdomain(
                    wildcard_domain,
                    normalized_target,
                )
            ):
                return "WILDCARD"

            return "EXTERNAL_DOMAIN"

        if (
            normalized_name == normalized_target
            or _is_subdomain(
                normalized_name,
                normalized_target,
            )
        ):
            return "VALID_DOMAIN"

        return "EXTERNAL_DOMAIN"

    @staticmethod
    def classify(
        certificate: Certificate,
        target: str,
    ) -> CertificateClassification:
        """
        Classify a certificate common name.
        """
        if not certificate.common_name:
            return "NON_DOMAIN"

        return CertificateClassifier.classify_name(
            certificate.common_name,
            target,
        )