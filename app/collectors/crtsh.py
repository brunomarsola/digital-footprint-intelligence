"""
Certificate Transparency collector using crt.sh.

Discovers domain names associated with certificates
issued for a target domain.
"""

from __future__ import annotations

import time
import re
from typing import Any

import requests

CRTSH_URL = "https://crt.sh/"
MAX_RETRIES = 3
RETRYABLE_STATUS_CODES = {502, 503, 504}

def _normalize_domain(domain: str) -> str:
    """
    Normalize a domain name.

    Removes whitespace, trailing dots and wildcard prefixes.
    """
    return (
        domain
        .strip()
        .lower()
        .rstrip(".")
        .removeprefix("*.")
    )

def _is_valid_dns_name(name: str) -> bool:
    """
    Validate a DNS hostname extracted from certificate data.

    Wildcard names such as *.example.com are accepted.
    Values containing whitespace, email addresses or other
    non-DNS characters are rejected.
    """
    name = name.strip().lower()

    if not name:
        return False

    if "@" in name:
        return False

    if any(char.isspace() for char in name):
        return False

    if name.startswith("*."):
        name = name[2:]

    if not name:
        return False

    if len(name) > 253:
        return False

    labels = name.split(".")

    if len(labels) < 2:
        return False

    label_pattern = re.compile(
        r"^[a-z0-9]"
        r"(?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    return all(
        label_pattern.fullmatch(label)
        for label in labels
    )


def _extract_domains(
    entries: list[dict[str, Any]],
) -> list[str]:
    """
    Extract valid DNS names from crt.sh results.

    Invalid certificate values are ignored instead of being
    treated as domains.
    """
    domains: set[str] = set()

    for entry in entries:
        name_value = entry.get(
            "name_value",
            "",
        )

        for name in name_value.splitlines():
            normalized = _normalize_domain(name)

            if _is_valid_dns_name(normalized):
                domains.add(normalized)

    return sorted(domains)


def collect_certificates(domain: str) -> dict[str, Any]:
    """
    Query crt.sh for Certificate Transparency records.

    Retries transient upstream failures such as HTTP 502,
    503 and 504 using a simple incremental backoff.

    Args:
        domain: Domain to investigate.

    Returns:
        Dictionary containing certificate records,
        discovered domains, retry information and errors.
    """
    domain = _normalize_domain(domain)

    params = {
        "q": f"%.{domain}",
        "output": "json",
    }

    last_error: str | None = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                CRTSH_URL,
                params=params,
                timeout=15,
                headers={
                    "User-Agent": (
                        "Digital-Footprint-Intelligence/0.1"
                    ),
                },
            )

            # -------------------------------------------------
            # Retry transient upstream failures
            # -------------------------------------------------

            if response.status_code in RETRYABLE_STATUS_CODES:
                last_error = (
                    f"HTTP {response.status_code}: "
                    "temporary upstream failure"
                )

                if attempt < MAX_RETRIES:
                    time.sleep(attempt)
                    continue

                return {
                    "domain": domain,
                    "certificates": [],
                    "domains": [],
                    "attempts": attempt,
                    "error": last_error,
                }

            # -------------------------------------------------
            # Handle non-retryable HTTP errors
            # -------------------------------------------------

            response.raise_for_status()

            # -------------------------------------------------
            # Parse response
            # -------------------------------------------------

            entries = response.json()

            discovered_domains = _extract_domains(entries)

            return {
                "domain": domain,
                "certificates": entries,
                "domains": discovered_domains,
                "attempts": attempt,
                "error": None,
            }

        except requests.RequestException as exc:
            last_error = str(exc)

            if attempt < MAX_RETRIES:
                time.sleep(attempt)
                continue

            return {
                "domain": domain,
                "certificates": [],
                "domains": [],
                "attempts": attempt,
                "error": last_error,
            }

        except ValueError as exc:
            return {
                "domain": domain,
                "certificates": [],
                "domains": [],
                "attempts": attempt,
                "error": f"Invalid JSON response: {exc}",
            }

    # ---------------------------------------------------------
    # Defensive fallback
    # ---------------------------------------------------------

    return {
        "domain": domain,
        "certificates": [],
        "domains": [],
        "attempts": MAX_RETRIES,
        "error": last_error,
    }