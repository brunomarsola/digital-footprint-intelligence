"""
DNS collector for Digital Footprint Intelligence.

Performs passive DNS resolution for common record types.
"""

from __future__ import annotations

from typing import Any

import dns.resolver


SUPPORTED_RECORD_TYPES = (
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
)


def _normalize_mx_answer(answer: Any) -> str | None:
    """
    Normalize a DNS MX answer.

    MX records contain two important fields:

        preference
        exchange

    Example:

        10 mail.example.com.

    Only the exchange is relevant for the Domain.mail_servers
    relationship model.

    A Null MX record is represented as:

        0 .

    The "." exchange means that the domain does not accept email
    and therefore must not be represented as a mail server.
    """

    exchange = getattr(
        answer,
        "exchange",
        None,
    )

    if exchange is None:
        return None

    exchange = str(
        exchange
    ).strip().lower().rstrip(".")

    if not exchange:
        return None

    if exchange == ".":
        return None

    return exchange


def _query_records(
    domain: str,
    record_type: str,
) -> list[str]:
    """
    Resolve a DNS record type for a domain.

    Returns an empty list when the record does not exist
    or cannot be resolved.
    """

    try:
        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=5,
        )

        if record_type == "MX":
            records: list[str] = []

            for answer in answers:
                normalized = _normalize_mx_answer(
                    answer
                )

                if normalized:
                    records.append(
                        normalized
                    )

            return records

        return [
            answer.to_text()
            for answer in answers
        ]

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []


def collect_dns(
    domain: str,
) -> dict[str, Any]:
    """
    Collect common DNS records for a domain.

    Args:
        domain: Domain name to investigate.

    Returns:
        Dictionary containing resolved DNS records.
    """

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    results: dict[str, Any] = {
        "domain": domain,
        "records": {},
    }

    for record_type in SUPPORTED_RECORD_TYPES:
        results["records"][record_type] = (
            _query_records(
                domain,
                record_type,
            )
        )

    return results