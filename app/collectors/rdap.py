"""
RDAP collector for Digital Footprint Intelligence.

Retrieves structured registration and network information
for a domain using the RDAP protocol.
"""

from __future__ import annotations

from typing import Any

import requests


RDAP_DOMAIN_URL = "https://rdap.org/domain/{domain}"


def _normalize_domain(domain: str) -> str:
    """
    Normalize a domain name.
    """
    return domain.strip().lower().rstrip(".")


def _extract_nameservers(data: dict[str, Any]) -> list[str]:
    """
    Extract nameserver hostnames from an RDAP response.
    """
    nameservers: set[str] = set()

    for nameserver in data.get("nameservers", []):
        hostname = nameserver.get("ldhName")

        if hostname:
            nameservers.add(hostname.lower().rstrip("."))

    return sorted(nameservers)


def _extract_events(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract relevant RDAP events.
    """
    events = []

    for event in data.get("events", []):
        event_action = event.get("eventAction")
        event_date = event.get("eventDate")

        if event_action:
            events.append(
                {
                    "action": event_action,
                    "date": event_date,
                }
            )

    return events


def collect_rdap(domain: str) -> dict[str, Any]:
    """
    Retrieve RDAP information for a domain.

    Args:
        domain: Domain name to investigate.

    Returns:
        Structured RDAP information.
    """
    domain = _normalize_domain(domain)

    url = RDAP_DOMAIN_URL.format(domain=domain)

    try:
        response = requests.get(
            url,
            timeout=15,
            headers={
                "Accept": "application/rdap+json, application/json",
                "User-Agent": "Digital-Footprint-Intelligence/0.1",
            },
        )

        response.raise_for_status()

        data = response.json()

    except requests.RequestException as exc:
        return {
            "domain": domain,
            "handle": None,
            "status": [],
            "nameservers": [],
            "events": [],
            "rdap_conformance": [],
            "error": str(exc),
        }

    except ValueError as exc:
        return {
            "domain": domain,
            "handle": None,
            "status": [],
            "nameservers": [],
            "events": [],
            "rdap_conformance": [],
            "error": f"Invalid JSON response: {exc}",
        }

    return {
        "domain": domain,
        "handle": data.get("handle"),
        "status": data.get("status", []),
        "nameservers": _extract_nameservers(data),
        "events": _extract_events(data),
        "rdap_conformance": data.get("rdapConformance", []),
        "error": None,
    }