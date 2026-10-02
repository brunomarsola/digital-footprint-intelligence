"""
IP address model for Digital Footprint Intelligence.

Represents a normalized IP infrastructure entity collected
from passive sources such as DNS and RDAP.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import ipaddress


@dataclass
class IPAddress:
    """
    Normalized representation of an IP address.

    The model stores passive infrastructure metadata and
    relationships discovered during intelligence collection.
    """

    address: str

    asn: int | None = None
    organization: str | None = None
    country: str | None = None
    network: str | None = None

    hostnames: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """
        Normalize and validate the IP address after initialization.
        """
        self.address = self._normalize_address(self.address)

        self.organization = self._normalize_optional_string(
            self.organization
        )

        self.country = self._normalize_optional_string(
            self.country
        )

        self.network = self._normalize_optional_string(
            self.network
        )

        self.hostnames = self._normalize_hostnames(
            self.hostnames
        )

    @staticmethod
    def _normalize_address(address: str) -> str:
        """
        Validate and normalize an IPv4 or IPv6 address.
        """
        address = address.strip()

        return str(ipaddress.ip_address(address))

    @staticmethod
    def _normalize_optional_string(
        value: str | None,
    ) -> str | None:
        """
        Normalize optional string fields.
        """
        if value is None:
            return None

        value = value.strip()

        return value if value else None

    @staticmethod
    def _normalize_hostnames(
        hostnames: list[str],
    ) -> list[str]:
        """
        Normalize and deduplicate hostnames.
        """
        normalized = {
            hostname.strip().lower().rstrip(".")
            for hostname in hostnames
            if hostname and hostname.strip()
        }

        return sorted(normalized)

    @property
    def version(self) -> int:
        """
        Return the IP version.

        Returns:
            4 for IPv4 or 6 for IPv6.
        """
        return ipaddress.ip_address(self.address).version

    def add_hostname(self, hostname: str) -> None:
        """
        Associate a hostname with this IP address.
        """
        normalized = hostname.strip().lower().rstrip(".")

        if normalized and normalized not in self.hostnames:
            self.hostnames.append(normalized)
            self.hostnames.sort()