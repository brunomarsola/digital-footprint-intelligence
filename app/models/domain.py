"""
Domain model for Digital Footprint Intelligence.

Represents a normalized domain entity collected from
passive sources such as DNS, RDAP and Certificate Transparency.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Domain:
    """
    Normalized representation of a domain.

    The model intentionally contains only passive intelligence
    collected from public sources.
    """

    name: str

    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)

    nameservers: list[str] = field(default_factory=list)
    mail_servers: list[str] = field(default_factory=list)

    txt_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)

    discovered_subdomains: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """
        Normalize the domain and remove duplicate values.
        """
        self.name = self._normalize_domain(self.name)

        self.ipv4 = self._normalize_list(self.ipv4)
        self.ipv6 = self._normalize_list(self.ipv6)
        self.nameservers = self._normalize_list(self.nameservers)
        self.mail_servers = self._normalize_list(self.mail_servers)
        self.txt_records = self._normalize_list(self.txt_records)
        self.cname_records = self._normalize_list(self.cname_records)
        self.discovered_subdomains = self._normalize_list(
            self.discovered_subdomains
        )

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """
        Normalize a domain name.
        """
        return (
            domain
            .strip()
            .lower()
            .rstrip(".")
            .removeprefix("*.")
        )

    @staticmethod
    def _normalize_list(values: list[str]) -> list[str]:
        """
        Normalize and deduplicate a list of strings.
        """
        normalized = {
            value.strip().lower().rstrip(".")
            for value in values
            if value and value.strip()
        }

        return sorted(normalized)

    def add_subdomain(self, subdomain: str) -> None:
        """
        Add a discovered subdomain to the domain entity.
        """
        normalized = self._normalize_domain(subdomain)

        if normalized and normalized not in self.discovered_subdomains:
            self.discovered_subdomains.append(normalized)
            self.discovered_subdomains.sort()

    def add_ipv4(self, address: str) -> None:
        """
        Add an IPv4 address associated with the domain.
        """
        address = address.strip()

        if address and address not in self.ipv4:
            self.ipv4.append(address)
            self.ipv4.sort()

    def add_ipv6(self, address: str) -> None:
        """
        Add an IPv6 address associated with the domain.
        """
        address = address.strip()

        if address and address not in self.ipv6:
            self.ipv6.append(address)
            self.ipv6.sort()