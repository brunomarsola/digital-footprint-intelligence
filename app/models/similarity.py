from dataclasses import dataclass
from typing import Literal


SimilarityType = Literal[
    "SHARED_IP",
    "SHARED_CERTIFICATE",
    "SHARED_NAMESERVER",
    "SHARED_MAIL_SERVER",
    "SHARED_CNAME",
    "SUBDOMAIN_RELATION",
]


@dataclass
class SimilaritySignal:
    source: str
    target: str
    similarity_type: SimilarityType
    evidence: str

    def __post_init__(self) -> None:
        self.source = self.source.strip().lower()
        self.target = self.target.strip().lower()
        self.similarity_type = (
            self.similarity_type.strip().upper()
        )
        self.evidence = self.evidence.strip()


@dataclass
class SimilarityResult:
    source: str
    target: str
    signals: list[SimilaritySignal]

    def __post_init__(self) -> None:
        self.source = self.source.strip().lower()
        self.target = self.target.strip().lower()