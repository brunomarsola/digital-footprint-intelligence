"""
Collection status models for Digital Footprint Intelligence.

Tracks the provenance and execution status of passive
intelligence sources used during an investigation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


CollectionState = Literal[
    "success",
    "error",
    "partial",
]


@dataclass
class CollectionStatus:
    """
    Represents the result of collecting data from one source.
    """

    source: str
    status: CollectionState

    attempts: int = 1
    error: str | None = None

    def __post_init__(self) -> None:
        """
        Normalize source metadata.
        """
        self.source = self.source.strip()

        if self.error:
            self.error = self.error.strip()