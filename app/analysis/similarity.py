from __future__ import annotations

from collections import defaultdict

from app.models.relationship import Relationship
from app.models.similarity import (
    SimilarityResult,
    SimilaritySignal,
)


RELATIONSHIP_TO_SIMILARITY = {
    "SHARES_IP": "SHARED_IP",
    "SHARES_CERTIFICATE": "SHARED_CERTIFICATE",
    "USES_NAMESERVER": "SHARED_NAMESERVER",
    "USES_MAIL_SERVER": "SHARED_MAIL_SERVER",
    "CNAME_TO": "SHARED_CNAME",
    "SUBDOMAIN_OF": "SUBDOMAIN_RELATION",
}


class SimilarityEngine:
    """
    Converts infrastructure relationships into
    explainable similarity signals.
    """

    def evaluate(
        self,
        relationships: list[Relationship],
    ) -> list[SimilaritySignal]:
        signals: list[SimilaritySignal] = []

        for relationship in relationships:
            similarity_type = RELATIONSHIP_TO_SIMILARITY.get(
                relationship.relation
            )

            if similarity_type is None:
                continue

            signals.append(
                SimilaritySignal(
                    source=relationship.source,
                    target=relationship.target,
                    similarity_type=similarity_type,
                    evidence=relationship.evidence,
                )
            )

        return signals

    def correlate(
        self,
        signals: list[SimilaritySignal],
    ) -> list[SimilarityResult]:
        grouped: dict[
            tuple[str, str],
            list[SimilaritySignal],
        ] = defaultdict(list)

        for signal in signals:
            pair = (
                signal.source,
                signal.target,
            )

            grouped[pair].append(signal)

        results: list[SimilarityResult] = []

        for (source, target), pair_signals in grouped.items():
            results.append(
                SimilarityResult(
                    source=source,
                    target=target,
                    signals=pair_signals,
                )
            )

        return results