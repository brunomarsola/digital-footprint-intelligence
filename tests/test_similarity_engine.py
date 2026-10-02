from app.analysis.similarity import SimilarityEngine
from app.models.relationship import Relationship
from app.models.similarity import SimilaritySignal


def test_similarity_engine_builds_shared_ip_signal():
    relationships = [
        Relationship(
            source="example.com",
            target="api.example.com",
            relation="SHARES_IP",
            confidence="HIGH",
            evidence="Shared IP address(es): 192.0.2.10",
        )
    ]

    engine = SimilarityEngine()

    signals = engine.evaluate(relationships)

    assert len(signals) == 1

    signal = signals[0]

    assert signal.source == "example.com"
    assert signal.target == "api.example.com"
    assert signal.similarity_type == "SHARED_IP"
    assert signal.evidence == "Shared IP address(es): 192.0.2.10"


def test_similarity_engine_builds_shared_certificate_signal():
    relationships = [
        Relationship(
            source="example.com",
            target="api.example.com",
            relation="SHARES_CERTIFICATE",
            confidence="HIGH",
            evidence="Shared certificate(s): cert-001",
        )
    ]

    engine = SimilarityEngine()

    signals = engine.evaluate(relationships)

    assert len(signals) == 1

    signal = signals[0]

    assert signal.similarity_type == "SHARED_CERTIFICATE"
    assert signal.evidence == "Shared certificate(s): cert-001"


def test_similarity_engine_ignores_non_similarity_relationships():
    relationships = [
        Relationship(
            source="example.com",
            target="192.0.2.10",
            relation="RESOLVES_TO",
            confidence="HIGH",
            evidence="DNS A record",
        ),
        Relationship(
            source="example.com",
            target="cert-001",
            relation="HAS_CERTIFICATE",
            confidence="HIGH",
            evidence="Certificate Transparency domain entry",
        ),
    ]

    engine = SimilarityEngine()

    signals = engine.evaluate(relationships)

    assert signals == []


def test_similarity_engine_builds_multiple_signals():
    relationships = [
        Relationship(
            source="example.com",
            target="api.example.com",
            relation="SHARES_IP",
            confidence="HIGH",
            evidence="Shared IP address(es): 192.0.2.10",
        ),
        Relationship(
            source="example.com",
            target="api.example.com",
            relation="SHARES_CERTIFICATE",
            confidence="HIGH",
            evidence="Shared certificate(s): cert-001",
        ),
    ]

    engine = SimilarityEngine()

    signals = engine.evaluate(relationships)

    assert len(signals) == 2

    similarity_types = {
        signal.similarity_type
        for signal in signals
    }

    assert similarity_types == {
        "SHARED_IP",
        "SHARED_CERTIFICATE",
    }

def test_similarity_engine_correlates_signals_for_same_pair():
    signals = [
        SimilaritySignal(
            source="example.com",
            target="api.example.com",
            similarity_type="SHARED_IP",
            evidence="Shared IP address(es): 192.0.2.10",
        ),
        SimilaritySignal(
            source="example.com",
            target="api.example.com",
            similarity_type="SHARED_CERTIFICATE",
            evidence="Shared certificate(s): cert-001",
        ),
    ]

    engine = SimilarityEngine()

    results = engine.correlate(signals)

    assert len(results) == 1

    result = results[0]

    assert result.source == "example.com"
    assert result.target == "api.example.com"

    assert {
        signal.similarity_type
        for signal in result.signals
    } == {
        "SHARED_IP",
        "SHARED_CERTIFICATE",
    }


def test_similarity_engine_keeps_different_pairs_separate():
    signals = [
        SimilaritySignal(
            source="example.com",
            target="api.example.com",
            similarity_type="SHARED_IP",
            evidence="Shared IP address(es): 192.0.2.10",
        ),
        SimilaritySignal(
            source="example.com",
            target="cdn.example.net",
            similarity_type="SHARED_CERTIFICATE",
            evidence="Shared certificate(s): cert-001",
        ),
    ]

    engine = SimilarityEngine()

    results = engine.correlate(signals)

    assert len(results) == 2

    pairs = {
        (result.source, result.target)
        for result in results
    }

    assert pairs == {
        ("example.com", "api.example.com"),
        ("example.com", "cdn.example.net"),
    }


def test_similarity_engine_correlates_multiple_signals_for_same_pair():
    signals = [
        SimilaritySignal(
            source="example.com",
            target="api.example.com",
            similarity_type="SHARED_IP",
            evidence="Shared IP address(es): 192.0.2.10",
        ),
        SimilaritySignal(
            source="example.com",
            target="api.example.com",
            similarity_type="SHARED_CERTIFICATE",
            evidence="Shared certificate(s): cert-001",
        ),
        SimilaritySignal(
            source="example.com",
            target="api.example.com",
            similarity_type="SHARED_NAMESERVER",
            evidence="Shared nameserver: ns1.example.net",
        ),
    ]

    engine = SimilarityEngine()

    results = engine.correlate(signals)

    assert len(results) == 1

    result = results[0]

    assert len(result.signals) == 3