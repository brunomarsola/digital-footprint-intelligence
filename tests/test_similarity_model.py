from app.models.similarity import SimilaritySignal
from app.models.similarity import (
    SimilarityResult,
    SimilaritySignal,
)

def test_similarity_signal_normalizes_values():
    signal = SimilaritySignal(
        source=" Example.COM ",
        target=" API.Example.COM ",
        similarity_type="shared_ip",
        evidence=" Shared IP: 192.0.2.10 ",
    )

    assert signal.source == "example.com"
    assert signal.target == "api.example.com"
    assert signal.similarity_type == "SHARED_IP"
    assert signal.evidence == "Shared IP: 192.0.2.10"


def test_similarity_signal_accepts_shared_certificate():
    signal = SimilaritySignal(
        source="example.com",
        target="api.example.com",
        similarity_type="SHARED_CERTIFICATE",
        evidence="Shared certificate(s): cert-001",
    )

    assert signal.similarity_type == "SHARED_CERTIFICATE"


def test_similarity_signal_accepts_subdomain_relation():
    signal = SimilaritySignal(
        source="api.example.com",
        target="example.com",
        similarity_type="SUBDOMAIN_RELATION",
        evidence="Domain discovered within target namespace",
    )

    assert signal.similarity_type == "SUBDOMAIN_RELATION"

def test_similarity_result_normalizes_values():
    signal = SimilaritySignal(
        source=" Example.COM ",
        target=" API.Example.COM ",
        similarity_type="SHARED_IP",
        evidence="Shared IP: 192.0.2.10",
    )

    result = SimilarityResult(
        source=" Example.COM ",
        target=" API.Example.COM ",
        signals=[signal],
    )

    assert result.source == "example.com"
    assert result.target == "api.example.com"
    assert result.signals == [signal]


def test_similarity_result_accepts_multiple_signals():
    signals = [
        SimilaritySignal(
            source="example.com",
            target="api.example.com",
            similarity_type="SHARED_IP",
            evidence="Shared IP: 192.0.2.10",
        ),
        SimilaritySignal(
            source="example.com",
            target="api.example.com",
            similarity_type="SHARED_CERTIFICATE",
            evidence="Shared certificate(s): cert-001",
        ),
    ]

    result = SimilarityResult(
        source="example.com",
        target="api.example.com",
        signals=signals,
    )

    assert len(result.signals) == 2

    assert {
        signal.similarity_type
        for signal in result.signals
    } == {
        "SHARED_IP",
        "SHARED_CERTIFICATE",
    }