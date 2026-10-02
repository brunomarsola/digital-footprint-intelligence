from app.analysis.risk import analyze_risk
from app.models.collection import CollectionStatus
from app.models.domain import Domain
from app.models.infrastructure import Infrastructure
from app.models.ip import IPAddress


def test_risk_detects_internet_facing_infrastructure():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_ip(
        IPAddress(
            address="192.0.2.10",
        )
    )

    signals = analyze_risk(infrastructure)

    assert len(signals) == 1

    assert (
        signals[0].title
        == "Internet-facing infrastructure observed"
    )

    assert signals[0].severity == "info"

    assert signals[0].evidence == [
        "192.0.2.10",
    ]


def test_risk_detects_expanded_domain_footprint():
    infrastructure = Infrastructure(
        target="example.com",
    )

    for name in [
        "example.com",
        "api.example.com",
        "mail.example.com",
        "vpn.example.com",
        "dev.example.com",
    ]:
        infrastructure.add_domain(
            Domain(name=name)
        )

    signals = analyze_risk(infrastructure)

    expanded_surface = next(
        signal
        for signal in signals
        if signal.title == "Expanded domain footprint"
    )

    assert expanded_surface.severity == "medium"

    assert len(expanded_surface.evidence) == 5


def test_risk_detects_collection_failure():
    infrastructure = Infrastructure(
        target="example.com",
    )

    infrastructure.add_collection_status(
        CollectionStatus(
            source="crt.sh",
            status="error",
            attempts=3,
            error="HTTP 502",
        )
    )

    signals = analyze_risk(infrastructure)

    assert len(signals) == 1

    assert signals[0].title == "Incomplete collection"

    assert signals[0].severity == "low"

    assert signals[0].evidence == [
        "crt.sh",
    ]


def test_no_risk_signals_for_empty_infrastructure():
    infrastructure = Infrastructure(
        target="example.com",
    )

    signals = analyze_risk(infrastructure)

    assert signals == []