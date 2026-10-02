from pathlib import Path

import app.cli
from app.cli import (
    build_parser,
    print_certificate_intelligence,
    print_certificates,
    print_findings,
)
from app.models.certificate import Certificate
from app.models.finding import Finding
from app.models.infrastructure import Infrastructure

def _build_infrastructure():
    infrastructure = Infrastructure(
        target="example.com"
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="1",
            common_name="example.com",
            classification="VALID_DOMAIN",
        )
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="2",
            common_name="www.example.com",
            classification="VALID_DOMAIN",
        )
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="3",
            common_name="*.example.com",
            classification="WILDCARD",
        )
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="4",
            common_name="www.example.org",
            classification="EXTERNAL_DOMAIN",
        )
    )

    infrastructure.add_certificate(
        Certificate(
            certificate_id="5",
            common_name=(
                "as207960 test intermediate - example.com"
            ),
            classification="NON_DOMAIN",
        )
    )

    return infrastructure


def test_print_certificate_intelligence(
    capsys,
):
    infrastructure = _build_infrastructure()

    print_certificate_intelligence(
        infrastructure
    )

    output = capsys.readouterr().out

    assert "[CERTIFICATE INTELLIGENCE]" in output

    assert "VALID DOMAIN" in output
    assert "WILDCARD" in output
    assert "EXTERNAL DOMAIN" in output
    assert "NON-DOMAIN" in output

    assert "    2" in output
    assert "    1" in output


def test_print_certificates_groups_by_classification(
    capsys,
):
    infrastructure = _build_infrastructure()

    print_certificates(
        infrastructure
    )

    output = capsys.readouterr().out

    assert "[CERTIFICATES]" in output

    assert "[VALID DOMAIN]" in output
    assert "[WILDCARD]" in output
    assert "[EXTERNAL DOMAIN]" in output
    assert "[NON-DOMAIN]" in output

    assert "1 | example.com" in output
    assert "2 | www.example.com" in output
    assert "3 | *.example.com" in output
    assert "4 | www.example.org" in output
    assert (
        "5 | as207960 test intermediate - example.com"
        in output
    )


def test_certificate_intelligence_does_not_print_without_certificates(
    capsys,
):
    infrastructure = Infrastructure(
        target="example.com"
    )

    print_certificate_intelligence(
        infrastructure
    )

    output = capsys.readouterr().out

    assert output == ""


def test_print_certificates_does_not_print_without_certificates(
    capsys,
):
    infrastructure = Infrastructure(
        target="example.com"
    )

    print_certificates(
        infrastructure
    )

    output = capsys.readouterr().out

    assert output == ""


def test_print_findings(
    capsys,
):
    infrastructure = Infrastructure(
        target="example.com"
    )

    infrastructure.add_finding(
        Finding(
            rule_id="CERT-WILD-001",
            severity="LOW",
            title="Wildcard certificate detected",
            description=(
                "The certificate uses a wildcard name "
                "covering multiple hosts within the "
                "target namespace."
            ),
            evidence=(
                "Certificate 12345 | *.example.com"
            ),
            confidence="HIGH",
        )
    )

    print_findings(
        infrastructure
    )

    output = capsys.readouterr().out

    assert "[RISK FINDINGS]" in output
    assert "[LOW] Wildcard certificate detected" in output
    assert "Rule: CERT-WILD-001" in output
    assert "Confidence: HIGH" in output
    assert (
        "The certificate uses a wildcard name"
        in output
    )
    assert (
        "Certificate 12345 | *.example.com"
        in output
    )


def test_print_findings_prints_multiple_findings(
    capsys,
):
    infrastructure = Infrastructure(
        target="example.com"
    )

    infrastructure.add_finding(
        Finding(
            rule_id="CERT-WILD-001",
            severity="LOW",
            title="Wildcard certificate detected",
            description="Wildcard certificate observed.",
            evidence=(
                "Certificate 12345 | *.example.com"
            ),
            confidence="HIGH",
        )
    )

    infrastructure.add_finding(
        Finding(
            rule_id="CERT-EXT-001",
            severity="MEDIUM",
            title="External certificate domain detected",
            description=(
                "An external domain was observed."
            ),
            evidence=(
                "Certificate 67890 | www.example.org"
            ),
            confidence="MEDIUM",
        )
    )

    infrastructure.add_finding(
        Finding(
            rule_id="DOMAIN-ENUM-001",
            severity="INFO",
            title="Multiple domains discovered",
            description=(
                "Multiple domain names were discovered."
            ),
            evidence=(
                "Target: example.com | "
                "Domains discovered: 7"
            ),
            confidence="HIGH",
        )
    )

    print_findings(
        infrastructure
    )

    output = capsys.readouterr().out

    assert "[RISK FINDINGS]" in output

    assert (
        "[LOW] Wildcard certificate detected"
        in output
    )

    assert (
        "[MEDIUM] External certificate domain detected"
        in output
    )

    assert (
        "[INFO] Multiple domains discovered"
        in output
    )

    assert "CERT-WILD-001" in output
    assert "CERT-EXT-001" in output
    assert "DOMAIN-ENUM-001" in output


def test_print_findings_does_not_print_without_findings(
    capsys,
):
    infrastructure = Infrastructure(
        target="example.com"
    )

    print_findings(
        infrastructure
    )

    output = capsys.readouterr().out

    assert output == ""

def test_build_parser_accepts_save_and_json():
    parser = build_parser()

    args = parser.parse_args(
        [
            "example.com",
            "--save",
            "--json",
        ]
    )

    assert args.target == "example.com"
    assert args.save is True
    assert args.json is True

def test_main_saves_json(
    monkeypatch,
    tmp_path: Path,
):
    infrastructure = Infrastructure(
        target="example.com"
    )

    monkeypatch.setattr(
        app.cli,
        "investigate",
        lambda target: infrastructure,
    )

    monkeypatch.setattr(
        app.cli,
        "OUTPUT_ROOT",
        tmp_path,
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "digital-footprint-intelligence",
            "example.com",
            "--save",
            "--json",
        ],
    )

    exit_code = app.cli.main()

    assert exit_code == 0

    output_files = list(
        tmp_path.rglob("report.json")
    )

    assert len(output_files) == 1

    assert output_files[0].read_text(
        encoding="utf-8"
    )