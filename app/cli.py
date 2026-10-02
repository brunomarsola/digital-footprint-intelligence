"""
Command-line interface for Digital Footprint Intelligence.

Provides a simple interface for running passive digital
footprint investigations from the terminal.
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

from app.exporters.csv import CSV_FIELDS, export_csv
from app.exporters.json import export_json
from app.exporters.markdown import export_markdown
from app.exporters.txt import export_txt
from app.exporters.csv import (
    CSV_FIELDS,
    export_csv,
)
from app.models.certificate import CertificateClassification
from app.output.writer import (
    create_investigation_directory,
    write_csv_tables,
    write_output,
)
from app.services.investigation import investigate

OUTPUT_ROOT = Path("output")


CERTIFICATE_CLASSIFICATION_ORDER: tuple[
    CertificateClassification,
    ...
] = (
    "VALID_DOMAIN",
    "WILDCARD",
    "EXTERNAL_DOMAIN",
    "NON_DOMAIN",
)


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line argument parser.
    """

    parser = argparse.ArgumentParser(
        prog="digital-footprint-intelligence",
        description=(
            "Passive Digital Footprint Intelligence "
            "collector and analyzer."
        ),
    )
    parser.add_argument(
    "--save",
    action="store_true",
    help="Save investigation results to the output directory.",
    )

    parser.add_argument(
        "--txt",
        action="store_true",
        help="Export the investigation as TXT.",
    )

    parser.add_argument(
        "--md",
        action="store_true",
        help="Export the investigation as Markdown.",
    )

    parser.add_argument(
        "--csv",
        action="store_true",
        help="Export the investigation as CSV.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Export the investigation as JSON.",
    )

    parser.add_argument(
        "target",
        help="Domain to investigate.",
    )

    return parser


def print_collection_status(
    infrastructure,
) -> None:
    """
    Print the status of each passive collection source.

    Collection status allows the operator to distinguish
    between an empty result and a failed collection.
    """

    if not infrastructure.collection_status:
        return

    print("\n[COLLECTION STATUS]")
    print("-" * 60)

    for collection in infrastructure.collection_status:
        source = collection.source
        status = collection.status.upper()
        attempts = collection.attempts

        print(
            f"{source:<12}"
            f"{status:<12}"
            f"{attempts} attempt(s)"
        )

        if collection.error:
            print(
                f"  Error: {collection.error}"
            )

    print("-" * 60)


def _get_certificate_classification(
    certificate,
) -> CertificateClassification:
    """
    Return a certificate classification.

    Certificates collected before classification
    support was introduced may not have a classification yet.
    Those certificates are treated as NON_DOMAIN for
    reporting purposes.
    """

    classification = certificate.classification

    if classification in CERTIFICATE_CLASSIFICATION_ORDER:
        return classification

    return "NON_DOMAIN"


def print_certificate_intelligence(
    infrastructure,
) -> None:
    """
    Print a summary of certificate classifications.

    The summary provides an analytical view of the
    certificate inventory instead of presenting only
    raw certificate records.
    """

    if not infrastructure.certificates:
        return

    classifications = Counter(
        _get_certificate_classification(
            certificate
        )
        for certificate in infrastructure.certificates
    )

    print("\n[CERTIFICATE INTELLIGENCE]")
    print("-" * 60)

    labels = {
        "VALID_DOMAIN": "VALID DOMAIN",
        "WILDCARD": "WILDCARD",
        "EXTERNAL_DOMAIN": "EXTERNAL DOMAIN",
        "NON_DOMAIN": "NON-DOMAIN",
    }

    for classification in CERTIFICATE_CLASSIFICATION_ORDER:
        label = labels[classification]
        count = classifications[classification]

        print(
            f"{label:<20}"
            f"{count:>5}"
        )

    print("-" * 60)


def print_certificates(
    infrastructure,
) -> None:
    """
    Print certificates grouped by intelligence classification.
    """

    if not infrastructure.certificates:
        return

    grouped: dict[
        CertificateClassification,
        list,
    ] = {
        classification: []
        for classification
        in CERTIFICATE_CLASSIFICATION_ORDER
    }

    for certificate in infrastructure.certificates:
        classification = _get_certificate_classification(
            certificate
        )

        grouped[classification].append(
            certificate
        )

    labels = {
        "VALID_DOMAIN": "VALID DOMAIN",
        "WILDCARD": "WILDCARD",
        "EXTERNAL_DOMAIN": "EXTERNAL DOMAIN",
        "NON_DOMAIN": "NON-DOMAIN",
    }

    print("\n[CERTIFICATES]")

    for classification in CERTIFICATE_CLASSIFICATION_ORDER:
        certificates = grouped[classification]

        if not certificates:
            continue

        print(
            f"\n[{labels[classification]}]"
        )

        for certificate in certificates:
            certificate_id = (
                certificate.certificate_id
                or "unknown"
            )

            common_name = (
                certificate.common_name
                or "unknown"
            )

            print(
                f"  - {certificate_id}"
                f" | {common_name}"
            )


def print_findings(
    infrastructure,
) -> None:
    """
    Print explainable analytical findings.
    """

    if not infrastructure.findings:
        return

    print("\n[RISK FINDINGS]")
    print("-" * 60)

    for finding in infrastructure.findings:
        print(
            f"[{finding.severity}] "
            f"{finding.title}"
        )

        print(
            f"  Rule: {finding.rule_id}"
        )

        print(
            f"  Confidence: "
            f"{finding.confidence}"
        )

        print(
            f"  Description: "
            f"{finding.description}"
        )

        print(
            f"  Evidence: "
            f"{finding.evidence}"
        )

        print()

    print("-" * 60)


def print_relationships(
    infrastructure,
) -> None:
    """
    Print analytical relationships discovered
    during the investigation.
    """

    if not infrastructure.relationships:
        return

    print("\n[RELATIONSHIPS]")
    print("-" * 60)

    for relationship in infrastructure.relationships:
        print(
            f"{relationship.source}"
        )

        print(
            f"  - {relationship.relation}"
            f" -> {relationship.target}"
        )

        print(
            f"    Confidence: "
            f"{relationship.confidence}"
        )

        print(
            f"    Evidence: "
            f"{relationship.evidence}"
        )

        print()

    print("-" * 60)


def print_report(
    infrastructure,
) -> None:
    """
    Print a human-readable investigation summary.
    """

    print()
    print("=" * 60)
    print(
        "       DIGITAL FOOTPRINT INTELLIGENCE"
    )
    print("=" * 60)

    print(
        f"\nTarget: {infrastructure.target}"
    )

    print("\n[INFRASTRUCTURE]")
    print("-" * 60)

    print(
        f"Domains discovered:     "
        f"{infrastructure.domain_count}"
    )

    print(
        f"IP addresses:           "
        f"{infrastructure.ip_count}"
    )

    print(
        f"Certificates:           "
        f"{infrastructure.certificate_count}"
    )

    print(
        f"Relationships:          "
        f"{len(infrastructure.relationships)}"
    )

    print_collection_status(
        infrastructure
    )

    print_findings(
        infrastructure
    )

    if infrastructure.domains:
        print("\n[DOMAINS]")

        for domain in infrastructure.domains:
            print(
                f"  - {domain.name}"
            )

    if infrastructure.ip_addresses:
        print("\n[IP ADDRESSES]")

        for ip_address in infrastructure.ip_addresses:
            print(
                f"  - {ip_address.address}"
            )

    print_certificate_intelligence(
        infrastructure
    )

    print_certificates(
        infrastructure
    )

    print_relationships(
        infrastructure
    )

    print(
        "\n" + "=" * 60
    )

    print(
        "Investigation completed."
    )

    print(
        "=" * 60
    )

    print()

def save_text_report(
    infrastructure,
    exporter,
    filename: str,
) -> Path:
    """
    Save a text-based investigation report.
    """

    output_dir = create_investigation_directory(
        OUTPUT_ROOT,
        infrastructure.target,
    )

    content = exporter(
        infrastructure
    )

    return write_output(
        output_dir=output_dir,
        filename=filename,
        content=content,
    )

def main() -> int:
    """
    Execute the command-line application.
    """

    parser = build_parser()
    args = parser.parse_args()

    try:
        infrastructure = investigate(
            args.target
        )

    except KeyboardInterrupt:
        print(
            "\nInvestigation interrupted by user.",
            file=sys.stderr,
        )

        return 130

    except Exception as exc:
        print(
            f"\nInvestigation failed: {exc}",
            file=sys.stderr,
        )

        return 1

    print_report(
        infrastructure
    )

    if args.save:
        if args.json:
            output_file = save_text_report(
                infrastructure,
                export_json,
                "report.json",
            )

            print(
                f"\nJSON report saved to: "
                f"{output_file}"
            )

        if args.txt:
            output_file = save_text_report(
                infrastructure,
                export_txt,
                "report.txt",
            )

            print(
                f"\nTXT report saved to: "
                f"{output_file}"
            )
        if args.md:
            output_file = save_text_report(
                infrastructure,
                export_markdown,
                "report.md",
            )

            print(
                f"\nMarkdown report saved to: "
                f"{output_file}"
            )
        if args.csv:
            output_dir = create_investigation_directory(
                OUTPUT_ROOT,
                infrastructure.target,
            )

            tables = export_csv(
                infrastructure
            )

            output_files = write_csv_tables(
                output_dir,
                tables,
                CSV_FIELDS,
            )

            print(
                "\nCSV reports saved:"
            )

            for output_file in output_files:
                print(
                    f"  - {output_file}"
                )

    return 0

if __name__ == "__main__":
    raise SystemExit(
        main()
    )