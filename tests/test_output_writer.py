from pathlib import Path

from app.output.writer import (
    create_investigation_directory,
    write_csv_tables,
    write_output,
)


def test_write_csv_tables_writes_headers_for_empty_tables(
    tmp_path,
):
    tables = {
        "certificates": [],
    }

    fieldnames = {
        "certificates": [
            "certificate_id",
            "issuer_name",
            "common_name",
            "serial_number",
            "not_before",
            "not_after",
            "classification",
            "domains",
        ],
    }

    output_files = write_csv_tables(
        tmp_path,
        tables,
        fieldnames,
    )

    assert len(output_files) == 1

    content = output_files[0].read_text(
        encoding="utf-8"
    )

    assert (
        content
        == (
            "certificate_id,issuer_name,common_name,"
            "serial_number,not_before,not_after,"
            "classification,domains\n"
        )
    )


def test_write_output_creates_directory_and_file(
    tmp_path: Path,
):
    output_dir = (
        tmp_path
        / "example.com"
        / "2026-10-01_221500"
    )

    file_path = write_output(
        output_dir=output_dir,
        filename="report.txt",
        content="Digital Footprint Intelligence\n",
    )

    assert file_path == output_dir / "report.txt"
    assert file_path.exists()
    assert file_path.read_text(
        encoding="utf-8"
    ) == (
        "Digital Footprint Intelligence\n"
    )


def test_create_investigation_directory(
    tmp_path: Path,
):
    investigation_dir = create_investigation_directory(
        output_root=tmp_path,
        target="Example.COM",
    )

    assert investigation_dir.parent == (
        tmp_path / "example.com"
    )
    assert investigation_dir.exists()
    assert investigation_dir.is_dir()