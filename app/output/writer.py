from __future__ import annotations

from datetime import datetime
from pathlib import Path
import csv
from pathlib import Path

def create_investigation_directory(
    output_root: Path,
    target: str,
) -> Path:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    investigation_dir = (
        output_root
        / target.strip().lower().rstrip(".")
        / timestamp
    )

    investigation_dir.mkdir(parents=True, exist_ok=True)

    return investigation_dir

def write_output(
    output_dir: Path,
    filename: str,
    content: str,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    file_path = output_dir / filename
    file_path.write_text(content, encoding="utf-8")

    return file_path

def write_csv_tables(
    output_dir: Path,
    tables: dict[str, list[dict[str, object]]],
    fieldnames: dict[str, list[str]],
) -> list[Path]:
    """
    Write multiple CSV tables to an output directory.
    """

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_files: list[Path] = []

    for table_name, rows in tables.items():
        file_path = output_dir / f"{table_name}.csv"

        columns = fieldnames.get(
            table_name,
            list(rows[0].keys()) if rows else [],
        )

        with file_path.open(
            "w",
            encoding="utf-8",
            newline="",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=columns,
            )

            writer.writeheader()

            if rows:
                writer.writerows(rows)

        output_files.append(file_path)

    return output_files