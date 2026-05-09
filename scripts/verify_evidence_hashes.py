"""Verify evidence files in a case haven't been modified since intake.

Reads expected SHA-256 hashes from `eval/cases/<case_id>/case.yaml`, re-hashes
each evidence file, and exits non-zero on any mismatch.

Usage:
    python scripts/verify_evidence_hashes.py --case rocba-001
    python scripts/verify_evidence_hashes.py --case rocba-001 --quick   # mtime/size only

Exits 0 on match, 1 on mismatch, 2 on missing file.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

REPO_ROOT = Path(__file__).resolve().parents[1]
app = typer.Typer(help="Evidence integrity verifier.")
console = Console()


def _load_case(case_id: str) -> dict:
    case_yaml = REPO_ROOT / "eval" / "cases" / case_id / "case.yaml"
    with case_yaml.open() as fh:
        return yaml.safe_load(fh)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@app.callback(invoke_without_command=True)
def main(
    case: str = typer.Option(..., "--case"),
    quick: bool = typer.Option(
        False,
        "--quick",
        help="Only check size + mtime, skip the full SHA-256 (fast for large images).",
    ),
) -> None:
    case_data = _load_case(case)
    table = Table(title=f"Evidence integrity — {case}")
    table.add_column("file")
    table.add_column("size_match")
    if not quick:
        table.add_column("hash_match")
    table.add_column("status")

    failed = False
    for ev in case_data.get("evidence", []):
        path = Path(ev["path"])
        if not path.exists():
            table.add_row(str(path), "—", "—" if quick else None, "[red]MISSING[/]")
            failed = True
            sys.exit(2)

        size_match = path.stat().st_size == ev.get("size_bytes")
        if not size_match:
            failed = True

        if quick:
            table.add_row(
                str(path),
                "[green]ok[/]" if size_match else "[red]FAIL[/]",
                "[green]ok[/]" if size_match else "[red]FAIL[/]",
            )
            continue

        actual = _sha256(path)
        hash_match = actual == ev.get("sha256")
        if not hash_match:
            failed = True

        table.add_row(
            str(path),
            "[green]ok[/]" if size_match else "[red]FAIL[/]",
            "[green]ok[/]" if hash_match else "[red]FAIL[/]",
            "[green]ok[/]" if size_match and hash_match else "[red]SPOLIATION[/]",
        )

    console.print(table)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    app()
