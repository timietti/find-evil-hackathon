"""Tests for `mcp_server.tools.memory.vol3_image_info`.

Two layers:

1. Path validation tests — assert the function refuses paths outside the
   evidence allow-list (architectural trust boundary TB3 / TB4).
2. End-to-end test — runs the actual `vol` binary against the real ROCBA-001
   memory image. Skipped if the image is missing or `vol` is not on PATH.

The e2e test uses the genuine 18 GB memory image because the only honest way
to verify our subprocess wrapper, parser, and audit logger work together is to
run them against real Vol3 output. Skipped automatically in environments
without the evidence file (e.g. CI).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from mcp_server.audit import AuditLogger
from mcp_server.tools._common import PathValidationError, validate_evidence_path
from mcp_server.tools.memory import vol3_image_info

ROCBA_IMG = Path("/cases/find-evil-test/Rocba-Memory.raw")
HAS_VOL = shutil.which("vol") is not None
HAS_IMG = ROCBA_IMG.exists()

REQUIRES_E2E = pytest.mark.skipif(
    not (HAS_VOL and HAS_IMG),
    reason="needs `vol` on PATH and ROCBA-001 evidence on disk",
)


# ---- Path validation -------------------------------------------------------


def test_validate_evidence_path_accepts_under_cases(tmp_path: Path) -> None:
    """Files under /cases/ resolve cleanly."""
    if not Path("/cases").exists():
        pytest.skip("/cases not present")
    # Use an existing file we already hashed at intake.
    sidecar = Path("/cases/find-evil-test/CLAUDE.md")
    if not sidecar.exists():
        pytest.skip("intake fixture missing")
    resolved = validate_evidence_path(sidecar)
    assert resolved == sidecar.resolve()


def test_validate_evidence_path_rejects_outside_root() -> None:
    """A path outside the allow-list raises PathValidationError."""
    with pytest.raises(PathValidationError):
        validate_evidence_path("/etc/passwd")


def test_validate_evidence_path_rejects_traversal(tmp_path: Path) -> None:
    """`..` traversal must be caught after path resolution."""
    sneaky = "/cases/find-evil-test/../../etc/passwd"
    with pytest.raises(PathValidationError):
        validate_evidence_path(sneaky)


def test_validate_evidence_path_rejects_missing_when_required() -> None:
    with pytest.raises(PathValidationError):
        validate_evidence_path("/cases/this-does-not-exist.E01")


# ---- vol3_image_info E2E (real Vol3 + real evidence) -----------------------


@REQUIRES_E2E
def test_vol3_image_info_rocba_returns_expected_profile(tmp_path: Path) -> None:
    """End-to-end: real `vol` against real Rocba memory, parsed result correct."""
    audit = AuditLogger(
        exec_log_path=tmp_path / "exec_log.jsonl",
        raw_output_dir=tmp_path / "raw",
    )

    out = vol3_image_info({"image": str(ROCBA_IMG)}, audit=audit, timeout_s=300)

    assert out["os"] == "Windows 10/11"
    assert out["build"] == "19041"
    assert out["arch"] == "x64"
    assert out["cpus"] == 4
    assert out["system_time_utc"] == "2020-11-16T02:32:38Z"
    assert out["symbols_resolved"] is True
    # exec_id wired through audit
    assert "exec_id" in out
    assert out["exec_id"]

    # Audit log has exactly one row with the right tool name + summary
    rows = (tmp_path / "exec_log.jsonl").read_text().strip().splitlines()
    assert len(rows) == 1
    import json

    row = json.loads(rows[0])
    assert row["tool"] == "vol3_image_info"
    assert row["exec_id"] == out["exec_id"]
    assert row["exit_code"] == 0
    assert "Windows 10/11" in row["summary"]
    assert row["parsed_summary"]["build"] == "19041"


@REQUIRES_E2E
def test_vol3_image_info_rejects_path_outside_evidence_root(tmp_path: Path) -> None:
    audit = AuditLogger(
        exec_log_path=tmp_path / "exec_log.jsonl",
        raw_output_dir=tmp_path / "raw",
    )
    with pytest.raises(PathValidationError):
        vol3_image_info({"image": "/etc/passwd"}, audit=audit)
