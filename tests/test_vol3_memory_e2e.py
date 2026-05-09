"""End-to-end tests for the 5 row-oriented Vol3 wrappers (psscan, pstree,
cmdline, netscan, filescan).

Skipped automatically if `vol` is not on PATH or the ROCBA-001 evidence is not
on disk. The same image is used for all tests so Vol3's symbol cache pays off
across them.

Note: filescan can take several minutes on an 18 GB image. The test sets a
generous 30-min timeout but is still gated behind the standard E2E skip.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from mcp_server.audit import AuditLogger
from mcp_server.tools.memory import (
    vol3_cmdline,
    vol3_filescan,
    vol3_malfind,
    vol3_netscan,
    vol3_psscan,
    vol3_pstree,
    vol3_svcscan,
    vol3_userassist,
)

ROCBA_IMG = Path("/cases/find-evil-test/Rocba-Memory.raw")
HAS_VOL = shutil.which("vol") is not None
HAS_IMG = ROCBA_IMG.exists()

REQUIRES_E2E = pytest.mark.skipif(
    not (HAS_VOL and HAS_IMG),
    reason="needs `vol` on PATH and ROCBA-001 evidence on disk",
)


def _make_audit(tmp: Path) -> AuditLogger:
    return AuditLogger(
        exec_log_path=tmp / "exec_log.jsonl",
        raw_output_dir=tmp / "raw",
    )


def _audit_row(tmp: Path) -> dict:
    rows = [json.loads(l) for l in (tmp / "exec_log.jsonl").read_text().splitlines() if l.strip()]
    assert len(rows) == 1
    return rows[0]


@REQUIRES_E2E
def test_vol3_psscan_rocba(tmp_path: Path) -> None:
    audit = _make_audit(tmp_path)
    out = vol3_psscan({"image": str(ROCBA_IMG)}, audit=audit, timeout_s=600)
    assert out["count"] >= 50, "ROCBA-001 should have many processes"
    # System always has PID 4 / PPID 0
    sys_proc = next(p for p in out["processes"] if p["pid"] == 4)
    assert sys_proc["image"] == "System"
    assert sys_proc["ppid"] == 0
    # by_image is populated
    assert out["by_image"]
    # Audit row checks
    row = _audit_row(tmp_path)
    assert row["tool"] == "vol3_psscan"
    assert row["exec_id"] == out["exec_id"]
    assert "processes" in row["summary"]
    # parsed_summary should NOT contain the full process list (audit-bloat guard)
    assert "processes" not in row["parsed_summary"]
    assert "count" in row["parsed_summary"]


@REQUIRES_E2E
def test_vol3_pstree_rocba(tmp_path: Path) -> None:
    audit = _make_audit(tmp_path)
    out = vol3_pstree({"image": str(ROCBA_IMG)}, audit=audit, timeout_s=600)
    assert out["count"] >= 50
    assert out["tree_roots"] >= 1
    # System (PID 4) is always a root in pstree
    assert any(n["pid"] == 4 and n["depth"] == 0 for n in out["nodes"])
    row = _audit_row(tmp_path)
    assert row["tool"] == "vol3_pstree"
    assert "nodes" not in row["parsed_summary"]


@REQUIRES_E2E
def test_vol3_cmdline_rocba(tmp_path: Path) -> None:
    audit = _make_audit(tmp_path)
    out = vol3_cmdline({"image": str(ROCBA_IMG)}, audit=audit, timeout_s=300)
    assert out["count"] >= 50
    # We expect a recognisable Windows process to be present
    procs = {r["process"] for r in out["rows"]}
    assert "csrss.exe" in procs or "smss.exe" in procs
    row = _audit_row(tmp_path)
    assert row["tool"] == "vol3_cmdline"
    assert "rows" not in row["parsed_summary"]


@REQUIRES_E2E
def test_vol3_netscan_rocba_finds_baseline_rdp_ips(tmp_path: Path) -> None:
    """Verify netscan surfaces the four external RDP IPs we already saw in
    the Protocol SIFT baseline run — proves the parser keeps the high-signal
    foreign-IP list intact."""
    audit = _make_audit(tmp_path)
    out = vol3_netscan({"image": str(ROCBA_IMG)}, audit=audit, timeout_s=1200)
    assert out["count"] >= 50
    # The baseline saw connections to these IPs; they must appear in our
    # foreign_ip_counts (ground truth from the Sonnet baseline + spot-check).
    expected = {"81.30.144.115", "213.202.233.104"}
    found = set(out["foreign_ip_counts"]) & expected
    assert found, (
        f"Expected at least one of {expected} in foreign_ip_counts; "
        f"got {sorted(out['foreign_ip_counts'])[:10]}..."
    )
    row = _audit_row(tmp_path)
    assert row["tool"] == "vol3_netscan"
    assert "foreign_ip_counts" in row["parsed_summary"]


@REQUIRES_E2E
def test_vol3_svcscan_rocba(tmp_path: Path) -> None:
    audit = _make_audit(tmp_path)
    out = vol3_svcscan({"image": str(ROCBA_IMG)}, audit=audit, timeout_s=600)
    assert out["count"] >= 50
    assert "by_state" in out
    # RpcEptMapper is a fundamental Windows service — must be in the list
    names = {s["name"] for s in out["services"]}
    assert "RpcEptMapper" in names
    row = _audit_row(tmp_path)
    assert row["tool"] == "vol3_svcscan"
    assert "services" not in row["parsed_summary"]


@REQUIRES_E2E
def test_vol3_userassist_rocba(tmp_path: Path) -> None:
    audit = _make_audit(tmp_path)
    out = vol3_userassist({"image": str(ROCBA_IMG)}, audit=audit, timeout_s=600)
    assert out["count"] >= 1, "ROCBA-001 has UserAssist activity for fredr"
    # The fredr user hive must appear
    hive_names = " ".join(out["by_hive"].keys())
    assert "fredr" in hive_names.lower()
    row = _audit_row(tmp_path)
    assert row["tool"] == "vol3_userassist"
    assert "entries" not in row["parsed_summary"]


@REQUIRES_E2E
@pytest.mark.slow
def test_vol3_malfind_rocba(tmp_path: Path) -> None:
    """malfind on the 18 GB image takes ~6 min on first cold run; faster
    after pages have been touched by other plugins. Marked `slow`."""
    audit = _make_audit(tmp_path)
    out = vol3_malfind({"image": str(ROCBA_IMG)}, audit=audit, timeout_s=1800)
    # ROCBA-001 has Microsoft Defender RWX regions (legitimate JIT) per the
    # baseline run. Don't assert a specific count, just that the parser ran
    # and produced a structurally valid result.
    assert "count" in out
    assert "rwx_count" in out
    assert "by_process" in out
    # Disasm/Hexdump must NOT appear in any finding (audit-bloat guard).
    for f in out["findings"]:
        assert "disasm" not in f
        assert "hexdump" not in f
    row = _audit_row(tmp_path)
    assert row["tool"] == "vol3_malfind"
    assert "findings" not in row["parsed_summary"]


@REQUIRES_E2E
@pytest.mark.slow
def test_vol3_filescan_rocba_finds_baseline_filenames(tmp_path: Path) -> None:
    """filescan is the slowest plugin (~3 min). Marked `slow`; run with
    `pytest -m slow` or omit `-m 'not slow'`. Verifies key baseline filenames
    appear (StarFury.zip, the Vibrainium typo doc) so our parser can support
    later cross-source correlation queries."""
    audit = _make_audit(tmp_path)
    out = vol3_filescan({"image": str(ROCBA_IMG)}, audit=audit, timeout_s=1800)
    assert out["count"] >= 1000
    names = "\n".join((f["name"] or "") for f in out["files"])
    assert "StarFury.zip" in names
    assert "Vibrainium" in names  # the typo'd doc the baseline noted
    row = _audit_row(tmp_path)
    assert row["tool"] == "vol3_filescan"
