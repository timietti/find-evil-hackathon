"""End-to-end tests for the disk-side wrappers against real STARK-APT-001
evidence. Skipped if the evidence file or the underlying tool is missing."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from mcp_server.audit import AuditLogger
from mcp_server.tools.disk import (
    ewf_info,
    tsk_fls_list,
    tsk_fs_stat,
    tsk_partition_table,
)

# Use the smallest STARK-APT image (XP, 7 GB) for E2E speed.
TDUNGAN_E01 = Path(
    "/cases/find-evil-test2/xp-tdungan-c-drive/xp-tdungan-c-drive.E01"
)
HAS_FLS = shutil.which("fls") is not None
HAS_EWFINFO = shutil.which("ewfinfo") is not None
HAS_E01 = TDUNGAN_E01.exists()

REQUIRES_E2E = pytest.mark.skipif(
    not (HAS_FLS and HAS_EWFINFO and HAS_E01),
    reason="needs sleuthkit + ewftools on PATH and STARK-APT-001 evidence on disk",
)


def _make_audit(tmp: Path) -> AuditLogger:
    return AuditLogger(
        exec_log_path=tmp / "exec_log.jsonl",
        raw_output_dir=tmp / "raw",
    )


def _audit_row(tmp: Path) -> dict:
    rows = [
        json.loads(l) for l in (tmp / "exec_log.jsonl").read_text().splitlines()
        if l.strip()
    ]
    return rows[0]


# ---- ewf_info --------------------------------------------------------------


@REQUIRES_E2E
def test_ewf_info_tdungan(tmp_path: Path) -> None:
    audit = _make_audit(tmp_path)
    out = ewf_info(str(TDUNGAN_E01), audit=audit)
    assert out["exec_id"]
    assert "Stark Research Labs" in (out.get("case_number") or "")
    assert (out.get("evidence_number") or "").startswith("tdungan")
    assert out["sector_count"] == 31473601
    assert out["bytes_per_sector"] == 512
    row = _audit_row(tmp_path)
    assert row["tool"] == "ewf_info"


# ---- mmls (logical drive — expected zero partitions) -----------------------


@REQUIRES_E2E
def test_tsk_partition_table_returns_zero_for_logical_drive(tmp_path: Path) -> None:
    """The XP image is a logical-drive E01 — mmls returns 0 partitions."""
    audit = _make_audit(tmp_path)
    out = tsk_partition_table(str(TDUNGAN_E01), audit=audit)
    assert out["count"] == 0
    assert out["partitions"] == []


# ---- fsstat ----------------------------------------------------------------


@REQUIRES_E2E
def test_tsk_fs_stat_ntfs(tmp_path: Path) -> None:
    audit = _make_audit(tmp_path)
    out = tsk_fs_stat(str(TDUNGAN_E01), offset=None, audit=audit)
    assert out["fs_type"] == "NTFS"
    # tdungan's volume should have sector + cluster sizes set
    assert out["sector_size"] == 512
    # Cluster size for NTFS is typically 4096
    assert out["cluster_size"] in (4096, 2048, 8192)


# ---- fls (recursive listing, truncation, by_extension) ---------------------


@REQUIRES_E2E
def test_tsk_fls_list_tdungan_finds_known_paths(tmp_path: Path) -> None:
    """fls on tdungan must surface real-world paths (full row list lives in
    raw_output_path; truncated to 50 in the response)."""
    audit = _make_audit(tmp_path)
    out = tsk_fls_list(str(TDUNGAN_E01), offset=None, audit=audit, timeout_s=600)

    # XP image has tens of thousands of entries
    assert out["count"] >= 1000
    # Truncated to 50 in the response, total preserved separately
    assert len(out["files"]) <= 50
    assert out.get("files_truncated") is True
    assert out["files_total"] == out["count"]

    # by_extension and by_top_dir should be populated
    assert isinstance(out["by_extension"], dict)
    assert isinstance(out["by_top_dir"], dict)
    # Documents and Settings is the canonical XP user-tree top dir
    top_dir_keys_lower = " ".join(out["by_top_dir"].keys()).lower()
    assert "documents" in top_dir_keys_lower or "windows" in top_dir_keys_lower

    row = _audit_row(tmp_path)
    assert row["tool"] == "tsk_fls_list"
    assert "files" not in row["parsed_summary"]  # bulky list excluded from audit summary


@REQUIRES_E2E
def test_tsk_fls_list_query_rows_finds_specific_file(tmp_path: Path) -> None:
    """fls + query_rows: drill into the full row list to find a known path."""
    from mcp_server.tools.memory import query_rows

    audit = _make_audit(tmp_path)
    out = tsk_fls_list(str(TDUNGAN_E01), offset=None, audit=audit, timeout_s=600)
    eid = out["exec_id"]

    # Drill for "ntuser.dat" — every Windows user has this; should be present.
    result = query_rows(
        {
            "exec_id": eid,
            "filter_field": "path",
            "filter_value": "ntuser.dat",
            "limit": 20,
        },
        audit=audit,
    )
    assert result["matched_rows"] >= 1
    for r in result["rows"]:
        assert "ntuser" in r["path"].lower()
