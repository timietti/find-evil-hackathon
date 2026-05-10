"""End-to-end tests for the EZ Tools wrappers.

Each test sets up an audit log with a fake `tsk_icat_extract` row pointing
at a real already-extracted artifact file (committed under
`tests/fixtures/ez_tools_artifacts/` or extracted at test time from
STARK-APT-001 evidence), then calls the EZ Tools wrapper and checks
the parsed output.

The wrapper is the architectural-trust-boundary enforcement point: it
looks up the extract_exec_id, validates the row's tool name, and runs
the EZ tool DLL via dotnet. These tests prove the chain works end-to-end.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from mcp_server.audit import AuditLogger
from mcp_server.tools._common import ToolError
from mcp_server.tools.ez_tools import (
    ezt_evtx_parse,
    ezt_mft_parse,
    ezt_shimcache_parse,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

# These artifacts live at /tmp/sift-owl-ezt-sample/ from the dev session that
# extracted them during EZ Tools integration. Re-extracted on demand if absent.
TDUNGAN_E01 = Path("/cases/find-evil-test2/xp-tdungan-c-drive/xp-tdungan-c-drive.E01")
NFURY_E01 = Path("/cases/find-evil-test2/win7-64-nfury-c-drive/win7-64-nfury-c-drive.E01")

HAS_DOTNET = shutil.which("dotnet") is not None
HAS_DLLS = (
    Path("/opt/zimmermantools/MFTECmd.dll").exists()
    and Path("/opt/zimmermantools/AppCompatCacheParser.dll").exists()
    and Path("/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll").exists()
)
HAS_EVIDENCE = TDUNGAN_E01.exists() and NFURY_E01.exists()
HAS_ICAT = shutil.which("icat") is not None

REQUIRES_EZT_E2E = pytest.mark.skipif(
    not (HAS_DOTNET and HAS_DLLS and HAS_EVIDENCE and HAS_ICAT),
    reason="needs dotnet, EZ Tools DLLs, sleuthkit, and STARK-APT-001 evidence",
)


def _make_audit(tmp: Path) -> AuditLogger:
    return AuditLogger(
        exec_log_path=tmp / "audit" / "exec_log.jsonl",
        raw_output_dir=tmp / "audit" / "raw",
    )


def _record_extract(audit: AuditLogger, extracted_file: Path) -> str:
    """Record a fake tsk_icat_extract audit row that points at an already-
    extracted file. Returns the exec_id."""
    eid = audit.new_exec_id()
    extracts_dir = audit.raw_output_dir / "extracts"
    extracts_dir.mkdir(parents=True, exist_ok=True)
    target = extracts_dir / f"{eid}.bin"
    target.write_bytes(extracted_file.read_bytes())
    audit.record(
        exec_id=eid, agent="disk_agent", tool="tsk_icat_extract",
        args={"image": "/cases/x.E01", "inode": 0},
        raw_output_path=target,
        exit_code=0, wall_ms=10,
        summary=f"extracted {extracted_file.name}",
        parsed_summary={"size_bytes": target.stat().st_size, "inode": 0},
    )
    return eid


@pytest.fixture(scope="module")
def shared_extracts(tmp_path_factory) -> dict[str, Path]:
    """Extract $MFT, SYSTEM hive, and Security.evtx once per test module."""
    if not (HAS_ICAT and HAS_EVIDENCE):
        pytest.skip("needs sleuthkit + STARK-APT-001 evidence on disk")
    import subprocess

    work = tmp_path_factory.mktemp("ezt_e2e_extracts")

    # $MFT (tdungan, inode 0)
    mft = work / "tdungan.mft"
    subprocess.run(
        ["icat", "-i", "ewf", str(TDUNGAN_E01), "0"],
        stdout=mft.open("wb"), check=True, timeout=300,
    )
    # SYSTEM hive (tdungan, inode 2409)
    system = work / "tdungan.system.hve"
    subprocess.run(
        ["icat", "-i", "ewf", str(TDUNGAN_E01), "2409"],
        stdout=system.open("wb"), check=True, timeout=300,
    )
    # Security.evtx (nfury, inode 57679)
    evtx = work / "nfury.security.evtx"
    subprocess.run(
        ["icat", "-i", "ewf", str(NFURY_E01), "57679"],
        stdout=evtx.open("wb"), check=True, timeout=300,
    )
    return {"mft": mft, "system": system, "evtx": evtx}


# ---- ezt_mft_parse ---------------------------------------------------------


@REQUIRES_EZT_E2E
def test_ezt_mft_parse_tdungan_full_chain(tmp_path: Path, shared_extracts) -> None:
    audit = _make_audit(tmp_path)
    extract_eid = _record_extract(audit, shared_extracts["mft"])
    out = ezt_mft_parse(extract_eid, audit=audit)

    # tdungan MFT has tens of thousands of entries
    assert out["count"] > 10_000
    # Inode 0 is always $MFT
    mft_record = next((r for r in out["rows"] if r.get("entry") == 0), None)
    if mft_record:
        assert mft_record["file_name"] == "$MFT"
    # Truncation flags applied
    assert out.get("rows_truncated") is True
    assert out["rows_total"] == out["count"]
    # exec_id is a fresh ID, not the extract_eid
    assert out["exec_id"] != extract_eid


@REQUIRES_EZT_E2E
def test_ezt_mft_parse_rejects_non_extract_exec_id(tmp_path: Path) -> None:
    """The wrapper must refuse to operate on an exec_id that didn't come
    from tsk_icat_extract."""
    audit = _make_audit(tmp_path)
    fake_eid = audit.new_exec_id()
    audit.record(
        exec_id=fake_eid, agent="x", tool="vol3_psscan",
        args={"image": "/cases/x.raw"}, raw_output_path=None,
        exit_code=0, wall_ms=1, summary="",
    )
    with pytest.raises(ToolError, match="not tsk_icat_extract"):
        ezt_mft_parse(fake_eid, audit=audit)


@REQUIRES_EZT_E2E
def test_ezt_mft_parse_rejects_unknown_exec_id(tmp_path: Path) -> None:
    audit = _make_audit(tmp_path)
    with pytest.raises(ToolError, match="not found"):
        ezt_mft_parse("019eaaaa-1111-7222-bbbb-cccccccccccc", audit=audit)


# ---- ezt_shimcache_parse ---------------------------------------------------


@REQUIRES_EZT_E2E
def test_ezt_shimcache_parse_tdungan_finds_spinlock(
    tmp_path: Path, shared_extracts,
) -> None:
    """ShimCache on tdungan SYSTEM hive should surface spinlock.exe as
    one of the cached entries — proves the full extract+parse chain
    works on real data."""
    audit = _make_audit(tmp_path)
    extract_eid = _record_extract(audit, shared_extracts["system"])
    out = ezt_shimcache_parse(extract_eid, audit=audit)

    assert out["count"] >= 1
    # spinlock.exe is in tdungan's ShimCache (per our manual sample)
    paths = " ".join(e.get("path") or "" for e in out["entries"]).lower()
    assert "spinlock" in paths


# ---- ezt_evtx_parse --------------------------------------------------------


@REQUIRES_EZT_E2E
def test_ezt_evtx_parse_nfury_security_log(
    tmp_path: Path, shared_extracts,
) -> None:
    """nfury Security.evtx parsed cleanly with rich event-data fields."""
    audit = _make_audit(tmp_path)
    extract_eid = _record_extract(audit, shared_extracts["evtx"])
    out = ezt_evtx_parse(extract_eid, audit=audit)

    assert out["count"] >= 1
    assert "by_event_id" in out
    assert "by_channel" in out
    # Security log → channel should include "Security"
    assert any("Security" in c for c in out["by_channel"].keys())


# ---- audit-log integrity across the chain ---------------------------------


@REQUIRES_EZT_E2E
def test_ezt_mft_parse_records_audit_row_with_extract_lineage(
    tmp_path: Path, shared_extracts,
) -> None:
    audit = _make_audit(tmp_path)
    extract_eid = _record_extract(audit, shared_extracts["mft"])
    out = ezt_mft_parse(extract_eid, audit=audit)

    # 2 rows: the fake tsk_icat_extract + the new ezt_mft_parse
    rows = [
        json.loads(l) for l in
        (tmp_path / "audit" / "exec_log.jsonl").read_text().splitlines()
        if l.strip()
    ]
    assert len(rows) == 2
    ezt_row = next(r for r in rows if r["tool"] == "ezt_mft_parse")
    # Audit row records the extract lineage
    assert ezt_row["args"]["extract_exec_id"] == extract_eid
    assert "extract_path" in ezt_row["args"]
    # parsed_summary excludes the bulky row list
    assert "rows" not in ezt_row["parsed_summary"]
    assert ezt_row["parsed_summary"]["count"] == out["count"]
