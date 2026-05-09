"""Smoke tests for mcp_server.audit — the core audit-trail writer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_server.audit import AuditLogger


@pytest.fixture
def audit(tmp_path: Path) -> AuditLogger:
    return AuditLogger(
        exec_log_path=tmp_path / "exec_log.jsonl",
        raw_output_dir=tmp_path / "raw",
    )


def _read_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_record_writes_full_row(audit: AuditLogger) -> None:
    eid = audit.new_exec_id()
    raw = audit.write_raw(eid, "PID Name\n4 System\n")
    audit.record(
        exec_id=eid,
        agent="memory_agent",
        tool="vol3_pslist",
        args={"image": "/cases/x.raw"},
        raw_output_path=raw,
        exit_code=0,
        wall_ms=123,
        summary="1 proc",
    )
    rows = _read_rows(audit.exec_log_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["exec_id"] == eid
    assert row["tool"] == "vol3_pslist"
    assert row["wall_ms"] == 123
    assert row["input_hash"].startswith("sha256:")
    assert row["output_hash"].startswith("sha256:")
    assert row["raw_output_path"].endswith(f"{eid}.txt")
    assert row["summary"] == "1 proc"


def test_time_call_context_manager(audit: AuditLogger) -> None:
    with audit.time_call(agent="a", tool="t", args={"x": 1}) as p:
        p.summary = "ok"
        p.parsed_summary = {"k": "v"}
    rows = _read_rows(audit.exec_log_path)
    assert len(rows) == 1
    assert rows[0]["tool"] == "t"
    assert rows[0]["summary"] == "ok"
    assert rows[0]["parsed_summary"] == {"k": "v"}
    assert rows[0]["wall_ms"] >= 0


def test_input_hash_is_argument_order_independent(audit: AuditLogger) -> None:
    """Same args in different key order must hash to the same value."""
    eid1 = audit.new_exec_id()
    eid2 = audit.new_exec_id()
    audit.record(
        exec_id=eid1, agent="a", tool="t",
        args={"image": "x", "pid": 1},
        raw_output_path=None, exit_code=0, wall_ms=1, summary="",
    )
    audit.record(
        exec_id=eid2, agent="a", tool="t",
        args={"pid": 1, "image": "x"},
        raw_output_path=None, exit_code=0, wall_ms=1, summary="",
    )
    rows = _read_rows(audit.exec_log_path)
    assert rows[0]["input_hash"] == rows[1]["input_hash"]


def test_exec_id_is_unique_and_sortable(audit: AuditLogger) -> None:
    """UUIDv7 IDs must be unique and lexicographically sort by creation time."""
    ids = [audit.new_exec_id() for _ in range(50)]
    assert len(set(ids)) == 50
    assert sorted(ids) == ids


def test_raw_output_text_and_bytes(audit: AuditLogger) -> None:
    eid_t = audit.new_exec_id()
    eid_b = audit.new_exec_id()
    p_text = audit.write_raw(eid_t, "hello\nworld\n")
    p_bin = audit.write_raw(eid_b, b"\x00\x01\x02")
    assert p_text.suffix == ".txt"
    assert p_bin.suffix == ".bin"
    assert p_text.read_text() == "hello\nworld\n"
    assert p_bin.read_bytes() == b"\x00\x01\x02"


def test_lookup_exec_finds_recorded_row(audit: AuditLogger) -> None:
    eid = audit.new_exec_id()
    audit.record(
        exec_id=eid, agent="a", tool="vol3_psscan",
        args={"image": "/x"}, raw_output_path=None,
        exit_code=0, wall_ms=10, summary="ok",
    )
    found = audit.lookup_exec(eid)
    assert found is not None
    assert found["exec_id"] == eid
    assert found["tool"] == "vol3_psscan"


def test_lookup_exec_returns_none_for_unknown(audit: AuditLogger) -> None:
    # Empty log
    assert audit.lookup_exec("nope") is None
    # Log with one row but different id
    eid = audit.new_exec_id()
    audit.record(
        exec_id=eid, agent="a", tool="t", args={},
        raw_output_path=None, exit_code=0, wall_ms=1, summary="",
    )
    assert audit.lookup_exec("does-not-exist") is None


def test_lookup_exec_skips_blank_and_invalid_lines(audit: AuditLogger) -> None:
    """Robust against partially-corrupted audit logs (e.g. a crash mid-write)."""
    eid = audit.new_exec_id()
    audit.record(
        exec_id=eid, agent="a", tool="t", args={},
        raw_output_path=None, exit_code=0, wall_ms=1, summary="",
    )
    # Append junk after the legit row
    with audit.exec_log_path.open("a") as fh:
        fh.write("\n   \n{not-json}\n")
    # Lookup must still succeed
    assert audit.lookup_exec(eid) is not None
