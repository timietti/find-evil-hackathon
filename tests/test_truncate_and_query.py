"""Unit tests for v1 row-truncation + query_rows.

Both pieces are pure-function-ish (no Vol3 needed) — we exercise them
directly against captured fixtures, no subprocess spawn. Runs in <50 ms.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_server.audit import AuditLogger
from mcp_server.parsers.vol3 import parse_psscan
from mcp_server.tools._common import QueryRowsArgs
from mcp_server.tools.memory import (
    DEFAULT_ROW_LIMIT,
    _coerce_filter_value,
    _truncate_rows,
    query_rows,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PSSCAN_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "vol3_jsonl" / "psscan_head.jsonl"


# ---- _truncate_rows --------------------------------------------------------


def test_truncate_rows_under_limit_passes_through() -> None:
    parsed = {
        "count": 3,
        "processes": [{"pid": 1}, {"pid": 2}, {"pid": 3}],
        "by_image": {"a": 1},
    }
    out = _truncate_rows(parsed, limit=50)
    assert out["count"] == 3
    assert len(out["processes"]) == 3
    assert out["processes_truncated"] is False
    assert out["processes_total"] == 3
    # Aggregate fields must be untouched.
    assert out["by_image"] == {"a": 1}


def test_truncate_rows_over_limit_caps_and_flags() -> None:
    parsed = {
        "count": 100,
        "processes": [{"pid": i} for i in range(100)],
    }
    out = _truncate_rows(parsed, limit=50)
    assert len(out["processes"]) == 50
    assert out["processes_truncated"] is True
    assert out["processes_total"] == 100
    # The first 50 must be the leading window (deterministic).
    assert [p["pid"] for p in out["processes"]] == list(range(50))


def test_truncate_rows_handles_multiple_row_keys() -> None:
    """Plugins can have different rows-keys (rows, nodes, connections, ...)."""
    parsed = {
        "rows":        [{"x": i} for i in range(60)],
        "nodes":       [{"y": i} for i in range(40)],
        "connections": [{"z": i} for i in range(80)],
    }
    out = _truncate_rows(parsed, limit=50)
    assert len(out["rows"]) == 50
    assert out["rows_truncated"] is True
    assert len(out["nodes"]) == 40
    assert out["nodes_truncated"] is False
    assert len(out["connections"]) == 50
    assert out["connections_truncated"] is True


def test_truncate_rows_doesnt_invent_keys() -> None:
    """Don't add 'foo_truncated' if 'foo' wasn't a list in the input."""
    parsed = {"count": 5}
    out = _truncate_rows(parsed, limit=50)
    for k in (
        "processes_truncated", "rows_truncated", "nodes_truncated",
        "connections_truncated", "files_truncated", "findings_truncated",
        "services_truncated", "entries_truncated",
    ):
        assert k not in out


def test_default_row_limit_is_50() -> None:
    """Document the default; v0 overflow happened around 200+ rows."""
    assert DEFAULT_ROW_LIMIT == 50


# ---- _coerce_filter_value --------------------------------------------------


@pytest.mark.parametrize(
    "field_value, filter_str, expected",
    [
        # exact PID match
        (4, "4", True),
        (4, "5", False),
        # bool match (must beat the int branch — bool is subclass of int)
        (True, "true", True),
        (True, "True", True),
        (False, "true", False),
        # case-insensitive substring on strings
        ("Microsoft Edge", "edge", True),
        ("Microsoft Edge", "EDGE", True),
        ("Microsoft Edge", "msedge", False),
        # None field never matches
        (None, "anything", False),
        # malformed numeric does not match
        (123, "abc", False),
    ],
)
def test_coerce_filter_value(field_value, filter_str, expected) -> None:
    assert _coerce_filter_value(field_value, filter_str) is expected


# ---- query_rows ------------------------------------------------------------


@pytest.fixture
def psscan_audit(tmp_path: Path) -> tuple[AuditLogger, str]:
    """Set up an audit log + raw output for a fake vol3_psscan call.

    Uses the committed psscan_head.jsonl fixture as the raw output, so we
    don't need to run vol3 to test query_rows.
    """
    if not PSSCAN_FIXTURE.exists():
        pytest.skip("psscan fixture not present")

    audit = AuditLogger(
        exec_log_path=tmp_path / "exec_log.jsonl",
        raw_output_dir=tmp_path / "raw",
    )
    eid = audit.new_exec_id()
    raw_path = audit.write_raw(eid, PSSCAN_FIXTURE.read_text())
    audit.record(
        exec_id=eid, agent="memory_agent", tool="vol3_psscan",
        args={"image": "/cases/find-evil-test/Rocba-Memory.raw"},
        raw_output_path=raw_path, exit_code=0, wall_ms=42,
        summary="N processes",
    )
    return audit, eid


def test_query_rows_no_filter_returns_all(psscan_audit) -> None:
    audit, eid = psscan_audit
    out = query_rows({"exec_id": eid}, audit=audit)
    assert out["tool"] == "vol3_psscan"
    assert out["rows_key"] == "processes"
    assert out["total_rows"] == out["matched_rows"]  # no filter
    assert out["returned_rows"] == out["matched_rows"]
    assert out["filter"] is None


def test_query_rows_filter_by_pid(psscan_audit) -> None:
    """PID 4 (System) is always present in any Windows memory image."""
    audit, eid = psscan_audit
    out = query_rows(
        {"exec_id": eid, "filter_field": "pid", "filter_value": "4"},
        audit=audit,
    )
    assert out["matched_rows"] == 1
    assert out["rows"][0]["pid"] == 4
    assert out["rows"][0]["image"] == "System"


def test_query_rows_filter_substring_image(psscan_audit) -> None:
    audit, eid = psscan_audit
    out = query_rows(
        {"exec_id": eid, "filter_field": "image", "filter_value": "ystem"},
        audit=audit,
    )
    # "ystem" matches "System" (case-insensitive substring)
    assert out["matched_rows"] >= 1
    for r in out["rows"]:
        assert "ystem" in (r["image"] or "").lower()


def test_query_rows_pagination(psscan_audit) -> None:
    audit, eid = psscan_audit
    page1 = query_rows({"exec_id": eid, "limit": 2}, audit=audit)
    page2 = query_rows({"exec_id": eid, "limit": 2, "offset": 2}, audit=audit)
    assert page1["returned_rows"] == 2
    assert page2["returned_rows"] >= 1
    assert page1["rows"] != page2["rows"]


def test_query_rows_unknown_exec_id_raises(psscan_audit) -> None:
    from mcp_server.tools._common import ToolError

    audit, _ = psscan_audit
    with pytest.raises(ToolError, match="exec_id not found"):
        query_rows({"exec_id": "this-id-was-never-recorded"}, audit=audit)


def test_query_rows_validates_args() -> None:
    """Pydantic must reject limit > 500."""
    with pytest.raises(ValueError):
        QueryRowsArgs(exec_id="x", limit=10000)
    with pytest.raises(ValueError):
        QueryRowsArgs(exec_id="x", limit=0)
    with pytest.raises(ValueError):
        QueryRowsArgs(exec_id="x", offset=-1)
