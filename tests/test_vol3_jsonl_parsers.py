"""Unit tests for the JSONL-based Vol3 parsers.

Fixtures: small (≤10 row) captures of `vol -r jsonl <plugin>` output saved at
test setup time under `tests/fixtures/vol3_jsonl/`. They're committed so the
test suite is reproducible without the 18 GB evidence file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_server.parsers.vol3 import (
    _normalise_dt,
    parse_cmdline,
    parse_filescan,
    parse_jsonl_rows,
    parse_malfind,
    parse_netscan,
    parse_psscan,
    parse_pstree,
    parse_svcscan,
    parse_userassist,
    summarise_cmdline,
    summarise_filescan,
    summarise_malfind,
    summarise_netscan,
    summarise_psscan,
    summarise_pstree,
    summarise_svcscan,
    summarise_userassist,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "vol3_jsonl"


def _read_fixture(name: str) -> str:
    p = FIXTURES / name
    if not p.exists() or p.stat().st_size == 0:
        pytest.skip(f"missing fixture: {name}")
    return p.read_text()


# ---- generic JSONL helper --------------------------------------------------


def test_parse_jsonl_rows_skips_blank_and_invalid() -> None:
    text = (
        '\n'
        '{"a": 1}\n'
        '   \n'
        'not-json\n'
        '{"b": 2}\n'
    )
    rows = parse_jsonl_rows(text)
    assert rows == [{"a": 1}, {"b": 2}]


def test_parse_jsonl_rows_handles_empty() -> None:
    assert parse_jsonl_rows("") == []
    assert parse_jsonl_rows("\n\n\n") == []


def test_parse_jsonl_rows_drops_non_dict() -> None:
    """Vol3 sometimes emits a final summary array — we want only dict rows."""
    text = '{"x": 1}\n[1, 2, 3]\n"a string"\n{"y": 2}\n'
    assert parse_jsonl_rows(text) == [{"x": 1}, {"y": 2}]


# ---- _normalise_dt ---------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2020-11-11T08:13:00+00:00",            "2020-11-11T08:13:00Z"),
        ("2020-11-11 08:13:00 UTC",              "2020-11-11T08:13:00Z"),
        ("2020-11-11 08:13:00.123456 UTC",       "2020-11-11T08:13:00Z"),
        ("N/A", None),
        ("",    None),
        (None,  None),
    ],
)
def test_normalise_dt(raw, expected) -> None:
    assert _normalise_dt(raw) == expected


# ---- psscan ----------------------------------------------------------------


def test_parse_psscan_rocba_head() -> None:
    text = _read_fixture("psscan_head.jsonl")
    out = parse_psscan(text)
    assert out["count"] >= 1
    assert all("pid" in p and "image" in p for p in out["processes"])
    # Real ROCBA-001: System (PID 4) has PPID 0
    sys_proc = next((p for p in out["processes"] if p["pid"] == 4), None)
    if sys_proc:
        assert sys_proc["image"] == "System"
        assert sys_proc["ppid"] == 0
    # CreateTime should normalise to ISO-8601 Z
    for p in out["processes"]:
        if p["create_time"]:
            assert p["create_time"].endswith("Z")
    assert "by_image" in out
    assert isinstance(out["by_image"], dict)


def test_summarise_psscan() -> None:
    parsed = {
        "count": 42,
        "exited": [{"pid": 1}, {"pid": 2}],
    }
    s = summarise_psscan(parsed)
    assert "42 processes" in s
    assert "2 exited" in s


# ---- pstree ----------------------------------------------------------------


def test_parse_pstree_rocba_head() -> None:
    text = _read_fixture("pstree_head.jsonl")
    out = parse_pstree(text)
    # tree_roots is the count of top-level nodes parsed (one per line)
    assert out["tree_roots"] >= 1
    # Walking the tree should produce at least as many nodes as roots
    assert out["count"] >= out["tree_roots"]
    # depth 0 nodes are the roots
    roots = [n for n in out["nodes"] if n["depth"] == 0]
    assert len(roots) == out["tree_roots"]


def test_summarise_pstree() -> None:
    parsed = {"count": 121, "tree_roots": 8}
    s = summarise_pstree(parsed)
    assert "121 processes" in s
    assert "8 root" in s


# ---- cmdline ---------------------------------------------------------------


def test_parse_cmdline_rocba_head() -> None:
    text = _read_fixture("cmdline_head.jsonl")
    out = parse_cmdline(text)
    assert out["count"] >= 1
    # PID 4 (System) has no Args
    sys_row = next((r for r in out["rows"] if r["pid"] == 4), None)
    if sys_row:
        assert sys_row["process"] == "System"
        assert sys_row["args"] in (None, "")


def test_summarise_cmdline() -> None:
    parsed = {
        "count": 5,
        "rows": [
            {"args": None}, {"args": ""}, {"args": "x"},
            {"args": "y"}, {"args": "z"},
        ],
    }
    s = summarise_cmdline(parsed)
    assert "5 command lines" in s
    assert "2 with null args" in s


# ---- netscan ---------------------------------------------------------------


def test_parse_netscan_rocba_head() -> None:
    text = _read_fixture("netscan_head.jsonl")
    out = parse_netscan(text)
    assert "connections" in out
    assert "foreign_ip_counts" in out
    # foreign_ip_counts must NOT contain loopback / 0.0.0.0 / "*"
    for ip in out["foreign_ip_counts"]:
        assert ip not in {"0.0.0.0", "127.0.0.1", "::", "::1", "*", "", None}


def test_summarise_netscan_with_top_ips() -> None:
    parsed = {
        "count": 200,
        "foreign_ip_counts": {"1.2.3.4": 50, "5.6.7.8": 10, "9.9.9.9": 1},
    }
    s = summarise_netscan(parsed)
    assert "200 endpoints" in s
    assert "1.2.3.4(50)" in s


def test_summarise_netscan_with_no_external() -> None:
    s = summarise_netscan({"count": 7, "foreign_ip_counts": {}})
    assert "7 endpoints" in s
    assert "none" in s


# ---- filescan --------------------------------------------------------------


def test_parse_filescan_rocba_head() -> None:
    text = _read_fixture("filescan_head.jsonl")
    out = parse_filescan(text)
    assert out["count"] >= 1
    for f in out["files"]:
        assert "offset" in f
        assert "name" in f
        # Vol3's filescan currently does not emit Size — None is OK.


def test_summarise_filescan() -> None:
    s = summarise_filescan({"count": 42802})
    assert "42802 file objects" in s


# ---- malfind ---------------------------------------------------------------


def test_parse_malfind_rocba_head() -> None:
    text = _read_fixture("malfind_head.jsonl")
    out = parse_malfind(text)
    # parsed should have count + rwx_count + by_process + findings
    assert "count" in out
    assert "rwx_count" in out
    assert "by_process" in out
    assert "findings" in out
    # Disasm and Hexdump must be dropped from each finding
    for f in out["findings"]:
        assert "disasm" not in f
        assert "hexdump" not in f


def test_summarise_malfind_with_findings() -> None:
    s = summarise_malfind({
        "count": 5,
        "rwx_count": 3,
        "by_process": {"MsMpEng.exe": 2, "explorer.exe": 1},
    })
    assert "5 suspicious" in s
    assert "3 RWX" in s
    assert "2 processes" in s


def test_summarise_malfind_when_clean() -> None:
    s = summarise_malfind({"count": 0, "rwx_count": 0, "by_process": {}})
    assert "no malfind" in s.lower()


# ---- svcscan ---------------------------------------------------------------


def test_parse_svcscan_rocba_head() -> None:
    text = _read_fixture("svcscan_head.jsonl")
    out = parse_svcscan(text)
    assert out["count"] >= 1
    assert "by_state" in out
    assert "by_start" in out
    assert "by_type" in out
    # All services must have name + state
    for s in out["services"]:
        assert "name" in s
        assert "state" in s


def test_summarise_svcscan() -> None:
    s = summarise_svcscan({"count": 200, "running": 80, "drivers": 50})
    assert "200 services" in s
    assert "80 running" in s
    assert "50 drivers" in s


# ---- userassist ------------------------------------------------------------


def test_parse_userassist_rocba_head() -> None:
    text = _read_fixture("userassist_head.jsonl")
    out = parse_userassist(text)
    # entries are extracted from `__children` of top-level Key rows
    assert "count" in out
    assert "real_count" in out
    assert "session_count" in out
    # Raw Data must NOT appear in any entry
    for e in out["entries"]:
        assert "raw_data" not in e
    # If we have any UEME_CTLSESSION entries they must be marked
    sessions = [e for e in out["entries"] if e["session_marker"]]
    for s in sessions:
        assert s["name"] == "UEME_CTLSESSION"
    # session_count must equal len(sessions)
    assert out["session_count"] == len(sessions)
    # real_count + session_count == count
    assert out["real_count"] + out["session_count"] == out["count"]


def test_summarise_userassist() -> None:
    s = summarise_userassist({
        "real_count": 42,
        "by_hive": {"\\??\\C:\\Users\\fredr\\ntuser.dat": 42},
    })
    assert "42 program-execution" in s
    assert "1 user hives" in s
