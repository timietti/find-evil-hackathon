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
    parse_cachedump,
    parse_cmdline,
    parse_dlllist,
    parse_envars,
    parse_filescan,
    parse_handles,
    parse_hashdump,
    parse_jsonl_rows,
    parse_malfind,
    parse_netscan,
    parse_psscan,
    parse_pstree,
    parse_scheduled_tasks,
    parse_skeleton_key,
    parse_svcscan,
    parse_userassist,
    summarise_cachedump,
    summarise_cmdline,
    summarise_dlllist,
    summarise_envars,
    summarise_filescan,
    summarise_handles,
    summarise_hashdump,
    summarise_malfind,
    summarise_netscan,
    summarise_psscan,
    summarise_pstree,
    summarise_scheduled_tasks,
    summarise_skeleton_key,
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


# ---- dlllist ---------------------------------------------------------------


def test_parse_dlllist_extracts_per_dll_records() -> None:
    out = parse_dlllist(_read_fixture("dlllist_head.jsonl"))
    assert out["count"] >= 5
    # The injected DLL with empty Path should be flagged as unbacked
    assert out["unbacked"] >= 1
    # by_process aggregates correctly: lsass.exe has 3 entries
    assert out["by_process"].get("lsass.exe") == 3


def test_parse_dlllist_normalises_load_time_and_keeps_path() -> None:
    out = parse_dlllist(_read_fixture("dlllist_head.jsonl"))
    rows = out["rows"]
    stun_row = next((r for r in rows if r["name"] == "stun.exe"), None)
    assert stun_row is not None
    assert stun_row["load_time"].endswith("Z")
    assert "frocba" in (stun_row["path"] or "").lower()


def test_summarise_dlllist_includes_unbacked_count() -> None:
    out = parse_dlllist(_read_fixture("dlllist_head.jsonl"))
    s = summarise_dlllist(out)
    assert "DLLs" in s
    assert "unbacked" in s


def test_parse_dlllist_handles_empty() -> None:
    out = parse_dlllist("")
    assert out["count"] == 0
    assert out["rows"] == []


# ---- handles ---------------------------------------------------------------


def test_parse_handles_extracts_per_handle_records() -> None:
    out = parse_handles(_read_fixture("handles_head.jsonl"))
    assert out["count"] >= 5
    by_type = out["by_type"]
    # We have 2 Mutant + 1 File + 1 Key + 1 Section in the fixture
    assert by_type.get("Mutant") == 2
    assert by_type.get("File") == 1
    assert by_type.get("Key") == 1


def test_parse_handles_curates_high_signal_lists() -> None:
    out = parse_handles(_read_fixture("handles_head.jsonl"))
    assert any("stun-singleton-mutex" in m for m in out["mutexes_top"])
    assert any("STUN-C2-CONFIG" in m for m in out["mutexes_top"])
    assert any("stun.exe" in f.lower() for f in out["file_handles_top"])
    assert any("Microsoft" in k for k in out["key_handles_top"])


def test_summarise_handles_lists_top_types() -> None:
    out = parse_handles(_read_fixture("handles_head.jsonl"))
    s = summarise_handles(out)
    assert "handles" in s
    # top types include Mutant
    assert "Mutant" in s


def test_parse_handles_handles_empty() -> None:
    out = parse_handles("")
    assert out["count"] == 0
    assert out["rows"] == []


# ---- scheduled_tasks (Phase 1.5, T1053) ------------------------------------


def test_parse_scheduled_tasks_extracts_actions_and_principals() -> None:
    out = parse_scheduled_tasks(_read_fixture("scheduled_tasks_head.jsonl"))
    assert out["count"] >= 2
    # spinlock-persist (the suspicious one)
    spin = next((r for r in out["rows"] if r["task_name"] == "spinlock-persist"), None)
    assert spin is not None
    assert spin["action_type"] == "Exec"
    assert "spinlock" in (spin["action_arguments"] or "")
    assert spin["enabled"] is True
    assert spin["principal_id"] == "LocalSystem"


def test_parse_scheduled_tasks_aggregates_principal_and_action() -> None:
    out = parse_scheduled_tasks(_read_fixture("scheduled_tasks_head.jsonl"))
    assert "by_principal" in out
    assert "by_action_type" in out
    assert out["by_action_type"].get("Exec") == 1
    assert out["by_action_type"].get("ComHandler") == 1


def test_parse_scheduled_tasks_handles_empty() -> None:
    out = parse_scheduled_tasks("")
    assert out["count"] == 0


def test_summarise_scheduled_tasks_mentions_enabled() -> None:
    out = parse_scheduled_tasks(_read_fixture("scheduled_tasks_head.jsonl"))
    s = summarise_scheduled_tasks(out)
    assert "scheduled tasks" in s


# ---- hashdump (Phase 1.5, T1003.002) ---------------------------------------


def test_parse_hashdump_extracts_users_and_rids() -> None:
    out = parse_hashdump(_read_fixture("hashdump_head.jsonl"))
    assert out["count"] >= 3
    admin = next((r for r in out["rows"] if r["user"] == "Administrator"), None)
    assert admin is not None
    assert admin["rid"] == 500


def test_parse_hashdump_flags_blank_passwords() -> None:
    out = parse_hashdump(_read_fixture("hashdump_head.jsonl"))
    # Guest has blank-password hash (31d6cfe0…)
    assert "Guest" in out["blank_password_users"]
    # Administrator does not
    assert "Administrator" not in out["blank_password_users"]


def test_summarise_hashdump_flags_blank_password_users() -> None:
    out = parse_hashdump(_read_fixture("hashdump_head.jsonl"))
    s = summarise_hashdump(out)
    assert "blank-password" in s
    assert "Guest" in s


def test_parse_hashdump_handles_empty() -> None:
    out = parse_hashdump("")
    assert out["count"] == 0
    assert out["blank_password_users"] == []


# ---- cachedump (Phase 1.5, T1003.005) --------------------------------------


def test_parse_cachedump_extracts_domain_credentials() -> None:
    out = parse_cachedump(_read_fixture("cachedump_head.jsonl"))
    assert out["count"] >= 2
    assert "SHIELDBASE" in out["by_domain"]
    rsydow = next((r for r in out["rows"] if r["username"] == "rsydow-a"), None)
    assert rsydow is not None
    assert rsydow["domain"] == "SHIELDBASE"


def test_summarise_cachedump_mentions_domain_count() -> None:
    out = parse_cachedump(_read_fixture("cachedump_head.jsonl"))
    s = summarise_cachedump(out)
    assert "cached domain credentials" in s


# ---- skeleton_key_check (Phase 1.5, T1558) ---------------------------------


def test_parse_skeleton_key_no_patch() -> None:
    out = parse_skeleton_key(_read_fixture("skeleton_key_head.jsonl"))
    assert out["count"] == 1
    assert out["found_count"] == 0


def test_parse_skeleton_key_positive_finding() -> None:
    text = '{"PID": 664, "Process": "lsass.exe", "Skeleton Key Found": true}\n'
    out = parse_skeleton_key(text)
    assert out["found_count"] == 1


def test_summarise_skeleton_key_negative_vs_positive() -> None:
    out_neg = parse_skeleton_key(_read_fixture("skeleton_key_head.jsonl"))
    assert "no skeleton-key" in summarise_skeleton_key(out_neg)
    text = '{"PID": 664, "Process": "lsass.exe", "Skeleton Key Found": true}\n'
    out_pos = parse_skeleton_key(text)
    assert "detected" in summarise_skeleton_key(out_pos)


# ---- envars (Phase 1.5, T1574) ---------------------------------------------


def test_parse_envars_extracts_per_process_vars() -> None:
    out = parse_envars(_read_fixture("envars_head.jsonl"))
    assert out["count"] >= 5
    # PATH appears for two processes (smss.exe + stun.exe) → by_variable[Path]=2
    assert out["by_variable"].get("Path") == 2


def test_parse_envars_path_like_curation() -> None:
    out = parse_envars(_read_fixture("envars_head.jsonl"))
    # path_like_rows should include the two Path entries + one PATHEXT
    assert len(out["path_like_rows"]) == 3
    # The stun.exe Path has the suspicious Temp directory prefix
    stun_path = next(
        (r for r in out["path_like_rows"]
         if r["process"] == "stun.exe" and r["variable"] == "Path"),
        None,
    )
    assert stun_path is not None
    assert "Temp" in stun_path["value"]


def test_summarise_envars_flags_path_like_count() -> None:
    out = parse_envars(_read_fixture("envars_head.jsonl"))
    s = summarise_envars(out)
    assert "env-var entries" in s
    assert "Path-like" in s
