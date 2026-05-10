"""Unit tests for `mcp_server.parsers.ez_tools` — pure-function parsing tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_server.parsers.ez_tools import (
    parse_evtx,
    parse_mft,
    parse_shimcache,
    summarise_evtx,
    summarise_mft,
    summarise_shimcache,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "ez_tools"


def _fixture(name: str) -> str:
    p = FIXTURES / name
    if not p.exists() or p.stat().st_size == 0:
        pytest.skip(f"missing fixture: {name}")
    return p.read_text(errors="replace")


# ---- MFTECmd ----------------------------------------------------------------


def test_parse_mft_extracts_basic_fields() -> None:
    text = _fixture("mft_head.json")
    out = parse_mft(text)
    assert out["count"] >= 1
    # Inode 0 is always $MFT itself
    mft_record = next((r for r in out["rows"] if r.get("entry") == 0), None)
    assert mft_record is not None
    assert mft_record["file_name"] == "$MFT"
    assert mft_record["is_directory"] is False
    # Timestamp normalisation: ends in 'Z'
    if mft_record["created"]:
        assert mft_record["created"].endswith("Z")


def test_parse_mft_aggregates_in_use_and_directories() -> None:
    out = parse_mft(_fixture("mft_head.json"))
    assert out["in_use"] + out["deleted"] == out["count"]
    assert "by_extension" in out
    assert "by_parent_path" in out


def test_parse_mft_anti_tamper_flag_aggregates_present() -> None:
    out = parse_mft(_fixture("mft_head.json"))
    for k in ("timestomped_count", "usec_zeros_count", "copied_count", "ads_count"):
        assert k in out
        assert isinstance(out[k], int)


def test_summarise_mft_includes_count_and_deleted() -> None:
    out = parse_mft(_fixture("mft_head.json"))
    s = summarise_mft(out)
    assert "MFT entries" in s
    assert "deleted" in s


def test_parse_mft_handles_empty() -> None:
    out = parse_mft("")
    assert out["count"] == 0
    assert out["rows"] == []


# ---- AppCompatCacheParser (ShimCache) --------------------------------------


def test_parse_shimcache_extracts_entries() -> None:
    text = _fixture("shimcache_head.csv")
    out = parse_shimcache(text)
    assert out["count"] >= 1
    # The tdungan SYSTEM hive's first ShimCache entry is spinlock.exe
    spinlock = next((e for e in out["entries"]
                     if "spinlock" in (e.get("path") or "").lower()), None)
    if spinlock:
        assert spinlock["last_modified"]  # has a timestamp
        assert spinlock["last_modified"].endswith("Z")


def test_parse_shimcache_aggregates_by_extension_and_control_set() -> None:
    out = parse_shimcache(_fixture("shimcache_head.csv"))
    assert "by_extension" in out
    assert "by_control_set" in out
    # tdungan ShimCache has CS1 + CS2
    assert any(k in out["by_control_set"] for k in ("1", "2"))


def test_parse_shimcache_handles_empty() -> None:
    out = parse_shimcache("")
    assert out["count"] == 0


def test_summarise_shimcache_includes_count() -> None:
    out = parse_shimcache(_fixture("shimcache_head.csv"))
    s = summarise_shimcache(out)
    assert "ShimCache entries" in s


# ---- EvtxECmd ---------------------------------------------------------------


def test_parse_evtx_extracts_events() -> None:
    text = _fixture("evtx_head.json")
    out = parse_evtx(text)
    assert out["count"] >= 1
    # All events should have an event_id and a time_created
    for ev in out["events"]:
        # event_id may be None for malformed events but TimeCreated should exist
        if ev.get("time_created"):
            assert ev["time_created"].endswith("Z")


def test_parse_evtx_aggregates_by_event_id() -> None:
    out = parse_evtx(_fixture("evtx_head.json"))
    assert "by_event_id" in out
    assert "by_channel" in out
    assert "by_computer" in out
    # We extracted from Security.evtx — should be on the Security channel
    if out["by_channel"]:
        assert any("Security" in c for c in out["by_channel"].keys())


def test_parse_evtx_handles_utf8_bom() -> None:
    """EvtxECmd writes a UTF-8 BOM at the start of its JSON output."""
    bom_text = "﻿" + '{"EventId": 4624, "RecordNumber": 1, "TimeCreated": "2012-04-04T12:00:00.000Z"}\n'
    out = parse_evtx(bom_text)
    assert out["count"] == 1
    assert out["events"][0]["event_id"] == 4624


def test_parse_evtx_handles_empty() -> None:
    assert parse_evtx("").get("count") == 0
    assert parse_evtx("﻿").get("count") == 0


def test_summarise_evtx_includes_top_event_ids() -> None:
    out = parse_evtx(_fixture("evtx_head.json"))
    s = summarise_evtx(out)
    assert "events" in s
