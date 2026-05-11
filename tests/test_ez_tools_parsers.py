"""Unit tests for `mcp_server.parsers.ez_tools` — pure-function parsing tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_server.parsers.ez_tools import (
    parse_amcache,
    parse_amcache_from_dir,
    parse_evtx,
    parse_jumplist,
    parse_mft,
    parse_persistence_keys,
    parse_persistence_keys_from_csv,
    parse_prefetch,
    parse_recyclebin,
    parse_shimcache,
    parse_srum,
    parse_srum_from_dir,
    parse_task_xml,
    summarise_amcache,
    summarise_evtx,
    summarise_jumplist,
    summarise_mft,
    summarise_persistence_keys,
    summarise_prefetch,
    summarise_recyclebin,
    summarise_shimcache,
    summarise_srum,
    summarise_task_xml,
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


# ---- AmcacheParser ----------------------------------------------------------


AMCACHE_FIXTURE_DIR = FIXTURES / "amcache_sample"


def test_parse_amcache_from_dir_finds_all_sections() -> None:
    if not AMCACHE_FIXTURE_DIR.exists():
        pytest.skip("missing amcache fixture dir")
    out = parse_amcache_from_dir(AMCACHE_FIXTURE_DIR)
    # The synthetic fixture has 3 CSVs (Unassociated, Program, Driver).
    assert "unassociated_file_entries" in out["section_counts"]
    assert "program_entries" in out["section_counts"]
    assert "driver_binaries" in out["section_counts"]
    # Unknown files list should be empty for a clean fixture set.
    assert out["unknown_files"] == []
    # Total should equal sum of section counts.
    assert out["total_count"] == sum(out["section_counts"].values())


def test_parse_amcache_from_dir_normalises_columns_lowercase() -> None:
    out = parse_amcache_from_dir(AMCACHE_FIXTURE_DIR)
    rows = out["sections"]["unassociated_file_entries"]["rows"]
    assert len(rows) >= 1
    # Original column was 'FullPath' / 'SHA1' / 'FileKeyLastWriteTimestamp'
    r = rows[0]
    assert "fullpath" in r
    assert "sha1" in r
    assert "filekeylastwritetimestamp" in r
    # The timestamp normaliser doesn't run on filekeylastwritetimestamp by name
    # (we only normalise the keys listed in _amcache_normalise_row), but the
    # raw value should be preserved.
    assert r["fullpath"].endswith("stun.exe")


def test_parse_amcache_from_dir_handles_empty_section_csv(tmp_path: Path) -> None:
    """A header-only CSV (no data rows) parses to count=0 cleanly."""
    f = tmp_path / "20240101010101_Amcache_ShortCuts.csv"
    f.write_text("ProgramId,ShortCutPath\n")
    out = parse_amcache_from_dir(tmp_path)
    assert out["section_counts"]["shortcuts"] == 0
    assert out["sections"]["shortcuts"]["rows"] == []


def test_parse_amcache_from_dir_skips_unknown_csv(tmp_path: Path) -> None:
    """A CSV with an unrecognised section suffix lands in unknown_files."""
    f = tmp_path / "20240101010101_Amcache_FooBarBaz.csv"
    f.write_text("a,b,c\n1,2,3\n")
    out = parse_amcache_from_dir(tmp_path)
    assert "FooBarBaz" in str(out["unknown_files"])
    assert out["section_counts"] == {}


def test_parse_amcache_from_text_round_trip() -> None:
    """parse_amcache(json_text) re-hydrates the dict produced by parse_amcache_from_dir."""
    import json
    parsed = parse_amcache_from_dir(AMCACHE_FIXTURE_DIR)
    text = json.dumps(parsed)
    rehydrated = parse_amcache(text)
    assert rehydrated["section_counts"] == parsed["section_counts"]
    assert rehydrated["total_count"] == parsed["total_count"]


def test_parse_amcache_from_text_handles_empty() -> None:
    """parse_amcache('') returns an empty-but-shaped dict."""
    out = parse_amcache("")
    assert out["total_count"] == 0
    assert out["section_counts"] == {}
    assert out["sections"] == {}


def test_parse_amcache_from_text_handles_garbage() -> None:
    """parse_amcache('not json') returns empty + a parse_error marker."""
    out = parse_amcache("not actually json")
    assert out["total_count"] == 0
    assert "_parse_error" in out


def test_summarise_amcache_includes_program_exec_total() -> None:
    parsed = parse_amcache_from_dir(AMCACHE_FIXTURE_DIR)
    s = summarise_amcache(parsed)
    # Should mention sections + program-exec record count
    assert "sections" in s
    assert "program-exec" in s


# ---- PECmd (Prefetch) -------------------------------------------------------


def test_parse_prefetch_extracts_per_binary_records() -> None:
    out = parse_prefetch(_fixture("prefetch_head.json"))
    assert out["count"] >= 1
    notepad = next((r for r in out["rows"] if r["executable_name"] == "NOTEPAD.EXE"), None)
    assert notepad is not None
    assert notepad["run_count"] == 12
    assert notepad["last_run"].endswith("Z")
    # PreviousRun list captures only non-null entries
    assert isinstance(notepad["previous_runs"], list)
    assert len(notepad["previous_runs"]) >= 2


def test_parse_prefetch_aggregates_by_executable_and_total_runs() -> None:
    out = parse_prefetch(_fixture("prefetch_head.json"))
    assert "by_executable" in out
    assert out["total_runs"] >= 12  # NOTEPAD has RunCount 12
    assert "notepad.exe" in out["by_executable"]


def test_parse_prefetch_handles_empty() -> None:
    out = parse_prefetch("")
    assert out["count"] == 0
    assert out["rows"] == []


def test_summarise_prefetch_includes_run_total() -> None:
    out = parse_prefetch(_fixture("prefetch_head.json"))
    s = summarise_prefetch(out)
    assert "Prefetch records" in s
    assert "cumulative runs" in s


# ---- JLECmd (Jump Lists) ----------------------------------------------------


def test_parse_jumplist_extracts_destlist_entries() -> None:
    out = parse_jumplist(_fixture("jumplist_head.json"))
    assert out["count"] >= 3
    starfury = next(
        (r for r in out["rows"] if "StarFury" in (r.get("path") or "")), None,
    )
    assert starfury is not None
    assert starfury["appid_description"] == "Microsoft Word 2016"
    # Removable drive should appear in by_drive aggregate
    assert "Removable" in out.get("by_drive", {}) or "Fixed" in out.get("by_drive", {})


def test_parse_jumplist_aggregates_by_appid() -> None:
    out = parse_jumplist(_fixture("jumplist_head.json"))
    assert "by_appid" in out
    # Word app id appears 2x (the two .docx entries)
    word_id = "a52cba65b4b7e2a9"
    assert out["by_appid"].get(word_id) == 2


def test_parse_jumplist_handles_empty() -> None:
    assert parse_jumplist("").get("count") == 0


def test_summarise_jumplist_mentions_apps_count() -> None:
    out = parse_jumplist(_fixture("jumplist_head.json"))
    s = summarise_jumplist(out)
    assert "Jump List" in s and "apps" in s


# ---- RBCmd (Recycle Bin) ----------------------------------------------------


def test_parse_recyclebin_extracts_records() -> None:
    out = parse_recyclebin(_fixture("recyclebin_head.json"))
    assert out["count"] >= 3
    pst = next((r for r in out["rows"] if r["file_name"].endswith(".pst")), None)
    assert pst is not None
    assert pst["file_size"] == 15728640
    assert pst["deleted_on"].endswith("Z")


def test_parse_recyclebin_aggregates_by_extension() -> None:
    out = parse_recyclebin(_fixture("recyclebin_head.json"))
    assert "pst" in out["by_extension"]
    assert "zip" in out["by_extension"]


def test_parse_recyclebin_handles_empty() -> None:
    assert parse_recyclebin("").get("count") == 0


def test_summarise_recyclebin_mentions_count() -> None:
    out = parse_recyclebin(_fixture("recyclebin_head.json"))
    s = summarise_recyclebin(out)
    assert "Recycle Bin records" in s


# ---- SrumECmd (System Resource Usage Monitor) -------------------------------


SRUM_FIXTURE_DIR = FIXTURES / "srum_sample"


def test_parse_srum_from_dir_finds_sections() -> None:
    if not SRUM_FIXTURE_DIR.exists():
        pytest.skip("missing srum fixture dir")
    out = parse_srum_from_dir(SRUM_FIXTURE_DIR)
    assert "network_usage" in out["section_counts"]
    assert "app_resource_use" in out["section_counts"]
    assert out["unknown_files"] == []
    assert out["total_count"] == sum(out["section_counts"].values())


def test_parse_srum_network_usage_normalises_columns() -> None:
    out = parse_srum_from_dir(SRUM_FIXTURE_DIR)
    rows = out["sections"]["network_usage"]["rows"]
    assert len(rows) >= 3
    # CSV column "BytesSent" should be lower-cased to "bytessent"
    r = rows[0]
    assert "bytessent" in r
    assert "bytesreceived" in r
    # ExeInfo retained
    assert "exeinfo" in r


def test_parse_srum_round_trip() -> None:
    """parse_srum(json_text) re-hydrates parse_srum_from_dir output."""
    import json
    parsed = parse_srum_from_dir(SRUM_FIXTURE_DIR)
    text = json.dumps(parsed)
    rehydrated = parse_srum(text)
    assert rehydrated["section_counts"] == parsed["section_counts"]


def test_parse_srum_empty_text() -> None:
    out = parse_srum("")
    assert out["total_count"] == 0
    assert out["section_counts"] == {}


def test_summarise_srum_includes_network_usage_when_present() -> None:
    parsed = parse_srum_from_dir(SRUM_FIXTURE_DIR)
    s = summarise_srum(parsed)
    assert "SRUM rows" in s
    assert "network-usage" in s.lower() or "network_usage" in s.lower() or "network" in s.lower()


# ---- Task XML parser (Phase 1.5, T1053 disk-side) --------------------------


def test_parse_task_xml_extracts_principal_and_actions() -> None:
    text = _fixture("task_xml_sample.xml")
    out = parse_task_xml(text)
    assert out["count"] == 1
    rec = out["rows"][0]
    assert rec["task_name"] == r"\Microsoft\Windows\spinlock-persist"
    assert rec["author"] == r"SHIELDBASE\rsydow-a"
    # Principal
    p = rec["principal"]
    assert p["user_id"] == "S-1-5-18"
    assert p["logon_type"] == "InteractiveToken"
    assert p["run_level"] == "HighestAvailable"


def test_parse_task_xml_extracts_triggers() -> None:
    out = parse_task_xml(_fixture("task_xml_sample.xml"))
    triggers = out["rows"][0]["triggers"]
    types = {t["type"] for t in triggers}
    assert "BootTrigger" in types
    assert "LogonTrigger" in types
    # LogonTrigger should have user_id
    logon = next(t for t in triggers if t["type"] == "LogonTrigger")
    assert logon["user_id"] == r"SHIELDBASE\rsydow-a"


def test_parse_task_xml_extracts_actions_with_command_args() -> None:
    out = parse_task_xml(_fixture("task_xml_sample.xml"))
    actions = out["rows"][0]["actions"]
    assert len(actions) == 1
    assert actions[0]["type"] == "Exec"
    assert actions[0]["command"].endswith("spinlock.exe")
    assert "-q" in (actions[0]["arguments"] or "")


def test_parse_task_xml_handles_invalid_xml() -> None:
    out = parse_task_xml("<<NOT XML>>")
    assert out["count"] == 0
    assert "_parse_error" in out


def test_parse_task_xml_handles_empty() -> None:
    out = parse_task_xml("")
    assert out["count"] == 0


def test_summarise_task_xml_includes_triggers_and_actions() -> None:
    out = parse_task_xml(_fixture("task_xml_sample.xml"))
    s = summarise_task_xml(out)
    assert "task" in s
    assert "trigger" in s
    assert "action" in s


# ---- Persistence keys (Phase 1.5, T1547 / T1574 disk-side) -----------------


def test_parse_persistence_keys_from_csv_groups_by_category() -> None:
    text = _fixture("persistence_keys_sample.csv")
    out = parse_persistence_keys_from_csv(text)
    sc = out["section_counts"]
    assert "run_keys" in sc
    assert "winlogon" in sc
    assert "ifeo" in sc
    assert "dll_hijack" in sc
    assert "services" in sc
    assert sc["run_keys"] == 3  # 3 HKLM Run rows in the fixture


def test_parse_persistence_keys_preserves_value_data() -> None:
    out = parse_persistence_keys_from_csv(_fixture("persistence_keys_sample.csv"))
    run_keys = out["sections"]["run_keys"]["rows"]
    # The suspicious "p.exe" Run entry should be present
    sus = next((r for r in run_keys if r["value_name"] == "p.exe"), None)
    assert sus is not None
    assert "temp" in (sus["value_data"] or "").lower()


def test_parse_persistence_keys_total_equals_section_sum() -> None:
    out = parse_persistence_keys_from_csv(_fixture("persistence_keys_sample.csv"))
    assert out["total_count"] == sum(out["section_counts"].values())


def test_parse_persistence_keys_round_trip() -> None:
    """parse_persistence_keys(json_text) re-hydrates the from_csv output."""
    import json
    parsed = parse_persistence_keys_from_csv(_fixture("persistence_keys_sample.csv"))
    text = json.dumps(parsed)
    rehydrated = parse_persistence_keys(text)
    assert rehydrated["section_counts"] == parsed["section_counts"]


def test_parse_persistence_keys_empty_text() -> None:
    assert parse_persistence_keys("").get("total_count") == 0


def test_summarise_persistence_keys_mentions_top_category() -> None:
    out = parse_persistence_keys_from_csv(_fixture("persistence_keys_sample.csv"))
    s = summarise_persistence_keys(out)
    assert "persistence values" in s
    assert "run_keys" in s
