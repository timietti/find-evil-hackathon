"""Unit tests for `mcp_server.parsers.threat_hunt` — pure-function parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_server.parsers.threat_hunt import (
    parse_bulk_extractor,
    parse_bulk_extractor_dir,
    parse_hash_result,
    parse_strings,
    parse_vadyarascan,
    parse_yara,
    summarise_bulk_extractor,
    summarise_hash_result,
    summarise_strings,
    summarise_yara,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "threat_hunt"


def _fixture(name: str) -> str:
    p = FIXTURES / name
    if not p.exists() or p.stat().st_size == 0:
        pytest.skip(f"missing fixture: {name}")
    return p.read_text(errors="replace")


# ---- YARA (CLI output) ------------------------------------------------------


def test_parse_yara_extracts_rule_matches() -> None:
    out = parse_yara(_fixture("yara_output.txt"))
    assert out["count"] == 3
    rules = {r["rule"] for r in out["rows"]}
    assert "SIFTOWL_Mimikatz_Strings" in rules
    assert "SIFTOWL_PowerShell_EncodedCommand" in rules
    assert "SIFTOWL_CobaltStrike_Beacon_Indicators" in rules


def test_parse_yara_extracts_matched_strings_under_dash_s() -> None:
    out = parse_yara(_fixture("yara_output.txt"))
    mimi = next(r for r in out["rows"] if r["rule"] == "SIFTOWL_Mimikatz_Strings")
    assert len(mimi["strings_matched"]) == 3
    # Each matched string has offset + id + bytes
    s0 = mimi["strings_matched"][0]
    assert s0["offset"] == "0x12340"
    assert s0["string_id"] == "$m1"
    assert "sekurlsa" in s0["bytes"]


def test_parse_yara_extracts_meta_kv() -> None:
    out = parse_yara(_fixture("yara_output.txt"))
    mimi = next(r for r in out["rows"] if r["rule"] == "SIFTOWL_Mimikatz_Strings")
    assert mimi["meta"]["mitre"] == "T1003"
    assert mimi["meta"]["severity"] == "high"


def test_parse_yara_rule_counts() -> None:
    out = parse_yara(_fixture("yara_output.txt"))
    assert sum(out["rule_counts"].values()) == out["count"]
    # Mimikatz has 1 match (the rule, not the 3 matched strings)
    assert out["rule_counts"]["SIFTOWL_Mimikatz_Strings"] == 1


def test_parse_yara_handles_empty() -> None:
    out = parse_yara("")
    assert out["count"] == 0
    assert out["rows"] == []


def test_summarise_yara_lists_top_rules() -> None:
    out = parse_yara(_fixture("yara_output.txt"))
    s = summarise_yara(out)
    assert "YARA matches" in s
    assert "SIFTOWL_" in s


# ---- vol3_vadyarascan (jsonl output) ---------------------------------------


def test_parse_vadyarascan_extracts_per_match_records() -> None:
    out = parse_vadyarascan(_fixture("vadyarascan_head.jsonl"))
    assert out["count"] == 3
    # 2 matches on PID 1912, 1 on PID 8260
    assert out["rule_counts"]["SIFTOWL_PyInstaller_Packed"] == 2
    assert out["rule_counts"]["SIFTOWL_CobaltStrike_Beacon_Indicators"] == 1


def test_parse_vadyarascan_preserves_pid_and_offset() -> None:
    out = parse_vadyarascan(_fixture("vadyarascan_head.jsonl"))
    p = next(r for r in out["rows"] if r["process"] == "p.exe")
    assert p["pid"] == 8260
    assert p["rule"] == "SIFTOWL_CobaltStrike_Beacon_Indicators"
    assert p["offset"] == "0x20000000"


def test_parse_vadyarascan_handles_empty() -> None:
    out = parse_vadyarascan("")
    assert out["count"] == 0


# ---- bulk_extractor (multi-file directory) ---------------------------------


BE_FIXTURE_DIR = FIXTURES / "bulk_extractor_sample"


def test_parse_bulk_extractor_finds_scanner_sections() -> None:
    if not BE_FIXTURE_DIR.exists():
        pytest.skip("missing bulk_extractor fixture dir")
    out = parse_bulk_extractor_dir(BE_FIXTURE_DIR)
    fc = out["feature_counts"]
    assert "url" in fc
    assert "email" in fc
    assert "ip" in fc
    assert "winpe" in fc
    assert fc["url"] == 3
    assert fc["email"] == 2
    assert fc["ip"] == 3
    assert fc["winpe"] == 2


def test_parse_bulk_extractor_features_preserve_offset() -> None:
    out = parse_bulk_extractor_dir(BE_FIXTURE_DIR)
    url_section = out["sections"]["url"]
    # First URL is the evil C2 at offset 12345
    first = url_section["top_features"][0]
    assert first["offset"] == "12345"
    assert "evil-c2" in first["feature"]


def test_parse_bulk_extractor_total_equals_sum() -> None:
    out = parse_bulk_extractor_dir(BE_FIXTURE_DIR)
    assert out["total_features"] == sum(out["feature_counts"].values())


def test_parse_bulk_extractor_skips_comments() -> None:
    """# header lines must not count as features."""
    out = parse_bulk_extractor_dir(BE_FIXTURE_DIR)
    # The url.txt fixture has 3 # comment lines + 3 features → count=3
    assert out["feature_counts"]["url"] == 3


def test_parse_bulk_extractor_round_trip_json() -> None:
    parsed = parse_bulk_extractor_dir(BE_FIXTURE_DIR)
    rehydrated = parse_bulk_extractor(json.dumps(parsed))
    assert rehydrated["feature_counts"] == parsed["feature_counts"]


def test_parse_bulk_extractor_empty_text() -> None:
    out = parse_bulk_extractor("")
    assert out["total_features"] == 0


def test_summarise_bulk_extractor_lists_top_scanners() -> None:
    parsed = parse_bulk_extractor_dir(BE_FIXTURE_DIR)
    s = summarise_bulk_extractor(parsed)
    assert "features" in s and "scanners" in s
    assert "url" in s or "ip" in s


# ---- bstrings ---------------------------------------------------------------


def test_parse_strings_filters_below_min_length() -> None:
    out = parse_strings(_fixture("bstrings_sample.txt"), min_length=6)
    # The fixture has short strings like "qX", "abc" that should be filtered
    short_strings = [r for r in out["rows"] if r["length"] < 6]
    assert short_strings == []


def test_parse_strings_extracts_high_signal_strings() -> None:
    out = parse_strings(_fixture("bstrings_sample.txt"), min_length=6)
    rendered = [r["string"] for r in out["rows"]]
    assert any("evil-c2" in s for s in rendered)
    assert any("ReflectiveLoader" in s for s in rendered)
    assert any("_MEIPASS2" in s for s in rendered)
    # PDB path is a classic dev-leak forensic signal
    assert any("\\beacon\\Release\\beacon.pdb" in s for s in rendered)


def test_parse_strings_length_buckets() -> None:
    out = parse_strings(_fixture("bstrings_sample.txt"), min_length=6)
    lb = out["length_buckets"]
    # At least one short bucket entry should be present
    assert sum(lb.values()) == out["count"]


def test_summarise_strings_includes_bracket_distribution() -> None:
    out = parse_strings(_fixture("bstrings_sample.txt"), min_length=6)
    s = summarise_strings(out)
    assert "strings" in s


# ---- hash_file --------------------------------------------------------------


def test_parse_hash_result_passes_through_json() -> None:
    payload = '{"size_bytes": 1024, "md5": "abc", "sha1": "def", "sha256": "ghi", "ssdeep": null}'
    parsed = parse_hash_result(payload)
    assert parsed["sha256"] == "ghi"
    assert parsed["size_bytes"] == 1024


def test_parse_hash_result_handles_invalid() -> None:
    parsed = parse_hash_result("not json")
    assert "_parse_error" in parsed


def test_summarise_hash_result_renders_sha256_prefix() -> None:
    out = parse_hash_result('{"size_bytes": 2048, "sha256": "abcdef1234567890abcdef1234567890"}')
    s = summarise_hash_result(out)
    assert "sha256=abcdef1234567890" in s
    assert "2,048" in s
