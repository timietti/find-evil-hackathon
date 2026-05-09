"""Unit tests for `mcp_server.parsers.vol3` — pure-function parsing tests.

Fixtures: real Vol3 windows.info captures from the case intake, kept in
`eval/cases/<case_id>/intake/`. We intentionally test against real captured
output rather than synthetic fixtures so parser regressions surface immediately.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_server.parsers.vol3 import (
    parse_image_info,
    summarise_image_info,
    _parse_system_time,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_fixture(rel: str) -> str:
    p = REPO_ROOT / rel
    if not p.exists():
        pytest.skip(f"fixture missing: {rel}")
    return p.read_text(errors="replace")


def test_parse_image_info_rocba_win10() -> None:
    """ROCBA-001: Windows 10 build 19041 x64, captured 2020-11-16."""
    text = _read_fixture("eval/cases/rocba-001/intake/rocba_windows_info.txt")
    out = parse_image_info(text)
    assert out["os"] == "Windows 10/11"
    assert out["build"] == "19041"
    assert out["arch"] == "x64"
    assert out["is64bit"] is True
    assert out["cpus"] == 4
    assert out["system_time_utc"] == "2020-11-16T02:32:38Z"
    assert out["system_root"] == "C:\\WINDOWS"
    assert out["product_type"] == "NtProductWinNt"
    assert out["symbols_resolved"] is True
    assert out["symbols_uri"].startswith("file://")
    # The raw key/value table should be preserved for audit.
    assert "Kernel Base" in out["raw"]
    assert "Major/Minor" in out["raw"]


def test_summarise_image_info_human_readable() -> None:
    parsed = {
        "os": "Windows 10/11",
        "build": "19041",
        "arch": "x64",
        "cpus": 4,
        "system_time_utc": "2020-11-16T02:32:38Z",
        "symbols_resolved": True,
    }
    s = summarise_image_info(parsed)
    assert "Windows 10/11" in s
    assert "build 19041" in s
    assert "x64" in s
    assert "4 CPU" in s
    assert "captured 2020-11-16T02:32:38Z" in s
    assert "[symbols missing]" not in s


def test_summarise_image_info_flags_missing_symbols() -> None:
    parsed = {
        "os": "Windows 10/11",
        "build": "19041",
        "arch": "x64",
        "cpus": 4,
        "system_time_utc": None,
        "symbols_resolved": False,
    }
    s = summarise_image_info(parsed)
    assert "[symbols missing]" in s


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2020-11-16 02:32:38+00:00", "2020-11-16T02:32:38Z"),
        ("2020-11-16 02:32:38",       "2020-11-16T02:32:38Z"),
        ("",                          None),
    ],
)
def test_parse_system_time(raw: str, expected: str | None) -> None:
    assert _parse_system_time(raw) == expected


def test_parse_image_info_handles_empty_input() -> None:
    out = parse_image_info("")
    # Should return a dict with all keys present, mostly None/falsy.
    assert "os" in out
    assert out["is64bit"] is False
    assert out["cpus"] is None
    assert out["raw"] == {}


def test_parse_image_info_handles_just_banner() -> None:
    out = parse_image_info("Volatility 3 Framework 2.28.0\n\n")
    assert out["raw"] == {}
