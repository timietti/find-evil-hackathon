"""Parsers for Volatility 3 plugin output.

Each parser is a pure function: `parse_<plugin>(stdout: str) -> dict`. No subprocess
calls, no I/O. Designed to be exhaustively unit-tested against captured fixtures.

Vol3 default output is tab-separated. The first non-empty section is the header
(`Variable\tValue` for windows.info; column names like `PID\tPPID\t...` for table
plugins). Then a blank line, then rows.

This module returns dicts shaped to be embedded directly into our audit log's
`parsed_summary` field. Keys use snake_case so they're stable across plugins.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


VOL3_BANNER = re.compile(r"^Volatility 3 Framework", re.MULTILINE)


def _strip_banner(stdout: str) -> str:
    """Remove the Volatility banner line so parsers see only data."""
    return VOL3_BANNER.sub("", stdout, count=1).lstrip("\n")


def _split_kv_table(stdout: str) -> list[tuple[str, str]]:
    """For plugins that output a single 2-column key/value table (e.g. windows.info).

    Output rows are tab-separated. The header is `Variable\tValue`. We skip the
    header and any blank lines, returning [(key, value), ...].
    """
    rows: list[tuple[str, str]] = []
    body = _strip_banner(stdout)
    lines = body.splitlines()
    seen_header = False
    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue
        # Header line is exactly "Variable\tValue"
        if not seen_header and line.split("\t", 1) == ["Variable", "Value"]:
            seen_header = True
            continue
        if "\t" not in line:
            continue
        k, v = line.split("\t", 1)
        rows.append((k.strip(), v.strip()))
    return rows


def parse_image_info(stdout: str) -> dict[str, Any]:
    """Parse `vol -q -f <image> windows.info` output.

    Returns a dict with normalised keys: os, build, arch, is64bit, cpus,
    system_time_utc, system_root, kernel_base, dtb, symbols_resolved, raw (the
    original key/value pairs preserved for audit).
    """
    pairs = dict(_split_kv_table(stdout))

    nt_major = pairs.get("NtMajorVersion")
    nt_minor = pairs.get("NtMinorVersion")
    major_minor = pairs.get("Major/Minor")  # e.g. "15.19041"
    build = None
    if major_minor and "." in major_minor:
        # Format is "<NTBuildNumber>.<RevisionMinor>" — the RHS is the build.
        build = major_minor.split(".", 1)[1]

    is64 = pairs.get("Is64Bit", "").lower() == "true"
    arch = "x64" if is64 else "x86"

    cpus_raw = pairs.get("KeNumberProcessors", "")
    try:
        cpus: int | None = int(cpus_raw)
    except ValueError:
        cpus = None

    system_time_utc = _parse_system_time(pairs.get("SystemTime", ""))

    # Symbols line looks like:  file:///.../ntkrnlmp.pdb/<GUID>-1.json.xz
    # Presence of a file:// URI means symbols were resolved successfully.
    symbols_uri = pairs.get("Symbols", "")
    symbols_resolved = symbols_uri.startswith("file://")

    os_name = "Windows"
    if nt_major == "10":
        os_name = "Windows 10/11"  # NT 10.0 covers both; build disambiguates
    elif nt_major == "6":
        if nt_minor == "1":
            os_name = "Windows 7 / Server 2008 R2"
        elif nt_minor == "2":
            os_name = "Windows 8 / Server 2012"
        elif nt_minor == "3":
            os_name = "Windows 8.1 / Server 2012 R2"
        elif nt_minor == "0":
            os_name = "Windows Vista / Server 2008"
    elif nt_major == "5":
        if nt_minor == "1":
            os_name = "Windows XP"
        elif nt_minor == "2":
            os_name = "Windows XP x64 / Server 2003"

    return {
        "os": os_name,
        "build": build,
        "arch": arch,
        "is64bit": is64,
        "cpus": cpus,
        "system_time_utc": system_time_utc,
        "system_root": pairs.get("NtSystemRoot"),
        "product_type": pairs.get("NtProductType"),
        "kernel_base": pairs.get("Kernel Base"),
        "dtb": pairs.get("DTB"),
        "symbols_resolved": symbols_resolved,
        "symbols_uri": symbols_uri or None,
        "nt_major": nt_major,
        "nt_minor": nt_minor,
        "raw": pairs,
    }


def summarise_image_info(parsed: dict[str, Any]) -> str:
    """One-line summary suitable for the audit log's `summary` field."""
    parts = [
        parsed.get("os") or "?",
        f"build {parsed.get('build') or '?'}",
        parsed.get("arch") or "?",
        f"{parsed.get('cpus') or '?'} CPU",
    ]
    sysT = parsed.get("system_time_utc")
    if sysT:
        parts.append(f"captured {sysT}")
    if not parsed.get("symbols_resolved"):
        parts.append("[symbols missing]")
    return " · ".join(parts)


def _parse_system_time(raw: str) -> str | None:
    """Convert Vol3's `SystemTime` field to an ISO-8601 UTC timestamp.

    Vol3 emits formats like `2020-11-16 02:32:38+00:00`.
    """
    raw = raw.strip()
    if not raw:
        return None
    # Try a couple of common formats Vol3 has emitted across versions.
    for fmt in (
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S+00:00",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return raw  # last-resort: return as-is so callers can see the unparsed value
