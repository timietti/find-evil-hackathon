"""Parsers for EZ Tools (Eric Zimmerman) output.

Pure-function parsers — given the tool's stdout-redirected file content,
return a structured dict shaped to embed into our audit log's
`parsed_summary`. Same shape as `parsers.vol3` and `parsers.disk`.

Tools wrapped here:
  - MFTECmd       (--json)  — NTFS $MFT records
  - AppCompatCacheParser (--csv) — ShimCache program execution
  - EvtxECmd      (--json)  — Windows Event Logs
  - AmcacheParser (--csv)   — Amcache.hve program-execution registry (Win8.1+)
"""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import Any

from mcp_server.parsers.vol3 import parse_jsonl_rows, _normalise_dt


# ---------------------------------------------------------------------------
# MFTECmd — NTFS $MFT records.
#
# Output format: line-delimited JSON (NDJSON), one entry per FILE record.
# Sample fields: EntryNumber, SequenceNumber, ParentEntryNumber, InUse,
# ParentPath, FileName, Extension, IsDirectory, HasAds, FileSize,
# Created0x10, LastModified0x10, LastRecordChange0x10, LastAccess0x10,
# Timestomped, uSecZeros, Copied (anti-forensic flags).
# ---------------------------------------------------------------------------


def parse_mft(stdout: str) -> dict[str, Any]:
    """Parse MFTECmd JSON output (one record per line)."""
    rows = parse_jsonl_rows(stdout)
    out_rows: list[dict[str, Any]] = []
    by_extension: dict[str, int] = {}
    by_parent_path: dict[str, int] = {}
    timestomped_count = 0
    usec_zeros_count = 0
    copied_count = 0
    in_use_count = 0
    deleted_count = 0
    directory_count = 0
    ads_count = 0

    for r in rows:
        in_use = bool(r.get("InUse"))
        is_dir = bool(r.get("IsDirectory"))
        has_ads = bool(r.get("HasAds"))
        timestomped = bool(r.get("Timestomped"))
        usec_zeros = bool(r.get("uSecZeros"))
        copied = bool(r.get("Copied"))

        if in_use:
            in_use_count += 1
        else:
            deleted_count += 1
        if is_dir:
            directory_count += 1
        if has_ads:
            ads_count += 1
        if timestomped:
            timestomped_count += 1
        if usec_zeros:
            usec_zeros_count += 1
        if copied:
            copied_count += 1

        ext = (r.get("Extension") or "").lstrip(".").lower()
        if ext and len(ext) <= 8 and ext.isalnum():
            by_extension[ext] = by_extension.get(ext, 0) + 1
        parent = r.get("ParentPath") or ""
        if parent:
            top = parent.split("\\", 1)[0].split("/", 1)[0]
            if top and top != ".":
                by_parent_path[top] = by_parent_path.get(top, 0) + 1

        out_rows.append({
            "entry":          r.get("EntryNumber"),
            "sequence":       r.get("SequenceNumber"),
            "parent_entry":   r.get("ParentEntryNumber"),
            "in_use":         in_use,
            "parent_path":    parent,
            "file_name":      r.get("FileName"),
            "extension":      r.get("Extension"),
            "is_directory":   is_dir,
            "has_ads":        has_ads,
            "is_ads":         bool(r.get("IsAds")),
            "file_size":      r.get("FileSize"),
            "created":        _normalise_dt(r.get("Created0x10")),
            "modified":       _normalise_dt(r.get("LastModified0x10")),
            "record_changed": _normalise_dt(r.get("LastRecordChange0x10")),
            "accessed":       _normalise_dt(r.get("LastAccess0x10")),
            "timestomped":    timestomped,
            "usec_zeros":     usec_zeros,
            "copied":         copied,
        })

    return {
        "count":             len(out_rows),
        "in_use":            in_use_count,
        "deleted":           deleted_count,
        "directories":       directory_count,
        "ads_count":         ads_count,
        "timestomped_count": timestomped_count,
        "usec_zeros_count":  usec_zeros_count,
        "copied_count":      copied_count,
        "by_extension":      dict(sorted(by_extension.items(), key=lambda kv: -kv[1])[:20]),
        "by_parent_path":    dict(sorted(by_parent_path.items(), key=lambda kv: -kv[1])[:10]),
        "rows":              out_rows,
    }


def summarise_mft(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    deleted = parsed.get("deleted", 0)
    ts = parsed.get("timestomped_count", 0)
    parts = [f"{n} MFT entries", f"{deleted} deleted"]
    if ts:
        parts.append(f"{ts} timestomped")
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# AppCompatCacheParser — ShimCache from SYSTEM hive.
#
# Output format: CSV. Columns: ControlSet,CacheEntryPosition,Path,
# LastModifiedTimeUTC,Executed,Duplicate,SourceFile.
# ---------------------------------------------------------------------------


def parse_shimcache(stdout: str) -> dict[str, Any]:
    """Parse AppCompatCacheParser CSV output."""
    if not stdout.strip():
        return {"count": 0, "entries": [], "by_extension": {}, "by_parent_dir": {}}
    reader = csv.DictReader(io.StringIO(stdout))
    entries: list[dict[str, Any]] = []
    by_extension: dict[str, int] = {}
    by_parent_dir: dict[str, int] = {}
    by_control_set: dict[str, int] = {}

    for row in reader:
        path = row.get("Path") or ""
        ext = ""
        if "." in path:
            ext = path.rsplit(".", 1)[-1].lower()
            if len(ext) <= 8 and ext.isalnum():
                by_extension[ext] = by_extension.get(ext, 0) + 1
        parent_dir = ""
        if "\\" in path:
            parent_dir = path.rsplit("\\", 1)[0]
        if parent_dir:
            by_parent_dir[parent_dir] = by_parent_dir.get(parent_dir, 0) + 1
        cs = row.get("ControlSet") or ""
        if cs:
            by_control_set[cs] = by_control_set.get(cs, 0) + 1

        entries.append({
            "control_set":   cs,
            "position":      _try_int(row.get("CacheEntryPosition")),
            "path":          path,
            "last_modified": _normalise_dt(row.get("LastModifiedTimeUTC")),
            "executed":      row.get("Executed"),
            "duplicate":     (row.get("Duplicate") or "").lower() == "true",
        })

    return {
        "count":          len(entries),
        "by_extension":   dict(sorted(by_extension.items(), key=lambda kv: -kv[1])[:20]),
        "by_parent_dir":  dict(sorted(by_parent_dir.items(), key=lambda kv: -kv[1])[:10]),
        "by_control_set": by_control_set,
        "entries":        entries,
    }


def summarise_shimcache(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    if n == 0:
        return "no ShimCache entries"
    cs = parsed.get("by_control_set") or {}
    cs_str = " + ".join(f"CS{k}" for k in sorted(cs.keys())) if cs else ""
    return f"{n} ShimCache entries{(' (' + cs_str + ')') if cs_str else ''}"


# ---------------------------------------------------------------------------
# EvtxECmd — Windows Event Logs (single .evtx file mode).
#
# Output format: line-delimited JSON. Sample fields: EventId, RecordNumber,
# TimeCreated, Channel, Provider, Computer, ProcessId, ThreadId, Level,
# Keywords, MapDescription (high-level event summary), Payload (raw event
# data as JSON-encoded string), plus PayloadData1..PayloadData5 (mapped
# from common event-data fields), UserName, RemoteHost, ExecutableInfo.
# ---------------------------------------------------------------------------


def parse_evtx(stdout: str) -> dict[str, Any]:
    """Parse EvtxECmd JSON output (one event per line).

    `stdout` may have a leading UTF-8 BOM (EvtxECmd writes one); we strip it
    before line-by-line parse.
    """
    cleaned = stdout.lstrip("﻿")
    rows = parse_jsonl_rows(cleaned)
    events: list[dict[str, Any]] = []
    by_event_id: dict[int, int] = {}
    by_channel: dict[str, int] = {}
    by_computer: dict[str, int] = {}
    by_provider: dict[str, int] = {}

    for r in rows:
        eid_raw = r.get("EventId")
        try:
            eid: int | None = int(eid_raw) if eid_raw is not None else None
        except (ValueError, TypeError):
            eid = None
        channel = r.get("Channel") or ""
        computer = r.get("Computer") or ""
        provider = r.get("Provider") or ""

        if eid is not None:
            by_event_id[eid] = by_event_id.get(eid, 0) + 1
        if channel:
            by_channel[channel] = by_channel.get(channel, 0) + 1
        if computer:
            by_computer[computer] = by_computer.get(computer, 0) + 1
        if provider:
            by_provider[provider] = by_provider.get(provider, 0) + 1

        events.append({
            "event_id":         eid,
            "record_number":    r.get("RecordNumber"),
            "time_created":     _normalise_dt(r.get("TimeCreated")),
            "channel":          channel,
            "provider":         provider,
            "computer":         computer,
            "level":            r.get("Level"),
            "process_id":       r.get("ProcessId"),
            "thread_id":        r.get("ThreadId"),
            "user_name":        r.get("UserName"),
            "remote_host":      r.get("RemoteHost"),
            "executable_info":  r.get("ExecutableInfo"),
            "map_description":  r.get("MapDescription"),
            # Compact view of mapped payload data — these are the human-readable
            # fields EvtxECmd extracts from the raw event payload. Full raw
            # payload preserved on disk in raw_output_path.
            "payload_summary":  {
                "data1": r.get("PayloadData1"),
                "data2": r.get("PayloadData2"),
                "data3": r.get("PayloadData3"),
                "data4": r.get("PayloadData4"),
                "data5": r.get("PayloadData5"),
            },
        })

    return {
        "count":      len(events),
        "by_event_id": dict(sorted(by_event_id.items(), key=lambda kv: -kv[1])[:20]),
        "by_channel":  dict(sorted(by_channel.items(),  key=lambda kv: -kv[1])[:10]),
        "by_computer": dict(sorted(by_computer.items(), key=lambda kv: -kv[1])[:10]),
        "by_provider": dict(sorted(by_provider.items(), key=lambda kv: -kv[1])[:10]),
        "events":      events,
    }


def summarise_evtx(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    if n == 0:
        return "no events parsed"
    top_ids = list((parsed.get("by_event_id") or {}).items())[:3]
    top_str = ", ".join(f"EID {k}×{v}" for k, v in top_ids) if top_ids else ""
    return f"{n} events; top: {top_str}"


# ---------------------------------------------------------------------------
# AmcacheParser — Amcache.hve program-execution registry (Win8.1+).
#
# AmcacheParser writes one CSV per artifact category into the output
# directory. Modern (Win10) Amcache emits ~6-8 files; legacy (Win8.1 / early
# Win10) emits a slightly different set. We parse every CSV we find and
# expose them as named sections with per-section row truncation.
#
# The most DFIR-relevant sections:
#   - UnassociatedFileEntries (a.k.a. InventoryApplicationFile, Win10) —
#     every program that ran, with SHA-1, FileName, FullPath, ProductName,
#     Size, FileVersion, registry-key timestamps. The program-execution
#     evidence backbone on modern Windows.
#   - AssociatedFileEntries (legacy Win8.1 / pre-1803 Win10) — equivalent
#     to UnassociatedFileEntries on older OSes.
#   - ProgramEntries (InventoryApplication) — installed-program inventory.
#   - ShortCuts — .lnk files referenced by Amcache.
#   - DriverBinaries / DriverPackages / DeviceContainers / DevicePnps —
#     hardware/driver enumeration; lower-signal for malware triage.
# ---------------------------------------------------------------------------


# Map AmcacheParser CSV filename suffix → semantic section key. The
# filenames take the form `<timestamp>_Amcache_<Suffix>.csv`.
_AMCACHE_SECTION_FROM_SUFFIX: dict[str, str] = {
    "AssociatedFileEntries":   "associated_file_entries",
    "UnassociatedFileEntries": "unassociated_file_entries",
    "ProgramEntries":          "program_entries",
    "ShortCuts":               "shortcuts",
    "DriverBinaries":          "driver_binaries",
    "DriverPackages":          "driver_packages",
    "DeviceContainers":        "device_containers",
    "DevicePnps":              "device_pnps",
}

# Sections considered "execution evidence" — surfaced in the one-line
# summary string so the agent knows the high-signal counts at a glance.
_AMCACHE_EXEC_SECTIONS = (
    "associated_file_entries",
    "unassociated_file_entries",
    "program_entries",
)


def _amcache_section_for(csv_filename: str) -> str | None:
    """Map a `*_Amcache_<Suffix>.csv` filename to its section key."""
    m = re.search(r"_Amcache_([A-Za-z]+)\.csv$", csv_filename)
    if not m:
        return None
    return _AMCACHE_SECTION_FROM_SUFFIX.get(m.group(1))


def _amcache_normalise_row(section: str, row: dict[str, str]) -> dict[str, Any]:
    """Light per-section field normalisation.

    AmcacheParser column names vary by section and Win build. We keep all
    fields the tool emits (lower-cased keys for consistency) and additionally
    normalise the common timestamp columns to the 'YYYY-MM-DDTHH:MM:SSZ'
    UTC form used elsewhere in the audit log.
    """
    out: dict[str, Any] = {}
    for k, v in row.items():
        if k is None:
            continue
        norm_key = k.replace(" ", "_").lower()
        out[norm_key] = v
    # Normalise common timestamp-bearing columns where present.
    for ts_field in (
        "key_last_write_timestamp",
        "last_modified_store",
        "last_modified",
        "link_date",
        "install_date",
        "install_date_arp_last_modified",
        "install_date_msi",
        "install_date_from_link_file",
        "binary_last_modified",
        "binary_first_run",
        "first_run",
        "driver_signed",
        "driver_last_write_time",
    ):
        if ts_field in out and out[ts_field]:
            out[ts_field] = _normalise_dt(out[ts_field])
    return out


def parse_amcache_from_dir(out_dir: Path) -> dict[str, Any]:
    """Scan an AmcacheParser output directory and build a structured dict.

    Returns:
        {
            "total_count": int,
            "section_counts": {section_key: int, ...},
            "sections": {
                section_key: {
                    "count": int,
                    "rows": [...],
                },
                ...
            },
            "unknown_files": [filename, ...],   # CSVs we couldn't classify
        }
    """
    sections: dict[str, dict[str, Any]] = {}
    unknown_files: list[str] = []
    for csv_path in sorted(out_dir.glob("*_Amcache_*.csv")):
        section = _amcache_section_for(csv_path.name)
        if section is None:
            unknown_files.append(csv_path.name)
            continue
        rows: list[dict[str, Any]] = []
        try:
            text = csv_path.read_text(errors="replace")
        except OSError:
            continue
        if not text.strip():
            sections[section] = {"count": 0, "rows": []}
            continue
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            rows.append(_amcache_normalise_row(section, row))
        sections[section] = {"count": len(rows), "rows": rows}

    section_counts = {k: v["count"] for k, v in sections.items()}
    return {
        "total_count":    sum(section_counts.values()),
        "section_counts": section_counts,
        "sections":       sections,
        "unknown_files":  unknown_files,
    }


def parse_amcache(text: str) -> dict[str, Any]:
    """Re-hydrate a previously serialised parse_amcache_from_dir result.

    The wrapper persists `parse_amcache_from_dir(out)` as JSON to the
    audit log's raw_output. This parser exists so `query_rows` can re-read
    the row lists. Just `json.loads`.
    """
    if not text.strip():
        return {
            "total_count": 0,
            "section_counts": {},
            "sections": {},
            "unknown_files": [],
        }
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "total_count": 0,
            "section_counts": {},
            "sections": {},
            "unknown_files": [],
            "_parse_error": "raw_output is not valid JSON",
        }


def summarise_amcache(parsed: dict[str, Any]) -> str:
    """Headline summary highlighting program-execution sections."""
    section_counts = parsed.get("section_counts") or {}
    if not section_counts:
        return "no Amcache sections parsed"
    exec_total = sum(section_counts.get(s, 0) for s in _AMCACHE_EXEC_SECTIONS)
    bits = [f"{parsed.get('total_count', 0)} entries across {len(section_counts)} sections"]
    if exec_total:
        bits.append(f"{exec_total} program-exec records")
    # Top 3 sections by count
    top = sorted(section_counts.items(), key=lambda kv: -kv[1])[:3]
    if top:
        bits.append("top: " + ", ".join(f"{k}×{v}" for k, v in top))
    return "; ".join(bits)


# ---------------------------------------------------------------------------
# Windows Prefetch (.pf) parser.
#
# Originally wrapped EZ Tools' PECmd, but PECmd v2026.5.0+ refuses to run on
# non-Windows platforms ("Non-Windows platforms not supported due to the need
# to load decompression specific Windows libraries"). Switched to libyal's
# `libscca` Python bindings (`pyscca`) which has a portable MAM/XPRESS-Huffman
# decompressor.
#
# parse_prefetch_file(path) does the actual parsing via pyscca and returns a
# dict shaped identically to what we surfaced to the agent before. The wrapper
# in `tools/ez_tools.py` serialises that dict to JSON in the audit raw_output,
# then `parse_prefetch(text)` is a json.loads re-hydrator used by query_rows.
# ---------------------------------------------------------------------------


def parse_prefetch_file(path: Path) -> dict[str, Any]:
    """Open a `.pf` file with libscca and return a structured dict.

    Returned shape (1 row, since one .pf file = one executable):
        {
          "count": 1,
          "total_runs": <int>,
          "by_executable": {exe: 1},
          "rows": [{
            "source_filename": <basename>,
            "executable_name": <exe>,
            "hash":            <8-hex>,
            "format_version":  <int>,
            "run_count":       <int>,
            "last_run":        <ISO timestamp>,
            "previous_runs":   [ISO, ISO, ...],
            "volume_name":     <str>,
            "volume_serial":   <hex>,
            "volume_created":  <ISO>,
            "files_loaded":    [<NT path>, ...],
            "directories":     [<NT path>, ...],
          }]
        }
    """
    try:
        import pyscca
    except ImportError as e:
        raise RuntimeError(
            "pyscca (libscca-python) not installed; install via "
            "`pip install libscca-python` or `bash scripts/bootstrap_sift_tools.sh`"
        ) from e

    pf = pyscca.file()
    pf.open(str(path))
    try:
        n_lasts = 8  # Win10+ stores 8 last-run timestamps; older versions 1
        last_runs: list[str] = []
        for i in range(n_lasts):
            try:
                t = pf.get_last_run_time(i)
            except (OSError, ValueError, IOError):
                break
            if t is None:
                continue
            last_runs.append(t.strftime("%Y-%m-%dT%H:%M:%SZ"))

        # Filenames loaded (DLLs, config) — these are NT paths
        n_files = pf.get_number_of_filenames()
        files_loaded = [pf.get_filename(i) for i in range(n_files)]

        # Volumes (typically 1)
        volume_info: dict[str, Any] = {}
        n_vols = pf.get_number_of_volumes()
        directories: list[str] = []
        if n_vols > 0:
            v0 = pf.get_volume_information(0)
            if v0 is not None:
                volume_info["device_path"]   = v0.device_path
                volume_info["serial_number"] = f"{v0.serial_number:08X}" if v0.serial_number is not None else None
                volume_info["creation_time"] = (
                    v0.creation_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                    if v0.creation_time else None
                )
                # libscca exposes directory_strings as a sub-list per volume
                n_dirs = getattr(v0, "number_of_directory_strings", 0) or 0
                for di in range(n_dirs):
                    try:
                        directories.append(v0.get_directory_string(di))
                    except (OSError, AttributeError, ValueError):
                        break

        executable = pf.get_executable_filename()
        prefetch_hash = pf.get_prefetch_hash()
        run_count = pf.get_run_count() or 0
        fmt_version = pf.get_format_version()

        row: dict[str, Any] = {
            "source_filename":  path.name,
            "executable_name":  executable,
            "hash":             f"{prefetch_hash:08X}" if prefetch_hash is not None else None,
            "format_version":   fmt_version,
            "run_count":        run_count,
            "last_run":         last_runs[0] if last_runs else None,
            "previous_runs":    last_runs[1:] if len(last_runs) > 1 else [],
            "volume_name":      volume_info.get("device_path"),
            "volume_serial":    volume_info.get("serial_number"),
            "volume_created":   volume_info.get("creation_time"),
            "files_loaded":     files_loaded,
            "directories":      directories,
        }
    finally:
        pf.close()

    by_executable = {(executable or "").lower(): 1} if executable else {}
    return {
        "count":         1,
        "total_runs":    int(run_count or 0),
        "by_executable": by_executable,
        "rows":          [row],
    }


def parse_prefetch(text: str) -> dict[str, Any]:
    """Re-hydrate a previously-serialised parse_prefetch_file result.

    The wrapper persists `parse_prefetch_file(path)` as JSON to audit
    raw_output. This parser exists so `query_rows` can re-read it.
    """
    if not text.strip():
        return {"count": 0, "total_runs": 0, "by_executable": {}, "rows": []}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "count": 0, "total_runs": 0, "by_executable": {}, "rows": [],
            "_parse_error": "raw_output is not valid JSON",
        }


def summarise_prefetch(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    if n == 0:
        return "no Prefetch records"
    runs = parsed.get("total_runs", 0)
    return f"{n} Prefetch records ({runs} cumulative runs)"


# ---------------------------------------------------------------------------
# JLECmd — Jump Lists parser (.automaticDestinations-ms / .customDestinations-ms).
#
# Each Jump List file is per-application (the filename is a CRC-32 of the
# appid). JLECmd emits one JSON object per DestList entry: AppId, EntryNumber,
# CreationTime, LastModified, Hostname, Path, Arguments, IconLocation,
# DriveType, VolumeSerialNumber, VolumeLabel, FileSize, MFTEntryNumber, etc.
# ---------------------------------------------------------------------------


def parse_jumplist(stdout: str) -> dict[str, Any]:
    """Parse JLECmd JSON output (one DestList entry per line).

    Jump Lists answer "what did the user open in app X". Recent files,
    pinned files, target paths (incl. external-drive paths even after the
    drive is detached). Critical for hands-on-keyboard investigation.
    """
    rows = parse_jsonl_rows(stdout)
    out_rows: list[dict[str, Any]] = []
    by_appid: dict[str, int] = {}
    by_drive: dict[str, int] = {}
    for r in rows:
        appid = (r.get("AppId") or r.get("AppIDDescription") or "").lower()
        drive = r.get("DriveType") or ""
        if appid:
            by_appid[appid] = by_appid.get(appid, 0) + 1
        if drive:
            by_drive[drive] = by_drive.get(drive, 0) + 1
        out_rows.append({
            "appid":           appid,
            "appid_description": r.get("AppIDDescription"),
            "entry_number":    r.get("EntryNumber"),
            "creation_time":   _normalise_dt(r.get("CreationTime")),
            "last_modified":   _normalise_dt(r.get("LastModified")),
            "hostname":        r.get("Hostname"),
            "path":            r.get("Path"),
            "arguments":       r.get("Arguments"),
            "drive_type":      drive,
            "volume_serial":   r.get("VolumeSerialNumber"),
            "volume_label":    r.get("VolumeLabel"),
            "mft_entry":       r.get("MFTEntryNumber"),
            "mft_sequence":    r.get("MFTSequenceNumber"),
            "file_size":       r.get("FileSize"),
            "tracker_mac":     r.get("MachineID") or r.get("TrackerCreatedOn"),
        })
    return {
        "count":      len(out_rows),
        "by_appid":   dict(sorted(by_appid.items(), key=lambda kv: -kv[1])[:30]),
        "by_drive":   by_drive,
        "rows":       out_rows,
    }


def summarise_jumplist(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    if n == 0:
        return "no Jump List entries"
    appid_count = len(parsed.get("by_appid") or {})
    return f"{n} Jump List entries across {appid_count} apps"


# ---------------------------------------------------------------------------
# RBCmd — Recycle Bin parser ($I records on Win10, INFO2 on XP).
#
# Output (JSON): SourceName, FileSize, DeletedOn, FileName.
# ---------------------------------------------------------------------------


def parse_recyclebin(stdout: str) -> dict[str, Any]:
    """Parse RBCmd JSON output (one record per deleted file)."""
    rows = parse_jsonl_rows(stdout)
    out_rows: list[dict[str, Any]] = []
    by_extension: dict[str, int] = {}
    for r in rows:
        fn = r.get("FileName") or ""
        ext = ""
        if "." in fn:
            ext = fn.rsplit(".", 1)[-1].lower()
            if ext.isalnum() and len(ext) <= 8:
                by_extension[ext] = by_extension.get(ext, 0) + 1
        out_rows.append({
            "source_name": r.get("SourceName"),
            "file_size":   r.get("FileSize"),
            "deleted_on":  _normalise_dt(r.get("DeletedOn")),
            "file_name":   fn,
        })
    return {
        "count":        len(out_rows),
        "by_extension": dict(sorted(by_extension.items(), key=lambda kv: -kv[1])[:20]),
        "rows":         out_rows,
    }


def summarise_recyclebin(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    if n == 0:
        return "no Recycle Bin records"
    return f"{n} Recycle Bin records"


# ---------------------------------------------------------------------------
# SRUM — System Resource Usage Monitor (Win8+).
#
# SRUDB.dat is an ESE database under `Windows\System32\sru\` that tracks,
# per app+user, accumulated network bytes in/out, wall-clock time used,
# push notifications, and energy state. Killer for exfil detection: "what
# process moved the most outbound bytes this hour".
#
# We parse the ESE database directly with libyal `libesedb` (pyesedb)
# because SrumECmd v2026.5.0 refuses to run on Linux ("Non-Windows
# platforms not supported due to the need to load ESI specific Windows
# libraries"). The provider tables (named by GUID inside the database):
#
#   {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}    App Resource Usage
#   {973F5D5C-1D90-4944-BE8E-24B94231A174}    Network Data Usage
#   {DD6636C4-8929-4683-974E-22C046A43763}    Network Connectivity
#   {D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}    Push Notifications
#   {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}    Energy Usage
#   {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT  Energy Usage (long-term)
#   {5C8CF1C7-7257-4F13-B223-970EF5939312}    App Timeline
#
# AppId / UserId columns are foreign keys into `SruDbIdMapTable`; we
# build that map once and join into every projected row.
# ---------------------------------------------------------------------------


import struct
from datetime import datetime, timedelta, timezone

# Map ESE table name -> our section key. Same keys as the old SrumECmd
# CSV-driven parser so consumers / fixtures don't have to change.
_SRUM_PROVIDER_SECTION: dict[str, str] = {
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}":   "app_resource_use",
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}":   "network_usage",
    "{DD6636C4-8929-4683-974E-22C046A43763}":   "network_connections",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}":   "push_notifications",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}":   "energy_usage",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT": "energy_usage_lt",
    "{5C8CF1C7-7257-4F13-B223-970EF5939312}":   "app_timeline",
}

_SRUM_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_SRUM_OLE_EPOCH      = datetime(1899, 12, 30, tzinfo=timezone.utc)


def _srum_ole_to_iso(raw: bytes | None) -> str | None:
    """Decode an 8-byte little-endian OLE Automation Date to ISO-Z UTC."""
    if not raw or len(raw) != 8:
        return None
    try:
        (d,) = struct.unpack("<d", raw)
    except struct.error:
        return None
    if d <= 0 or d != d:  # negative / NaN
        return None
    try:
        return (_SRUM_OLE_EPOCH + timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return None


def _srum_filetime_to_iso(value: int | None) -> str | None:
    """100ns-since-1601 (Windows FILETIME) -> ISO-Z UTC."""
    if not value or value <= 0:
        return None
    try:
        return (_SRUM_FILETIME_EPOCH + timedelta(microseconds=value // 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (OverflowError, ValueError):
        return None


def _srum_sid_to_str(raw: bytes) -> str:
    """Render a binary Windows SID as `S-1-5-...`."""
    if not raw or len(raw) < 8:
        return raw.hex() if raw else ""
    revision = raw[0]
    sub_count = raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    end = 8 + 4 * sub_count
    if len(raw) < end:
        return raw.hex()
    subs = [
        int.from_bytes(raw[8 + 4 * i : 12 + 4 * i], "little")
        for i in range(sub_count)
    ]
    return "S-" + "-".join([str(revision), str(authority)] + [str(x) for x in subs])


def _srum_decode_idmap_blob(idtype: int, blob: bytes | None) -> tuple[str, str | None]:
    """Decode one SruDbIdMapTable row's IdBlob using its IdType."""
    if blob is None:
        return ("empty", None)
    if idtype == 3:
        return ("user_sid", _srum_sid_to_str(blob) if blob else None)
    if idtype in (0, 1, 2):
        try:
            value = blob.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            value = blob.hex()
        kind = {0: "app_path", 1: "service", 2: "appx_name"}[idtype]
        return (kind, value)
    return ("unknown", blob.hex() if blob else None)


def _srum_build_id_map(esedb_file: Any) -> dict[int, tuple[str, str | None]]:
    """SruDbIdMapTable -> {IdIndex: (kind, decoded_value)}."""
    out: dict[int, tuple[str, str | None]] = {}
    for ti in range(esedb_file.get_number_of_tables()):
        table = esedb_file.get_table(ti)
        if table.get_name() != "SruDbIdMapTable":
            continue
        nrows = table.get_number_of_records()
        for ri in range(nrows):
            rec = table.get_record(ri)
            try:
                idtype = rec.get_value_data_as_integer(0)
                idx    = rec.get_value_data_as_integer(1)
                blob   = rec.get_value_data(2)
            except (OSError, IOError):
                continue
            if idx is None:
                continue
            out[idx] = _srum_decode_idmap_blob(idtype, blob)
        break
    return out


def _srum_safe_int(rec: Any, col_idx: int) -> int | None:
    """Pull an integer column, returning None when libesedb errors *or* when
    it hands back the "missing fixed column" sentinel (`*` byte pattern).

    ESE pre-allocates fixed-size columns even in records that never wrote
    them; libesedb fills those bytes with 0x2A (ASCII "*"). For an Int32
    that surfaces as 707406378; for an Int64, 3038287259199220266. Both
    are noise we don't want to ship to the agent — return None instead.
    """
    try:
        raw = rec.get_value_data(col_idx)
    except (OSError, IOError):
        return None
    if not raw:
        return None
    if all(b == 0x2A for b in raw):
        return None
    try:
        return rec.get_value_data_as_integer(col_idx)
    except (OSError, IOError, OverflowError):
        return None


def _srum_safe_raw(rec: Any, col_idx: int) -> bytes | None:
    try:
        raw = rec.get_value_data(col_idx)
    except (OSError, IOError):
        return None
    if raw and all(b == 0x2A for b in raw):
        return None
    return raw


def _srum_resolve_app(id_map: dict[int, tuple[str, str | None]],
                     app_id: int | None) -> dict[str, Any]:
    if app_id is None:
        return {"app_id": None, "app_name": None, "app_kind": None}
    entry = id_map.get(app_id)
    if not entry:
        return {"app_id": app_id, "app_name": None, "app_kind": None}
    kind, value = entry
    return {"app_id": app_id, "app_name": value, "app_kind": kind}


def _srum_resolve_user(id_map: dict[int, tuple[str, str | None]],
                      user_id: int | None) -> dict[str, Any]:
    if user_id is None:
        return {"user_id": None, "user_sid": None}
    entry = id_map.get(user_id)
    if not entry:
        return {"user_id": user_id, "user_sid": None}
    _kind, value = entry
    return {"user_id": user_id, "user_sid": value}


# Per-provider column projections. Indexes match the schemas confirmed
# against the libesedb table layout — see the inline comment in each.
# Each projector returns a flat dict suitable for query_rows.

def _project_app_resource_use(rec: Any, id_map: dict) -> dict[str, Any]:
    # Cols: AutoIncId TimeStamp AppId UserId FgCycleTime BgCycleTime FaceTime
    # FgCtxSw BgCtxSw FgBytesR FgBytesW FgNumR FgNumW FgFlush BgBytesR BgBytesW
    # BgNumR BgNumW BgFlush
    row: dict[str, Any] = {
        "auto_inc_id":            _srum_safe_int(rec, 0),
        "timestamp":              _srum_ole_to_iso(_srum_safe_raw(rec, 1)),
        **_srum_resolve_app(id_map, _srum_safe_int(rec, 2)),
        **_srum_resolve_user(id_map, _srum_safe_int(rec, 3)),
        "foreground_cycle_time":  _srum_safe_int(rec, 4),
        "background_cycle_time":  _srum_safe_int(rec, 5),
        "face_time":              _srum_safe_int(rec, 6),
        "foreground_bytes_read":  _srum_safe_int(rec, 9),
        "foreground_bytes_written": _srum_safe_int(rec, 10),
        "background_bytes_read":  _srum_safe_int(rec, 14),
        "background_bytes_written": _srum_safe_int(rec, 15),
    }
    return row


def _project_network_usage(rec: Any, id_map: dict) -> dict[str, Any]:
    # Cols: AutoIncId TimeStamp AppId UserId InterfaceLuid L2ProfileId
    # L2ProfileFlags BytesSent BytesRecvd
    return {
        "auto_inc_id":      _srum_safe_int(rec, 0),
        "timestamp":        _srum_ole_to_iso(_srum_safe_raw(rec, 1)),
        **_srum_resolve_app(id_map, _srum_safe_int(rec, 2)),
        **_srum_resolve_user(id_map, _srum_safe_int(rec, 3)),
        "interface_luid":   _srum_safe_int(rec, 4),
        "l2_profile_id":    _srum_safe_int(rec, 5),
        "l2_profile_flags": _srum_safe_int(rec, 6),
        "bytes_sent":       _srum_safe_int(rec, 7),
        "bytes_recvd":      _srum_safe_int(rec, 8),
    }


def _project_network_connections(rec: Any, id_map: dict) -> dict[str, Any]:
    # Cols: AutoIncId TimeStamp AppId UserId InterfaceLuid L2ProfileId
    # ConnectedTime ConnectStartTime L2ProfileFlags
    return {
        "auto_inc_id":         _srum_safe_int(rec, 0),
        "timestamp":           _srum_ole_to_iso(_srum_safe_raw(rec, 1)),
        **_srum_resolve_app(id_map, _srum_safe_int(rec, 2)),
        **_srum_resolve_user(id_map, _srum_safe_int(rec, 3)),
        "interface_luid":      _srum_safe_int(rec, 4),
        "l2_profile_id":       _srum_safe_int(rec, 5),
        "connected_time_s":    _srum_safe_int(rec, 6),
        "connect_start_time":  _srum_filetime_to_iso(_srum_safe_int(rec, 7)),
        "l2_profile_flags":    _srum_safe_int(rec, 8),
    }


def _project_push_notifications(rec: Any, id_map: dict) -> dict[str, Any]:
    # Cols: AutoIncId TimeStamp AppId UserId NotificationType PayloadSize NetworkType
    return {
        "auto_inc_id":       _srum_safe_int(rec, 0),
        "timestamp":         _srum_ole_to_iso(_srum_safe_raw(rec, 1)),
        **_srum_resolve_app(id_map, _srum_safe_int(rec, 2)),
        **_srum_resolve_user(id_map, _srum_safe_int(rec, 3)),
        "notification_type": _srum_safe_int(rec, 4),
        "payload_size":      _srum_safe_int(rec, 5),
        "network_type":      _srum_safe_int(rec, 6),
    }


def _project_energy_usage(rec: Any, id_map: dict, *, lt: bool) -> dict[str, Any]:
    # Both energy_usage and energy_usage_lt share cols 0..14; LT adds a
    # ConfigurationHash at col 15 (we surface it as hex).
    row: dict[str, Any] = {
        "auto_inc_id":        _srum_safe_int(rec, 0),
        "timestamp":          _srum_ole_to_iso(_srum_safe_raw(rec, 1)),
        **_srum_resolve_app(id_map, _srum_safe_int(rec, 2)),
        **_srum_resolve_user(id_map, _srum_safe_int(rec, 3)),
        "active_ac_time_s":   _srum_safe_int(rec, 4),
        "cs_ac_time_s":       _srum_safe_int(rec, 5),
        "active_dc_time_s":   _srum_safe_int(rec, 6),
        "cs_dc_time_s":       _srum_safe_int(rec, 7),
        "active_discharge_s": _srum_safe_int(rec, 8),
        "cs_discharge_s":     _srum_safe_int(rec, 9),
        "active_energy":      _srum_safe_int(rec, 10),
        "cs_energy":          _srum_safe_int(rec, 11),
        "designed_capacity":  _srum_safe_int(rec, 12),
        "full_charge_capacity": _srum_safe_int(rec, 13),
        "cycle_count":        _srum_safe_int(rec, 14),
    }
    if lt:
        cfg = _srum_safe_raw(rec, 15)
        row["configuration_hash"] = cfg.hex() if cfg else None
    return row


def _project_app_timeline(rec: Any, id_map: dict) -> dict[str, Any]:
    # 44 cols — project the high-value ones; the rest are mostly time-bin
    # blobs whose interpretation is undocumented enough that we surface
    # the integer scalars and skip the raw binary timelines.
    return {
        "auto_inc_id":          _srum_safe_int(rec, 0),
        "timestamp":            _srum_ole_to_iso(_srum_safe_raw(rec, 1)),
        **_srum_resolve_app(id_map, _srum_safe_int(rec, 2)),
        **_srum_resolve_user(id_map, _srum_safe_int(rec, 3)),
        "flags":                _srum_safe_int(rec, 4),
        "end_time":             _srum_filetime_to_iso(_srum_safe_int(rec, 5)),
        "duration_ms":          _srum_safe_int(rec, 6),
        "span_ms":              _srum_safe_int(rec, 7),
        "in_focus_s":           _srum_safe_int(rec, 20),
        "psm_foreground_s":     _srum_safe_int(rec, 21),
        "user_input_s":         _srum_safe_int(rec, 22),
        "audio_in_s":           _srum_safe_int(rec, 26),
        "audio_out_s":          _srum_safe_int(rec, 27),
        "display_required_s":   _srum_safe_int(rec, 39),
        "keyboard_input_s":     _srum_safe_int(rec, 42),
        "mouse_input_s":        _srum_safe_int(rec, 43),
    }


_SRUM_PROJECTORS: dict[str, Any] = {
    "app_resource_use":    _project_app_resource_use,
    "network_usage":       _project_network_usage,
    "network_connections": _project_network_connections,
    "push_notifications":  _project_push_notifications,
    "app_timeline":        _project_app_timeline,
}


def parse_srum_file(path: Path) -> dict[str, Any]:
    """In-process SRUDB.dat parser using libyal libesedb (pyesedb).

    Replaces the SrumECmd subprocess (which exits "Non-Windows platforms
    not supported" on Linux). Output shape mirrors the old CSV-driven
    parser so consumers (truncation, query_rows, summary) are unchanged.
    """
    try:
        import pyesedb
    except ImportError as e:
        raise RuntimeError(
            "pyesedb (libesedb-python3) not installed; install via "
            "`apt install libesedb-python3` or "
            "`bash scripts/bootstrap_sift_tools.sh`"
        ) from e

    f = pyesedb.file()
    f.open(str(path))
    try:
        id_map = _srum_build_id_map(f)
        sections: dict[str, dict[str, Any]] = {}
        unknown_tables: list[str] = []
        for ti in range(f.get_number_of_tables()):
            table = f.get_table(ti)
            tname = table.get_name()
            section = _SRUM_PROVIDER_SECTION.get(tname)
            if section is None:
                continue
            if section in ("energy_usage", "energy_usage_lt"):
                projector = lambda r, m, lt=(section == "energy_usage_lt"): (
                    _project_energy_usage(r, m, lt=lt)
                )
            else:
                projector = _SRUM_PROJECTORS.get(section)
            if projector is None:
                unknown_tables.append(tname)
                continue
            rows: list[dict[str, Any]] = []
            for ri in range(table.get_number_of_records()):
                try:
                    rec = table.get_record(ri)
                    rows.append(projector(rec, id_map))
                except (OSError, IOError):
                    continue
            sections[section] = {"count": len(rows), "rows": rows}
    finally:
        f.close()

    section_counts = {k: v["count"] for k, v in sections.items()}
    id_map_summary = {
        "total":     len(id_map),
        "app_path":  sum(1 for v in id_map.values() if v[0] == "app_path"),
        "service":   sum(1 for v in id_map.values() if v[0] == "service"),
        "appx_name": sum(1 for v in id_map.values() if v[0] == "appx_name"),
        "user_sid":  sum(1 for v in id_map.values() if v[0] == "user_sid"),
    }
    return {
        "total_count":    sum(section_counts.values()),
        "section_counts": section_counts,
        "sections":       sections,
        "unknown_files":  unknown_tables,
        "id_map_summary": id_map_summary,
    }


def parse_srum(text: str) -> dict[str, Any]:
    """Re-hydrate a previously-serialised parse_srum_file result.

    The wrapper persists `parse_srum_file(path)` as JSON to raw_output;
    this parser is just `json.loads` so query_rows works against the
    nested-section layout.
    """
    if not text.strip():
        return {
            "total_count": 0,
            "section_counts": {},
            "sections": {},
            "unknown_files": [],
        }
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "total_count": 0,
            "section_counts": {},
            "sections": {},
            "unknown_files": [],
            "_parse_error": "raw_output is not valid JSON",
        }


def summarise_srum(parsed: dict[str, Any]) -> str:
    sc = parsed.get("section_counts") or {}
    if not sc:
        return "no SRUM sections parsed"
    total = parsed.get("total_count", 0)
    n_sections = len(sc)
    bits = [f"{total} SRUM rows across {n_sections} sections"]
    netu = sc.get("network_usage", 0)
    if netu:
        bits.append(f"{netu} network-usage rows (per-process bytes)")
    return "; ".join(bits)


# ---------------------------------------------------------------------------
# Task XML parser (Windows Task Scheduler, T1053 disk-side).
#
# `\Windows\System32\Tasks\<folder>\<TaskName>` files are well-formed XML.
# The Task Scheduler 1.0 / 2.0 schemas are stable; we extract the
# high-signal fields and pass through unknown elements.
#
# Pure Python — no EZ Tool dependency.
# ---------------------------------------------------------------------------


import xml.etree.ElementTree as _ET


_TS_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def _ts_text(el: _ET.Element | None, tag: str) -> str | None:
    """Look up <tag>...</tag> under `el`, namespace-tolerant."""
    if el is None:
        return None
    for candidate in (_TS_NS + tag, tag):
        node = el.find(candidate)
        if node is not None and node.text is not None:
            return node.text.strip() or None
    return None


def _ts_findall(el: _ET.Element | None, tag: str) -> list[_ET.Element]:
    if el is None:
        return []
    for candidate in (_TS_NS + tag, tag):
        found = el.findall(candidate)
        if found:
            return found
    return []


def parse_task_xml(stdout: str) -> dict[str, Any]:
    """Parse a single Task Scheduler XML file.

    Returns a dict shaped like other ez_tools parsers (with a `rows` list
    so query_rows registration works), even though a Task XML is a single
    record. The single-task case still benefits from the structured fields
    (Triggers / Actions / Principal / Settings).
    """
    if not stdout.strip():
        return {"count": 0, "rows": [], "_parse_error": "empty input"}
    try:
        root = _ET.fromstring(stdout)
    except _ET.ParseError as e:
        return {"count": 0, "rows": [], "_parse_error": f"XML parse failed: {e}"}

    def _first_present(*tags: str) -> _ET.Element | None:
        for t in tags:
            el = root.find(t)
            if el is not None:
                return el
        return None

    reg_info     = _first_present(_TS_NS + "RegistrationInfo", "RegistrationInfo")
    triggers_el  = _first_present(_TS_NS + "Triggers",         "Triggers")
    actions_el   = _first_present(_TS_NS + "Actions",          "Actions")
    principals_el = _first_present(_TS_NS + "Principals",      "Principals")
    settings_el  = _first_present(_TS_NS + "Settings",         "Settings")

    # Triggers: each child element is a trigger type
    triggers: list[dict[str, Any]] = []
    for trig in (list(triggers_el) if triggers_el is not None else []):
        trig_type = (trig.tag.split("}")[-1] if "}" in trig.tag else trig.tag)
        triggers.append({
            "type":          trig_type,
            "enabled":       _ts_text(trig, "Enabled"),
            "start_boundary": _ts_text(trig, "StartBoundary"),
            "end_boundary":  _ts_text(trig, "EndBoundary"),
            "user_id":       _ts_text(trig, "UserId"),
            "subscription":  _ts_text(trig, "Subscription"),  # EventTrigger XML query
            "delay":         _ts_text(trig, "Delay"),
        })

    # Actions: typically <Exec><Command>X</Command><Arguments>Y</Arguments></Exec>
    actions: list[dict[str, Any]] = []
    for act in (list(actions_el) if actions_el is not None else []):
        act_type = (act.tag.split("}")[-1] if "}" in act.tag else act.tag)
        actions.append({
            "type":         act_type,
            "command":      _ts_text(act, "Command"),
            "arguments":    _ts_text(act, "Arguments"),
            "working_dir":  _ts_text(act, "WorkingDirectory"),
            # ComHandler action
            "class_id":     _ts_text(act, "ClassId"),
            "data":         _ts_text(act, "Data"),
        })

    # Principal: <Principal id="Author"><UserId>...</UserId><RunLevel>...</RunLevel></Principal>
    principal: dict[str, Any] = {}
    if principals_el is not None:
        for p in list(principals_el):
            principal = {
                "id":          p.attrib.get("id"),
                "user_id":     _ts_text(p, "UserId"),
                "logon_type":  _ts_text(p, "LogonType"),
                "run_level":   _ts_text(p, "RunLevel"),
                "group_id":    _ts_text(p, "GroupId"),
            }
            break  # only inspect the first principal

    record: dict[str, Any] = {
        "uri":          _ts_text(reg_info, "URI"),
        "task_name":    _ts_text(reg_info, "URI") or root.attrib.get("name"),
        "author":       _ts_text(reg_info, "Author"),
        "description":  _ts_text(reg_info, "Description"),
        "source":       _ts_text(reg_info, "Source"),
        "date":         _normalise_dt(_ts_text(reg_info, "Date")),
        "version":      _ts_text(reg_info, "Version"),
        "principal":    principal,
        "triggers":     triggers,
        "actions":      actions,
        "settings": {
            "enabled":           _ts_text(settings_el, "Enabled"),
            "hidden":            _ts_text(settings_el, "Hidden"),
            "run_only_if_idle":  _ts_text(settings_el, "RunOnlyIfIdle"),
            "run_only_if_net":   _ts_text(settings_el, "RunOnlyIfNetworkAvailable"),
            "allow_start_on_demand": _ts_text(settings_el, "AllowStartOnDemand"),
            "wake_to_run":       _ts_text(settings_el, "WakeToRun"),
            "priority":          _ts_text(settings_el, "Priority"),
        },
    }
    return {
        "count":   1,
        "rows":    [record],
    }


def summarise_task_xml(parsed: dict[str, Any]) -> str:
    if parsed.get("_parse_error"):
        return f"task XML parse error: {parsed['_parse_error']}"
    rows = parsed.get("rows") or []
    if not rows:
        return "no task XML records"
    t = rows[0]
    bits = [f"task '{t.get('task_name') or '<unnamed>'}'"]
    principal = t.get("principal") or {}
    if principal.get("run_level"):
        bits.append(f"runlevel={principal['run_level']}")
    n_triggers = len(t.get("triggers") or [])
    n_actions = len(t.get("actions") or [])
    if n_triggers:
        bits.append(f"{n_triggers} trigger(s)")
    if n_actions:
        bits.append(f"{n_actions} action(s)")
    return "; ".join(bits)


# ---------------------------------------------------------------------------
# Persistence-keys parser (RECmd output → grouped by Category).
#
# Wrapper runs RECmd with mcp_server/recmd_batches/triage_persistence.reb
# against an extracted SOFTWARE / NTUSER.DAT / SYSTEM hive. RECmd emits a
# single CSV with a Category column; we group rows by Category into the
# usual `sections` shape (mirrors Amcache + SRUM).
# ---------------------------------------------------------------------------


def _persistence_category_key(raw: str) -> str:
    """Normalize RECmd Category to a stable section key."""
    return (raw or "").strip().replace(" ", "_").lower() or "other"


def parse_persistence_keys_from_csv(text: str) -> dict[str, Any]:
    """Parse the single RECmd batch-output CSV into per-category sections."""
    if not text.strip():
        return {
            "total_count":    0,
            "section_counts": {},
            "sections":       {},
        }
    reader = csv.DictReader(io.StringIO(text))
    sections: dict[str, dict[str, Any]] = {}
    for row in reader:
        cat_key = _persistence_category_key(row.get("Category", ""))
        out_row = {
            "category":       row.get("Category"),
            "description":    row.get("Description"),
            "hive_path":      row.get("HivePath"),
            "key_path":       row.get("KeyPath"),
            "value_name":     row.get("ValueName"),
            "value_data":     row.get("ValueData"),
            "value_data2":    row.get("ValueData2"),
            "value_data3":    row.get("ValueData3"),
            "key_timestamp":  _normalise_dt(row.get("KeyTimestamp") or row.get("Timestamp")),
            "comment":        row.get("Comment"),
            "deleted":        (row.get("Deleted") or "").lower() == "true",
            "recursive":      (row.get("Recursive") or "").lower() == "true",
        }
        section = sections.setdefault(cat_key, {"count": 0, "rows": []})
        section["rows"].append(out_row)
        section["count"] += 1
    section_counts = {k: v["count"] for k, v in sections.items()}
    return {
        "total_count":    sum(section_counts.values()),
        "section_counts": section_counts,
        "sections":       sections,
    }


def parse_persistence_keys(text: str) -> dict[str, Any]:
    """Re-hydrate a persistence-keys dict from JSON-encoded raw_output.

    Mirrors `parse_amcache` / `parse_srum`: the wrapper writes the combined
    dict as JSON to audit raw_output; this parser is the query_rows-compat
    deserialiser.
    """
    if not text.strip():
        return {"total_count": 0, "section_counts": {}, "sections": {}}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "total_count": 0, "section_counts": {}, "sections": {},
            "_parse_error": "raw_output is not valid JSON",
        }


def summarise_persistence_keys(parsed: dict[str, Any]) -> str:
    sc = parsed.get("section_counts") or {}
    if not sc:
        return "no persistence keys present in hive"
    total = parsed.get("total_count", 0)
    n_cats = len(sc)
    top = sorted(sc.items(), key=lambda kv: -kv[1])[:4]
    return f"{total} persistence values across {n_cats} categories; top: " + ", ".join(f"{k}×{v}" for k, v in top)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _try_int(s: str | None) -> int | None:
    if s is None or not str(s).strip():
        return None
    try:
        return int(str(s).strip().replace(",", ""))
    except (ValueError, TypeError):
        return None
