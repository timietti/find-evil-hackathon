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
# PECmd — Windows Prefetch (.pf) parser.
#
# Output format: line-delimited JSON per .pf file with fields like
# SourceFilename, SourceCreated, SourceModified, SourceAccessed, ExecutableName,
# Hash, Size, Version, RunCount, LastRun, PreviousRun0..6, Volume0Name,
# Volume0Serial, Volume0Created, Directories, FilesLoaded.
# ---------------------------------------------------------------------------


def parse_prefetch(stdout: str) -> dict[str, Any]:
    """Parse PECmd JSON output (one .pf record per line).

    Prefetch is the Win10/Win11 program-execution gold standard: per-binary
    last-run + 7 previous runs, plus the list of files loaded (libraries,
    config files) by the binary.
    """
    rows = parse_jsonl_rows(stdout)
    out_rows: list[dict[str, Any]] = []
    by_executable: dict[str, int] = {}
    total_runs = 0
    for r in rows:
        exe = (r.get("ExecutableName") or "").lower()
        run_count = r.get("RunCount") or 0
        if exe:
            by_executable[exe] = by_executable.get(exe, 0) + 1
        try:
            total_runs += int(run_count)
        except (TypeError, ValueError):
            pass
        out_rows.append({
            "source_filename":  r.get("SourceFilename"),
            "executable_name":  r.get("ExecutableName"),
            "hash":             r.get("Hash"),
            "size":             r.get("Size"),
            "version":          r.get("Version"),
            "run_count":        run_count,
            "last_run":         _normalise_dt(r.get("LastRun")),
            "previous_runs":    [
                _normalise_dt(r.get(f"PreviousRun{i}")) for i in range(7)
                if r.get(f"PreviousRun{i}")
            ],
            "source_created":   _normalise_dt(r.get("SourceCreated")),
            "source_modified":  _normalise_dt(r.get("SourceModified")),
            "source_accessed":  _normalise_dt(r.get("SourceAccessed")),
            "volume_name":      r.get("Volume0Name"),
            "volume_serial":    r.get("Volume0Serial"),
            "volume_created":   _normalise_dt(r.get("Volume0Created")),
            "directories":      r.get("Directories"),
            "files_loaded":     r.get("FilesLoaded"),
        })
    return {
        "count":         len(out_rows),
        "total_runs":    total_runs,
        "by_executable": dict(sorted(by_executable.items(), key=lambda kv: -kv[1])[:30]),
        "rows":          out_rows,
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
# SrumECmd — System Resource Usage Monitor (Win8+).
#
# SRUDB.dat tracks, per process+user+app, accumulated network bytes
# in/out, wall-clock time used, push notifications, etc. Killer for
# exfil detection: "what process moved the most outbound bytes this hour".
# Output: multi-CSV directory (one per ESE table). Sections we care about:
#   - SrumECmd_AppResourceUseInfo.csv      (CPU + bytes per app per session)
#   - SrumECmd_NetworkUsages.csv           (bytes in/out per app + interface)
#   - SrumECmd_NetworkConnections.csv      (per-connection metadata)
#   - SrumECmd_PushNotificationData.csv    (toast / WNS pushes)
#   - SrumECmd_EnergyUsage.csv             (battery state)
# ---------------------------------------------------------------------------


_SRUM_SECTION_FROM_SUFFIX: dict[str, str] = {
    "AppResourceUseInfo":   "app_resource_use",
    "NetworkUsages":        "network_usage",
    "NetworkConnections":   "network_connections",
    "PushNotificationData": "push_notifications",
    "EnergyUsage":          "energy_usage",
    "EnergyUsageLT":        "energy_usage_lt",
    "vfuprov":              "vfuprov",
    "Unknown312":           "unknown_312",
    "Unknown313":           "unknown_313",
    "Unknown314":           "unknown_314",
}


def _srum_section_for(csv_filename: str) -> str | None:
    """Map a `<ts>_SrumECmd_<Suffix>.csv` filename to a section key."""
    m = re.search(r"_SrumECmd_([A-Za-z0-9]+)\.csv$", csv_filename)
    if not m:
        return None
    return _SRUM_SECTION_FROM_SUFFIX.get(m.group(1))


def parse_srum_from_dir(out_dir: Path) -> dict[str, Any]:
    """Walk a SrumECmd output directory; build per-section row lists.

    Mirrors `parse_amcache_from_dir`'s shape so the wrapper can reuse the
    multi-file runner pattern.
    """
    sections: dict[str, dict[str, Any]] = {}
    unknown_files: list[str] = []
    for csv_path in sorted(out_dir.glob("*_SrumECmd_*.csv")):
        section = _srum_section_for(csv_path.name)
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
            normalised: dict[str, Any] = {}
            for k, v in row.items():
                if k is None:
                    continue
                normalised[k.replace(" ", "_").lower()] = v
            # Normalise common timestamp columns
            for ts_field in ("timestamp", "event_timestamp", "connectstarttime", "endtime"):
                if ts_field in normalised and normalised[ts_field]:
                    normalised[ts_field] = _normalise_dt(normalised[ts_field])
            rows.append(normalised)
        sections[section] = {"count": len(rows), "rows": rows}

    section_counts = {k: v["count"] for k, v in sections.items()}
    return {
        "total_count":    sum(section_counts.values()),
        "section_counts": section_counts,
        "sections":       sections,
        "unknown_files":  unknown_files,
    }


def parse_srum(text: str) -> dict[str, Any]:
    """Re-hydrate a previously-serialised parse_srum_from_dir result.

    Same pattern as parse_amcache: wrapper writes JSON to raw_output,
    parser is `json.loads` so query_rows works even for nested-section
    layouts.
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
