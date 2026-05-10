"""Parsers for EZ Tools (Eric Zimmerman) output.

Pure-function parsers — given the tool's stdout-redirected file content,
return a structured dict shaped to embed into our audit log's
`parsed_summary`. Same shape as `parsers.vol3` and `parsers.disk`.

Tools wrapped here:
  - MFTECmd       (--json)  — NTFS $MFT records
  - AppCompatCacheParser (--csv) — ShimCache program execution
  - EvtxECmd      (--json)  — Windows Event Logs
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timezone
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
# helpers
# ---------------------------------------------------------------------------


def _try_int(s: str | None) -> int | None:
    if s is None or not str(s).strip():
        return None
    try:
        return int(str(s).strip().replace(",", ""))
    except (ValueError, TypeError):
        return None
