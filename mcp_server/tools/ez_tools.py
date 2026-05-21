"""Typed MCP functions wrapping EZ Tools (Eric Zimmerman's forensic suite).

Each function takes the **exec_id of a previous `tsk_icat_extract` call** that
extracted a Windows artifact file ($MFT, SYSTEM hive, .evtx) from an E01
disk image. The wrapper:

  1. Looks up the extract exec_id in the audit log → finds the on-disk path
     of the extracted bytes (`audit/raw/extracts/<extract_exec_id>.bin`).
  2. Runs the EZ tool's .NET DLL via dotnet, writing JSON/CSV output to a
     fresh per-call directory under `audit/raw/ez_tools/<this_exec_id>/`.
  3. Reads + parses the tool's output (parsers.ez_tools).
  4. Records a single audit row referencing both the source extract exec_id
     and the produced output.
  5. Returns the parsed dict (truncated to top-N rows for MCP-wire fit).

This means the agent uses the audit log itself as the file-handoff
mechanism — it never names a path on disk directly, and the EZ tool can
only ever read files that the agent already extracted via the typed
`tsk_icat_extract` function. Architecturally clean: the agent has no way
to point an EZ tool at an arbitrary file outside `audit/raw/extracts/`.

Tool inventory:

  ezt_mft_parse(extract_exec_id)        — MFTECmd on extracted $MFT
  ezt_shimcache_parse(extract_exec_id)  — AppCompatCacheParser on extracted SYSTEM hive
  ezt_evtx_parse(extract_exec_id)       — EvtxECmd on extracted .evtx file
  ezt_amcache_parse(extract_exec_id)    — AmcacheParser on extracted Amcache.hve
  ezt_prefetch_parse(extract_exec_id)   — PECmd on extracted .pf file
  ezt_jumplist_parse(extract_exec_id)   — JLECmd on extracted Jump List
  ezt_recyclebin_parse(extract_exec_id) — RBCmd on extracted $I record
  ezt_srum_parse(extract_exec_id)       — SrumECmd on extracted SRUDB.dat
  ezt_task_xml_parse(extract_exec_id)   — Python XML parser on \\Windows\\System32\\Tasks\\<name>
  ezt_persistence_keys_parse(extract_exec_id) — RECmd persistence triage batch
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Callable

from mcp_server.audit import AuditLogger
from mcp_server.parsers.ez_tools import (
    parse_amcache_from_dir,
    parse_evtx,
    parse_jumplist,
    parse_mft,
    parse_persistence_keys_from_csv,
    parse_prefetch_file,
    parse_recyclebin,
    parse_shimcache,
    parse_srum_file,
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
from mcp_server.tools._common import (
    DEFAULT_EVIDENCE_ROOTS,
    ToolError,
    run_subprocess,
)
from mcp_server.tools.memory import _truncate_rows


_DOTNET = "dotnet"

# Default install paths on SIFT 24.x. Override via SIFT_OWL_EZTOOLS_DIR if needed.
_EZT_DIR = Path(os.environ.get("SIFT_OWL_EZTOOLS_DIR", "/opt/zimmermantools"))


def _check_dotnet() -> str:
    found = shutil.which(_DOTNET)
    if not found:
        raise ToolError(f"`{_DOTNET}` not found on PATH (EZ Tools require .NET runtime)")
    return found


def _check_dll(name: str, *, subdir: str = "") -> Path:
    """Locate an EZ Tool DLL under the install root."""
    p = (_EZT_DIR / subdir / name) if subdir else (_EZT_DIR / name)
    if not p.exists():
        raise ToolError(f"EZ Tool DLL not found at {p}")
    return p


def _resolve_extract(audit: AuditLogger, extract_exec_id: str) -> Path:
    """Look up an extract exec_id and return its on-disk extracted-bytes path.

    Architectural enforcement: the agent can ONLY point an EZ tool at the
    output of a prior `tsk_icat_extract` call. The exec_id must resolve to
    an audit row with `tool == "tsk_icat_extract"` and an existing
    `raw_output_path` under `audit/raw/extracts/`.
    """
    row = audit.lookup_exec(extract_exec_id)
    if row is None:
        raise ToolError(f"extract_exec_id not found in audit log: {extract_exec_id}")
    if row.get("tool") != "tsk_icat_extract":
        raise ToolError(
            f"extract_exec_id {extract_exec_id} cites tool "
            f"{row.get('tool')}, not tsk_icat_extract"
        )
    raw = row.get("raw_output_path")
    if not raw:
        raise ToolError(f"extract row {extract_exec_id} has no raw_output_path")
    p = Path(raw)
    if not p.exists():
        raise ToolError(f"extracted file missing on disk: {p}")
    return p


def _run_ez_tool(
    *,
    audit: AuditLogger,
    agent: str,
    tool_name: str,
    dll_path: Path,
    extract_exec_id: str,
    output_format: str,    # "json" or "csv"
    output_glob: str,      # filename pattern under output_dir
    parser: Callable[[str], dict[str, Any]],
    summariser: Callable[[dict[str, Any]], str],
    timeout_s: float,
) -> dict[str, Any]:
    """Shared runner: extract path lookup → dotnet invocation → parse → audit.

    Mirrors `_run_jsonl_plugin` and `_run_disk_tool` from the other tool
    modules. Per-call output goes to `audit/raw/ez_tools/<exec_id>/` to
    keep the audit tree single-source-of-truth.
    """
    extract_path = _resolve_extract(audit, extract_exec_id)
    exec_id = audit.new_exec_id()
    out_subdir = audit.raw_output_dir / "ez_tools" / exec_id
    out_subdir.mkdir(parents=True, exist_ok=True)
    sub_dir = audit.raw_output_dir / "subprocess"

    argv = [_check_dotnet(), str(dll_path), "-f", str(extract_path),
            f"--{output_format}", str(out_subdir)]

    rr = run_subprocess(argv, output_dir=sub_dir, name=exec_id, timeout_s=timeout_s)

    if not rr.ok:
        # Persist whatever the tool wrote, then audit the failure.
        raw_capture = audit.write_raw(exec_id,
                                      f"FAILED ({rr.error}). stderr: {rr.stderr_path}\n")
        audit.record(
            exec_id=exec_id, agent=agent, tool=tool_name,
            args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
            raw_output_path=raw_capture,
            exit_code=rr.exit_code, wall_ms=rr.wall_ms,
            summary=f"FAILED: {rr.error or 'non-zero exit'}",
            error=rr.error or f"exit {rr.exit_code}",
        )
        raise ToolError(
            f"{tool_name} failed (exit {rr.exit_code}, "
            f"timed_out={rr.timed_out}): {rr.error}. "
            f"stderr at {rr.stderr_path}"
        )

    # Locate the produced output file (EZ tools name with embedded timestamp).
    matches = sorted(out_subdir.glob(output_glob))
    if not matches:
        raise ToolError(
            f"{tool_name} produced no output matching {output_glob} in {out_subdir}"
        )
    output_path = matches[0]

    output_text = output_path.read_text(errors="replace")
    raw_path = audit.write_raw(exec_id, output_text)
    parsed = parser(output_text)
    summary = summariser(parsed)

    parsed_summary_compact = {
        k: v for k, v in parsed.items()
        if k not in {"rows", "entries", "events"}  # bulky row lists
    }

    audit.record(
        exec_id=exec_id, agent=agent, tool=tool_name,
        args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
        raw_output_path=raw_path,
        exit_code=0, wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    truncated = _truncate_rows(parsed)
    return {"exec_id": exec_id, **truncated}


# ---------------------------------------------------------------------------
# Public typed wrappers.
# ---------------------------------------------------------------------------


def ezt_mft_parse(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    timeout_s: float = 1800,
) -> dict[str, Any]:
    """`MFTECmd -f <extracted-MFT> --json <out>` — full $MFT timeline.

    Parsed result includes per-entry timestamps (Created/Modified/Accessed/
    Recorded), MFT-anti-tamper flags (Timestomped, uSecZeros, Copied),
    file-name + ParentPath, FileSize, IsDirectory, HasAds, IsAds, plus
    aggregates count / deleted / timestomped_count / by_extension /
    by_parent_path. Truncated to the first 50 entries on the wire; full
    set reachable via query_rows.
    """
    return _run_ez_tool(
        audit=audit, agent=agent,
        tool_name="ezt_mft_parse",
        dll_path=_check_dll("MFTECmd.dll"),
        extract_exec_id=extract_exec_id,
        output_format="json",
        output_glob="*_MFTECmd_*.json",
        parser=parse_mft,
        summariser=summarise_mft,
        timeout_s=timeout_s,
    )


def ezt_shimcache_parse(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    timeout_s: float = 600,
) -> dict[str, Any]:
    """`AppCompatCacheParser -f <extracted-SYSTEM-hive> --csv <out>` — ShimCache.

    Per-entry: ControlSet, position, Path, LastModifiedTimeUTC, Executed
    flag, Duplicate flag. Aggregates: count, by_extension, by_parent_dir,
    by_control_set. ShimCache is high-signal for program-execution
    evidence — it captures binary path + last-modified time even for
    binaries that have been deleted.
    """
    return _run_ez_tool(
        audit=audit, agent=agent,
        tool_name="ezt_shimcache_parse",
        dll_path=_check_dll("AppCompatCacheParser.dll"),
        extract_exec_id=extract_exec_id,
        output_format="csv",
        output_glob="*_AppCompatCache.csv",
        parser=parse_shimcache,
        summariser=summarise_shimcache,
        timeout_s=timeout_s,
    )


# Default per-section row cap on the wire for amcache. Each Amcache section
# is independent so we cap each at this limit; full rows remain on disk.
_AMCACHE_SECTION_ROW_LIMIT = 50


def _truncate_amcache(parsed: dict[str, Any], limit: int = _AMCACHE_SECTION_ROW_LIMIT) -> dict[str, Any]:
    """Cap each Amcache section's row list independently.

    Mirrors `_truncate_rows()` in tools.memory but per-section. Aggregates
    (count, section_counts, total_count) are unaffected.
    """
    out = {k: v for k, v in parsed.items() if k != "sections"}
    out_sections: dict[str, Any] = {}
    for sec_key, sec in (parsed.get("sections") or {}).items():
        rows = sec.get("rows") or []
        truncated = len(rows) > limit
        out_sections[sec_key] = {
            "count":          sec.get("count", len(rows)),
            "rows":           rows[:limit],
            "rows_truncated": truncated,
            "rows_total":     len(rows),
        }
    out["sections"] = out_sections
    return out


def ezt_amcache_parse(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    timeout_s: float = 600,
) -> dict[str, Any]:
    """`AmcacheParser -f <Amcache.hve> -i --csv <out>` — Win8.1+ program-execution
    registry parser.

    Pre-req: extract `Windows/AppCompat/Programs/Amcache.hve` via
    `tsk_icat_extract`. Returns multiple sections (UnassociatedFileEntries,
    ProgramEntries, ShortCuts, DriverBinaries, DriverPackages, DeviceContainers,
    DevicePnps, AssociatedFileEntries) with per-section rows. The `-i` flag
    includes file entries on the legacy AssociatedFileEntries section.

    Output layout:
      {
        "exec_id": "<uuid>",
        "total_count": <int>,
        "section_counts": {section_name: count, ...},
        "sections": {
          section_name: {"count", "rows", "rows_truncated", "rows_total"},
          ...
        },
        "unknown_files": [...],
      }

    Each section's rows are truncated to 50 entries on the wire; full rows
    persisted to audit raw_output as JSON, drillable via `query_rows`.
    """
    extract_path = _resolve_extract(audit, extract_exec_id)
    exec_id = audit.new_exec_id()
    out_subdir = audit.raw_output_dir / "ez_tools" / exec_id
    out_subdir.mkdir(parents=True, exist_ok=True)
    sub_dir = audit.raw_output_dir / "subprocess"

    dll = _check_dll("AmcacheParser.dll")
    argv = [
        _check_dotnet(), str(dll),
        "-f", str(extract_path),
        "-i",                      # include legacy AssociatedFileEntries detail
        "--csv", str(out_subdir),
    ]

    rr = run_subprocess(argv, output_dir=sub_dir, name=exec_id, timeout_s=timeout_s)

    if not rr.ok:
        raw_capture = audit.write_raw(
            exec_id, f"FAILED ({rr.error}). stderr: {rr.stderr_path}\n",
        )
        audit.record(
            exec_id=exec_id, agent=agent, tool="ezt_amcache_parse",
            args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
            raw_output_path=raw_capture,
            exit_code=rr.exit_code, wall_ms=rr.wall_ms,
            summary=f"FAILED: {rr.error or 'non-zero exit'}",
            error=rr.error or f"exit {rr.exit_code}",
        )
        raise ToolError(
            f"ezt_amcache_parse failed (exit {rr.exit_code}, "
            f"timed_out={rr.timed_out}): {rr.error}. "
            f"stderr at {rr.stderr_path}"
        )

    parsed = parse_amcache_from_dir(out_subdir)

    # Persist as JSON to raw_output so query_rows can re-read it later.
    raw_text = json.dumps(parsed, default=str)
    raw_path = audit.write_raw(exec_id, raw_text)
    summary = summarise_amcache(parsed)

    parsed_summary_compact = {
        "total_count":    parsed.get("total_count"),
        "section_counts": parsed.get("section_counts"),
        "unknown_files":  parsed.get("unknown_files"),
    }

    audit.record(
        exec_id=exec_id, agent=agent, tool="ezt_amcache_parse",
        args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
        raw_output_path=raw_path,
        exit_code=0, wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    truncated = _truncate_amcache(parsed)
    return {"exec_id": exec_id, **truncated}


def ezt_evtx_parse(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    timeout_s: float = 1200,
) -> dict[str, Any]:
    """`EvtxECmd -f <extracted-evtx> --json <out>` — Windows Event Log parser.

    Per-event: EventId, TimeCreated, Channel, Provider, Computer, Level,
    Process/Thread IDs, UserName, RemoteHost, MapDescription (high-level
    summary), and PayloadData1..5 (extracted from raw event-data fields).
    Aggregates: count + by_event_id + by_channel + by_computer + by_provider.
    """
    return _run_ez_tool(
        audit=audit, agent=agent,
        tool_name="ezt_evtx_parse",
        dll_path=_check_dll("EvtxECmd.dll", subdir="EvtxeCmd"),
        extract_exec_id=extract_exec_id,
        output_format="json",
        output_glob="*_EvtxECmd_*.json",
        parser=parse_evtx,
        summariser=summarise_evtx,
        timeout_s=timeout_s,
    )


def ezt_prefetch_parse(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    timeout_s: float = 60,  # noqa: ARG001 — in-process parser
) -> dict[str, Any]:
    """In-process Windows Prefetch parser via libyal `libscca` (pyscca).

    Pre-req: extract a single `.pf` file from
    `Windows\\Prefetch\\<NAME>-<HASH>.pf` via `tsk_icat_extract`.

    Per-binary execution evidence: executable_name + 8-hex hash, run_count,
    last_run (most recent) + previous_runs (up to 7 prior on Win10+),
    list of files_loaded (DLLs + config), directories, and volume info
    (device_path, serial_number, creation_time). Survives binary deletion.

    Note: this used to wrap EZ Tools' PECmd, but PECmd refuses to run on
    non-Windows ("Non-Windows platforms not supported due to the need to
    load decompression specific Windows libraries"). libscca's pyscca
    bindings include a portable MAM/XPRESS-Huffman decompressor and work
    cross-platform; functionally equivalent output.
    """
    extract_path = _resolve_extract(audit, extract_exec_id)
    exec_id = audit.new_exec_id()

    try:
        parsed = parse_prefetch_file(extract_path)
    except RuntimeError as e:
        # libscca import error or invalid file signature
        raw_capture = audit.write_raw(exec_id, f"FAILED: {e}\n")
        audit.record(
            exec_id=exec_id, agent=agent, tool="ezt_prefetch_parse",
            args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
            raw_output_path=raw_capture,
            exit_code=1, wall_ms=0,
            summary=f"FAILED: {e}",
            error=str(e),
        )
        raise ToolError(f"ezt_prefetch_parse failed: {e}") from e
    except (OSError, IOError) as e:
        # File isn't a valid Prefetch (bad signature, etc.)
        raw_capture = audit.write_raw(exec_id, f"FAILED: libscca: {e}\n")
        audit.record(
            exec_id=exec_id, agent=agent, tool="ezt_prefetch_parse",
            args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
            raw_output_path=raw_capture,
            exit_code=1, wall_ms=0,
            summary=f"FAILED: not a valid Prefetch file ({e})",
            error=str(e),
        )
        raise ToolError(
            f"ezt_prefetch_parse: libscca could not parse {extract_path} "
            f"(likely not a valid .pf file): {e}"
        ) from e

    raw_text = json.dumps(parsed, default=str)
    raw_path = audit.write_raw(exec_id, raw_text)
    summary = summarise_prefetch(parsed)

    parsed_summary_compact = {k: v for k, v in parsed.items() if k != "rows"}

    audit.record(
        exec_id=exec_id, agent=agent, tool="ezt_prefetch_parse",
        args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
        raw_output_path=raw_path,
        exit_code=0, wall_ms=0,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    return {"exec_id": exec_id, **parsed}


def ezt_jumplist_parse(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    timeout_s: float = 600,
) -> dict[str, Any]:
    """`JLECmd -f <extracted-jumplist> --json <out>` — Jump List parser.

    Pre-req: extract a single `.automaticDestinations-ms` or
    `.customDestinations-ms` file from
    `\\Users\\<u>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\
    {Automatic,Custom}Destinations\\` via `tsk_icat_extract`.

    Per-DestList entry: AppId + AppIDDescription, target Path, hostname,
    drive type + serial, MFT entry, MAC address of the originating
    machine (link-tracker creator). Strong "what did the user open" signal
    that survives even after external drives are detached.
    """
    return _run_ez_tool(
        audit=audit, agent=agent,
        tool_name="ezt_jumplist_parse",
        dll_path=_check_dll("JLECmd.dll"),
        extract_exec_id=extract_exec_id,
        output_format="json",
        output_glob="*_JLECmd_*.json",
        parser=parse_jumplist,
        summariser=summarise_jumplist,
        timeout_s=timeout_s,
    )


def ezt_recyclebin_parse(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    timeout_s: float = 300,
) -> dict[str, Any]:
    """`RBCmd -f <extracted-$I> --json <out>` — Recycle Bin parser.

    Pre-req: extract a single `$Recycle.Bin\\S-<SID>\\$I*` record (Win10)
    or `INFO2` (XP) via `tsk_icat_extract`.

    Per record: SourceName (original full path), FileSize, DeletedOn
    timestamp, FileName. Strong "user deleted X" evidence; the deleted
    file body is in the paired `$R*`.
    """
    return _run_ez_tool(
        audit=audit, agent=agent,
        tool_name="ezt_recyclebin_parse",
        dll_path=_check_dll("RBCmd.dll"),
        extract_exec_id=extract_exec_id,
        output_format="json",
        output_glob="*_RBCmd_*.json",
        parser=parse_recyclebin,
        summariser=summarise_recyclebin,
        timeout_s=timeout_s,
    )


# SRUM wire-fit constants. The parser typically produces a *very* large
# dict (179K rows across 7 sections on a 35 MB SRUDB.dat is normal). The
# tool-result on the wire has to stay under Claude Code's per-call
# transport envelope (~25 KB headroom is the convention used by the
# memory plugins — see `mcp_server/tools/memory.py:308`).
#
# Strategy: start at the standard 50-row default; if serialised JSON
# exceeds the target, halve the per-section cap and retry. The parser
# is NOT re-invoked — only `_truncate_srum` + `json.dumps` are repeated,
# each pass costs ~5-10 ms on already-parsed data. Worst case ends in
# a `count`-only fallback (no rows on the wire; agent uses `query_rows`).
_SRUM_SECTION_ROW_LIMIT  = 50
_SRUM_WIRE_TARGET_BYTES  = 25 * 1024          # match single-section tools
_SRUM_WIRE_SHRINK_LADDER = (50, 25, 12, 6, 3, 1)


def _truncate_srum(
    parsed: dict[str, Any], limit: int = _SRUM_SECTION_ROW_LIMIT,
) -> dict[str, Any]:
    """Cap each SRUM section's row list independently (mirrors `_truncate_amcache`)."""
    out = {k: v for k, v in parsed.items() if k != "sections"}
    out_sections: dict[str, Any] = {}
    for sec_key, sec in (parsed.get("sections") or {}).items():
        rows = sec.get("rows") or []
        truncated = len(rows) > limit
        out_sections[sec_key] = {
            "count":          sec.get("count", len(rows)),
            "rows":           rows[:limit],
            "rows_truncated": truncated,
            "rows_total":     len(rows),
        }
    out["sections"] = out_sections
    return out


def _fit_srum_to_wire(
    parsed: dict[str, Any],
    *,
    target_bytes: int = _SRUM_WIRE_TARGET_BYTES,
    ladder: tuple[int, ...] = _SRUM_WIRE_SHRINK_LADDER,
) -> tuple[dict[str, Any], int, str]:
    """Shrink per-section row caps until the JSON payload fits the wire.

    Walks `ladder` (50, 25, 12, …) and re-runs `_truncate_srum`+`json.dumps`
    on the already-parsed dict at each step until `len(json) <= target_bytes`.
    If even the smallest cap is too big, returns a `count`-only payload
    (rows dropped entirely; the agent must use `query_rows` to drill).

    Returns: (fitted_dict, applied_row_cap, reason).
    `reason` is one of:
      - "default"           — first cap fit, no shrink needed
      - "size-fit"          — needed to shrink to stay under target
      - "minimum-fallback"  — even cap=1 was too big; rows dropped
    """
    last_serialised_len: int | None = None
    for cap in ladder:
        candidate = _truncate_srum(parsed, limit=cap)
        serialised_len = len(json.dumps(candidate, default=str))
        last_serialised_len = serialised_len
        if serialised_len <= target_bytes:
            reason = "default" if cap == ladder[0] else "size-fit"
            candidate["wire_cap_applied"] = cap
            candidate["wire_target_bytes"] = target_bytes
            candidate["wire_payload_bytes"] = serialised_len
            candidate["wire_cap_reason"] = reason
            return candidate, cap, reason

    # Fallback: drop all rows; the agent has section_counts + id_map_summary
    # in the audit trail and can query_rows for any specific section.
    fallback = {k: v for k, v in parsed.items() if k != "sections"}
    out_sections: dict[str, Any] = {}
    for sec_key, sec in (parsed.get("sections") or {}).items():
        rows = sec.get("rows") or []
        out_sections[sec_key] = {
            "count":          sec.get("count", len(rows)),
            "rows":           [],
            "rows_truncated": True,
            "rows_total":     len(rows),
        }
    fallback["sections"] = out_sections
    fallback["wire_cap_applied"]   = 0
    fallback["wire_target_bytes"]  = target_bytes
    fallback["wire_payload_bytes"] = last_serialised_len or 0
    fallback["wire_cap_reason"]    = "minimum-fallback"
    return fallback, 0, "minimum-fallback"


def ezt_srum_parse(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    timeout_s: float = 900,  # noqa: ARG001 — in-process parser
) -> dict[str, Any]:
    """In-process SRUM parser via libyal `libesedb` (pyesedb).

    Pre-req: extract `Windows\\System32\\sru\\SRUDB.dat` via `tsk_icat_extract`.
    SRUM is Win8+ — XP/Win7 hosts will not have this file.

    Returns the canonical SRUM provider tables — keyed by section:
    `app_resource_use`, `network_usage`, `network_connections`,
    `push_notifications`, `energy_usage`, `energy_usage_lt`, `app_timeline`.
    AppId / UserId integers are joined to `SruDbIdMapTable` so each row
    carries an `app_name` (program path / service / AppX) and `user_sid`.
    Each section's rows are truncated to 50 on the wire; full rows on
    disk under `audit/raw/<exec_id>.json`, drillable via `query_rows`.

    The killer section for exfil detection is **network_usage**: per-app
    per-interface accumulated bytes_sent / bytes_recvd by hour.

    Note: this used to wrap EZ Tools' SrumECmd, but SrumECmd refuses to
    run on non-Windows ("Non-Windows platforms not supported due to the
    need to load ESI specific Windows libraries"). libesedb is a portable
    ESE parser; output is functionally equivalent.
    """
    extract_path = _resolve_extract(audit, extract_exec_id)
    exec_id = audit.new_exec_id()

    try:
        parsed = parse_srum_file(extract_path)
    except RuntimeError as e:
        # pyesedb import error
        raw_capture = audit.write_raw(exec_id, f"FAILED: {e}\n")
        audit.record(
            exec_id=exec_id, agent=agent, tool="ezt_srum_parse",
            args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
            raw_output_path=raw_capture,
            exit_code=1, wall_ms=0,
            summary=f"FAILED: {e}",
            error=str(e),
        )
        raise ToolError(f"ezt_srum_parse failed: {e}") from e
    except (OSError, IOError) as e:
        raw_capture = audit.write_raw(exec_id, f"FAILED: libesedb: {e}\n")
        audit.record(
            exec_id=exec_id, agent=agent, tool="ezt_srum_parse",
            args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
            raw_output_path=raw_capture,
            exit_code=1, wall_ms=0,
            summary=f"FAILED: not a valid SRUDB.dat ({e})",
            error=str(e),
        )
        raise ToolError(
            f"ezt_srum_parse: libesedb could not parse {extract_path} "
            f"(likely not a valid SRUDB.dat / ESE file): {e}"
        ) from e

    raw_text = json.dumps(parsed, default=str)
    raw_path = audit.write_raw(exec_id, raw_text)

    # Fit to wire BEFORE recording the audit row so the summary string
    # carries the wire-cap status (the agent reads `summary` in the
    # audit log + the response payload carries `wire_cap_*` fields too).
    fitted, applied_cap, reason = _fit_srum_to_wire(parsed)
    summary = summarise_srum(parsed)
    if reason == "size-fit":
        summary += (
            f"; wire shrink: capped to {applied_cap} rows/section "
            f"({fitted['wire_payload_bytes']}B fit under "
            f"{fitted['wire_target_bytes']}B target — use query_rows for "
            f"more)"
        )
    elif reason == "minimum-fallback":
        summary += (
            "; wire shrink: even cap=1 exceeded target — rows dropped from "
            "response; section_counts retained; use query_rows to drill"
        )

    parsed_summary_compact = {
        "total_count":      parsed.get("total_count"),
        "section_counts":   parsed.get("section_counts"),
        "id_map_summary":   parsed.get("id_map_summary"),
        "unknown_files":    parsed.get("unknown_files"),
        "wire_cap_applied": applied_cap,
        "wire_cap_reason":  reason,
    }

    audit.record(
        exec_id=exec_id, agent=agent, tool="ezt_srum_parse",
        args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
        raw_output_path=raw_path,
        exit_code=0, wall_ms=0,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    return {"exec_id": exec_id, **fitted}


# ---------------------------------------------------------------------------
# Phase 1.5 disk-side parsers (no EZ Tool DLL — pure Python for task XML,
# RECmd batch for persistence keys).
# ---------------------------------------------------------------------------


def ezt_task_xml_parse(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    timeout_s: float = 60,  # noqa: ARG001 — XML parse is in-process
) -> dict[str, Any]:
    """Parse a single Windows Task Scheduler XML file (T1053 disk-side).

    Pre-req: extract one task file from
    `\\Windows\\System32\\Tasks\\<folder>\\<TaskName>` via
    `tsk_icat_extract`. Returns a structured dict with: task_name, author,
    description, principal (UserId, RunLevel, LogonType), triggers
    (CalendarTrigger / BootTrigger / LogonTrigger / TimeTrigger / EventTrigger),
    actions (Exec command + arguments, or ComHandler ClassId), settings
    (Enabled, Hidden, RunOnlyIfNetworkAvailable), creation date.

    Corroborates `vol3_scheduled_tasks` (live in-memory state) and
    TaskScheduler EVTX events (106 / 140 / 141 / 200) — full T1053 closure.
    """
    extract_path = _resolve_extract(audit, extract_exec_id)
    exec_id = audit.new_exec_id()
    try:
        xml_text = extract_path.read_text(errors="replace")
    except OSError as e:
        raise ToolError(f"failed to read extracted XML at {extract_path}: {e}") from e

    parsed = parse_task_xml(xml_text)
    raw_path = audit.write_raw(exec_id, xml_text)
    summary = summarise_task_xml(parsed)

    parsed_summary_compact = {k: v for k, v in parsed.items() if k != "rows"}
    audit.record(
        exec_id=exec_id, agent=agent, tool="ezt_task_xml_parse",
        args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
        raw_output_path=raw_path,
        exit_code=0, wall_ms=0,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    # Task XML is a single record — no truncation needed.
    return {"exec_id": exec_id, **parsed}


# Persistence keys: per-section row cap (mirrors Amcache / SRUM patterns).
_PERSISTENCE_SECTION_ROW_LIMIT = 50


def _truncate_persistence(
    parsed: dict[str, Any], limit: int = _PERSISTENCE_SECTION_ROW_LIMIT,
) -> dict[str, Any]:
    out = {k: v for k, v in parsed.items() if k != "sections"}
    out_sections: dict[str, Any] = {}
    for sec_key, sec in (parsed.get("sections") or {}).items():
        rows = sec.get("rows") or []
        out_sections[sec_key] = {
            "count":          sec.get("count", len(rows)),
            "rows":           rows[:limit],
            "rows_truncated": len(rows) > limit,
            "rows_total":     len(rows),
        }
    out["sections"] = out_sections
    return out


def ezt_persistence_keys_parse(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    timeout_s: float = 600,
) -> dict[str, Any]:
    """`RECmd --bn triage_persistence.reb --csv` on an extracted registry hive.

    Pre-req: extract `\\Windows\\System32\\config\\SOFTWARE` (HKLM autostart),
    `\\Windows\\System32\\config\\SYSTEM` (services), or
    `\\Users\\<u>\\NTUSER.DAT` (HKCU autostart) via `tsk_icat_extract`.

    Curated batch (`mcp_server/recmd_batches/triage_persistence.reb`)
    extracts: Run / RunOnce / RunOnceEx / Policies-Explorer-Run (T1547.001),
    Winlogon Shell / Userinit / Notify (T1547.004),
    IFEO Debugger + GlobalFlag + SilentProcessExit (T1574.012),
    AppInit_DLLs + AppCertDlls (T1574.001),
    Services ImagePath + ServiceDll (T1543.003).

    Returns sections grouped by Category (run_keys / winlogon / ifeo /
    dll_hijack / services). Each section's rows are truncated to 50.
    """
    extract_path = _resolve_extract(audit, extract_exec_id)
    exec_id = audit.new_exec_id()
    out_subdir = audit.raw_output_dir / "ez_tools" / exec_id
    out_subdir.mkdir(parents=True, exist_ok=True)
    sub_dir = audit.raw_output_dir / "subprocess"

    dll = _check_dll("RECmd.dll", subdir="RECmd")
    batch_file = Path(__file__).resolve().parents[1] / "recmd_batches" / "triage_persistence.reb"
    if not batch_file.exists():
        raise ToolError(f"persistence batch file missing at {batch_file}")

    argv = [
        _check_dotnet(), str(dll),
        "-f", str(extract_path),
        "--bn", str(batch_file),
        "--csv", str(out_subdir),
        "--nl",  # ignore transaction logs (we already extracted a quiesced hive)
    ]

    rr = run_subprocess(argv, output_dir=sub_dir, name=exec_id, timeout_s=timeout_s)

    if not rr.ok:
        raw_capture = audit.write_raw(
            exec_id, f"FAILED ({rr.error}). stderr: {rr.stderr_path}\n",
        )
        audit.record(
            exec_id=exec_id, agent=agent, tool="ezt_persistence_keys_parse",
            args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
            raw_output_path=raw_capture,
            exit_code=rr.exit_code, wall_ms=rr.wall_ms,
            summary=f"FAILED: {rr.error or 'non-zero exit'}",
            error=rr.error or f"exit {rr.exit_code}",
        )
        raise ToolError(
            f"ezt_persistence_keys_parse failed (exit {rr.exit_code}, "
            f"timed_out={rr.timed_out}): {rr.error}. stderr at {rr.stderr_path}"
        )

    # RECmd writes a single CSV with the batch name embedded.
    matches = sorted(out_subdir.glob("*_RECmd_Batch_*Output.csv"))
    if not matches:
        # Fall back: any CSV at all
        matches = sorted(out_subdir.glob("*.csv"))
    if not matches:
        raise ToolError(
            f"ezt_persistence_keys_parse: RECmd produced no CSV in {out_subdir}"
        )

    csv_text = matches[0].read_text(errors="replace")
    parsed = parse_persistence_keys_from_csv(csv_text)

    # Persist as JSON for query_rows compat.
    raw_text = json.dumps(parsed, default=str)
    raw_path = audit.write_raw(exec_id, raw_text)
    summary = summarise_persistence_keys(parsed)

    parsed_summary_compact = {
        "total_count":    parsed.get("total_count"),
        "section_counts": parsed.get("section_counts"),
    }

    audit.record(
        exec_id=exec_id, agent=agent, tool="ezt_persistence_keys_parse",
        args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
        raw_output_path=raw_path,
        exit_code=0, wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    truncated = _truncate_persistence(parsed)
    return {"exec_id": exec_id, **truncated}
