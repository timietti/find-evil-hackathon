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

Tool inventory (v0):

  ezt_mft_parse(extract_exec_id)        — MFTECmd on extracted $MFT
  ezt_shimcache_parse(extract_exec_id)  — AppCompatCacheParser on extracted SYSTEM hive
  ezt_evtx_parse(extract_exec_id)       — EvtxECmd on extracted .evtx file
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Callable

from mcp_server.audit import AuditLogger
from mcp_server.parsers.ez_tools import (
    parse_evtx,
    parse_mft,
    parse_shimcache,
    summarise_evtx,
    summarise_mft,
    summarise_shimcache,
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
