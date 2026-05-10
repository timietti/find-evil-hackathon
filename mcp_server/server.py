"""SIFT-OWL MCP server.

Exposes the typed read-only forensic functions from `mcp_server.tools.memory`
as MCP tools over stdio. Any MCP client (Claude Code, an arbitrary LLM agent,
or a test harness) can connect, discover the tool inventory, and invoke them.

The agent on the other end of the wire **never has shell access** — it can only
call the functions registered below. That is the architectural enforcement of
trust boundary TB1 from `docs/ARCHITECTURE.md`.

Configuration (env vars):

    SIFT_OWL_AUDIT_DIR     — where to write exec_log.jsonl + raw/. Default:
                             $PWD/audit. The dir is created if missing.
    SIFT_OWL_EVIDENCE_ROOT — comma-separated allow-list of evidence roots.
                             Default: /cases. Paths outside these are rejected.
    SIFT_OWL_VOL3_BIN      — override the `vol` binary location. Default: PATH.

Run with:

    sift-mcp                # stdio transport (default for MCP clients)
    sift-mcp inspect        # print tool inventory + version, exit
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer
from mcp.server.fastmcp import FastMCP

from mcp_server.audit import AuditLogger
from mcp_server.tools.memory import (
    query_rows as _query_rows,
    vol3_cmdline as _cmdline,
    vol3_dlllist as _dlllist,
    vol3_filescan as _filescan,
    vol3_handles as _handles,
    vol3_image_info as _image_info,
    vol3_malfind as _malfind,
    vol3_netscan as _netscan,
    vol3_psscan as _psscan,
    vol3_pstree as _pstree,
    vol3_svcscan as _svcscan,
    vol3_userassist as _userassist,
)
from mcp_server.tools.disk import (
    ewf_info as _ewf_info,
    ewf_verify as _ewf_verify,
    tsk_fls_list as _tsk_fls_list,
    tsk_fs_stat as _tsk_fs_stat,
    tsk_icat_extract as _tsk_icat_extract,
    tsk_partition_table as _tsk_partition_table,
)
from mcp_server.tools.ez_tools import (
    ezt_amcache_parse as _ezt_amcache_parse,
    ezt_evtx_parse as _ezt_evtx_parse,
    ezt_jumplist_parse as _ezt_jumplist_parse,
    ezt_mft_parse as _ezt_mft_parse,
    ezt_prefetch_parse as _ezt_prefetch_parse,
    ezt_recyclebin_parse as _ezt_recyclebin_parse,
    ezt_shimcache_parse as _ezt_shimcache_parse,
    ezt_srum_parse as _ezt_srum_parse,
)


# ---------------------------------------------------------------------------
# Module-level state. FastMCP doesn't pass per-call context for state, so we
# scope the AuditLogger and evidence-root config at the module level. This is
# fine because the MCP server is single-process / single-tenant by design.
# ---------------------------------------------------------------------------


_AUDIT: AuditLogger | None = None
_EVIDENCE_ROOTS: tuple[Path, ...] = (Path("/cases").resolve(),)


def _init(audit_dir: Path, evidence_roots: tuple[Path, ...]) -> None:
    global _AUDIT, _EVIDENCE_ROOTS
    audit_dir.mkdir(parents=True, exist_ok=True)
    _AUDIT = AuditLogger(
        exec_log_path=audit_dir / "exec_log.jsonl",
        raw_output_dir=audit_dir / "raw",
    )
    _EVIDENCE_ROOTS = evidence_roots


def _audit() -> AuditLogger:
    if _AUDIT is None:
        raise RuntimeError(
            "MCP server audit not initialised. Call _init() before mcp.run(), "
            "or set SIFT_OWL_AUDIT_DIR and re-launch."
        )
    return _AUDIT


# ---------------------------------------------------------------------------
# FastMCP instance + tool registrations.
#
# Each registered tool is a thin wrapper around the underlying function in
# `tools/memory.py`. We re-declare the signature here (one positional `image`
# arg) so MCP clients see a clean schema. Internal kwargs like `audit=` and
# `evidence_roots=` are bound to the module-level state at call time.
# ---------------------------------------------------------------------------


mcp = FastMCP("sift-owl")


@mcp.tool()
def vol3_image_info(image: str) -> dict[str, Any]:
    """Get OS / build / arch / CPU count / capture-time from a Windows memory image.

    Wraps `vol -q -f <image> windows.info`. Use this first on any new memory
    image to confirm Vol3 can resolve symbols and to get the system time
    anchor for cross-source correlation.
    """
    return _image_info({"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def vol3_psscan(image: str) -> dict[str, Any]:
    """Pool-tag scan for processes — finds hidden + exited processes that
    pslist (EPROCESS list walk) misses. Use this as the primary process
    enumeration method."""
    return _psscan({"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def vol3_pstree(image: str) -> dict[str, Any]:
    """Process parent/child tree from EPROCESS hierarchy. Use to spot LOLBins
    spawned from unexpected parents (e.g. cmd.exe under winword.exe)."""
    return _pstree({"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def vol3_cmdline(image: str) -> dict[str, Any]:
    """Per-process command-line arguments. Most-revealing single plugin for
    attacker activity — captures the actual command lines executed."""
    return _cmdline({"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def vol3_netscan(image: str) -> dict[str, Any]:
    """TCP/UDP endpoints — current + historical (pool-tag scan). Returns the
    full connection list plus a foreign-IP frequency table with loopback /
    listen-only addresses pre-filtered."""
    return _netscan({"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def vol3_filescan(image: str) -> dict[str, Any]:
    """File objects cached in pool memory — every file open at capture time
    plus residue from recently-closed files. Slowest of the standard plugins
    (~3 min on an 18 GB image) but the highest-signal source for what was on
    disk during the incident."""
    return _filescan({"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def vol3_malfind(image: str) -> dict[str, Any]:
    """Suspicious VAD regions — RWX, MZ-headed without on-disk backing,
    classic shellcode-injection indicators. Note: Microsoft Defender JIT and
    .NET CLR produce legitimate RWX regions; triage hits manually."""
    return _malfind({"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def vol3_svcscan(image: str) -> dict[str, Any]:
    """Service Control Manager + driver enumeration. Look for services with
    binary paths in user-writable directories (Temp, AppData) or service
    names that don't match their on-disk binary."""
    return _svcscan({"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def vol3_userassist(image: str) -> dict[str, Any]:
    """UserAssist registry values — Explorer-driven program-execution log
    per user hive. Strong indicator for hands-on-keyboard activity (programs
    launched via Explorer/Start menu)."""
    return _userassist({"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def vol3_dlllist(image: str, pid: int | None = None) -> dict[str, Any]:
    """`windows.dlllist [--pid PID]` — DLLs loaded per process.

    Returns per-DLL records: pid, process, base, size, name, path, load_time.
    Aggregates by_process count, by_path_top (top-20 directories), unbacked
    count (DLLs with no on-disk path — in-memory injected modules).

    Pass `pid` to narrow to a single process (much faster + smaller). Without
    pid, enumerates all processes — use only if you need the full picture."""
    return _dlllist(
        {"image": image, "pid": pid},
        audit=_audit(), evidence_roots=_EVIDENCE_ROOTS,
    )


@mcp.tool()
def vol3_handles(image: str, pid: int) -> dict[str, Any]:
    """`windows.handles --pid PID` — process open handles.

    Per-PID required: scanning all processes is multi-hour on big images.
    Returns per-handle records (type, name, granted_access) and curated
    high-signal lists: mutexes_top (malware-family fingerprint),
    file_handles_top, key_handles_top.

    Mutex name conventions reveal malware families (e.g.
    `Global\\rundll32.exe` is a known APT marker)."""
    return _handles(
        {"image": image, "pid": pid},
        audit=_audit(), evidence_roots=_EVIDENCE_ROOTS,
    )


# ---------------------------------------------------------------------------
# Disk-side tools.
# ---------------------------------------------------------------------------


@mcp.tool()
def ewf_verify(image: str) -> dict[str, Any]:
    """Verify an E01 image against its stored MD5/SHA1 acquisition hashes.

    SLOW on large images — re-reads every byte. The harness already
    pre-hashes evidence files; only call this if you specifically need
    libewf-level integrity confirmation."""
    return _ewf_verify(image, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def ewf_info(image: str) -> dict[str, Any]:
    """E01 metadata — case number, examiner, acquisition tool, sector count,
    stored MD5/SHA1 hashes. Useful first call on any new disk image to
    confirm chain of custody and image type (logical vs full-disk)."""
    return _ewf_info(image, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def tsk_partition_table(image: str) -> dict[str, Any]:
    """`mmls -i ewf <image>` — list partitions and their start sectors.

    Returns 0 partitions for logical-drive images (single-volume captures
    common in SANS lab data) — that's expected and means subsequent
    fsstat/fls/icat calls should pass `offset=null`."""
    return _tsk_partition_table(image, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def tsk_fs_stat(image: str, offset: int | None = None) -> dict[str, Any]:
    """`fsstat -i ewf [-o offset] <image>` — filesystem type, cluster size,
    volume name, sector size."""
    return _tsk_fs_stat(image, offset=offset, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def tsk_fls_list(image: str, offset: int | None = None) -> dict[str, Any]:
    """`fls -i ewf -r -p -F [-o offset] <image>` — recursive listing of all
    regular files in the volume, including deleted entries (marked
    `deleted: true`).

    Truncated at the MCP boundary to the first 50 entries; use
    `query_rows(<exec_id>, "path", "<substring>")` to drill by filename
    or by extension. Aggregates `count`, `deleted_count`, `by_extension`,
    `by_top_dir` are unaffected by truncation."""
    return _tsk_fls_list(image, offset=offset, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS)


@mcp.tool()
def tsk_icat_extract(
    image: str, inode: int, offset: int | None = None,
) -> dict[str, Any]:
    """Extract a single file from the E01 by inode/MFT entry. Writes to
    `audit/raw/extracts/<exec_id>.bin` (NEVER to /cases/, NEVER to user-
    supplied paths). Returns size + sha256 of the extracted bytes plus
    the on-disk path so subsequent tools (yara_scan, etc.) can reference it."""
    return _tsk_icat_extract(
        image, inode=inode, offset=offset,
        audit=_audit(), evidence_roots=_EVIDENCE_ROOTS,
    )


# ---------------------------------------------------------------------------
# EZ Tools — extract-then-parse Windows artifacts.
# All take an extract_exec_id (from a prior tsk_icat_extract) so the agent
# never specifies a filesystem path directly. Architectural enforcement
# of the no-arbitrary-paths trust boundary.
# ---------------------------------------------------------------------------


@mcp.tool()
def ezt_mft_parse(extract_exec_id: str) -> dict[str, Any]:
    """`MFTECmd --json` on an extracted $MFT — full NTFS file timeline.

    Pre-req: call `tsk_icat_extract` first with `inode=0` (the $MFT is
    always inode 0 on NTFS) to get an extract_exec_id, then pass it here.
    Returns per-entry timestamps (Created / Modified / Accessed / Recorded),
    MFT-anti-tamper flags (Timestomped / uSecZeros / Copied), file_name,
    parent_path, file_size — plus aggregates count / deleted /
    timestomped_count / by_extension / by_parent_path.

    Truncated to the first 50 entries; drill via `query_rows` filtered
    on `file_name`, `parent_path`, or `extension`."""
    return _ezt_mft_parse(extract_exec_id, audit=_audit())


@mcp.tool()
def ezt_shimcache_parse(extract_exec_id: str) -> dict[str, Any]:
    """`AppCompatCacheParser --csv` on an extracted SYSTEM hive — ShimCache.

    Pre-req: extract `Windows/System32/config/SYSTEM` (or
    `WINDOWS/system32/config/system` on XP) via `tsk_icat_extract`.
    Returns per-entry: ControlSet, Path, LastModifiedTimeUTC, Executed
    flag, Duplicate flag. ShimCache is high-signal for program-execution
    evidence — it captures binary path + last-modified time **even for
    binaries that have been deleted**, so it survives sdelete cleanup."""
    return _ezt_shimcache_parse(extract_exec_id, audit=_audit())


@mcp.tool()
def ezt_evtx_parse(extract_exec_id: str) -> dict[str, Any]:
    """`EvtxECmd --json` on an extracted .evtx — Windows Event Log parser.

    Pre-req: extract a single .evtx file (Security.evtx, System.evtx,
    Application.evtx, etc. from `Windows/System32/winevt/Logs/`) via
    `tsk_icat_extract`. Returns per-event: EventId, TimeCreated, Channel,
    Provider, Computer, Level, Process/Thread IDs, UserName, RemoteHost,
    MapDescription (high-level summary), PayloadData1..5 (extracted from
    raw event data). Aggregates by_event_id / by_channel / by_computer /
    by_provider.

    Critical event IDs for IR work: 4624 (logon), 4625 (failed logon),
    4688 (process create), 4768/4769 (Kerberos), 4720 (account create),
    4732/4756 (group membership), 7045 (service install), 1102 (log clear)."""
    return _ezt_evtx_parse(extract_exec_id, audit=_audit())


@mcp.tool()
def ezt_prefetch_parse(extract_exec_id: str) -> dict[str, Any]:
    """`PECmd --json` on an extracted Prefetch (.pf) file — Win10/Win11
    program-execution gold standard.

    Pre-req: extract a single `.pf` file from `Windows\\Prefetch\\` via
    `tsk_icat_extract`. Returns ExecutableName + Hash, RunCount, LastRun
    + 7 PreviousRun timestamps, plus directories + files_loaded the
    binary referenced. Survives binary deletion."""
    return _ezt_prefetch_parse(extract_exec_id, audit=_audit())


@mcp.tool()
def ezt_jumplist_parse(extract_exec_id: str) -> dict[str, Any]:
    """`JLECmd --json` on an extracted Jump List file —
    `.automaticDestinations-ms` or `.customDestinations-ms`.

    Pre-req: extract one Jump List file from
    `\\Users\\<u>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\
    {Automatic,Custom}Destinations\\` via `tsk_icat_extract`. Returns
    per-DestList entry: AppId + AppIDDescription, target Path, hostname,
    drive type + serial, MFT entry + sequence. Strong "what did the user
    open in app X" evidence — survives external-drive detachment."""
    return _ezt_jumplist_parse(extract_exec_id, audit=_audit())


@mcp.tool()
def ezt_recyclebin_parse(extract_exec_id: str) -> dict[str, Any]:
    """`RBCmd --json` on an extracted Recycle Bin record (`$I*` on Win10,
    `INFO2` on XP).

    Pre-req: extract one `$I*` file from `$Recycle.Bin\\S-<SID>\\` via
    `tsk_icat_extract`. Returns per record: SourceName (original full
    path), FileSize, DeletedOn timestamp, FileName. The deleted file's
    body lives in the paired `$R*`."""
    return _ezt_recyclebin_parse(extract_exec_id, audit=_audit())


@mcp.tool()
def ezt_srum_parse(extract_exec_id: str) -> dict[str, Any]:
    """`SrumECmd --csv` on an extracted SRUDB.dat — System Resource Usage
    Monitor (Win8+).

    Pre-req: extract `Windows\\System32\\sru\\SRUDB.dat` via `tsk_icat_extract`.
    Returns multiple sections; the killer one is **NetworkUsages** — per-app
    accumulated bytes-in / bytes-out by hour and interface. Strong **exfil
    detector**: the largest outbound bytes-out per process per hour.

    XP/Win7 hosts will not have SRUDB.dat — call only on Win8+ images."""
    return _ezt_srum_parse(extract_exec_id, audit=_audit())


@mcp.tool()
def ezt_amcache_parse(extract_exec_id: str) -> dict[str, Any]:
    """`AmcacheParser -i --csv` on an extracted Amcache.hve — Win8.1+ program-execution
    registry parser.

    Pre-req: extract `Windows/AppCompat/Programs/Amcache.hve` via
    `tsk_icat_extract`. Returns multiple Amcache sections, each with its
    own row list. The richest sections for malware triage are:

      * UnassociatedFileEntries (Win10) — every program executed, with
        SHA-1 hash, FullPath, FileVersion, ProductName, Size, registry
        key timestamps. Surviving evidence even after binary deletion.
      * ProgramEntries — installed programs (publisher, install time).
      * AssociatedFileEntries — legacy equivalent of UnassociatedFileEntries
        on Win8.1 / pre-1803 Win10.

    Other sections (DriverBinaries, DriverPackages, DeviceContainers,
    DevicePnps, ShortCuts) are also parsed but lower-signal for malware.

    Each section's rows are truncated to 50 on the wire; full entries
    persisted to audit raw_output as JSON for offline review."""
    return _ezt_amcache_parse(extract_exec_id, audit=_audit())


@mcp.tool()
def query_rows(
    exec_id: str,
    filter_field: str | None = None,
    filter_value: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Drill into a previous tool's full row list by exec_id.

    Each `vol3_*` tool returns a summary + the first 50 rows of its
    structured output. The full data is preserved on disk and reachable via
    this tool. Use it to:

    - find a specific PID across the 2000+ procs in psscan
    - find files matching a substring in the 40K-row filescan output
    - paginate through the full netscan connection list
    - retrieve all rows of any prior call by its exec_id

    Args:
      exec_id: the exec_id from a previous vol3_* call.
      filter_field: optional field name to filter on (e.g. 'pid', 'image',
        'name', 'foreign_addr', 'process'). See the original tool's row
        schema for available field names.
      filter_value: optional value. For strings: case-insensitive substring
        match. For numbers/booleans: exact match.
      limit: max rows to return (default 50, max 500).
      offset: skip the first N matching rows (for pagination).

    Returns:
      dict with `tool`, `total_rows`, `matched_rows`, `returned_rows`,
      `rows`, plus echoes of `exec_id`, `filter`, `offset`, `limit`.
    """
    return _query_rows(
        {
            "exec_id": exec_id,
            "filter_field": filter_field,
            "filter_value": filter_value,
            "limit": limit,
            "offset": offset,
        },
        audit=_audit(),
    )


# ---------------------------------------------------------------------------
# CLI entry — parses env / flags, then either prints the tool inventory or
# starts the stdio MCP server.
# ---------------------------------------------------------------------------


app = typer.Typer(help="SIFT-OWL MCP server (typed read-only DFIR functions).")


def _resolve_config(
    audit_dir: str | None,
    evidence_root: str | None,
) -> tuple[Path, tuple[Path, ...]]:
    """Resolve audit dir + evidence roots from CLI args + env."""
    audit = Path(
        audit_dir
        or os.environ.get("SIFT_OWL_AUDIT_DIR")
        or "./audit"
    ).resolve()
    raw_roots = (
        evidence_root
        or os.environ.get("SIFT_OWL_EVIDENCE_ROOT")
        or "/cases"
    )
    roots = tuple(Path(p.strip()).resolve() for p in raw_roots.split(",") if p.strip())
    return audit, roots


@app.command()
def inspect(
    audit_dir: str = typer.Option(None, "--audit-dir"),
    evidence_root: str = typer.Option(None, "--evidence-root"),
) -> None:
    """Print the tool inventory and configuration, then exit."""
    audit, roots = _resolve_config(audit_dir, evidence_root)
    inventory = []
    for name, tool in sorted(mcp._tool_manager._tools.items()):  # noqa: SLF001
        inventory.append({
            "name": name,
            "description": (tool.description or "").strip().splitlines()[0],
        })
    typer.echo(json.dumps({
        "server":     "sift-owl",
        "audit_dir":  str(audit),
        "evidence_roots": [str(r) for r in roots],
        "tool_count": len(inventory),
        "tools":      inventory,
        "now_utc":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }, indent=2))


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    audit_dir: str = typer.Option(None, "--audit-dir", help="Audit log directory."),
    evidence_root: str = typer.Option(
        None, "--evidence-root",
        help="Comma-separated allow-list of evidence roots.",
    ),
    transport: str = typer.Option(
        "stdio", "--transport", help="MCP transport (only 'stdio' supported).",
    ),
) -> None:
    """Start the MCP server (default action when no subcommand given)."""
    if ctx.invoked_subcommand is not None:
        return
    audit, roots = _resolve_config(audit_dir, evidence_root)
    _init(audit, roots)
    if transport != "stdio":
        raise typer.BadParameter(f"only stdio transport is supported, got: {transport}")
    mcp.run()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
