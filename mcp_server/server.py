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
    vol3_cachedump as _cachedump,
    vol3_cmdline as _cmdline,
    vol3_dlllist as _dlllist,
    vol3_envars as _envars,
    vol3_filescan as _filescan,
    vol3_handles as _handles,
    vol3_hashdump as _hashdump,
    vol3_image_info as _image_info,
    vol3_malfind as _malfind,
    vol3_netscan as _netscan,
    vol3_psscan as _psscan,
    vol3_pstree as _pstree,
    vol3_scheduled_tasks as _scheduled_tasks,
    vol3_skeleton_key_check as _skeleton_key,
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
    ezt_persistence_keys_parse as _ezt_persistence_keys_parse,
    ezt_prefetch_parse as _ezt_prefetch_parse,
    ezt_recyclebin_parse as _ezt_recyclebin_parse,
    ezt_shimcache_parse as _ezt_shimcache_parse,
    ezt_srum_parse as _ezt_srum_parse,
    ezt_task_xml_parse as _ezt_task_xml_parse,
)
from mcp_server.tools.threat_hunt import (
    bulk_extract as _bulk_extract,
    hash_file as _hash_file,
    strings_extract as _strings_extract,
    vol3_vadyarascan as _vadyarascan,
    yara_scan_extract as _yara_scan_extract,
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


@mcp.tool()
def vol3_scheduled_tasks(image: str) -> dict[str, Any]:
    """`windows.scheduled_tasks` — Task Scheduler entries from in-memory registry.

    T1053 — Scheduled Task/Job. Per-task: Task Name, Action + Arguments +
    Context + Type, Principal ID, Trigger Description/Type, Working Directory,
    Creation/LastRun/LastSuccessful timestamps, Enabled flag. Live in-memory
    state; pair with `ezt_task_xml_parse` on disk for full T1053 closure."""
    return _scheduled_tasks(
        {"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS,
    )


@mcp.tool()
def vol3_hashdump(image: str) -> dict[str, Any]:
    """`windows.hashdump` — local SAM hashes (T1003.002 OS Credential Dumping).

    Per-account: User, RID, LM Hash, NT Hash. Empty NT hashes flagged as
    blank-password accounts (a security-policy red flag and a credential-
    theft prerequisite the agent should call out)."""
    return _hashdump(
        {"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS,
    )


@mcp.tool()
def vol3_cachedump(image: str) -> dict[str, Any]:
    """`windows.cachedump` — LSA cached domain credentials (T1003.005 DCC2/MSCASH).

    Per-cached-account: Username, Domain Name, Domain Hash, Hash.
    MSCASH/DCC2 hashes here are strong offline-cracking targets — surface
    these to flag credential exposure even from offline images."""
    return _cachedump(
        {"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS,
    )


@mcp.tool()
def vol3_skeleton_key_check(image: str) -> dict[str, Any]:
    """`windows.skeleton_key_check` — Mimikatz skeleton-key patch detection
    (T1558 Steal/Forge Kerberos Tickets).

    Inspects lsass.exe in-memory for the Mimikatz skeleton-key patch that
    forces Kerberos to accept a single master password for all accounts.
    Negative result is normal; positive = critical finding."""
    return _skeleton_key(
        {"image": image}, audit=_audit(), evidence_roots=_EVIDENCE_ROOTS,
    )


@mcp.tool()
def vol3_envars(image: str, pid: int | None = None) -> dict[str, Any]:
    """`windows.envars [--pid PID]` — per-process environment variables.

    T1574 Hijack Execution Flow (Path interception). Returns full env-var
    list with a curated `path_like_rows` slice (PATH / PATHEXT /
    PSModulePath / INCLUDE / LIB) — attacker prepends or PSModulePath
    injection surface here."""
    return _envars(
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
    """In-process SRUM parser (libyal `libesedb`) over an extracted
    `Windows\\System32\\sru\\SRUDB.dat`.

    Pre-req: extract `SRUDB.dat` via `tsk_icat_extract`. SRUM is Win8+;
    XP/Win7 hosts will not have this file. Returns 7 provider sections
    keyed by GUID — `network_usage` (per-app per-interface bytes_sent /
    bytes_recvd), `app_resource_use` (CPU + I/O counters per app per
    hour), `network_connections` (per-app L2 profile + connected_time),
    `push_notifications`, `energy_usage` + `energy_usage_lt`,
    `app_timeline`. AppId / UserId integers are joined to
    `SruDbIdMapTable` so each row carries `app_name` (program path /
    service / AppX) and `user_sid`. Each section's rows truncated to 50
    on the wire; full row lists on disk, drillable via `query_rows`.

    Reimplemented in W3-43 — SrumECmd v2026.5.0 refuses to run on Linux
    ("Non-Windows platforms not supported due to the need to load ESI
    specific Windows libraries"). libesedb is portable; output is
    functionally equivalent."""
    return _ezt_srum_parse(extract_exec_id, audit=_audit())


@mcp.tool()
def ezt_task_xml_parse(extract_exec_id: str) -> dict[str, Any]:
    """Parse a Windows Task Scheduler XML file from disk (T1053).

    Pre-req: extract one task file from `\\Windows\\System32\\Tasks\\<folder>\\
    <TaskName>` via `tsk_icat_extract`. The files are well-formed XML;
    this parser surfaces task_name, author, principal (UserId + RunLevel +
    LogonType), triggers (Calendar/Boot/Logon/Time/Event/Registration),
    actions (Exec command + arguments, ComHandler ClassId), settings
    (Enabled, Hidden, RunOnlyIfNetworkAvailable).

    Cross-source: corroborates `vol3_scheduled_tasks` (live memory state)
    and `ezt_evtx_parse` on Microsoft-Windows-TaskScheduler/Operational
    (events 106 / 140 / 141 / 200)."""
    return _ezt_task_xml_parse(extract_exec_id, audit=_audit())


@mcp.tool()
def ezt_persistence_keys_parse(extract_exec_id: str) -> dict[str, Any]:
    """RECmd persistence-triage batch on an extracted registry hive.

    Pre-req: extract a registry hive via `tsk_icat_extract`:
      - `\\Windows\\System32\\config\\SOFTWARE` (HKLM Run / Winlogon / IFEO / AppInit)
      - `\\Windows\\System32\\config\\SYSTEM` (Services)
      - `\\Users\\<u>\\NTUSER.DAT` (HKCU Run / RunOnce)

    Returns sections grouped by Category:
      * run_keys — HKLM/HKCU Run, RunOnce, RunOnceEx, Policies-Explorer-Run (T1547.001)
      * winlogon — Shell, Userinit, Notify (T1547.004)
      * ifeo     — Image File Execution Options Debugger / GlobalFlag /
                   SilentProcessExit (T1574.012)
      * dll_hijack — AppInit_DLLs, AppCertDlls (T1574.001)
      * services — ServiceDll + ImagePath (T1543.003)

    Each section's rows are truncated to 50 on the wire."""
    return _ezt_persistence_keys_parse(extract_exec_id, audit=_audit())


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
# Phase 3 — Threat hunt + carving + hashing.
# ---------------------------------------------------------------------------


@mcp.tool()
def yara_scan_extract(extract_exec_id: str, ruleset_path: str | None = None) -> dict[str, Any]:
    """`yara -s -m -w <rules> <extracted_file>` — file-level YARA scan.

    Pre-req: extract a binary (or hive / EVTX / any blob) via
    `tsk_icat_extract`. Returns per-match: rule_name, matched_strings
    (offset + bytes), rule metadata (mitre / severity tags).

    Ruleset defaults to `mcp_server/yara_rules/sift_owl_starter.yar` —
    curated set covering Mimikatz residue, Cobalt Strike beacons,
    PowerShell encoded loaders, common webshells, RAS software,
    PyInstaller packing, LSASS-dump magic. Override with
    `SIFT_OWL_YARA_RULES=/path/to/rules.yar` env var or `ruleset_path`."""
    return _yara_scan_extract(extract_exec_id, audit=_audit(), ruleset_path=ruleset_path)


@mcp.tool()
def vol3_vadyarascan(image: str, pid: int, ruleset_path: str | None = None) -> dict[str, Any]:
    """`vol3 windows.vadyarascan --pid PID --yara-file <rules>` — per-process
    memory YARA scan.

    Pre-req: a specific PID identified via `vol3_psscan` / `vol3_malfind`.
    Scans every committed VAD region in that process against the ruleset.
    SLOW (multi-minute on a complex process); per-PID required.

    Returns per-match: PID, Process, Rule, Offset, Value. Curated rules
    catch in-memory Mimikatz patches, Cobalt Strike beacon residue,
    PyInstaller-packed payloads."""
    return _vadyarascan(
        image, pid=pid, ruleset_path=ruleset_path,
        audit=_audit(), evidence_roots=_EVIDENCE_ROOTS,
    )


@mcp.tool()
def bulk_extract(
    image: str,
    disable_scanners: list[str] | None = None,
    enable_scanners: list[str] | None = None,
    threads: int = 4,
) -> dict[str, Any]:
    """`bulk_extractor -j <n> -o <out> <image>` — multi-scanner feature
    extraction over raw bytes.

    Surfaces URLs / emails / IPs / domains / PE+ZIP+RAR signatures /
    EXIF / GPS / phone numbers from anywhere in the image — including
    unallocated space, pagefile fragments, kernel pool, allocator residue.
    Crucial for **T1071** (URL/IP/DNS evidence beyond browser history)
    and **T1140** (decoded payload remnants in raw memory).

    SLOW: 5-15 min on a multi-GB image. Returns sections grouped by
    scanner (url / email / ip / winpe / zip / rar / ...). Each section's
    top 50 features land on the wire; full feature files stay on disk.

    Defaults disable noisy `accts` / `httplogs` / `json` / `msxml` scanners.
    Override `disable_scanners=[]` to enable them, or set
    `enable_scanners=["xor","wordlist"]` for off-by-default scanners."""
    return _bulk_extract(
        image,
        audit=_audit(), evidence_roots=_EVIDENCE_ROOTS,
        disable_scanners=tuple(disable_scanners) if disable_scanners is not None else None,
        enable_scanners=tuple(enable_scanners) if enable_scanners is not None else (),
        threads=threads,
    )


@mcp.tool()
def strings_extract(
    extract_exec_id: str,
    min_length: int = 6,
    encoding: str = "all",
) -> dict[str, Any]:
    """`bstrings.dll -f <file> --ms <min>` — extract printable strings from a
    previously-extracted file.

    Pre-req: `tsk_icat_extract`. `encoding` ∈ {"ascii", "unicode", "all"}.
    `min_length` defaults to 6 (filter out noise).

    Triage use: hardcoded URLs / mutex names / anti-sandbox checks /
    PDB paths / error messages in unknown binaries. Cheap — typically
    <1 second per file. Truncated to 50 strings on the wire; full set
    drillable via `query_rows(<exec_id>, "string", "<substr>")`."""
    return _strings_extract(
        extract_exec_id, audit=_audit(),
        min_length=min_length, encoding=encoding,
    )


@mcp.tool()
def hash_file(extract_exec_id: str) -> dict[str, Any]:
    """Compute MD5 + SHA-1 + SHA-256 (+ optional ssdeep fuzzy hash) on a
    previously-extracted file.

    Pre-req: `tsk_icat_extract`. Returns size_bytes, md5, sha1, sha256
    (+ ssdeep when the binary is installed). Useful for:
      * Matching dropped binaries against external IOC lists (VirusTotal,
        threat-intel feeds — agent does the matching offline).
      * Chain-of-custody anchors for evidence sub-elements.
      * Fuzzy similarity to known-malicious samples (ssdeep)."""
    return _hash_file(extract_exec_id, audit=_audit())


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
