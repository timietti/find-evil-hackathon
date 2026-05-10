"""Typed MCP functions wrapping Volatility 3.

Each function:

1. Validates inputs (Pydantic model from `_common`).
2. Resolves evidence paths against the evidence-root allow-list.
3. Runs the underlying Vol3 plugin via `run_subprocess` (no shell).
4. Streams raw stdout to disk via `AuditLogger.write_raw`.
5. Parses the raw output with `parsers.vol3.parse_<plugin>`.
6. Records a single audit row (`exec_id`, args, hashes, parsed_summary, summary).
7. Returns the parsed dict augmented with `exec_id` so callers can cite it.

The audit row's `exec_id` is the trust anchor: any agent claim that cites this
function must reference the returned `exec_id`, and the validator can re-read
the parsed JSON to confirm or refute the claim.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from mcp_server.audit import AuditLogger
from mcp_server.parsers.vol3 import (
    parse_cmdline,
    parse_dlllist,
    parse_filescan,
    parse_handles,
    parse_image_info,
    parse_malfind,
    parse_netscan,
    parse_psscan,
    parse_pstree,
    parse_svcscan,
    parse_userassist,
    summarise_cmdline,
    summarise_dlllist,
    summarise_filescan,
    summarise_handles,
    summarise_image_info,
    summarise_malfind,
    summarise_netscan,
    summarise_psscan,
    summarise_pstree,
    summarise_svcscan,
    summarise_userassist,
)
from mcp_server.tools._common import (
    DEFAULT_EVIDENCE_ROOTS,
    CmdlineArgs,
    DllListArgs,
    FileScanArgs,
    HandlesArgs,
    ImageInfoArgs,
    MalfindArgs,
    NetScanArgs,
    PathValidationError,
    PsScanArgs,
    PsTreeArgs,
    SvcScanArgs,
    ToolError,
    UserAssistArgs,
    run_subprocess,
    validate_evidence_path,
)


# Fall back to PATH lookup; on this SIFT instance `vol` is at /usr/local/bin/vol
# (symlink to /opt/volatility3/bin/vol). The Protocol SIFT global CLAUDE.md
# hard-codes /opt/volatility3-2.20.0/vol.py which is stale — discover at runtime.
def _vol_executable() -> str:
    override = os.environ.get("SIFT_OWL_VOL3_BIN")
    if override:
        return override
    found = shutil.which("vol")
    if not found:
        raise ToolError(
            "`vol` (Volatility 3) not found on PATH. "
            "Set $SIFT_OWL_VOL3_BIN to override."
        )
    return found


def vol3_image_info(
    args: ImageInfoArgs | dict,
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 600,
) -> dict[str, Any]:
    """Wrap `vol -q -f <image> windows.info`.

    Returns the parsed image-info dict augmented with `exec_id`.

    Raises:
        PathValidationError: image is outside allowed evidence roots.
        ToolError:           subprocess failed or timed out.
    """
    if isinstance(args, dict):
        args = ImageInfoArgs(**args)

    image_path = validate_evidence_path(args.image, allowed_roots=evidence_roots)

    exec_id = audit.new_exec_id()
    raw_dir = audit.raw_output_dir / "subprocess"
    argv = [_vol_executable(), "-q", "-f", str(image_path), "windows.info"]

    rr = run_subprocess(
        argv,
        output_dir=raw_dir,
        name=exec_id,
        timeout_s=timeout_s,
    )

    if not rr.ok:
        # Persist what little output we got, then audit the failure.
        raw_path = audit.write_raw(
            exec_id,
            rr.stdout_path.read_bytes() if rr.stdout_path.exists() else b"",
        )
        audit.record(
            exec_id=exec_id,
            agent=agent,
            tool="vol3_image_info",
            args={"image": str(image_path)},
            raw_output_path=raw_path,
            exit_code=rr.exit_code,
            wall_ms=rr.wall_ms,
            summary=f"FAILED: {rr.error or 'non-zero exit'}",
            error=rr.error or f"exit {rr.exit_code}",
        )
        raise ToolError(
            f"vol3_image_info failed (exit {rr.exit_code}, "
            f"timed_out={rr.timed_out}): {rr.error}. "
            f"Stderr at {rr.stderr_path}"
        )

    stdout_text = rr.stdout_path.read_text(errors="replace")
    raw_path = audit.write_raw(exec_id, stdout_text)
    parsed = parse_image_info(stdout_text)
    summary = summarise_image_info(parsed)

    audit.record(
        exec_id=exec_id,
        agent=agent,
        tool="vol3_image_info",
        args={"image": str(image_path)},
        raw_output_path=raw_path,
        exit_code=0,
        wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary=parsed,
    )

    return {"exec_id": exec_id, **parsed}


# ---------------------------------------------------------------------------
# Shared helper for the row-oriented (jsonl-emitting) plugins.
# ---------------------------------------------------------------------------


# Maps tool name → key holding the bulky row list in the parser's output.
# Used by `_truncate_rows()` and by `query_rows` for re-parse + filtering.
_ROWS_KEY: dict[str, str] = {
    "vol3_psscan":         "processes",
    "vol3_pstree":         "nodes",
    "vol3_cmdline":        "rows",
    "vol3_netscan":        "connections",
    "vol3_filescan":       "files",
    "vol3_malfind":        "findings",
    "vol3_svcscan":        "services",
    "vol3_userassist":     "entries",
    "vol3_dlllist":        "rows",
    "vol3_handles":        "rows",
    "tsk_partition_table": "partitions",
    "tsk_fls_list":        "files",
    "ezt_mft_parse":       "rows",
    "ezt_shimcache_parse": "entries",
    "ezt_evtx_parse":      "events",
    "ezt_prefetch_parse":  "rows",
    "ezt_jumplist_parse":  "rows",
    "ezt_recyclebin_parse": "rows",
    # ezt_amcache_parse / ezt_srum_parse have nested-section layout — query_rows
    # not registered (per-section truncation already returns 50 rows each).
    # ewf_info / ewf_verify / tsk_fs_stat have no row list — n/a
    # tsk_icat_extract has no parsed-text output — n/a
}

# Maps tool name → parser fn (used by query_rows to re-parse raw output).
_PARSERS: dict[str, Any] = {}


def _register_parsers() -> None:
    """Populated lazily to avoid an import cycle in module-init order.

    Disk-side parsers register themselves here too — query_rows needs to
    know how to re-parse any tool's raw output.
    """
    if _PARSERS:
        return
    _PARSERS.update({
        "vol3_image_info": parse_image_info,
        "vol3_psscan":     parse_psscan,
        "vol3_pstree":     parse_pstree,
        "vol3_cmdline":    parse_cmdline,
        "vol3_netscan":    parse_netscan,
        "vol3_filescan":   parse_filescan,
        "vol3_malfind":    parse_malfind,
        "vol3_svcscan":    parse_svcscan,
        "vol3_userassist": parse_userassist,
        "vol3_dlllist":    parse_dlllist,
        "vol3_handles":    parse_handles,
    })
    # Disk-side parsers — registered lazily here to avoid a circular import
    # at module-load time (tools.disk imports from tools.memory).
    from mcp_server.parsers.disk import (
        parse_ewfinfo, parse_ewfverify, parse_fls, parse_fsstat, parse_mmls,
    )
    _PARSERS.update({
        "ewf_info":            parse_ewfinfo,
        "ewf_verify":          parse_ewfverify,
        "tsk_partition_table": parse_mmls,
        "tsk_fs_stat":         parse_fsstat,
        "tsk_fls_list":        parse_fls,
        # tsk_icat_extract has no parsed-text output; it writes raw bytes.
        # Excluded from query_rows by omission.
    })
    # EZ Tools parsers (extract-then-parse flow).
    from mcp_server.parsers.ez_tools import (
        parse_amcache, parse_evtx, parse_mft, parse_shimcache,
    )
    _PARSERS.update({
        "ezt_mft_parse":        parse_mft,
        "ezt_shimcache_parse":  parse_shimcache,
        "ezt_evtx_parse":       parse_evtx,
        "ezt_amcache_parse":    parse_amcache,
    })
    # Phase 1 EZ Tools (Prefetch, JumpList, RecycleBin, SRUM).
    from mcp_server.parsers.ez_tools import (
        parse_prefetch, parse_jumplist, parse_recyclebin, parse_srum,
    )
    _PARSERS.update({
        "ezt_prefetch_parse":   parse_prefetch,
        "ezt_jumplist_parse":   parse_jumplist,
        "ezt_recyclebin_parse": parse_recyclebin,
        "ezt_srum_parse":       parse_srum,
    })


# Default row cap returned to MCP callers per plugin invocation. Picked to
# stay well under Claude Code's per-tool-result size cap (~330 KB observed
# in v0 on the 18 GB Rocba image; we observed overflow on psscan at 2212
# procs × ~150 B/row ≈ 330 KB). 50 rows × ~500 B = ~25 KB headroom.
DEFAULT_ROW_LIMIT = 50


def _truncate_rows(parsed: dict[str, Any], limit: int = DEFAULT_ROW_LIMIT) -> dict[str, Any]:
    """Cap any embedded row list to `limit` items.

    The full row list is preserved on disk at `raw_output_path` (re-parseable
    via `query_rows`); only the on-the-wire MCP payload is truncated. This
    closes the architectural bug v0 surfaced (large MCP results overflow
    Claude Code's per-tool-result cap, agent can't rehydrate when Read is
    denied).
    """
    out = dict(parsed)
    for key in ("processes", "nodes", "rows", "connections", "files",
                "findings", "services", "entries"):
        if key in out and isinstance(out[key], list):
            full = out[key]
            if len(full) > limit:
                out[key] = full[:limit]
                out[f"{key}_truncated"] = True
                out[f"{key}_total"] = len(full)
            else:
                out[f"{key}_truncated"] = False
                out[f"{key}_total"] = len(full)
    return out


def _run_jsonl_plugin(
    *,
    image_path: Path,
    plugin: str,
    tool_name: str,
    parser,
    summariser,
    audit: AuditLogger,
    agent: str,
    timeout_s: float,
    extra_plugin_args: list[str] | None = None,
    extra_audit_args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run a Vol3 plugin with `-r jsonl`, parse its output, audit-log the call.

    Same pre/post pattern as `vol3_image_info` but uses jsonl renderer so the
    parser doesn't have to deal with tab-separated text. Used by every
    row-oriented Vol3 wrapper (psscan / pstree / cmdline / netscan / filescan /
    dlllist / handles).

    `extra_plugin_args` are appended after the plugin name (e.g. ["--pid", "1912"]).
    `extra_audit_args` extends the audit row's `args` dict so per-PID calls are
    distinguishable in the log.
    """
    exec_id = audit.new_exec_id()
    raw_dir = audit.raw_output_dir / "subprocess"
    argv = [_vol_executable(), "-q", "-r", "jsonl", "-f", str(image_path), plugin]
    if extra_plugin_args:
        argv.extend(extra_plugin_args)

    audit_args: dict[str, Any] = {"image": str(image_path)}
    if extra_audit_args:
        audit_args.update(extra_audit_args)

    rr = run_subprocess(argv, output_dir=raw_dir, name=exec_id, timeout_s=timeout_s)

    if not rr.ok:
        raw_path = audit.write_raw(
            exec_id,
            rr.stdout_path.read_bytes() if rr.stdout_path.exists() else b"",
        )
        audit.record(
            exec_id=exec_id,
            agent=agent,
            tool=tool_name,
            args=audit_args,
            raw_output_path=raw_path,
            exit_code=rr.exit_code,
            wall_ms=rr.wall_ms,
            summary=f"FAILED: {rr.error or 'non-zero exit'}",
            error=rr.error or f"exit {rr.exit_code}",
        )
        raise ToolError(
            f"{tool_name} failed (exit {rr.exit_code}, "
            f"timed_out={rr.timed_out}): {rr.error}. "
            f"Stderr at {rr.stderr_path}"
        )

    stdout_text = rr.stdout_path.read_text(errors="replace")
    raw_path = audit.write_raw(exec_id, stdout_text)
    parsed = parser(stdout_text)
    summary = summariser(parsed)

    # Don't store the full row list inside parsed_summary — that bloats every
    # audit row and undermines the point of the audit log. Keep just the
    # high-signal aggregate fields, plus the raw_output_path so the validator
    # can rehydrate full rows when checking a specific claim.
    parsed_summary_compact = {
        k: v for k, v in parsed.items()
        if k not in {
            "processes", "rows", "nodes", "connections", "files",
            "findings", "services", "entries",
        }
    }

    audit.record(
        exec_id=exec_id,
        agent=agent,
        tool=tool_name,
        args=audit_args,
        raw_output_path=raw_path,
        exit_code=0,
        wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    # Truncate the on-the-wire response so it stays under Claude Code's
    # per-tool-result size cap. Full data is on disk at raw_output_path
    # for the validator + query_rows tool.
    truncated = _truncate_rows(parsed)
    return {"exec_id": exec_id, **truncated}


# ---------------------------------------------------------------------------
# Process discovery — psscan, pstree, cmdline.
# ---------------------------------------------------------------------------


def vol3_psscan(
    args: PsScanArgs | dict,
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 1200,
) -> dict[str, Any]:
    """Pool-tag scan for processes — finds hidden + exited."""
    if isinstance(args, dict):
        args = PsScanArgs(**args)
    image_path = validate_evidence_path(args.image, allowed_roots=evidence_roots)
    return _run_jsonl_plugin(
        image_path=image_path,
        plugin="windows.psscan",
        tool_name="vol3_psscan",
        parser=parse_psscan,
        summariser=summarise_psscan,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
    )


def vol3_pstree(
    args: PsTreeArgs | dict,
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 600,
) -> dict[str, Any]:
    """Process parent/child tree from EPROCESS hierarchy."""
    if isinstance(args, dict):
        args = PsTreeArgs(**args)
    image_path = validate_evidence_path(args.image, allowed_roots=evidence_roots)
    return _run_jsonl_plugin(
        image_path=image_path,
        plugin="windows.pstree",
        tool_name="vol3_pstree",
        parser=parse_pstree,
        summariser=summarise_pstree,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
    )


def vol3_cmdline(
    args: CmdlineArgs | dict,
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 600,
) -> dict[str, Any]:
    """Per-process command-line arguments."""
    if isinstance(args, dict):
        args = CmdlineArgs(**args)
    image_path = validate_evidence_path(args.image, allowed_roots=evidence_roots)
    return _run_jsonl_plugin(
        image_path=image_path,
        plugin="windows.cmdline",
        tool_name="vol3_cmdline",
        parser=parse_cmdline,
        summariser=summarise_cmdline,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
    )


# ---------------------------------------------------------------------------
# Network — netscan.
# ---------------------------------------------------------------------------


def vol3_netscan(
    args: NetScanArgs | dict,
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 1200,
) -> dict[str, Any]:
    """TCP/UDP endpoints — current + historical (pool-tag scan)."""
    if isinstance(args, dict):
        args = NetScanArgs(**args)
    image_path = validate_evidence_path(args.image, allowed_roots=evidence_roots)
    return _run_jsonl_plugin(
        image_path=image_path,
        plugin="windows.netscan",
        tool_name="vol3_netscan",
        parser=parse_netscan,
        summariser=summarise_netscan,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
    )


# ---------------------------------------------------------------------------
# Files — filescan.
# ---------------------------------------------------------------------------


def vol3_filescan(
    args: FileScanArgs | dict,
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 1800,  # filescan is the slowest of the five — full pool walk
) -> dict[str, Any]:
    """File objects cached in pool memory — open + recently-closed files."""
    if isinstance(args, dict):
        args = FileScanArgs(**args)
    image_path = validate_evidence_path(args.image, allowed_roots=evidence_roots)
    return _run_jsonl_plugin(
        image_path=image_path,
        plugin="windows.filescan",
        tool_name="vol3_filescan",
        parser=parse_filescan,
        summariser=summarise_filescan,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
    )


# ---------------------------------------------------------------------------
# Code injection / services / GUI execution.
# ---------------------------------------------------------------------------


def vol3_malfind(
    args: MalfindArgs | dict,
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 1800,
) -> dict[str, Any]:
    """Suspicious VAD regions — RWX, MZ-headed, no on-disk backing."""
    if isinstance(args, dict):
        args = MalfindArgs(**args)
    image_path = validate_evidence_path(args.image, allowed_roots=evidence_roots)
    return _run_jsonl_plugin(
        image_path=image_path,
        plugin="windows.malfind",
        tool_name="vol3_malfind",
        parser=parse_malfind,
        summariser=summarise_malfind,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
    )


def vol3_svcscan(
    args: SvcScanArgs | dict,
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 1200,
) -> dict[str, Any]:
    """Service Control Manager + driver enumeration."""
    if isinstance(args, dict):
        args = SvcScanArgs(**args)
    image_path = validate_evidence_path(args.image, allowed_roots=evidence_roots)
    return _run_jsonl_plugin(
        image_path=image_path,
        plugin="windows.svcscan",
        tool_name="vol3_svcscan",
        parser=parse_svcscan,
        summariser=summarise_svcscan,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
    )


def vol3_userassist(
    args: UserAssistArgs | dict,
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 1200,
) -> dict[str, Any]:
    """UserAssist registry values — Explorer-driven program execution log."""
    if isinstance(args, dict):
        args = UserAssistArgs(**args)
    image_path = validate_evidence_path(args.image, allowed_roots=evidence_roots)
    return _run_jsonl_plugin(
        image_path=image_path,
        plugin="windows.registry.userassist",
        tool_name="vol3_userassist",
        parser=parse_userassist,
        summariser=summarise_userassist,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
    )


def vol3_dlllist(
    args: DllListArgs | dict,
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 1800,
) -> dict[str, Any]:
    """`windows.dlllist` — DLLs loaded per process.

    Optional pid filter narrows to a single process (much faster + smaller).
    Catch unsigned DLLs in lsass / svchost (credential stealers, sideloaded
    DLLs adjacent to LOLBins, in-memory injected modules with no on-disk path).
    """
    if isinstance(args, dict):
        args = DllListArgs(**args)
    image_path = validate_evidence_path(args.image, allowed_roots=evidence_roots)
    extra_plugin = ["--pid", str(args.pid)] if args.pid is not None else None
    extra_audit = {"pid": args.pid} if args.pid is not None else None
    return _run_jsonl_plugin(
        image_path=image_path,
        plugin="windows.dlllist",
        tool_name="vol3_dlllist",
        parser=parse_dlllist,
        summariser=summarise_dlllist,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
        extra_plugin_args=extra_plugin,
        extra_audit_args=extra_audit,
    )


def vol3_handles(
    args: HandlesArgs | dict,
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 600,
) -> dict[str, Any]:
    """`windows.handles --pid <PID>` — process open handles.

    Per-PID required: enumerating all processes' handles is multi-hour on
    big images. Mutexes are malware-family fingerprints; file/key/section
    handles reveal what the process held open at capture time.
    """
    if isinstance(args, dict):
        args = HandlesArgs(**args)
    image_path = validate_evidence_path(args.image, allowed_roots=evidence_roots)
    return _run_jsonl_plugin(
        image_path=image_path,
        plugin="windows.handles",
        tool_name="vol3_handles",
        parser=parse_handles,
        summariser=summarise_handles,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
        extra_plugin_args=["--pid", str(args.pid)],
        extra_audit_args={"pid": args.pid},
    )


# ---------------------------------------------------------------------------
# query_rows — drill into a previous tool call's full row list.
# ---------------------------------------------------------------------------


def _coerce_filter_value(field_value: Any, filter_value: str) -> bool:
    """Match a filter_value (always str) against a field value of any type."""
    if field_value is None:
        return False
    if isinstance(field_value, bool):
        # Match before int — bool is a subclass of int.
        return str(field_value).lower() == filter_value.strip().lower()
    if isinstance(field_value, (int, float)):
        try:
            return field_value == type(field_value)(filter_value)
        except (ValueError, TypeError):
            return False
    # String fields: case-insensitive substring match.
    return filter_value.lower() in str(field_value).lower()


def query_rows(
    args: "QueryRowsArgs | dict",
    *,
    audit: AuditLogger,
    agent: str = "memory_agent",
) -> dict[str, Any]:
    """Re-parse a previous tool's raw output, filter, return matching rows.

    Look up `exec_id` in the audit log to find:
      1. which `tool_name` produced it (so we know which parser to use)
      2. where its `raw_output_path` is on disk

    Re-parse the raw output, apply the optional `(filter_field, filter_value)`
    filter, paginate via `(offset, limit)`. Returns the rows + counts.
    """
    from mcp_server.tools._common import QueryRowsArgs  # local: avoid cycle

    if isinstance(args, dict):
        args = QueryRowsArgs(**args)

    _register_parsers()

    row = audit.lookup_exec(args.exec_id)
    if row is None:
        raise ToolError(f"exec_id not found in audit log: {args.exec_id}")

    tool_name = row.get("tool")
    raw_path = row.get("raw_output_path")
    if not tool_name or not raw_path:
        raise ToolError(f"audit row malformed for exec_id {args.exec_id}: {row}")

    rows_key = _ROWS_KEY.get(tool_name)
    parser = _PARSERS.get(tool_name)
    if rows_key is None or parser is None:
        raise ToolError(
            f"query_rows does not support tool_name={tool_name} "
            f"(no rows key or parser registered)"
        )

    raw_path_obj = Path(raw_path)
    if not raw_path_obj.exists():
        raise ToolError(f"raw output missing on disk: {raw_path_obj}")

    parsed = parser(raw_path_obj.read_text(errors="replace"))
    full_rows = parsed.get(rows_key) or []

    if args.filter_field and args.filter_value is not None:
        matched = [
            r for r in full_rows
            if _coerce_filter_value(r.get(args.filter_field), args.filter_value)
        ]
    else:
        matched = list(full_rows)

    page = matched[args.offset:args.offset + args.limit]

    return {
        "exec_id":       args.exec_id,
        "tool":          tool_name,
        "rows_key":      rows_key,
        "total_rows":    len(full_rows),
        "matched_rows":  len(matched),
        "returned_rows": len(page),
        "offset":        args.offset,
        "limit":         args.limit,
        "filter":        (
            {"field": args.filter_field, "value": args.filter_value}
            if args.filter_field else None
        ),
        "rows":          page,
    }
