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
    parse_filescan,
    parse_image_info,
    parse_netscan,
    parse_psscan,
    parse_pstree,
    summarise_cmdline,
    summarise_filescan,
    summarise_image_info,
    summarise_netscan,
    summarise_psscan,
    summarise_pstree,
)
from mcp_server.tools._common import (
    DEFAULT_EVIDENCE_ROOTS,
    CmdlineArgs,
    FileScanArgs,
    ImageInfoArgs,
    NetScanArgs,
    PathValidationError,
    PsScanArgs,
    PsTreeArgs,
    ToolError,
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
) -> dict[str, Any]:
    """Run a Vol3 plugin with `-r jsonl`, parse its output, audit-log the call.

    Same pre/post pattern as `vol3_image_info` but uses jsonl renderer so the
    parser doesn't have to deal with tab-separated text. Used by every
    row-oriented Vol3 wrapper (psscan / pstree / cmdline / netscan / filescan).
    """
    exec_id = audit.new_exec_id()
    raw_dir = audit.raw_output_dir / "subprocess"
    argv = [_vol_executable(), "-q", "-r", "jsonl", "-f", str(image_path), plugin]

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
            args={"image": str(image_path)},
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
        if k not in {"processes", "rows", "nodes", "connections", "files"}
    }

    audit.record(
        exec_id=exec_id,
        agent=agent,
        tool=tool_name,
        args={"image": str(image_path)},
        raw_output_path=raw_path,
        exit_code=0,
        wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    return {"exec_id": exec_id, **parsed}


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
