"""Typed MCP functions wrapping disk-side forensic tools.

Each function takes an E01 image path (validated against the evidence-root
allow-list), runs the underlying tool with `-i ewf` so TSK reads the E01
directly without `ewfmount` (no privilege escalation, no mount syscall),
streams stdout to disk via the audit logger, parses the result, and
records a single audit row.

Tool inventory (v0):

  ewf_verify(image)           — ewfverify <image>           — chain of custody
  ewf_info(image)             — ewfinfo <image>             — image metadata
  tsk_partition_table(image)  — mmls -i ewf <image>         — partitions
  tsk_fs_stat(image, offset?) — fsstat -i ewf -o N <image>  — FS metadata
  tsk_fls_list(image, offset?)— fls -i ewf -r -p -F -o N    — recursive listing
  tsk_icat_extract(image, offset?, inode, target_filename?) — extract one file

Each row-emitting function (`tsk_fls_list`) honours the same truncate-at-50
pattern as the Vol3 wrappers, so its result fits Claude Code's per-tool-result
size cap. The full data is preserved on disk and reachable via `query_rows`.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from mcp_server.audit import AuditLogger
from mcp_server.parsers.disk import (
    parse_ewfinfo,
    parse_ewfverify,
    parse_fls,
    parse_fsstat,
    parse_mmls,
    summarise_ewfinfo,
    summarise_ewfverify,
    summarise_fls,
    summarise_fsstat,
    summarise_mmls,
)
from mcp_server.tools._common import (
    DEFAULT_EVIDENCE_ROOTS,
    PathValidationError,
    ToolError,
    run_subprocess,
    validate_evidence_path,
)
from mcp_server.tools.memory import _truncate_rows


def _bin(name: str, env_override: str | None = None) -> str:
    """Resolve a forensic CLI binary, honouring env-var overrides for tests."""
    import os
    if env_override:
        v = os.environ.get(env_override)
        if v:
            return v
    found = shutil.which(name)
    if not found:
        raise ToolError(f"`{name}` not found on PATH")
    return found


def _run_disk_tool(
    *,
    argv: list[str],
    image_path: Path,
    extra_args_for_audit: dict[str, Any],
    tool_name: str,
    parser,
    summariser,
    audit: AuditLogger,
    agent: str,
    timeout_s: float,
    truncate: bool = True,
    accept_exit_codes: tuple[int, ...] = (0,),
) -> dict[str, Any]:
    """Shared runner for non-JSONL disk tools (text output, parser-aware).

    Mirrors the shape of `tools.memory._run_jsonl_plugin` but the parser
    consumes raw stdout (text) instead of JSONL.

    `accept_exit_codes` lets specific tools tolerate non-zero exits that
    are informative rather than errors. The canonical case is `mmls` on
    a logical-drive E01: it exits 1 with empty stdout to signal "no
    partition table" — we want to record that as a 0-partition result,
    not raise.
    """
    exec_id = audit.new_exec_id()
    raw_dir = audit.raw_output_dir / "subprocess"
    rr = run_subprocess(argv, output_dir=raw_dir, name=exec_id, timeout_s=timeout_s)

    exit_acceptable = (rr.exit_code in accept_exit_codes) and not rr.timed_out
    if not exit_acceptable:
        raw_path = audit.write_raw(
            exec_id,
            rr.stdout_path.read_bytes() if rr.stdout_path.exists() else b"",
        )
        audit.record(
            exec_id=exec_id,
            agent=agent,
            tool=tool_name,
            args={"image": str(image_path), **extra_args_for_audit},
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

    parsed_summary_compact = {
        k: v for k, v in parsed.items()
        if k not in {
            "files", "partitions",  # row lists
            "raw_fields", "sections", "status_lines",  # bulky sub-dicts
        }
    }

    audit.record(
        exec_id=exec_id,
        agent=agent,
        tool=tool_name,
        args={"image": str(image_path), **extra_args_for_audit},
        raw_output_path=raw_path,
        exit_code=0,
        wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    if truncate:
        parsed = _truncate_rows(parsed)
    return {"exec_id": exec_id, **parsed}


# ---------------------------------------------------------------------------
# ewf_verify / ewf_info — image-level integrity + metadata.
# ---------------------------------------------------------------------------


def ewf_verify(
    image: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 1800,
) -> dict[str, Any]:
    """Verify an E01 image's stored MD5/SHA1 hashes against the data.

    Slow on large images (re-reads every byte) — 18 GB takes ~5 min.
    Use sparingly; the harness re-hashes evidence pre/post-run anyway.
    """
    image_path = validate_evidence_path(image, allowed_roots=evidence_roots)
    return _run_disk_tool(
        argv=[_bin("ewfverify"), str(image_path)],
        image_path=image_path,
        extra_args_for_audit={},
        tool_name="ewf_verify",
        parser=parse_ewfverify,
        summariser=summarise_ewfverify,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
        truncate=False,
    )


def ewf_info(
    image: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 60,
) -> dict[str, Any]:
    """Image metadata: case info, examiner, acquisition tool, sector count, MD5/SHA1."""
    image_path = validate_evidence_path(image, allowed_roots=evidence_roots)
    return _run_disk_tool(
        argv=[_bin("ewfinfo"), str(image_path)],
        image_path=image_path,
        extra_args_for_audit={},
        tool_name="ewf_info",
        parser=parse_ewfinfo,
        summariser=summarise_ewfinfo,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
        truncate=False,
    )


# ---------------------------------------------------------------------------
# Partition / filesystem metadata.
# ---------------------------------------------------------------------------


def tsk_partition_table(
    image: str,
    *,
    audit: AuditLogger,
    agent: str = "disk_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 60,
) -> dict[str, Any]:
    """`mmls -i ewf <image>` — list partitions with start/end sectors.

    Logical-drive E01s (single NTFS volume captured directly, common for
    SANS lab images) return empty / 0 partitions. Callers should treat
    that as "no offset needed for fls/fsstat/icat — pass offset=None".

    mmls exits 1 with empty stdout on logical-drive images; we accept
    that as the successful "0-partition" result.
    """
    image_path = validate_evidence_path(image, allowed_roots=evidence_roots)
    return _run_disk_tool(
        argv=[_bin("mmls"), "-i", "ewf", str(image_path)],
        image_path=image_path,
        extra_args_for_audit={},
        tool_name="tsk_partition_table",
        parser=parse_mmls,
        summariser=summarise_mmls,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
        truncate=False,
        accept_exit_codes=(0, 1),
    )


def tsk_fs_stat(
    image: str,
    *,
    offset: int | None = None,
    audit: AuditLogger,
    agent: str = "disk_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 120,
) -> dict[str, Any]:
    """`fsstat -i ewf [-o N] <image>` — FS type, cluster size, volume name, etc."""
    image_path = validate_evidence_path(image, allowed_roots=evidence_roots)
    argv = [_bin("fsstat"), "-i", "ewf"]
    if offset is not None:
        argv += ["-o", str(offset)]
    argv += [str(image_path)]
    return _run_disk_tool(
        argv=argv,
        image_path=image_path,
        extra_args_for_audit={"offset": offset},
        tool_name="tsk_fs_stat",
        parser=parse_fsstat,
        summariser=summarise_fsstat,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
        truncate=False,
    )


# ---------------------------------------------------------------------------
# File listing + extraction.
# ---------------------------------------------------------------------------


def tsk_fls_list(
    image: str,
    *,
    offset: int | None = None,
    audit: AuditLogger,
    agent: str = "disk_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 1800,
) -> dict[str, Any]:
    """`fls -i ewf -r -p -F [-o N] <image>` — recursive file listing of regular files.

    `-F` filters to regular files (excluding directories) — useful for
    forensic triage where directory entries are noise. The full row list
    is truncated at the MCP boundary; agent uses `query_rows` to drill
    by path / extension.
    """
    image_path = validate_evidence_path(image, allowed_roots=evidence_roots)
    argv = [_bin("fls"), "-i", "ewf", "-r", "-p", "-F"]
    if offset is not None:
        argv += ["-o", str(offset)]
    argv += [str(image_path)]
    return _run_disk_tool(
        argv=argv,
        image_path=image_path,
        extra_args_for_audit={"offset": offset, "filter": "regular_files"},
        tool_name="tsk_fls_list",
        parser=parse_fls,
        summariser=summarise_fls,
        audit=audit,
        agent=agent,
        timeout_s=timeout_s,
        truncate=True,
    )


def tsk_icat_extract(
    image: str,
    *,
    inode: int,
    offset: int | None = None,
    target_dir: str | None = None,
    audit: AuditLogger,
    agent: str = "disk_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    timeout_s: float = 600,
) -> dict[str, Any]:
    """`icat -i ewf [-o N] <image> <inode>` → write to a file under audit/extracts/.

    Extracts a single file by inode (from `tsk_fls_list` output). Writes
    to `audit/raw/extracts/<exec_id>.bin` to keep extraction artifacts
    inside the audit-tree (same chain-of-custody story as raw plugin
    outputs). Returns size + sha256 of the extracted bytes.

    NEVER writes outside `audit/raw/extracts/` — even if the agent
    suggests `target_dir`, that argument is currently ignored for safety.
    """
    import hashlib
    image_path = validate_evidence_path(image, allowed_roots=evidence_roots)

    extracts_dir = audit.raw_output_dir / "extracts"
    extracts_dir.mkdir(parents=True, exist_ok=True)
    exec_id = audit.new_exec_id()
    out_path = extracts_dir / f"{exec_id}.bin"

    argv = [_bin("icat"), "-i", "ewf"]
    if offset is not None:
        argv += ["-o", str(offset)]
    argv += [str(image_path), str(inode)]

    # icat emits raw bytes on stdout. We want them in `out_path`, not
    # `subprocess/{exec_id}.stdout` — write directly there via run_subprocess
    # and then move; cleanest: redirect to extracts_dir under run_subprocess'
    # stdout name, then rename.
    rr = run_subprocess(
        argv,
        output_dir=extracts_dir,
        name=exec_id,
        timeout_s=timeout_s,
    )
    extracted_path = extracts_dir / f"{exec_id}.stdout"

    if not rr.ok:
        audit.record(
            exec_id=exec_id,
            agent=agent,
            tool="tsk_icat_extract",
            args={"image": str(image_path), "inode": inode, "offset": offset},
            raw_output_path=extracted_path if extracted_path.exists() else None,
            exit_code=rr.exit_code,
            wall_ms=rr.wall_ms,
            summary=f"FAILED: {rr.error or 'non-zero exit'}",
            error=rr.error or f"exit {rr.exit_code}",
        )
        raise ToolError(
            f"tsk_icat_extract failed (exit {rr.exit_code}): {rr.error}"
        )

    # Rename .stdout → .bin (extension reflects raw bytes content)
    out_path.write_bytes(extracted_path.read_bytes())
    extracted_path.unlink(missing_ok=True)

    size = out_path.stat().st_size
    h = hashlib.sha256()
    with out_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 << 20), b""):
            h.update(chunk)
    sha256 = h.hexdigest()

    summary = f"extracted inode={inode}, {size} bytes, sha256={sha256[:16]}…"
    audit.record(
        exec_id=exec_id,
        agent=agent,
        tool="tsk_icat_extract",
        args={"image": str(image_path), "inode": inode, "offset": offset},
        raw_output_path=out_path,
        exit_code=0,
        wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary={"size_bytes": size, "sha256": sha256, "inode": inode},
    )

    return {
        "exec_id":  exec_id,
        "inode":    inode,
        "size_bytes": size,
        "sha256":   sha256,
        "extract_path": str(out_path),
    }
