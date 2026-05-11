"""Phase 3 threat-hunting + carving + hashing tools.

Tool inventory:

  yara_scan_extract(extract_exec_id, ruleset?)  — yara CLI on extracted file
  vol3_vadyarascan(image, pid, ruleset?)         — Vol3 windows.vadyarascan
  bulk_extract(image, scanners_disable?)         — bulk_extractor full-image scan
  strings_extract(extract_exec_id, min_length?, encoding?) — bstrings dump
  hash_file(extract_exec_id)                     — MD5+SHA1+SHA256(+ssdeep)
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from mcp_server.audit import AuditLogger
from mcp_server.parsers.threat_hunt import (
    parse_bulk_extractor,
    parse_bulk_extractor_dir,
    parse_hash_result,
    parse_strings,
    parse_yara,
    summarise_bulk_extractor,
    summarise_hash_result,
    summarise_strings,
    summarise_yara,
)
from mcp_server.tools._common import (
    DEFAULT_EVIDENCE_ROOTS,
    ToolError,
    run_subprocess,
    validate_evidence_path,
)
from mcp_server.tools.ez_tools import _check_dll, _check_dotnet, _resolve_extract


# Default YARA ruleset shipped with SIFT-OWL. Override with
# SIFT_OWL_YARA_RULES=/path/to/rules.yar (single file or dir of .yar).
_DEFAULT_YARA_RULES = (
    Path(__file__).resolve().parents[1] / "yara_rules" / "sift_owl_starter.yar"
)


def _yara_ruleset() -> Path:
    override = os.environ.get("SIFT_OWL_YARA_RULES")
    if override:
        p = Path(override)
        if not p.exists():
            raise ToolError(f"SIFT_OWL_YARA_RULES path does not exist: {p}")
        return p
    if not _DEFAULT_YARA_RULES.exists():
        raise ToolError(
            f"default YARA ruleset missing at {_DEFAULT_YARA_RULES}; "
            "install SIFT-OWL bundled rules or set SIFT_OWL_YARA_RULES"
        )
    return _DEFAULT_YARA_RULES


def _check_yara() -> str:
    found = shutil.which("yara")
    if not found:
        raise ToolError(
            "`yara` binary not on PATH — install with `apt install yara` or "
            "run scripts/bootstrap_sift_tools.sh"
        )
    return found


def _check_bulk_extractor() -> str:
    found = shutil.which("bulk_extractor")
    if not found:
        raise ToolError("`bulk_extractor` not on PATH")
    return found


# ---------------------------------------------------------------------------
# yara_scan_extract — yara CLI on a previously-extracted file.
# ---------------------------------------------------------------------------


def yara_scan_extract(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "threat_hunt_agent",
    ruleset_path: str | None = None,
    timeout_s: float = 300,
) -> dict[str, Any]:
    """Run `yara -s -m -w <rules> <extracted_file>` for malware-family hits.

    `ruleset_path` defaults to the bundled `mcp_server/yara_rules/
    sift_owl_starter.yar`. Override with `SIFT_OWL_YARA_RULES` env var.
    `-s` includes the matched strings; `-m` includes rule metadata;
    `-w` suppresses warnings (cleaner output).
    """
    extract_path = _resolve_extract(audit, extract_exec_id)
    rules = Path(ruleset_path) if ruleset_path else _yara_ruleset()
    if not rules.exists():
        raise ToolError(f"YARA rules path missing: {rules}")

    exec_id = audit.new_exec_id()
    sub_dir = audit.raw_output_dir / "subprocess"

    argv = [_check_yara(), "-s", "-m", "-w", str(rules), str(extract_path)]
    rr = run_subprocess(argv, output_dir=sub_dir, name=exec_id, timeout_s=timeout_s)

    # YARA exits non-zero on rule-syntax errors; 0 = success even with no matches.
    if not rr.ok and rr.exit_code != 0:
        raw_capture = audit.write_raw(
            exec_id, f"FAILED ({rr.error}). stderr: {rr.stderr_path}\n",
        )
        audit.record(
            exec_id=exec_id, agent=agent, tool="yara_scan_extract",
            args={"extract_exec_id": extract_exec_id, "ruleset": str(rules)},
            raw_output_path=raw_capture,
            exit_code=rr.exit_code, wall_ms=rr.wall_ms,
            summary=f"FAILED: {rr.error or 'non-zero exit'}",
            error=rr.error or f"exit {rr.exit_code}",
        )
        raise ToolError(
            f"yara_scan_extract failed (exit {rr.exit_code}): {rr.error}"
        )

    stdout_text = rr.stdout_path.read_text(errors="replace")
    raw_path = audit.write_raw(exec_id, stdout_text)
    parsed = parse_yara(stdout_text)
    summary = summarise_yara(parsed)

    parsed_summary_compact = {k: v for k, v in parsed.items() if k != "rows"}

    audit.record(
        exec_id=exec_id, agent=agent, tool="yara_scan_extract",
        args={"extract_exec_id": extract_exec_id, "ruleset": str(rules)},
        raw_output_path=raw_path,
        exit_code=0, wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    # Truncate rows for wire fit (50 matches max). Full data on disk.
    truncated = dict(parsed)
    full_rows = truncated.get("rows") or []
    if len(full_rows) > 50:
        truncated["rows"] = full_rows[:50]
        truncated["rows_truncated"] = True
        truncated["rows_total"] = len(full_rows)
    else:
        truncated["rows_truncated"] = False
        truncated["rows_total"] = len(full_rows)
    return {"exec_id": exec_id, **truncated}


# ---------------------------------------------------------------------------
# vol3_vadyarascan — Vol3 `windows.vadyarascan` for memory YARA per PID.
#
# Lives here (not in tools/memory.py) because it's a threat-hunt primitive
# that depends on the YARA ruleset resolution above.
# ---------------------------------------------------------------------------


def vol3_vadyarascan(
    image: str,
    *,
    pid: int,
    audit: AuditLogger,
    agent: str = "threat_hunt_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    ruleset_path: str | None = None,
    timeout_s: float = 1800,
) -> dict[str, Any]:
    """`windows.vadyarascan --pid <PID> --yara-file <rules>` — per-process
    memory YARA scan.

    Per-PID required: scanning all processes is hours on a multi-GB image.
    Returns per-match records: PID, ImageFileName, Rule, Offset, ...
    """
    from mcp_server.tools.memory import _vol_executable
    image_path = validate_evidence_path(image, allowed_roots=evidence_roots)
    rules = Path(ruleset_path) if ruleset_path else _yara_ruleset()
    if not rules.exists():
        raise ToolError(f"YARA rules path missing: {rules}")

    exec_id = audit.new_exec_id()
    sub_dir = audit.raw_output_dir / "subprocess"

    argv = [
        _vol_executable(),
        "-q", "-r", "jsonl",
        "-f", str(image_path),
        "windows.vadyarascan",
        "--pid", str(pid),
        "--yara-file", str(rules),
    ]
    rr = run_subprocess(argv, output_dir=sub_dir, name=exec_id, timeout_s=timeout_s)

    if not rr.ok:
        raw_capture = audit.write_raw(
            exec_id, f"FAILED ({rr.error}). stderr: {rr.stderr_path}\n",
        )
        audit.record(
            exec_id=exec_id, agent=agent, tool="vol3_vadyarascan",
            args={"image": str(image_path), "pid": pid, "ruleset": str(rules)},
            raw_output_path=raw_capture,
            exit_code=rr.exit_code, wall_ms=rr.wall_ms,
            summary=f"FAILED: {rr.error or 'non-zero exit'}",
            error=rr.error or f"exit {rr.exit_code}",
        )
        raise ToolError(
            f"vol3_vadyarascan failed (exit {rr.exit_code}): {rr.error}"
        )

    from mcp_server.parsers.vol3 import parse_jsonl_rows
    stdout_text = rr.stdout_path.read_text(errors="replace")
    raw_path = audit.write_raw(exec_id, stdout_text)
    rows = parse_jsonl_rows(stdout_text)
    rule_counts: dict[str, int] = {}
    out_rows: list[dict[str, Any]] = []
    for r in rows:
        rule = r.get("Rule") or r.get("rule") or ""
        if rule:
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
        out_rows.append({
            "pid":     r.get("PID"),
            "process": r.get("Process"),
            "rule":    rule,
            "offset":  r.get("Offset"),
            "value":   r.get("Value"),
        })
    parsed = {
        "count":       len(out_rows),
        "rule_counts": dict(sorted(rule_counts.items(), key=lambda kv: -kv[1])),
        "rows":        out_rows,
    }
    summary = f"{len(out_rows)} VAD-YARA matches" + (
        f" across {len(rule_counts)} rules" if rule_counts else ""
    )

    audit.record(
        exec_id=exec_id, agent=agent, tool="vol3_vadyarascan",
        args={"image": str(image_path), "pid": pid, "ruleset": str(rules)},
        raw_output_path=raw_path,
        exit_code=0, wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary={"count": parsed["count"], "rule_counts": parsed["rule_counts"]},
    )

    full_rows = parsed["rows"]
    truncated = dict(parsed)
    if len(full_rows) > 50:
        truncated["rows"] = full_rows[:50]
        truncated["rows_truncated"] = True
        truncated["rows_total"] = len(full_rows)
    return {"exec_id": exec_id, **truncated}


# ---------------------------------------------------------------------------
# bulk_extract — full-image multi-scanner feature extraction.
#
# bulk_extractor defaults run a comprehensive scanner set. We accept
# `disable_scanners` to drop noisy ones (e.g. accts/httplogs) and
# `enable_scanners` for off-by-default scanners (e.g. xor, wordlist).
# ---------------------------------------------------------------------------


# Per-scanner row cap on the wire (mirrors Amcache / SRUM patterns).
_BE_SECTION_ROW_LIMIT = 50

# Default scanners we disable — high-noise / overlap with other tools.
_BE_DEFAULT_DISABLE = ("accts", "httplogs", "json", "msxml")


def bulk_extract(
    image: str,
    *,
    audit: AuditLogger,
    agent: str = "threat_hunt_agent",
    evidence_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
    disable_scanners: tuple[str, ...] = _BE_DEFAULT_DISABLE,
    enable_scanners: tuple[str, ...] = (),
    threads: int = 4,
    timeout_s: float = 1800,
) -> dict[str, Any]:
    """`bulk_extractor -j <threads> -o <out_dir> <image>` — full-image feature
    extraction.

    Default scanners enabled per bulk_extractor's own defaults (URLs, emails,
    domains, IPs, PE/ZIP/RAR signatures, EXIF, ...). The `accts` /
    `httplogs` / `json` / `msxml` scanners are disabled by default — they're
    high-noise on Windows images. Override with `disable_scanners=()`.

    SLOW: 5-15 min on a multi-GB image. Per-scanner output is parsed into
    sections (top 50 features per scanner on the wire; full feature files
    on disk).
    """
    image_path = validate_evidence_path(image, allowed_roots=evidence_roots)
    exec_id = audit.new_exec_id()
    out_subdir = audit.raw_output_dir / "bulk_extractor" / exec_id
    out_subdir.mkdir(parents=True, exist_ok=True)
    sub_dir = audit.raw_output_dir / "subprocess"

    argv = [_check_bulk_extractor(), "-j", str(threads), "-o", str(out_subdir)]
    for s in disable_scanners:
        argv += ["-x", s]
    for s in enable_scanners:
        argv += ["-e", s]
    argv.append(str(image_path))

    rr = run_subprocess(argv, output_dir=sub_dir, name=exec_id, timeout_s=timeout_s)

    if not rr.ok:
        raw_capture = audit.write_raw(
            exec_id, f"FAILED ({rr.error}). stderr: {rr.stderr_path}\n",
        )
        audit.record(
            exec_id=exec_id, agent=agent, tool="bulk_extract",
            args={"image": str(image_path), "disable": list(disable_scanners),
                  "enable": list(enable_scanners), "threads": threads},
            raw_output_path=raw_capture,
            exit_code=rr.exit_code, wall_ms=rr.wall_ms,
            summary=f"FAILED: {rr.error or 'non-zero exit'}",
            error=rr.error or f"exit {rr.exit_code}",
        )
        raise ToolError(
            f"bulk_extract failed (exit {rr.exit_code}, timed_out={rr.timed_out}): "
            f"{rr.error}. stderr at {rr.stderr_path}"
        )

    parsed = parse_bulk_extractor_dir(out_subdir, top_n=_BE_SECTION_ROW_LIMIT)
    # Persist as JSON for query_rows compat (full feature files stay on disk).
    raw_text = json.dumps(parsed, default=str)
    raw_path = audit.write_raw(exec_id, raw_text)
    summary = summarise_bulk_extractor(parsed)

    parsed_summary_compact = {
        "total_features":  parsed.get("total_features"),
        "feature_counts":  parsed.get("feature_counts"),
        "unknown_files":   parsed.get("unknown_files"),
    }

    audit.record(
        exec_id=exec_id, agent=agent, tool="bulk_extract",
        args={"image": str(image_path), "disable": list(disable_scanners),
              "enable": list(enable_scanners), "threads": threads},
        raw_output_path=raw_path,
        exit_code=0, wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    # Sections already truncated to top_n=50 by parse_bulk_extractor_dir.
    return {"exec_id": exec_id, **parsed}


# ---------------------------------------------------------------------------
# strings_extract — bstrings (EZ Tools) on a previously-extracted file.
# ---------------------------------------------------------------------------


def strings_extract(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "threat_hunt_agent",
    min_length: int = 6,
    encoding: str = "all",
    timeout_s: float = 300,
) -> dict[str, Any]:
    """`bstrings --get-strings -f <file> --ms <min>` on an extracted blob.

    `encoding` ∈ {"ascii", "unicode", "all"} (default all). `min_length`
    is the minimum length filter (default 6). Hardcoded URLs, mutex
    names, anti-sandbox strings, debug paths all surface here.
    """
    extract_path = _resolve_extract(audit, extract_exec_id)
    exec_id = audit.new_exec_id()
    sub_dir = audit.raw_output_dir / "subprocess"

    dll = _check_dll("bstrings.dll")
    argv = [
        _check_dotnet(), str(dll),
        "-f", str(extract_path),
        "--ms", str(min_length),
        "-q",                          # quiet header
    ]
    if encoding == "ascii":
        argv.append("--asn")           # ASCII-narrow only
    elif encoding == "unicode":
        argv.append("--asu")           # ASCII-unicode only
    # else: bstrings defaults to both

    rr = run_subprocess(argv, output_dir=sub_dir, name=exec_id, timeout_s=timeout_s)

    if not rr.ok:
        raw_capture = audit.write_raw(
            exec_id, f"FAILED ({rr.error}). stderr: {rr.stderr_path}\n",
        )
        audit.record(
            exec_id=exec_id, agent=agent, tool="strings_extract",
            args={"extract_exec_id": extract_exec_id, "encoding": encoding,
                  "min_length": min_length},
            raw_output_path=raw_capture,
            exit_code=rr.exit_code, wall_ms=rr.wall_ms,
            summary=f"FAILED: {rr.error or 'non-zero exit'}",
            error=rr.error or f"exit {rr.exit_code}",
        )
        raise ToolError(
            f"strings_extract failed (exit {rr.exit_code}): {rr.error}"
        )

    stdout_text = rr.stdout_path.read_text(errors="replace")
    raw_path = audit.write_raw(exec_id, stdout_text)
    parsed = parse_strings(stdout_text, min_length=min_length)
    summary = summarise_strings(parsed)

    parsed_summary_compact = {k: v for k, v in parsed.items() if k != "rows"}

    audit.record(
        exec_id=exec_id, agent=agent, tool="strings_extract",
        args={"extract_exec_id": extract_exec_id, "encoding": encoding,
              "min_length": min_length},
        raw_output_path=raw_path,
        exit_code=0, wall_ms=rr.wall_ms,
        summary=summary,
        parsed_summary=parsed_summary_compact,
    )

    full_rows = parsed.get("rows") or []
    truncated = dict(parsed)
    if len(full_rows) > 50:
        truncated["rows"] = full_rows[:50]
        truncated["rows_truncated"] = True
        truncated["rows_total"] = len(full_rows)
    else:
        truncated["rows_truncated"] = False
        truncated["rows_total"] = len(full_rows)
    return {"exec_id": exec_id, **truncated}


# ---------------------------------------------------------------------------
# hash_file — MD5 + SHA-1 + SHA-256 + optional ssdeep on an extracted file.
# ---------------------------------------------------------------------------


def _maybe_ssdeep(path: Path) -> str | None:
    """Try `ssdeep -b -s <file>` and parse out the fuzzy hash. Returns None
    if ssdeep is not installed or the call fails."""
    if not shutil.which("ssdeep"):
        return None
    try:
        r = subprocess.run(
            ["ssdeep", "-b", "-s", str(path)],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            return None
        # Output line: "<blocksize>:<h1>:<h2>,<filename>"
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("ssdeep,"):
                continue
            return line.split(",")[0].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    return None


def hash_file(
    extract_exec_id: str,
    *,
    audit: AuditLogger,
    agent: str = "threat_hunt_agent",
    timeout_s: float = 120,  # noqa: ARG001 — hashing is in-process
) -> dict[str, Any]:
    """Compute MD5 + SHA-1 + SHA-256 (+ optional ssdeep) on an extracted file.

    Standard hashes are computed in-process via `hashlib`; ssdeep via
    subprocess if the binary is on PATH. Useful for: matching dropped
    binaries against external IOC lists, evidence chain-of-custody anchors,
    fuzzy similarity to known-malicious samples.
    """
    extract_path = _resolve_extract(audit, extract_exec_id)
    exec_id = audit.new_exec_id()

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    with extract_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 << 20), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            size += len(chunk)

    parsed = {
        "size_bytes":  size,
        "md5":         md5.hexdigest(),
        "sha1":        sha1.hexdigest(),
        "sha256":      sha256.hexdigest(),
        "ssdeep":      _maybe_ssdeep(extract_path),
    }
    raw_path = audit.write_raw(exec_id, json.dumps(parsed, indent=2))
    summary = summarise_hash_result(parsed)

    audit.record(
        exec_id=exec_id, agent=agent, tool="hash_file",
        args={"extract_exec_id": extract_exec_id, "extract_path": str(extract_path)},
        raw_output_path=raw_path,
        exit_code=0, wall_ms=0,
        summary=summary,
        parsed_summary=parsed,
    )

    return {"exec_id": exec_id, **parsed}
