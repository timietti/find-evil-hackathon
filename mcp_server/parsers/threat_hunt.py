"""Parsers for Phase 3 threat-hunting / carving tools.

Tools wrapped here:
  - YARA scan output (yara CLI / vol3 vadyarascan)
  - bulk_extractor feature-file directory
  - bstrings (EZ Tools) output
  - hash_file (Python hashlib + ssdeep)

Same shape contract as parsers.vol3 / parsers.ez_tools: pure functions,
input is text (or a directory), output is a dict shaped to embed into
parsed_summary + serialize-to-JSON for query_rows compat.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# YARA — `yara <rules> <target>` text-output parser.
#
# Default yara CLI output is one line per match:
#   <rule_name> <target_path>
# With -s (print strings), additional lines show the matched strings + offsets:
#   0x<hex>:$<str_id>: <bytes>
# With -m (print metadata), additional `[meta: <kv>]` block.
# We invoke with `-s -m` for richest context.
# ---------------------------------------------------------------------------


_RE_YARA_RULE_LINE = re.compile(
    r"^(?P<rule>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+\[(?P<meta>[^\]]*)\])?"
    r"\s+(?P<target>.*)$"
)

# Matched-string line under -s: "0x12345:$id: bytes"
_RE_YARA_STRING_LINE = re.compile(
    r"^0x(?P<offset>[0-9a-fA-F]+):"
    r"\$(?P<id>[A-Za-z0-9_]+):"
    r"\s*(?P<bytes>.*)$"
)


def _parse_yara_meta(raw: str | None) -> dict[str, str]:
    """Parse YARA -m metadata fragment `key=value,key=value` into dict."""
    if not raw:
        return {}
    out: dict[str, str] = {}
    for pair in raw.split(","):
        if "=" not in pair:
            continue
        k, _, v = pair.partition("=")
        out[k.strip()] = v.strip().strip('"')
    return out


def parse_yara(stdout: str) -> dict[str, Any]:
    """Parse yara CLI output with `-s -m` flags.

    Returns:
        count: number of rule matches
        rule_counts: {rule_name: count}
        rows: per-match records with rule_name, target, meta, strings_matched
    """
    rows: list[dict[str, Any]] = []
    rule_counts: Counter[str] = Counter()
    current: dict[str, Any] | None = None
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        # YARA `-s` flag emits matched-string lines flush-left (not indented):
        #   0x<hex>:$<id>: <bytes>
        # Disambiguate by trying the string-match regex first.
        m_str = _RE_YARA_STRING_LINE.match(line)
        if m_str is not None and current is not None:
            current["strings_matched"].append({
                "offset":    "0x" + m_str.group("offset"),
                "string_id": "$" + m_str.group("id"),
                "bytes":     m_str.group("bytes")[:200],  # cap match preview
            })
            continue
        # New rule match line: `<rule> [meta] <target>`
        m_rule = _RE_YARA_RULE_LINE.match(line)
        if m_rule is None:
            continue
        # Heuristic guard: rule lines have a target that looks path-like.
        # `0x...` lines could in theory match `_RE_YARA_RULE_LINE`'s leading
        # token but they'd have already been picked off by _RE_YARA_STRING_LINE.
        if current is not None:
            rows.append(current)
        rule = m_rule.group("rule")
        rule_counts[rule] += 1
        current = {
            "rule":             rule,
            "target":           m_rule.group("target"),
            "meta":             _parse_yara_meta(m_rule.group("meta")),
            "strings_matched":  [],
        }
    if current is not None:
        rows.append(current)
    return {
        "count":       len(rows),
        "rule_counts": dict(rule_counts.most_common()),
        "rows":        rows,
    }


def summarise_yara(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    if n == 0:
        return "no YARA matches"
    rc = parsed.get("rule_counts") or {}
    top = ", ".join(f"{r}×{c}" for r, c in list(rc.items())[:3])
    return f"{n} YARA matches across {len(rc)} rules; top: {top}"


def parse_vadyarascan(stdout: str) -> dict[str, Any]:
    """Parse `vol3 -r jsonl windows.vadyarascan` output.

    Distinct from parse_yara (which handles the standalone yara CLI's
    text output). Vol3 emits one JSON object per match with fields:
    PID, Process, Rule, Offset, Value.
    """
    from mcp_server.parsers.vol3 import parse_jsonl_rows
    rows = parse_jsonl_rows(stdout)
    rule_counts: Counter[str] = Counter()
    out: list[dict[str, Any]] = []
    for r in rows:
        rule = r.get("Rule") or r.get("rule") or ""
        if rule:
            rule_counts[rule] += 1
        out.append({
            "pid":     r.get("PID"),
            "process": r.get("Process"),
            "rule":    rule,
            "offset":  r.get("Offset"),
            "value":   r.get("Value"),
        })
    return {
        "count":       len(out),
        "rule_counts": dict(rule_counts.most_common()),
        "rows":        out,
    }


# ---------------------------------------------------------------------------
# bulk_extractor — multi-scanner feature-file directory parser.
#
# Each scanner produces a .txt file with one feature per line:
#   <offset>\t<feature>\t<context>
# Comment lines start with '#'. Empty lines skipped.
#
# We walk the directory, identify per-scanner files by filename, and
# build a `{scanner_name: {count, top_features}}` shape.
# ---------------------------------------------------------------------------


# Default-on bulk_extractor scanners we want to surface as their own sections.
# Keys are the canonical filenames bulk_extractor emits.
_BE_SCANNER_FILES: dict[str, str] = {
    "url.txt":              "url",
    "email.txt":            "email",
    "domain.txt":           "domain",
    "ip.txt":               "ip",
    "ip_histogram.txt":     "ip_histogram",
    "url_histogram.txt":    "url_histogram",
    "email_histogram.txt":  "email_histogram",
    "domain_histogram.txt": "domain_histogram",
    "winpe.txt":            "winpe",
    "zip.txt":              "zip",
    "rar.txt":              "rar",
    "elf.txt":              "elf",
    "exif.txt":             "exif",
    "gps.txt":              "gps",
    "ccn.txt":              "credit_cards",
    "telephone.txt":        "telephone",
    "kml.txt":              "kml",
    "json.txt":             "json",
    "evtx_carved.txt":      "evtx_carved",
    "ether.txt":            "mac_addr",
    "find.txt":             "lightgrep",
    "alerts.txt":           "alerts",
}


def _parse_be_feature_line(line: str) -> tuple[str | None, str | None, str | None]:
    """Return (offset, feature, context) from a bulk_extractor feature line.

    bulk_extractor feature files are tab-separated. Histogram files have a
    different shape (`n\\t<feature>`) — caller handles those separately.
    """
    if not line or line.startswith("#"):
        return None, None, None
    parts = line.split("\t", 2)
    if len(parts) < 2:
        return None, None, None
    return parts[0], parts[1], (parts[2] if len(parts) == 3 else "")


def parse_bulk_extractor_dir(out_dir: Path, top_n: int = 50) -> dict[str, Any]:
    """Walk a bulk_extractor output directory; build per-scanner summaries.

    For each recognised feature file:
      - count = number of feature lines
      - top_features = first `top_n` (offset, feature, context) records
    Aggregate `feature_counts` for the wire payload.
    """
    sections: dict[str, dict[str, Any]] = {}
    unknown_files: list[str] = []
    if not out_dir.exists() or not out_dir.is_dir():
        return {
            "total_features": 0,
            "feature_counts": {},
            "sections":       {},
            "unknown_files":  [],
        }
    for f in sorted(out_dir.iterdir()):
        if not f.is_file() or not f.name.endswith(".txt"):
            continue
        section = _BE_SCANNER_FILES.get(f.name)
        if section is None:
            # Track non-empty unknown files for visibility
            try:
                if f.stat().st_size > 0:
                    unknown_files.append(f.name)
            except OSError:
                pass
            continue

        rows: list[dict[str, Any]] = []
        count = 0
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            offset, feature, context = _parse_be_feature_line(line)
            if feature is None:
                continue
            count += 1
            if len(rows) < top_n:
                rows.append({
                    "offset":  offset,
                    "feature": feature,
                    "context": (context or "")[:160],  # cap context
                })
        sections[section] = {
            "count":         count,
            "top_features": rows,
        }
    feature_counts = {k: v["count"] for k, v in sections.items()}
    return {
        "total_features":  sum(feature_counts.values()),
        "feature_counts":  feature_counts,
        "sections":        sections,
        "unknown_files":   unknown_files,
    }


def parse_bulk_extractor(text: str) -> dict[str, Any]:
    """JSON re-hydrator. Wrapper writes the from_dir dict as JSON to raw_output.

    Same pattern as `parse_amcache` / `parse_srum` — needed for query_rows
    compatibility on nested-section dicts.
    """
    if not text.strip():
        return {"total_features": 0, "feature_counts": {}, "sections": {}, "unknown_files": []}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "total_features": 0, "feature_counts": {}, "sections": {},
            "unknown_files": [], "_parse_error": "raw_output is not valid JSON",
        }


def summarise_bulk_extractor(parsed: dict[str, Any]) -> str:
    fc = parsed.get("feature_counts") or {}
    if not fc:
        return "no bulk_extractor features found"
    total = parsed.get("total_features", 0)
    top = sorted(fc.items(), key=lambda kv: -kv[1])[:5]
    bits = [f"{total} features across {len(fc)} scanners"]
    bits.append("top: " + ", ".join(f"{k}×{v}" for k, v in top))
    return "; ".join(bits)


# ---------------------------------------------------------------------------
# bstrings (EZ Tools) — extracted strings list.
#
# bstrings emits one string per line (with optional metadata depending on
# flags). We invoke with simple flags so each line is a plain string.
# ---------------------------------------------------------------------------


def parse_strings(stdout: str, min_length: int = 6) -> dict[str, Any]:
    """Parse bstrings output (one string per line)."""
    rows: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        s = line.rstrip("\r\n")
        if not s or len(s) < min_length:
            continue
        # bstrings sometimes emits header lines beginning with '*' or 'bstrings'
        if s.startswith("bstrings ") or s.startswith("***"):
            continue
        rows.append({"string": s, "length": len(s)})
    # Aggregate: bucket by length brackets for at-a-glance distribution
    length_buckets: Counter[str] = Counter()
    for r in rows:
        L = r["length"]
        bucket = "≤16" if L <= 16 else "17-64" if L <= 64 else "65-256" if L <= 256 else ">256"
        length_buckets[bucket] += 1
    return {
        "count":          len(rows),
        "min_length":     min_length,
        "length_buckets": dict(length_buckets),
        "rows":           rows,
    }


def summarise_strings(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    if n == 0:
        return "no extracted strings"
    lb = parsed.get("length_buckets") or {}
    bracket_str = ", ".join(f"{k}:{v}" for k, v in lb.items())
    return f"{n} strings; length brackets: {bracket_str}"


# ---------------------------------------------------------------------------
# hash_file — Python hashlib + ssdeep wrapper.
#
# Computes MD5 / SHA-1 / SHA-256 always. SSDEEP is conditional on the
# binary being available (the wrapper sets `ssdeep` to None when missing).
# Pure-output parser is trivial — included for symmetry.
# ---------------------------------------------------------------------------


def parse_hash_result(stdout: str) -> dict[str, Any]:
    """Trivial passthrough — the wrapper writes JSON directly."""
    if not stdout.strip():
        return {}
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {"_parse_error": "invalid JSON"}


def summarise_hash_result(parsed: dict[str, Any]) -> str:
    if not parsed:
        return "no hashes computed"
    bits = []
    if parsed.get("sha256"):
        bits.append(f"sha256={parsed['sha256'][:16]}…")
    if parsed.get("size_bytes") is not None:
        bits.append(f"{parsed['size_bytes']:,} bytes")
    if parsed.get("ssdeep"):
        bits.append("ssdeep available")
    return ", ".join(bits) or "hashes computed"
