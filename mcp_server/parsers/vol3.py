"""Parsers for Volatility 3 plugin output.

Each parser is a pure function: `parse_<plugin>(stdout: str) -> dict`. No subprocess
calls, no I/O. Designed to be exhaustively unit-tested against captured fixtures.

For plugins that produce a single key/value table (e.g. windows.info), we use
the default tab-separated text output and `_split_kv_table()`.

For plugins that produce a row-oriented table (psscan, pstree, cmdline, netscan,
filescan, ...), we invoke vol with `-r jsonl` and parse one JSON object per line
with `parse_jsonl_rows()`. This avoids fragile tab-splitting on outputs that may
contain literal tabs or commas, and preserves field types Vol3 already inferred.

Returned dicts are shaped to embed directly into our audit log's `parsed_summary`
field. Keys use snake_case so they're stable across plugins.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable


VOL3_BANNER = re.compile(r"^Volatility 3 Framework", re.MULTILINE)


def parse_jsonl_rows(stdout: str) -> list[dict[str, Any]]:
    """Parse `vol -r jsonl <plugin>` output into a list of dict rows.

    Vol3 emits one JSON object per line. Lines that are empty or that fail to
    JSON-parse (e.g. log messages on stderr that leaked into stdout) are skipped
    rather than raising — forensic tools sometimes interleave warnings and we
    do not want a single bad line to tank the entire parse.
    """
    rows: list[dict[str, Any]] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _normalise_dt(raw: Any) -> str | None:
    """Vol3 emits timestamps in several formats across plugins:

      `2020-11-11T08:13:00+00:00`         (jsonl renderer, ISO-8601)
      `2020-11-11 08:13:00 UTC`           (text renderer, space + suffix)
      `2020-11-11 08:13:00.123456 UTC`    (text renderer, with microseconds)

    Normalise to a plain ISO-8601 UTC string ending in `Z` so the validator and
    correlator can compare timestamps across plugins by string equality.
    Returns None for `N/A` / `None` / `null` / empty.
    """
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or s.upper() in {"N/A", "NONE", "NULL"}:
        return None
    # First try Python's permissive ISO parser (handles `T` separator and
    # `+00:00` offset natively on 3.11+).
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass
    # Fall back: text renderer formats.
    s_normalised = s.replace(" UTC", "+00:00")
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(s_normalised, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return s


def _strip_banner(stdout: str) -> str:
    """Remove the Volatility banner line so parsers see only data."""
    return VOL3_BANNER.sub("", stdout, count=1).lstrip("\n")


def _split_kv_table(stdout: str) -> list[tuple[str, str]]:
    """For plugins that output a single 2-column key/value table (e.g. windows.info).

    Output rows are tab-separated. The header is `Variable\tValue`. We skip the
    header and any blank lines, returning [(key, value), ...].
    """
    rows: list[tuple[str, str]] = []
    body = _strip_banner(stdout)
    lines = body.splitlines()
    seen_header = False
    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue
        # Header line is exactly "Variable\tValue"
        if not seen_header and line.split("\t", 1) == ["Variable", "Value"]:
            seen_header = True
            continue
        if "\t" not in line:
            continue
        k, v = line.split("\t", 1)
        rows.append((k.strip(), v.strip()))
    return rows


def parse_image_info(stdout: str) -> dict[str, Any]:
    """Parse `vol -q -f <image> windows.info` output.

    Returns a dict with normalised keys: os, build, arch, is64bit, cpus,
    system_time_utc, system_root, kernel_base, dtb, symbols_resolved, raw (the
    original key/value pairs preserved for audit).
    """
    pairs = dict(_split_kv_table(stdout))

    nt_major = pairs.get("NtMajorVersion")
    nt_minor = pairs.get("NtMinorVersion")
    major_minor = pairs.get("Major/Minor")  # e.g. "15.19041"
    build = None
    if major_minor and "." in major_minor:
        # Format is "<NTBuildNumber>.<RevisionMinor>" — the RHS is the build.
        build = major_minor.split(".", 1)[1]

    is64 = pairs.get("Is64Bit", "").lower() == "true"
    arch = "x64" if is64 else "x86"

    cpus_raw = pairs.get("KeNumberProcessors", "")
    try:
        cpus: int | None = int(cpus_raw)
    except ValueError:
        cpus = None

    system_time_utc = _parse_system_time(pairs.get("SystemTime", ""))

    # Symbols line looks like:  file:///.../ntkrnlmp.pdb/<GUID>-1.json.xz
    # Presence of a file:// URI means symbols were resolved successfully.
    symbols_uri = pairs.get("Symbols", "")
    symbols_resolved = symbols_uri.startswith("file://")

    os_name = "Windows"
    if nt_major == "10":
        os_name = "Windows 10/11"  # NT 10.0 covers both; build disambiguates
    elif nt_major == "6":
        if nt_minor == "1":
            os_name = "Windows 7 / Server 2008 R2"
        elif nt_minor == "2":
            os_name = "Windows 8 / Server 2012"
        elif nt_minor == "3":
            os_name = "Windows 8.1 / Server 2012 R2"
        elif nt_minor == "0":
            os_name = "Windows Vista / Server 2008"
    elif nt_major == "5":
        if nt_minor == "1":
            os_name = "Windows XP"
        elif nt_minor == "2":
            os_name = "Windows XP x64 / Server 2003"

    return {
        "os": os_name,
        "build": build,
        "arch": arch,
        "is64bit": is64,
        "cpus": cpus,
        "system_time_utc": system_time_utc,
        "system_root": pairs.get("NtSystemRoot"),
        "product_type": pairs.get("NtProductType"),
        "kernel_base": pairs.get("Kernel Base"),
        "dtb": pairs.get("DTB"),
        "symbols_resolved": symbols_resolved,
        "symbols_uri": symbols_uri or None,
        "nt_major": nt_major,
        "nt_minor": nt_minor,
        "raw": pairs,
    }


def summarise_image_info(parsed: dict[str, Any]) -> str:
    """One-line summary suitable for the audit log's `summary` field."""
    parts = [
        parsed.get("os") or "?",
        f"build {parsed.get('build') or '?'}",
        parsed.get("arch") or "?",
        f"{parsed.get('cpus') or '?'} CPU",
    ]
    sysT = parsed.get("system_time_utc")
    if sysT:
        parts.append(f"captured {sysT}")
    if not parsed.get("symbols_resolved"):
        parts.append("[symbols missing]")
    return " · ".join(parts)


# ---------------------------------------------------------------------------
# Row-oriented plugins (parsed from `vol -r jsonl` output).
# ---------------------------------------------------------------------------


def parse_psscan(stdout: str) -> dict[str, Any]:
    """Parse `vol -r jsonl <image> windows.psscan` output.

    psscan walks the kernel pool tag scan, finding processes the EPROCESS list
    walker (`pslist`) misses — including hidden and exited processes.

    Returns:
        count: total rows
        processes: list of process dicts with normalised `create_time` /
            `exit_time` ISO-8601 timestamps
        exited: list of processes whose ExitTime != null (terminated by capture
            time, but their EPROCESS still in pool memory)
        by_image: counts keyed by ImageFileName for quick eyeballing
    """
    rows = parse_jsonl_rows(stdout)
    procs: list[dict[str, Any]] = []
    by_image: dict[str, int] = {}
    for r in rows:
        proc = {
            "pid":            r.get("PID"),
            "ppid":           r.get("PPID"),
            "image":          r.get("ImageFileName"),
            "session_id":     r.get("SessionId"),
            "threads":        r.get("Threads"),
            "handles":        r.get("Handles"),
            "wow64":          r.get("Wow64"),
            "offset_virtual": r.get("Offset(V)") or r.get("Offset(P)"),
            "create_time":    _normalise_dt(r.get("CreateTime")),
            "exit_time":      _normalise_dt(r.get("ExitTime")),
        }
        procs.append(proc)
        if proc["image"]:
            by_image[proc["image"]] = by_image.get(proc["image"], 0) + 1
    exited = [p for p in procs if p["exit_time"]]
    return {
        "count": len(procs),
        "processes": procs,
        "exited": exited,
        "by_image": by_image,
    }


def summarise_psscan(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    exited_n = len(parsed.get("exited") or [])
    return f"{n} processes ({exited_n} exited at capture time)"


def parse_cmdline(stdout: str) -> dict[str, Any]:
    """Parse `vol -r jsonl <image> windows.cmdline` output."""
    rows = parse_jsonl_rows(stdout)
    out: list[dict[str, Any]] = []
    for r in rows:
        out.append({
            "pid":     r.get("PID"),
            "process": r.get("Process"),
            "args":    r.get("Args"),
        })
    return {"count": len(out), "rows": out}


def summarise_cmdline(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    null_args = sum(1 for r in (parsed.get("rows") or []) if r.get("args") in (None, ""))
    return f"{n} command lines ({null_args} with null args)"


def parse_pstree(stdout: str) -> dict[str, Any]:
    """Parse `vol -r jsonl <image> windows.pstree` output.

    pstree's JSONL output uses Vol3's `__children` field to encode the parent/
    child hierarchy. We flatten to a list of (pid, ppid, image, depth) and
    also keep the nested tree for callers that want it.
    """
    rows = parse_jsonl_rows(stdout)

    flat: list[dict[str, Any]] = []

    def _walk(node: dict[str, Any], depth: int = 0) -> None:
        flat.append({
            "pid":          node.get("PID"),
            "ppid":         node.get("PPID"),
            "image":        node.get("ImageFileName") or node.get("Process"),
            "depth":        depth,
            "create_time":  _normalise_dt(node.get("CreateTime")),
            "exit_time":    _normalise_dt(node.get("ExitTime")),
            "session_id":   node.get("SessionId"),
            "threads":      node.get("Threads"),
            "handles":      node.get("Handles"),
            "wow64":        node.get("Wow64"),
        })
        for child in node.get("__children", []) or []:
            _walk(child, depth + 1)

    for top in rows:
        _walk(top)

    return {"count": len(flat), "tree_roots": len(rows), "nodes": flat}


def summarise_pstree(parsed: dict[str, Any]) -> str:
    return f"{parsed.get('count', 0)} processes; {parsed.get('tree_roots', 0)} root(s)"


def parse_netscan(stdout: str) -> dict[str, Any]:
    """Parse `vol -r jsonl <image> windows.netscan` output.

    netscan finds TCP/UDP endpoints and connections via pool tag scanning,
    surfacing both current and historical (closed) connections.
    """
    rows = parse_jsonl_rows(stdout)
    conns: list[dict[str, Any]] = []
    foreign_ips: dict[str, int] = {}
    # "*" is Vol3's encoding for UDP "any" remote (listener with no remote yet);
    # "0.0.0.0" / "::" are listen-only locals; loopback is local-only traffic.
    LOOPBACK_OR_NULL = {"0.0.0.0", "127.0.0.1", "::", "::1", "*", None, ""}
    for r in rows:
        foreign_addr = r.get("ForeignAddr")
        c = {
            "offset":        r.get("Offset"),
            "proto":         r.get("Proto"),
            "local_addr":    r.get("LocalAddr"),
            "local_port":    r.get("LocalPort"),
            "foreign_addr":  foreign_addr,
            "foreign_port":  r.get("ForeignPort"),
            "state":         r.get("State"),
            "pid":           r.get("PID"),
            "owner":         r.get("Owner"),
            "created":       _normalise_dt(r.get("Created")),
        }
        conns.append(c)
        if foreign_addr and foreign_addr not in LOOPBACK_OR_NULL:
            foreign_ips[foreign_addr] = foreign_ips.get(foreign_addr, 0) + 1
    return {
        "count": len(conns),
        "connections": conns,
        "foreign_ip_counts": dict(
            sorted(foreign_ips.items(), key=lambda kv: -kv[1])
        ),
    }


def summarise_netscan(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    fips = parsed.get("foreign_ip_counts") or {}
    top = list(fips.items())[:3]
    top_str = ", ".join(f"{ip}({c})" for ip, c in top) if top else "none"
    return f"{n} endpoints; top external IPs: {top_str}"


def parse_filescan(stdout: str) -> dict[str, Any]:
    """Parse `vol -r jsonl <image> windows.filescan` output.

    filescan enumerates _FILE_OBJECT structures in pool memory — every file
    open at capture time plus residue from recently closed files.
    """
    rows = parse_jsonl_rows(stdout)
    files: list[dict[str, Any]] = []
    for r in rows:
        files.append({
            "offset": r.get("Offset"),
            "name":   r.get("Name"),
            "size":   r.get("Size"),
        })
    return {"count": len(files), "files": files}


def summarise_filescan(parsed: dict[str, Any]) -> str:
    return f"{parsed.get('count', 0)} file objects in pool memory"


def _parse_system_time(raw: str) -> str | None:
    """Convert Vol3's `SystemTime` field to an ISO-8601 UTC timestamp.

    Vol3 emits formats like `2020-11-16 02:32:38+00:00`.
    """
    raw = raw.strip()
    if not raw:
        return None
    # Try a couple of common formats Vol3 has emitted across versions.
    for fmt in (
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S+00:00",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return raw  # last-resort: return as-is so callers can see the unparsed value
