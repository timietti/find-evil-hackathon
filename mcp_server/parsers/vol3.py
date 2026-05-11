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


def parse_malfind(stdout: str) -> dict[str, Any]:
    """Parse `vol -r jsonl <image> windows.malfind` output.

    malfind flags VAD regions with anomalous protection (RWX, no on-disk
    backing, MZ headers in unexpected places). Each row carries multi-KB
    `Disasm` and `Hexdump` strings — we drop those from the parsed result
    (they're preserved on disk in the raw_output_path the audit log cites)
    and keep only the discriminating fields.
    """
    rows = parse_jsonl_rows(stdout)
    findings: list[dict[str, Any]] = []
    rwx_count = 0
    by_process: dict[str, int] = {}
    for r in rows:
        protection = r.get("Protection") or ""
        is_rwx = "PAGE_EXECUTE_READWRITE" in protection
        if is_rwx:
            rwx_count += 1
        finding = {
            "pid":            r.get("PID"),
            "process":        r.get("Process"),
            "start_vpn":      r.get("Start VPN"),
            "end_vpn":        r.get("End VPN"),
            "tag":            r.get("Tag"),
            "protection":     protection,
            "rwx":            is_rwx,
            "private_memory": r.get("PrivateMemory"),
            "commit_charge":  r.get("CommitCharge"),
            "notes":          r.get("Notes"),
            # Disasm / Hexdump intentionally dropped — caller can reread
            # raw_output_path if it needs the bytes.
        }
        findings.append(finding)
        if finding["process"]:
            by_process[finding["process"]] = by_process.get(finding["process"], 0) + 1
    return {
        "count": len(findings),
        "rwx_count": rwx_count,
        "by_process": dict(sorted(by_process.items(), key=lambda kv: -kv[1])),
        "findings": findings,
    }


def summarise_malfind(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    rwx = parsed.get("rwx_count", 0)
    nproc = len(parsed.get("by_process") or {})
    if n == 0:
        return "no malfind findings (0 suspicious VAD regions)"
    return f"{n} suspicious VAD regions ({rwx} RWX) in {nproc} processes"


def parse_svcscan(stdout: str) -> dict[str, Any]:
    """Parse `vol -r jsonl <image> windows.svcscan` output."""
    rows = parse_jsonl_rows(stdout)
    services: list[dict[str, Any]] = []
    by_state: dict[str, int] = {}
    by_start: dict[str, int] = {}
    by_type: dict[str, int] = {}
    drivers = 0
    running = 0
    for r in rows:
        state = r.get("State") or ""
        start = r.get("Start") or ""
        stype = r.get("Type") or ""
        svc = {
            "name":            r.get("Name"),
            "display":         r.get("Display"),
            "type":            stype,
            "start":           start,
            "state":           state,
            "pid":             r.get("PID"),
            "binary":          r.get("Binary"),
            "binary_registry": r.get("Binary (Registry)"),
            "dll":             r.get("Dll"),
            "order":           r.get("Order"),
            "offset":          r.get("Offset"),
        }
        services.append(svc)
        if state:
            by_state[state] = by_state.get(state, 0) + 1
        if start:
            by_start[start] = by_start.get(start, 0) + 1
        if stype:
            by_type[stype] = by_type.get(stype, 0) + 1
        if "DRIVER" in stype:
            drivers += 1
        if state == "SERVICE_RUNNING":
            running += 1
    return {
        "count":    len(services),
        "running":  running,
        "drivers":  drivers,
        "by_state": by_state,
        "by_start": by_start,
        "by_type":  by_type,
        "services": services,
    }


def summarise_svcscan(parsed: dict[str, Any]) -> str:
    return (
        f"{parsed.get('count', 0)} services "
        f"({parsed.get('running', 0)} running, "
        f"{parsed.get('drivers', 0)} drivers)"
    )


def parse_userassist(stdout: str) -> dict[str, Any]:
    """Parse `vol -r jsonl <image> windows.registry.userassist` output.

    UserAssist is a two-level hierarchy in Vol3's JSONL: top-level rows are
    `Type: "Key"` (one per UserAssist subkey) with their `__children` being
    `Type: "Value"` rows holding the actual recorded program-execution data.

    The `Raw Data` field on the value rows is a 4 KB hex blob that Vol3 has
    already decoded into Count / Focus Count / Time Focused — we drop the raw
    blob entirely (caller can reread raw_output_path if needed).
    """
    rows = parse_jsonl_rows(stdout)
    entries: list[dict[str, Any]] = []
    by_hive: dict[str, int] = {}
    for top in rows:
        for child in top.get("__children", []) or []:
            if child.get("Type") != "Value":
                continue
            name = child.get("Name") or ""
            # The fake "UEME_CTLSESSION" record exists per UserAssist subkey
            # and is not a program execution — skip it from the entry list
            # but still let the user see the totals via `count`.
            is_session_marker = name == "UEME_CTLSESSION"
            entry = {
                "name":            name,
                "count":           child.get("Count"),
                "focus_count":     child.get("Focus Count"),
                "time_focused":    child.get("Time Focused"),
                "last_updated":    _normalise_dt(child.get("Last Updated")),
                "last_write_time": _normalise_dt(child.get("Last Write Time")),
                "hive_name":       child.get("Hive Name"),
                "session_marker":  is_session_marker,
            }
            entries.append(entry)
            hive = child.get("Hive Name") or ""
            if hive:
                by_hive[hive] = by_hive.get(hive, 0) + 1
    real = [e for e in entries if not e["session_marker"]]
    return {
        "count":          len(entries),
        "real_count":     len(real),
        "session_count":  len(entries) - len(real),
        "by_hive":        by_hive,
        "entries":        entries,
    }


def summarise_userassist(parsed: dict[str, Any]) -> str:
    return (
        f"{parsed.get('real_count', 0)} program-execution entries "
        f"across {len(parsed.get('by_hive') or {})} user hives"
    )


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


# ---------------------------------------------------------------------------
# windows.dlllist — DLLs loaded per process.
#
# JSONL fields (Vol3 2.x): PID, Process, Base, Size, Name, Path, LoadTime, File
# output. High-signal for malware triage:
#   - unsigned DLLs in lsass / spoolsv / svchost (credential stealers, hooks)
#   - sideloaded DLLs adjacent to LOLBin executables
#   - DLLs without an on-disk path (in-memory injected modules)
# ---------------------------------------------------------------------------


def parse_dlllist(stdout: str) -> dict[str, Any]:
    """Parse `vol -r jsonl <image> windows.dlllist` output.

    Returns:
        count: total rows
        rows: per-DLL records (pid, process, base, size, name, path, load_time)
        by_process: count of loaded DLLs keyed by process name
        by_path_top: top-20 directory roots (e.g. `C:\\Windows\\System32`,
            `C:\\Users\\frocba\\AppData\\Local`) for distribution analysis
        unbacked: count of DLLs with no on-disk Path (in-memory only)
    """
    rows = parse_jsonl_rows(stdout)
    out_rows: list[dict[str, Any]] = []
    by_process: dict[str, int] = {}
    by_dir: dict[str, int] = {}
    unbacked = 0
    for r in rows:
        path = r.get("Path") or ""
        proc = r.get("Process") or ""
        out_rows.append({
            "pid":       r.get("PID"),
            "process":   proc,
            "base":      r.get("Base"),
            "size":      r.get("Size"),
            "name":      r.get("Name"),
            "path":      path,
            "load_time": _normalise_dt(r.get("LoadTime")),
        })
        if proc:
            by_process[proc] = by_process.get(proc, 0) + 1
        if not path:
            unbacked += 1
        else:
            # Top-level dir e.g. 'C:\Windows\System32'
            head = path.rsplit("\\", 1)[0] if "\\" in path else path
            if head:
                by_dir[head] = by_dir.get(head, 0) + 1
    return {
        "count":        len(out_rows),
        "unbacked":     unbacked,
        "by_process":   dict(sorted(by_process.items(), key=lambda kv: -kv[1])[:20]),
        "by_path_top":  dict(sorted(by_dir.items(), key=lambda kv: -kv[1])[:20]),
        "rows":         out_rows,
    }


def summarise_dlllist(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    unbacked = parsed.get("unbacked", 0)
    parts = [f"{n} DLLs"]
    if unbacked:
        parts.append(f"{unbacked} unbacked (no on-disk path)")
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# windows.handles — process open handles.
#
# JSONL fields: PID, Process, Offset, HandleValue, Type, GrantedAccess,
# Name. High-signal for:
#   - mutex names (malware-family fingerprint: e.g. `Global\rundll32.exe`)
#   - file handles (what was open at capture time)
#   - registry handles (persistence locations actively held)
#   - Section / Event handles (IPC primitives)
#
# Per-PID required by Vol3 — calling without --pid scans all procs (very slow).
# ---------------------------------------------------------------------------


def parse_handles(stdout: str) -> dict[str, Any]:
    """Parse `vol -r jsonl <image> windows.handles --pid <PID>` output."""
    rows = parse_jsonl_rows(stdout)
    out_rows: list[dict[str, Any]] = []
    by_type: dict[str, int] = {}
    mutexes: list[str] = []
    files: list[str] = []
    keys: list[str] = []
    for r in rows:
        htype = r.get("Type") or ""
        name = r.get("Name") or ""
        out_rows.append({
            "pid":            r.get("PID"),
            "process":        r.get("Process"),
            "handle_value":   r.get("HandleValue"),
            "type":           htype,
            "granted_access": r.get("GrantedAccess"),
            "name":           name,
        })
        if htype:
            by_type[htype] = by_type.get(htype, 0) + 1
        # High-signal name lists for triage. Limited to keep summary small.
        if htype == "Mutant" and name:
            mutexes.append(name)
        elif htype == "File" and name:
            files.append(name)
        elif htype == "Key" and name:
            keys.append(name)
    return {
        "count":           len(out_rows),
        "by_type":         dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "mutexes_top":     mutexes[:30],
        "file_handles_top": files[:30],
        "key_handles_top": keys[:30],
        "rows":            out_rows,
    }


def summarise_handles(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    by_type = parsed.get("by_type") or {}
    parts = [f"{n} handles"]
    if by_type:
        top = ", ".join(f"{k}×{v}" for k, v in list(by_type.items())[:3])
        parts.append(f"top: {top}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# windows.scheduled_tasks — Task Scheduler tasks from registry-in-memory.
#
# JSONL fields (Vol3 2.28): "Task Name", "Action", "Action Arguments",
# "Action Context", "Action Type", "Creation Time", "Display Name",
# "Enabled", "Key Name", "Last Run Time", "Last Successful Run Time",
# "Principal ID", "Trigger Description", "Trigger Type", "Working Directory".
# ---------------------------------------------------------------------------


def parse_scheduled_tasks(stdout: str) -> dict[str, Any]:
    rows = parse_jsonl_rows(stdout)
    out_rows: list[dict[str, Any]] = []
    by_principal: dict[str, int] = {}
    by_action_type: dict[str, int] = {}
    enabled_count = 0
    for r in rows:
        principal = r.get("Principal ID") or ""
        action_type = r.get("Action Type") or ""
        action_args = r.get("Action Arguments") or ""
        action = r.get("Action") or ""
        if r.get("Enabled"):
            enabled_count += 1
        if principal:
            by_principal[principal] = by_principal.get(principal, 0) + 1
        if action_type:
            by_action_type[action_type] = by_action_type.get(action_type, 0) + 1
        out_rows.append({
            "task_name":               r.get("Task Name"),
            "display_name":            r.get("Display Name"),
            "key_name":                r.get("Key Name"),
            "action":                  action,
            "action_type":             action_type,
            "action_arguments":        action_args,
            "action_context":          r.get("Action Context"),
            "principal_id":            principal,
            "trigger_description":     r.get("Trigger Description"),
            "trigger_type":            r.get("Trigger Type"),
            "working_directory":       r.get("Working Directory"),
            "creation_time":           _normalise_dt(r.get("Creation Time")),
            "last_run_time":           _normalise_dt(r.get("Last Run Time")),
            "last_successful_run":     _normalise_dt(r.get("Last Successful Run Time")),
            "enabled":                 r.get("Enabled"),
        })
    return {
        "count":          len(out_rows),
        "enabled_count":  enabled_count,
        "by_principal":   dict(sorted(by_principal.items(),   key=lambda kv: -kv[1])[:15]),
        "by_action_type": dict(sorted(by_action_type.items(), key=lambda kv: -kv[1])),
        "rows":           out_rows,
    }


def summarise_scheduled_tasks(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    if n == 0:
        return "no scheduled tasks found"
    enabled = parsed.get("enabled_count", 0)
    parts = [f"{n} scheduled tasks"]
    if enabled:
        parts.append(f"{enabled} enabled")
    bp = parsed.get("by_principal") or {}
    if bp:
        parts.append(f"top principal: {next(iter(bp.keys()))}×{next(iter(bp.values()))}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# windows.hashdump — local SAM hashes (T1003.002).
#
# JSONL fields: "User", "RID", "LM Hash", "NT Hash".
# (Empty NT hashes = "31d6cfe0d16ae931b73c59d7e0c089c0" = empty-string hash;
#  flagged so the agent can spot blank-password accounts.)
# ---------------------------------------------------------------------------


_BLANK_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"


def parse_hashdump(stdout: str) -> dict[str, Any]:
    rows = parse_jsonl_rows(stdout)
    out_rows: list[dict[str, Any]] = []
    blank_password_users: list[str] = []
    for r in rows:
        user = r.get("User") or ""
        nt = (r.get("NT Hash") or "").lower()
        if nt == _BLANK_NT_HASH:
            blank_password_users.append(user)
        out_rows.append({
            "user":     user,
            "rid":      r.get("RID"),
            "lm_hash":  r.get("LM Hash"),
            "nt_hash":  r.get("NT Hash"),
        })
    return {
        "count":                  len(out_rows),
        "blank_password_users":   blank_password_users,
        "rows":                   out_rows,
    }


def summarise_hashdump(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    if n == 0:
        return "no SAM accounts parsed (likely missing SYSTEM bootkey)"
    blanks = parsed.get("blank_password_users") or []
    parts = [f"{n} local accounts"]
    if blanks:
        parts.append(f"{len(blanks)} blank-password: {','.join(blanks[:3])}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# windows.cachedump — LSA cached domain credentials (MSCASH/DCC2, T1003.005).
#
# JSONL fields: "Username", "Domain Name", "Domain Hash", "Hash".
# ---------------------------------------------------------------------------


def parse_cachedump(stdout: str) -> dict[str, Any]:
    rows = parse_jsonl_rows(stdout)
    out_rows: list[dict[str, Any]] = []
    by_domain: dict[str, int] = {}
    for r in rows:
        dom = r.get("Domain Name") or ""
        if dom:
            by_domain[dom] = by_domain.get(dom, 0) + 1
        out_rows.append({
            "username":     r.get("Username"),
            "domain":       dom,
            "domain_hash":  r.get("Domain Hash"),
            "hash":         r.get("Hash"),
        })
    return {
        "count":     len(out_rows),
        "by_domain": dict(sorted(by_domain.items(), key=lambda kv: -kv[1])),
        "rows":      out_rows,
    }


def summarise_cachedump(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    if n == 0:
        return "no cached domain credentials (machine is workgroup-only or LSA secret missing)"
    bd = parsed.get("by_domain") or {}
    return f"{n} cached domain credentials across {len(bd)} domain(s)"


# ---------------------------------------------------------------------------
# windows.skeleton_key_check — Mimikatz skeleton-key detection (T1558).
#
# Output is usually empty (negative result). When the skeleton-key patch is
# present, fields are: "PID", "Process", "Skeleton Key Found".
# ---------------------------------------------------------------------------


def parse_skeleton_key(stdout: str) -> dict[str, Any]:
    rows = parse_jsonl_rows(stdout)
    out_rows: list[dict[str, Any]] = []
    found_count = 0
    for r in rows:
        skeleton = r.get("Skeleton Key Found") or r.get("skeleton_key_found") or False
        if skeleton:
            found_count += 1
        out_rows.append({
            "pid":                  r.get("PID"),
            "process":              r.get("Process"),
            "skeleton_key_found":   bool(skeleton),
        })
    return {
        "count":       len(out_rows),
        "found_count": found_count,
        "rows":        out_rows,
    }


def summarise_skeleton_key(parsed: dict[str, Any]) -> str:
    found = parsed.get("found_count", 0)
    n = parsed.get("count", 0)
    if found:
        return f"⚠ skeleton-key Mimikatz patch detected ({found} of {n} lsass instances)"
    return f"no skeleton-key patch detected ({n} lsass instance(s) scanned)"


# ---------------------------------------------------------------------------
# windows.envars — per-process environment variables (T1574 Path interception).
#
# JSONL fields: "Block", "PID", "Process", "Value", "Variable".
# Most useful: rows where Variable == "Path" or "PATHEXT" — attacker Path
# prepends would show up here.
# ---------------------------------------------------------------------------


_PATH_LIKE_VARS = {"path", "pathext", "psmodulepath", "include", "lib"}


def parse_envars(stdout: str) -> dict[str, Any]:
    rows = parse_jsonl_rows(stdout)
    out_rows: list[dict[str, Any]] = []
    by_variable: dict[str, int] = {}
    path_like_rows: list[dict[str, Any]] = []
    for r in rows:
        var = (r.get("Variable") or "").strip()
        proc = r.get("Process") or ""
        value = r.get("Value") or ""
        if var:
            by_variable[var] = by_variable.get(var, 0) + 1
        row = {
            "pid":      r.get("PID"),
            "process":  proc,
            "variable": var,
            "value":    value,
            "block":    r.get("Block"),
        }
        out_rows.append(row)
        if var.lower() in _PATH_LIKE_VARS:
            path_like_rows.append(row)
    return {
        "count":          len(out_rows),
        "by_variable":    dict(sorted(by_variable.items(), key=lambda kv: -kv[1])[:25]),
        "path_like_rows": path_like_rows,
        "rows":           out_rows,
    }


def summarise_envars(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    pl = len(parsed.get("path_like_rows") or [])
    parts = [f"{n} env-var entries"]
    if pl:
        parts.append(f"{pl} Path-like (PATH/PATHEXT/PSModulePath)")
    return "; ".join(parts)


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
