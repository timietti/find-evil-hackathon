"""Parsers for disk-side forensic tool output.

Pure functions — given stdout, return structured dicts. Same shape as
parsers.vol3 so the validator can hold them by tool_name uniformly.

Tools wrapped here:
  - ewfinfo / ewfverify (libewf-tools)
  - mmls / fsstat / fls / icat (Sleuth Kit)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# ewfinfo — image metadata + acquisition info.
#
# Output is a series of section headers ("Acquiry information",
# "EWF information", "Media information", "Hash values") followed by
# tab-indented `key:\tvalue` lines. We parse it into a flat dict keyed
# by lowercased + underscored field names, plus preserve the section
# membership for callers that care.
# ---------------------------------------------------------------------------


_RE_EWFINFO_SECTION = re.compile(r"^(?:[A-Z][A-Za-z ]+) information$")
_RE_EWFINFO_FIELD = re.compile(r"^\t([^:]+):\s*(.*)$")


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.strip().lower()).strip("_")


def parse_ewfinfo(stdout: str) -> dict[str, Any]:
    """Parse `ewfinfo <image>` output."""
    sections: dict[str, dict[str, str]] = {}
    flat: dict[str, str] = {}
    current_section: str | None = None
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if _RE_EWFINFO_SECTION.match(line):
            current_section = _slug(line)
            sections.setdefault(current_section, {})
            continue
        m = _RE_EWFINFO_FIELD.match(line)
        if not m:
            continue
        key = _slug(m.group(1))
        value = m.group(2).strip()
        if current_section is not None:
            sections[current_section][key] = value
        flat[key] = value

    # Common fields lifted to top level for convenience.
    return {
        "case_number":      flat.get("case_number"),
        "description":      flat.get("description"),
        "examiner_name":    flat.get("examiner_name"),
        "evidence_number":  flat.get("evidence_number"),
        "notes":            flat.get("notes"),
        "acquisition_date": flat.get("acquisition_date"),
        "acquisition_os":   flat.get("operating_system_used"),
        "software":         flat.get("software_version_used"),
        "media_type":       flat.get("media_type"),
        "is_physical":      flat.get("is_physical"),
        "bytes_per_sector": _try_int(flat.get("bytes_per_sector")),
        "sector_count":     _try_int(flat.get("number_of_sectors")),
        "media_size":       _try_int(flat.get("media_size")),
        "md5":              flat.get("md5_hash") or flat.get("md5"),
        "sha1":             flat.get("sha1_hash") or flat.get("sha1"),
        "sections":         sections,
        "raw_fields":       flat,
    }


def summarise_ewfinfo(parsed: dict[str, Any]) -> str:
    desc = parsed.get("description") or "?"
    case = parsed.get("case_number") or "?"
    sectors = parsed.get("sector_count")
    bps = parsed.get("bytes_per_sector")
    size_str = ""
    if sectors and bps:
        gb = (sectors * bps) / (1024 ** 3)
        size_str = f", {gb:.1f} GB"
    return f"E01 — {desc} (case: {case}{size_str})"


# ---------------------------------------------------------------------------
# ewfverify — boolean integrity check + computed hashes.
# ---------------------------------------------------------------------------


_RE_EWFVERIFY_HASH = re.compile(
    r"^(MD5|SHA1)\s+hash\s+(?:calculated|stored)\s+over data:\s*(.+)$",
    re.IGNORECASE,
)


def parse_ewfverify(stdout: str) -> dict[str, Any]:
    """Parse `ewfverify <image>` output.

    Returns: { verified: bool, md5_calculated, md5_stored, sha1_calculated,
               sha1_stored, status_lines }
    """
    lower = stdout.lower()
    verified = "match" in lower or "verification was successful" in lower
    md5_calc, md5_stored, sha1_calc, sha1_stored = (None,) * 4
    status_lines: list[str] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        # ewfverify output varies by version; capture both common forms.
        if "successful" in line.lower() or "match" in line.lower() or "do not match" in line.lower():
            status_lines.append(line)
        m = _RE_EWFVERIFY_HASH.match(line)
        if m:
            kind = m.group(1).upper()
            val = m.group(2).strip()
            if "calculated" in line.lower():
                if kind == "MD5":  md5_calc = val
                if kind == "SHA1": sha1_calc = val
            elif "stored" in line.lower():
                if kind == "MD5":  md5_stored = val
                if kind == "SHA1": sha1_stored = val
    return {
        "verified": verified,
        "md5_calculated":  md5_calc,
        "md5_stored":      md5_stored,
        "md5_match":       (md5_calc == md5_stored) if (md5_calc and md5_stored) else None,
        "sha1_calculated": sha1_calc,
        "sha1_stored":     sha1_stored,
        "sha1_match":      (sha1_calc == sha1_stored) if (sha1_calc and sha1_stored) else None,
        "status_lines":    status_lines,
    }


def summarise_ewfverify(parsed: dict[str, Any]) -> str:
    if parsed.get("verified"):
        return "✅ E01 hashes verified"
    if parsed.get("md5_match") is False or parsed.get("sha1_match") is False:
        return "❌ E01 hash MISMATCH — possible spoliation"
    return "⚠ E01 verification result inconclusive"


# ---------------------------------------------------------------------------
# mmls — partition table.
#
# Expected output shape:
#     DOS Partition Table
#     Offset Sector: 0
#     Units are in 512-byte sectors
#
#          Slot      Start        End          Length       Description
#     000: Meta      0000000000   0000000000   0000000001   Primary Table (#0)
#     001: -------   0000000000   0000002047   0000002048   Unallocated
#     002: 000:000   0000002048   0083884031   0083881984   NTFS / exFAT (0x07)
#
# Logical-drive E01s return empty stdout — handle that as zero-partition.
# ---------------------------------------------------------------------------


_RE_MMLS_PART = re.compile(
    r"^\s*(\d{3}):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)\s*$"
)


def parse_mmls(stdout: str) -> dict[str, Any]:
    """Parse `mmls -i ewf <image>` output."""
    partitions: list[dict[str, Any]] = []
    table_type = None
    sector_size = 512
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if "Partition Table" in line:
            table_type = line.strip()
            continue
        if line.lower().startswith("units are in"):
            m = re.search(r"(\d+)-byte", line)
            if m:
                sector_size = int(m.group(1))
            continue
        m = _RE_MMLS_PART.match(line)
        if not m:
            continue
        slot, slot_role, start, end, length, desc = m.groups()
        partitions.append({
            "slot":         int(slot),
            "slot_role":    slot_role,
            "start_sector": int(start),
            "end_sector":   int(end),
            "length_sectors": int(length),
            "description":  desc.strip(),
            "is_filesystem": all(s not in desc.lower()
                                 for s in ("unallocated", "primary table",
                                           "extended", "meta")),
        })
    return {
        "table_type":   table_type,
        "sector_size":  sector_size,
        "count":        len(partitions),
        "partitions":   partitions,
    }


def summarise_mmls(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    if n == 0:
        return "no partition table (logical-drive image)"
    fs = sum(1 for p in (parsed.get("partitions") or []) if p["is_filesystem"])
    return f"{n} partitions ({fs} filesystem-bearing)"


# ---------------------------------------------------------------------------
# fsstat — filesystem metadata. Output is heavily section-header'd K/V text.
# Output varies by FS type but the universally-useful fields are:
#   - File System Type (NTFS / FAT / etc.)
#   - Volume Serial Number
#   - Volume Name
#   - Cluster Size
#   - Total Cluster Range
#   - Last Mount Time / Created Time (FS-specific)
#
# We parse to a flat dict keyed by slugged field names; callers query
# specific fields by name.
# ---------------------------------------------------------------------------


_RE_FSSTAT_FIELD = re.compile(r"^([A-Z][A-Za-z0-9 /\-]+):\s*(.+?)\s*$")


def parse_fsstat(stdout: str) -> dict[str, Any]:
    out: dict[str, str] = {}
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        m = _RE_FSSTAT_FIELD.match(line)
        if not m:
            continue
        key = _slug(m.group(1))
        value = m.group(2).strip()
        # Don't overwrite first occurrence (fsstat repeats some fields)
        out.setdefault(key, value)
    return {
        "fs_type":          out.get("file_system_type"),
        "volume_name":      out.get("volume_name"),
        "volume_serial":    out.get("volume_serial_number"),
        "cluster_size":     _try_int(out.get("cluster_size")),
        "sector_size":      _try_int(out.get("sector_size")),
        "total_clusters":   out.get("total_cluster_range"),
        "raw_fields":       out,
    }


def summarise_fsstat(parsed: dict[str, Any]) -> str:
    fs = parsed.get("fs_type") or "?"
    name = parsed.get("volume_name") or ""
    serial = parsed.get("volume_serial") or ""
    bits = [fs]
    if name:   bits.append(f"name={name}")
    if serial: bits.append(f"serial={serial}")
    return " · ".join(bits)


# ---------------------------------------------------------------------------
# fls — file listing. Format:
#     <type1>/<type2> <inode>-<attr>-<id>:\t<path>
# `type1` is the directory-entry view, `type2` is the inode view.
# Common values: r=regular, d=directory, l=link, *=deleted (prefix).
# ---------------------------------------------------------------------------


_RE_FLS_ROW = re.compile(
    r"^(?P<deleted>\*?\s*)"
    r"(?P<type1>[\-rdlc])/(?P<type2>[\-rdlc])\s+"
    r"(?P<inode>\d+)-(?P<attr>\d+)-(?P<id>\d+)(?:\(realloc\))?:\s*"
    r"(?P<path>.+?)\s*$"
)


def parse_fls(stdout: str) -> dict[str, Any]:
    """Parse `fls -i ewf -r -p [-F] <image>` output."""
    files: list[dict[str, Any]] = []
    by_extension: dict[str, int] = {}
    by_top_dir: dict[str, int] = {}
    deleted_count = 0

    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        m = _RE_FLS_ROW.match(line)
        if not m:
            continue
        is_deleted = bool(m.group("deleted").strip())
        path = m.group("path").strip()

        ext = ""
        # Strip ":$ATTR" suffix that fls uses for alternate streams /
        # named attributes — `\path\to\file:$Bad` etc.
        path_clean = path.split(":", 1)[0]
        if "." in path_clean:
            ext = path_clean.rsplit(".", 1)[-1].lower()
            if len(ext) <= 8 and ext.isalnum():
                by_extension[ext] = by_extension.get(ext, 0) + 1

        top = path_clean.split("/", 1)[0] if "/" in path_clean else path_clean.split("\\", 1)[0]
        if top:
            by_top_dir[top] = by_top_dir.get(top, 0) + 1

        if is_deleted:
            deleted_count += 1

        files.append({
            "type1":     m.group("type1"),  # dirent type
            "type2":     m.group("type2"),  # inode type
            "deleted":   is_deleted,
            "inode":     int(m.group("inode")),
            "attr":      int(m.group("attr")),
            "id":        int(m.group("id")),
            "path":      path,
        })

    # Top-of-tree dir counts — keep top 10 for the summary slice.
    top_dirs_sorted = sorted(by_top_dir.items(), key=lambda kv: -kv[1])
    return {
        "count":           len(files),
        "deleted_count":   deleted_count,
        "by_extension":    dict(sorted(by_extension.items(), key=lambda kv: -kv[1])[:20]),
        "by_top_dir":      dict(top_dirs_sorted[:10]),
        "files":           files,
    }


def summarise_fls(parsed: dict[str, Any]) -> str:
    n = parsed.get("count", 0)
    d = parsed.get("deleted_count", 0)
    return f"{n} entries ({d} deleted)"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _try_int(s: str | None) -> int | None:
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    try:
        return int(s.replace(",", ""))
    except ValueError:
        # ewfinfo emits things like "31,473,601" with commas; if that fails
        # too, return None.
        return None
