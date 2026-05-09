"""Token extraction for the SIFT-OWL validator.

Pure functions only — given a claim text, return the structured tokens we
can mechanically check against the cited tool's parsed JSON.

The extractor is deliberately conservative: if we can't extract anything
testable from a claim, we mark the claim as `unverifiable_by_rule` rather
than failing it. The validator's overall scoring treats those separately.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


# ---------------------------------------------------------------------------
# Regex patterns. Tuned against the v1 final_response.md on ROCBA-001 and
# the baseline run's report — they cover real-world claim phrasing without
# overshooting (no false-positive captures of generic prose).
# ---------------------------------------------------------------------------

_RE_PID = re.compile(
    r"\b(?:PID|pid)\s*(?:=|\(|:)?\s*(\d{1,7})\b",
)
_RE_IPV4 = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})){3})\b"
)
_RE_TIMESTAMP_ISO = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?)\b"
)
# Extensions worth checking. A blunter "any.exe" is fine but we don't want
# to match generic words like "report.txt" appearing in prose; keep the
# extension list to forensically-meaningful types.
_FORENSIC_EXTS = (
    "exe|dll|sys|drv|ps1|bat|cmd|vbs|js|jar|wsf|"        # executables/scripts
    "pst|ost|nst|pf|evtx|hve|dat|reg|"                    # forensic artifacts
    "zip|rar|7z|tar|gz|"                                  # archives
    "docx|doc|xlsx|xls|pptx|ppt|pdf|"                     # documents
    "jpg|jpeg|png|gif|bmp|mov|mp4|"                       # media
    "lnk|url|ini|cfg|log|tmp"                             # misc
)
_RE_FILENAME = re.compile(
    rf"\b([\w.\-]+?\.(?:{_FORENSIC_EXTS}))\b",
    re.IGNORECASE,
)
# Backslash-style Windows paths (`C:\Users\fredr\...`, `\\?\C:\...`,
# `\Device\HarddiskVolume3\Windows`).  The agent often quotes these.
_RE_WIN_PATH = re.compile(
    r"(\\\\?\\?[A-Za-z]:\\[^\s\"']+|"        # `\\?\C:\…` or `C:\…`
    r"\\\\[^\s\\\"']+(?:\\[^\s\\\"']+)+|"    # UNC `\\host\share\…`
    r"\\Device\\[^\s\"']+|"                  # `\Device\…`
    r"\\Users\\[^\s\\\"']+(?:\\[^\s\\\"']+)*|"  # `\Users\fredr\…` (forensic-volume style)
    r"\\Windows\\[^\s\\\"']+(?:\\[^\s\\\"']+)*)"
)
# Letter-drive references like `D:\Tools\` or `D:\` — distinct from `C:\Users\…`
# already caught above.
_RE_DRIVE_REF = re.compile(r"\b([A-Za-z]:\\[^\s\"']*)")
# UserAssist GUIDs / curly-brace identifiers: `{9E04CAB2-CC14-11DF-...}`
_RE_BRACE_GUID = re.compile(
    r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}"
)
# Email addresses
_RE_EMAIL = re.compile(
    r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
)
# Plain hex offsets like `0xb78d106d2080` (Vol3 emits these for VAD/Offset).
_RE_HEX_OFFSET = re.compile(r"\b(0x[0-9a-fA-F]{8,})\b")
# Process / image-name candidates (quoted backticked names).
_RE_BACKTICK = re.compile(r"`([^`\n]{1,80})`")


@dataclass
class ExtractedTokens:
    """Bag of testable tokens pulled from a single claim's text."""

    pids:        list[str] = field(default_factory=list)
    ips:         list[str] = field(default_factory=list)
    timestamps:  list[str] = field(default_factory=list)
    filenames:   list[str] = field(default_factory=list)
    paths:       list[str] = field(default_factory=list)
    drive_refs:  list[str] = field(default_factory=list)
    brace_guids: list[str] = field(default_factory=list)
    emails:      list[str] = field(default_factory=list)
    hex_offsets: list[str] = field(default_factory=list)
    quoted:      list[str] = field(default_factory=list)

    def all(self) -> list[str]:
        """Flat list of all extracted tokens (deduplicated, preserving order)."""
        seen, out = set(), []
        for bucket in (
            self.pids, self.ips, self.timestamps, self.filenames,
            self.paths, self.drive_refs, self.brace_guids, self.emails,
            self.hex_offsets, self.quoted,
        ):
            for t in bucket:
                if t in seen:
                    continue
                seen.add(t)
                out.append(t)
        return out

    def is_empty(self) -> bool:
        return all(
            not bucket for bucket in (
                self.pids, self.ips, self.timestamps, self.filenames,
                self.paths, self.drive_refs, self.brace_guids, self.emails,
                self.hex_offsets, self.quoted,
            )
        )


def extract_tokens(claim: str) -> ExtractedTokens:
    """Pull testable tokens from a claim. Conservative, no false positives.

    Returns an `ExtractedTokens` bag. Callers iterate the buckets they care
    about (PIDs go through int comparison, IPs through string substring,
    etc.) — see `agents.validator.validate.verify_claim_against_parsed`.
    """
    if not claim or not claim.strip():
        return ExtractedTokens()

    pids        = list({m.group(1) for m in _RE_PID.finditer(claim)})
    ips         = list({m.group(1) for m in _RE_IPV4.finditer(claim)})
    timestamps  = list({m.group(1) for m in _RE_TIMESTAMP_ISO.finditer(claim)})
    filenames   = list({m.group(1) for m in _RE_FILENAME.finditer(claim)})
    paths       = list({m.group(1) for m in _RE_WIN_PATH.finditer(claim)})
    drive_refs  = list({m.group(1) for m in _RE_DRIVE_REF.finditer(claim)})
    brace_guids = list({m.group(0) for m in _RE_BRACE_GUID.finditer(claim)})
    hex_offsets = list({m.group(1) for m in _RE_HEX_OFFSET.finditer(claim)})
    quoted      = list({m.group(1) for m in _RE_BACKTICK.finditer(claim)})

    # Email post-processing: the regex greedily matches a `.tld`, but in
    # forensic prose we often see `email@domain.com.lnk` where `.lnk` is
    # a file extension on a Recent shortcut. Strip trailing forensic
    # extensions so we get `email@domain.com` not `…@…com.lnk`.
    _EXT_TOKENS = set(_FORENSIC_EXTS.split("|"))
    raw_emails = {m.group(1) for m in _RE_EMAIL.finditer(claim)}
    emails: list[str] = []
    for e in raw_emails:
        parts = e.rsplit(".", 1)
        while len(parts) == 2 and parts[1].lower() in _EXT_TOKENS:
            e = parts[0]
            parts = e.rsplit(".", 1)
        emails.append(e)
    emails = list(set(emails))

    # Drop any path that's a strict prefix of another captured path (avoid
    # double-counting `\Users\fredr` when we already captured the full path).
    def _drop_strict_prefixes(items: Iterable[str]) -> list[str]:
        items = sorted(set(items), key=len, reverse=True)
        out: list[str] = []
        for it in items:
            if not any(it != bigger and bigger.startswith(it) for bigger in out):
                out.append(it)
        return out

    paths = _drop_strict_prefixes(paths)
    drive_refs = _drop_strict_prefixes(drive_refs)

    return ExtractedTokens(
        pids=pids, ips=ips, timestamps=timestamps, filenames=filenames,
        paths=paths, drive_refs=drive_refs, brace_guids=brace_guids,
        emails=emails, hex_offsets=hex_offsets, quoted=quoted,
    )
