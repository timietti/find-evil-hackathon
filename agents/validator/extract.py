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
# Sentence segmentation + negation detection.
#
# Used by the validator to distinguish positive claims ("X was observed")
# from negative claims ("no X found"). A token sitting inside a negated
# sentence flips the verification logic — the token's *absence* from the
# cited tool's data is what counts as confirmation.
# ---------------------------------------------------------------------------

# Sentence/clause boundary. Splits on:
#   - period / ? / ! followed by whitespace
#   - newline
#   - colon followed by whitespace (`Foo: bar baz` → ["Foo", "bar baz"]).
#     Important: does NOT split `C:\path\to\file` because there's no
#     whitespace after the colon.
#   - semicolon followed by whitespace.
#
# We treat the colon-joined clauses as separate "sentences" for negation
# scoping. This stops "No malware: Foo, Bar in Foo.exe" from tagging
# Foo.exe as negated — Foo.exe is in the second clause where no negation
# applies.
_RE_SENTENCE_BOUNDARY = re.compile(r"(?:(?<=[.?!])\s+|\n+|:\s+|;\s+)")

# Negation cues. Looked up case-insensitively in the sentence containing
# each extracted token. Conservative — over-counting negation produces
# false positives on the validator's side, which we'd rather avoid.
_NEGATION_CUES = (
    r"\bno\b",
    r"\bnot\b",
    r"n['']t\b",        # contractions: doesn't / didn't / wasn't / hasn't (no \b prefix —
                        # inside-word position; trailing \b stops at apostrophe)
    r"\bnever\b",
    r"\babsent\b",
    r"\bmissing\b",
    r"\bnone\b",
    r"\bdid\s+not\b",
    r"\bdoes\s+not\b",
    r"\bwithout\b",
    r"\bnowhere\b",
)
_RE_NEGATION = re.compile("|".join(_NEGATION_CUES), re.IGNORECASE)


# Strip markdown emphasis markers (`**bold**`, `*italic*`, `_under_`) and
# inline-code backticks before sentence segmentation. They confuse the
# clause-boundary regex (e.g. `**No malware:**` puts `**` between the colon
# and the space, defeating `:\s+`), but they carry no semantic load for
# negation detection.
_RE_MD_EMPHASIS = re.compile(r"[*_`]+")


def split_sentences(text: str) -> list[str]:
    """Cheap sentence segmentation suitable for paragraph-level claims.

    Markdown emphasis (`**bold**`, `*italic*`, backticks) is stripped before
    segmentation so that constructs like `**No spinlock:**` produce the
    expected clause split.
    """
    if not text:
        return []
    cleaned = _RE_MD_EMPHASIS.sub("", text)
    parts = _RE_SENTENCE_BOUNDARY.split(cleaned)
    return [p.strip() for p in parts if p.strip()]


_RE_PARENTHETICAL = re.compile(r"\([^)]*\)")


def is_negated_sentence(sentence: str) -> bool:
    """True if the sentence contains a negation cue.

    Strips parenthetical content first — phrases like
    "EXFIL.pst is on tdungan (not DC)" have a "not" inside the parens that
    applies to the parenthetical exception, not the main clause's subject.
    Without this strip, every token in such sentences would be flagged as
    negated, producing false negation_violations.

    Trade-off: simple lexical detection. Misses ironic / double-negation
    constructions, but those are vanishingly rare in DFIR reports. Catches
    the common patterns: "no spinlock service", "X was not found",
    "absent from filesystem", "never executed".
    """
    if not sentence:
        return False
    cleaned = _RE_PARENTHETICAL.sub("", sentence)
    return bool(_RE_NEGATION.search(cleaned))


def token_is_negated_in(claim_text: str, token: str) -> bool:
    """True if `token` appears in any negated sentence of `claim_text`.

    Two ways a token can be negated:

      1. **Direct**: token appears in a sentence/clause that itself contains
         a negation cue. ("usboesrv.exe was not found on nromanoff.")

      2. **Subject-clause**: token appears alone (or very nearly so — clause
         length ≤ len(token) + 5 characters, ignoring trailing punctuation)
         in a clause that is *immediately followed* by a negated clause.
         ("usboesrv.exe: **Not found on nromanoff**" → after clause-split
         by `:\s+`, clause 1 is just "usboesrv.exe" and clause 2 has the
         negation. The negation logically applies to clause 1's subject.)

    If the token appears in BOTH a positive and a negative sentence in the
    same claim, we treat it as negated (the conservative choice raises the
    bar for "verified" — better to flag for human review than let a
    hallucination slip).
    """
    tlow = token.lower()
    sentences = split_sentences(claim_text)
    for i, sent in enumerate(sentences):
        sent_lower = sent.lower()
        if tlow not in sent_lower:
            continue
        # (1) Direct negation in the same clause.
        if is_negated_sentence(sent):
            return True
        # (2) Subject-clause negation: very short clause that's basically
        #     just the token, immediately followed by a negated clause.
        bare = sent.strip().rstrip(":;")
        if len(bare) <= len(token) + 5 and i + 1 < len(sentences):
            if is_negated_sentence(sentences[i + 1]):
                return True
    return False


# ---------------------------------------------------------------------------
# Regex patterns. Tuned against the v1 final_response.md on ROCBA-001 and
# the baseline run's report — they cover real-world claim phrasing without
# overshooting (no false-positive captures of generic prose).
# ---------------------------------------------------------------------------

_RE_PID = re.compile(
    r"\b(?:PID|pid)\s*(?:=|\(|:)?\s*(\d{1,7})\b",
)
# Inode / MFT-entry references: "inode 12345", "MFT entry 67890". Same pattern
# but distinct semantic — used when the agent cites a file by its NTFS inode.
_RE_INODE = re.compile(
    r"\b(?:inode|MFT(?:\s+entry)?)\s*(?:=|\(|:|#)?\s*(\d{1,9})\b",
    re.IGNORECASE,
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
#
# Bug D fix (W3-54): exclude backtick from the path character class so
# a claim like "`\Users\srl-h\`" doesn't sweep the trailing backtick
# into the path token (which then fails to match the haystack).
_RE_WIN_PATH = re.compile(
    r"(\\\\?\\?[A-Za-z]:\\[^\s\"'`]+|"        # `\\?\C:\…` or `C:\…`
    r"\\\\[^\s\\\"'`]+(?:\\[^\s\\\"'`]+)+|"   # UNC `\\host\share\…`
    r"\\Device\\[^\s\"'`]+|"                  # `\Device\…`
    r"\\Users\\[^\s\\\"'`]+(?:\\[^\s\\\"'`]+)*|"  # `\Users\fredr\…`
    r"\\Windows\\[^\s\\\"'`]+(?:\\[^\s\\\"'`]+)*)"
)
# Letter-drive references like `D:\Tools\` or `D:\` — distinct from `C:\Users\…`
# already caught above.
_RE_DRIVE_REF = re.compile(r"\b([A-Za-z]:\\[^\s\"'`]*)")
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
# Hash-shaped hex strings: 16+ contiguous hex chars (no 0x prefix). Captures
# MD5 (32), SHA1 (40), SHA256 (64), and partial-prefix quotes ("sha256 abc…").
# Word-boundary anchored so it doesn't grab embedded substrings of longer
# tokens like exec_ids (which are UUIDv7 with dashes).
_RE_HEX_HASH = re.compile(r"\b([0-9a-fA-F]{16,64})\b")
# Process / image-name candidates (quoted backticked names).
_RE_BACKTICK = re.compile(r"`([^`\n]{1,80})`")


@dataclass
class ExtractedTokens:
    """Bag of testable tokens pulled from a single claim's text."""

    pids:        list[str] = field(default_factory=list)
    inodes:      list[str] = field(default_factory=list)
    ips:         list[str] = field(default_factory=list)
    timestamps:  list[str] = field(default_factory=list)
    filenames:   list[str] = field(default_factory=list)
    paths:       list[str] = field(default_factory=list)
    drive_refs:  list[str] = field(default_factory=list)
    brace_guids: list[str] = field(default_factory=list)
    emails:      list[str] = field(default_factory=list)
    hex_offsets: list[str] = field(default_factory=list)
    hex_hashes:  list[str] = field(default_factory=list)
    quoted:      list[str] = field(default_factory=list)

    def _buckets(self) -> tuple[list[str], ...]:
        return (
            self.pids, self.inodes, self.ips, self.timestamps, self.filenames,
            self.paths, self.drive_refs, self.brace_guids, self.emails,
            self.hex_offsets, self.hex_hashes, self.quoted,
        )

    def all(self) -> list[str]:
        """Flat list of all extracted tokens (deduplicated, preserving order)."""
        seen, out = set(), []
        for bucket in self._buckets():
            for t in bucket:
                if t in seen:
                    continue
                seen.add(t)
                out.append(t)
        return out

    def is_empty(self) -> bool:
        return all(not bucket for bucket in self._buckets())


def extract_tokens(claim: str) -> ExtractedTokens:
    """Pull testable tokens from a claim. Conservative, no false positives.

    Returns an `ExtractedTokens` bag. Callers iterate the buckets they care
    about (PIDs go through int comparison, IPs through string substring,
    etc.) — see `agents.validator.validate.verify_claim_against_parsed`.
    """
    if not claim or not claim.strip():
        return ExtractedTokens()

    pids        = list({m.group(1) for m in _RE_PID.finditer(claim)})
    inodes      = list({m.group(1) for m in _RE_INODE.finditer(claim)})
    ips         = list({m.group(1) for m in _RE_IPV4.finditer(claim)})
    timestamps  = list({m.group(1) for m in _RE_TIMESTAMP_ISO.finditer(claim)})
    filenames   = list({m.group(1) for m in _RE_FILENAME.finditer(claim)})
    paths       = list({m.group(1) for m in _RE_WIN_PATH.finditer(claim)})
    drive_refs  = list({m.group(1) for m in _RE_DRIVE_REF.finditer(claim)})
    brace_guids = list({m.group(0) for m in _RE_BRACE_GUID.finditer(claim)})
    hex_offsets = list({m.group(1) for m in _RE_HEX_OFFSET.finditer(claim)})
    # Hash extraction needs a tight filter — UUIDv7 exec_ids are also long
    # hex strings (with dashes between segments), but they're cited as
    # `exec_id <uuid>`. We don't want to treat the exec_id citation itself
    # as a verifiable token. Drop hex matches that immediately follow
    # "exec_id" or sit inside a UUIDv7 dash pattern.
    raw_hashes = []
    for m in _RE_HEX_HASH.finditer(claim):
        s, e = m.span(1)
        # Skip if preceded by "exec_id" / "exec id"
        before = claim[max(0, s - 20):s].lower()
        if "exec_id" in before or "exec id" in before:
            continue
        # Skip if surrounded by hyphens (UUIDv7 segment)
        if (s > 0 and claim[s - 1] == "-") or (e < len(claim) and claim[e] == "-"):
            continue
        raw_hashes.append(m.group(1))
    hex_hashes  = list(set(raw_hashes))
    # Backtick-quoted tokens. Skip ones that are clearly an exec_id citation
    # (preceded by `exec_id` / `exec ids:`), mirroring the hex_hash guard
    # above — otherwise the agent's prose-style cite `(exec_id `UUID`)`
    # leaks the UUID into the "verifiable tokens" list and the verifier
    # marks it missing from the cited tool's parsed output.
    raw_quoted: list[str] = []
    for m in _RE_BACKTICK.finditer(claim):
        s, _ = m.span(1)
        before = claim[max(0, s - 20) : s].lower()
        if "exec_id" in before or "exec id" in before or "exec ids" in before:
            continue
        raw_quoted.append(m.group(1))
    quoted      = list(set(raw_quoted))

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
        pids=pids, inodes=inodes, ips=ips, timestamps=timestamps,
        filenames=filenames, paths=paths, drive_refs=drive_refs,
        brace_guids=brace_guids, emails=emails,
        hex_offsets=hex_offsets, hex_hashes=hex_hashes, quoted=quoted,
    )
