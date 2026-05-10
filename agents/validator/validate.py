"""SIFT-OWL validator agent (rule-based v0).

Reads a SIFT-OWL run directory's `final_response.md` and `audit/exec_log.jsonl`,
and for every `[CONFIRMED — exec_id X]` claim:

  1. Parses the claim text to extract testable tokens (PIDs, IPs, filenames,
     timestamps, Windows paths, etc.) via `agents.validator.extract`.
  2. Looks up `X` in the audit log → finds the tool name + raw_output_path.
  3. Re-parses the raw output with the matching parser from
     `mcp_server.parsers.vol3` (registered via `mcp_server.tools.memory._PARSERS`).
  4. Checks whether each extracted token is structurally present in the
     parsed JSON.
  5. Emits a verdict:
       - `verified`           — every extracted token found
       - `partial`            — some tokens found, some missing
       - `failed`             — no tokens found
       - `unverifiable`       — claim has no extractable tokens (prose only)
       - `exec_id_not_found`  — cited exec_id does not exist in the audit log
       - `tool_not_supported` — citation points at a tool whose parser is
                                not registered (e.g. a future tool)

Outputs:
  - `validator_report.json` — full per-claim verdicts
  - `validator_report.md`   — human-readable summary

Usage:
  python -m agents.validator.validate --run-dir <path-to-run>
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from agents.validator.extract import (
    ExtractedTokens,
    extract_tokens,
    token_is_negated_in,
)
from mcp_server.audit import AuditLogger
from mcp_server.tools.memory import _PARSERS, _ROWS_KEY, _register_parsers

app = typer.Typer(help="SIFT-OWL claim validator (rule-based v0).")
console = Console()


# ---------------------------------------------------------------------------
# Claim extraction from final_response.md.
#
# Markdown structure varies across runs but the [CONFIRMED — exec_id X] tag
# is the anchor. We treat the surrounding paragraph (or list bullet) as the
# claim text.
# ---------------------------------------------------------------------------

_RE_TAG = re.compile(
    r"\[(CONFIRMED|INFERRED|HYPOTHESIS|GAP|FAILED)"
    r"([^\]]*)"      # capture the full tag body so we can find ALL exec_ids
    r"\]",
    re.IGNORECASE,
)
# UUIDv7 (or any reasonable hex-and-dash ID) extractor for the tag body.
# Restricted to >=8 hex chars to avoid catching 4-digit room numbers etc.
_RE_EXEC_ID = re.compile(r"\b([0-9a-fA-F]{8,}(?:-[0-9a-fA-F]+)*)\b")


@dataclass
class Claim:
    """A single tagged claim pulled from a final report."""

    tag: str                  # CONFIRMED / INFERRED / HYPOTHESIS / GAP / FAILED
    exec_id: str | None       # primary (first-cited) exec_id; None if not cited
    exec_ids: list[str] = field(default_factory=list)  # ALL cited exec_ids
    text: str = ""            # the claim's surrounding paragraph
    raw_match: str = ""       # the literal `[CONFIRMED — ...]` text
    line_no: int = 0          # 1-based line number where the tag appears


def parse_claims(report_text: str) -> list[Claim]:
    """Pull every tagged claim out of a final-response markdown.

    A "claim" is the paragraph (or list bullet) that contains a tag. We use
    blank-line-separated paragraphs as the unit. Multiple tags inside the
    same paragraph all reference the same paragraph text.
    """
    paragraphs = []  # list of (text, start_line)
    current: list[str] = []
    start_line = 1
    line_no = 0

    for raw_line in report_text.splitlines():
        line_no += 1
        if raw_line.strip() == "":
            if current:
                paragraphs.append(("\n".join(current), start_line))
                current = []
            start_line = line_no + 1
        else:
            current.append(raw_line)
    if current:
        paragraphs.append(("\n".join(current), start_line))

    claims: list[Claim] = []
    for para, start in paragraphs:
        tags = list(_RE_TAG.finditer(para))
        if not tags:
            continue

        # Per-tag text policy:
        #   - 1 tag in paragraph  → use the WHOLE paragraph as the claim text
        #     (v2 behaviour). Many agent reports place a single citation tag
        #     at the end of the paragraph that asserts the claim.
        #   - 2+ tags in paragraph → each Claim's text is the slice from the
        #     previous tag's end (or paragraph start) to this tag's end. This
        #     stops sibling claims from polluting each other's tokens
        #     (failure type #1 from the EZ-Tool run COMPARISON.md).
        is_multi_tag = len(tags) > 1
        prev_end = 0
        for m in tags:
            tag = m.group(1).upper()
            body = m.group(2) or ""
            exec_ids = _RE_EXEC_ID.findall(body)
            primary = exec_ids[0] if exec_ids else None

            if is_multi_tag:
                claim_text = para[prev_end : m.end()].strip()
            else:
                claim_text = para
            offset_lines = para[: m.start()].count("\n")
            claims.append(Claim(
                tag=tag,
                exec_id=primary,
                exec_ids=exec_ids,
                text=claim_text,
                raw_match=m.group(0),
                line_no=start + offset_lines,
            ))
            prev_end = m.end()
    return claims


# ---------------------------------------------------------------------------
# Per-claim verification.
# ---------------------------------------------------------------------------


@dataclass
class ClaimVerdict:
    claim: Claim
    status: str                              # verified | partial | failed |
                                             # unverifiable | exec_id_not_found |
                                             # tool_not_supported | not_confirmed
    tool_name: str | None = None             # primary tool — kept for back-compat
    tool_names: list[str] = field(default_factory=list)  # all cited tools
    tokens: ExtractedTokens = field(default_factory=ExtractedTokens)
    matched: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    negation_violations: list[str] = field(default_factory=list)
    verified_absences: list[str] = field(default_factory=list)
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["claim"] = {
            "tag":       self.claim.tag,
            "exec_id":   self.claim.exec_id,
            "text":      self.claim.text,
            "raw_match": self.claim.raw_match,
            "line_no":   self.claim.line_no,
        }
        return d


_RE_HAYSTACK_TIMESTAMP = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}t\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?z?)\b"
)


def _token_in_haystack(token: str, haystack: str) -> bool:
    """Substring match with two extensions for forensic prose.

    1. **Plain substring** (default). Token is already lower-cased.
    2. **ISO timestamp prefix match**. Agents quote timestamps at coarser
       precision than the underlying tool stores ("T23:09Z" claim vs
       "T23:09:14.123Z" data). If `token` looks like an ISO timestamp,
       strip its trailing "z" (UTC suffix sits flush against minute-precision)
       and check whether any haystack timestamp's prefix matches the
       stripped token.

       So claim `"2012-04-03T23:09Z"` → strip `z` → `"2012-04-03t23:09"`,
       and haystack timestamp `"2012-04-03t23:09:14z"` starts with that → match.
    """
    if token in haystack:
        return True
    # Cheap pre-check: timestamp tokens contain a dash + 'T' + ':'.
    if "-" in token and "t" in token and ":" in token:
        # Strip the trailing UTC marker so a coarser-precision claim's
        # timestamp can prefix-match a finer-precision haystack value.
        token_root = token.rstrip("z")
        for m in _RE_HAYSTACK_TIMESTAMP.finditer(haystack):
            if m.group(1).startswith(token_root):
                return True
    return False


def _flatten_to_searchable(parsed: dict[str, Any]) -> str:
    """Render parsed JSON as a single lower-case string for substring search.

    Normalises JSON-escaped backslashes back to single backslashes so that
    Windows-path tokens captured by the extractor (`\\Users\\fredr\\…`) match
    paths in the parsed data (which JSON-encode each backslash as `\\\\`).
    Without this, claims about disk paths fail to verify even when the path
    is structurally present.

    Sufficient for v0/v1. A smarter validator would walk specific fields per
    plugin (e.g. only check `pid` against `processes[].pid`), but the
    flatten-and-search approach gets us 90% of the way and is robust.
    """
    return json.dumps(parsed, default=str).lower().replace("\\\\", "\\")


def verify_claim_against_parsed(
    claim: Claim,
    *,
    parsed: dict[str, Any] | None = None,
    tool_name: str | None = None,
    parsed_by_tool: list[tuple[str, dict[str, Any]]] | None = None,
) -> ClaimVerdict:
    """Check `claim` against the parsed JSON of one or more cited tools.

    Two call shapes:
      - **single-citation**: pass `parsed=` + `tool_name=`. Token must
        appear in that single tool's data.
      - **multi-citation**: pass `parsed_by_tool=[(tool_name, parsed_dict), ...]`.
        Token is "matched" if it appears in ANY cited tool's data; only
        "missing" if NONE of them contain it. Mirrors the agent semantic
        when it cites `[CONFIRMED — exec_id A, exec_id B]`.

    Negation handling: tokens that appear inside a negated sentence flip
    the check — their *absence* from the haystack counts as confirmation
    (`verified_absences`), and their *presence* counts as a violation
    (`negation_violations`).
    """
    tokens = extract_tokens(claim.text)
    if tokens.is_empty():
        return ClaimVerdict(
            claim=claim,
            status="unverifiable",
            tool_name=tool_name,
            tool_names=[tool_name] if tool_name else [],
            tokens=tokens,
            notes="claim has no extractable tokens (prose only)",
        )

    if parsed_by_tool is None:
        if parsed is None or tool_name is None:
            raise ValueError(
                "verify_claim_against_parsed needs either `parsed_by_tool` "
                "or both `parsed` and `tool_name`."
            )
        parsed_by_tool = [(tool_name, parsed)]

    haystacks = [(t, _flatten_to_searchable(p)) for t, p in parsed_by_tool]

    matched: list[str] = []
    missing: list[str] = []
    negation_violations: list[str] = []
    verified_absences: list[str] = []

    for tok in tokens.all():
        tlow = tok.lower()
        present_in_any = any(_token_in_haystack(tlow, h) for _, h in haystacks)
        is_negated = token_is_negated_in(claim.text, tok)

        if is_negated:
            # The claim says this token is NOT in the data.
            if present_in_any:
                negation_violations.append(tok)
            else:
                verified_absences.append(tok)
        else:
            if present_in_any:
                matched.append(tok)
            else:
                missing.append(tok)

    # Status logic.
    failures = missing + negation_violations
    successes = matched + verified_absences
    if not failures and successes:
        status = "verified"
    elif successes and failures:
        status = "partial"
    elif not successes and failures:
        status = "failed"
    else:
        # Shouldn't happen — `tokens.is_empty()` already short-circuited
        # the no-token case.
        status = "unverifiable"

    return ClaimVerdict(
        claim=claim,
        status=status,
        tool_name=parsed_by_tool[0][0] if parsed_by_tool else tool_name,
        tool_names=[t for t, _ in parsed_by_tool],
        tokens=tokens,
        matched=matched,
        missing=missing,
        negation_violations=negation_violations,
        verified_absences=verified_absences,
    )


# ---------------------------------------------------------------------------
# Run-directory validation entry point.
# ---------------------------------------------------------------------------


@dataclass
class RunVerdict:
    run_dir: str
    total_claims:        int = 0
    confirmed_count:     int = 0
    inferred_count:      int = 0
    hypothesis_count:    int = 0
    gap_count:           int = 0
    other_count:         int = 0
    verified:            int = 0
    partial:             int = 0
    failed:              int = 0
    unverifiable:        int = 0
    exec_id_not_found:   int = 0
    tool_not_supported:  int = 0
    not_confirmed:       int = 0  # confirmed-tagged but missing exec_id
    confirmation_score:  float = 0.0  # verified / confirmed_count


def validate_run(run_dir: Path) -> tuple[RunVerdict, list[ClaimVerdict]]:
    """Validate every CONFIRMED claim in `run_dir/final_response.md`."""
    _register_parsers()

    report_path = run_dir / "final_response.md"
    audit_log_path = run_dir / "audit" / "exec_log.jsonl"
    raw_dir = run_dir / "audit" / "raw"

    if not report_path.exists():
        raise FileNotFoundError(f"missing final_response.md: {report_path}")
    if not audit_log_path.exists():
        raise FileNotFoundError(f"missing audit log: {audit_log_path}")

    audit = AuditLogger(exec_log_path=audit_log_path, raw_output_dir=raw_dir)
    report_text = report_path.read_text()
    claims = parse_claims(report_text)

    verdicts: list[ClaimVerdict] = []
    for claim in claims:
        if claim.tag != "CONFIRMED":
            continue  # we only mechanically verify CONFIRMED claims
        if not claim.exec_ids:
            verdicts.append(ClaimVerdict(
                claim=claim,
                status="not_confirmed",
                notes="claim is tagged CONFIRMED but cites no exec_id",
            ))
            continue

        # Gather (tool_name, parsed_dict) for every cited exec_id. If ANY
        # citation fails to resolve we still try the others; the verdict
        # records the partial coverage in `notes`.
        parsed_by_tool: list[tuple[str, dict[str, Any]]] = []
        unresolved: list[str] = []
        unsupported_tools: set[str] = set()

        for eid in claim.exec_ids:
            row = audit.lookup_exec(eid)
            if row is None:
                unresolved.append(eid)
                continue
            tname = row.get("tool")
            parser = _PARSERS.get(tname)
            if parser is None:
                # Fallback: tools that have no text parser but DO record
                # structured metadata in the audit row's parsed_summary
                # (e.g. tsk_icat_extract — emits raw bytes; the audit row
                # has size_bytes + sha256 + inode). Use the parsed_summary
                # as the verification haystack so the agent's claim
                # ("hash X / size Y / inode Z") can be checked.
                parsed_summary = row.get("parsed_summary") or {}
                if parsed_summary:
                    parsed_by_tool.append((tname, parsed_summary))
                else:
                    unsupported_tools.add(tname or "?")
                continue
            raw_path = Path(row.get("raw_output_path") or "")
            if not raw_path.exists():
                unresolved.append(f"{eid} (raw missing)")
                continue
            parsed_by_tool.append(
                (tname, parser(raw_path.read_text(errors="replace")))
            )

        if not parsed_by_tool:
            # All citations failed to resolve — bubble up the most
            # informative status. Order: tool_not_supported > exec_id_not_found.
            if unsupported_tools:
                verdicts.append(ClaimVerdict(
                    claim=claim,
                    status="tool_not_supported",
                    notes=f"no parser for cited tool(s): {sorted(unsupported_tools)}",
                ))
            else:
                verdicts.append(ClaimVerdict(
                    claim=claim,
                    status="exec_id_not_found",
                    notes=f"unresolved exec_ids: {unresolved}",
                ))
            continue

        v = verify_claim_against_parsed(claim, parsed_by_tool=parsed_by_tool)
        if unresolved or unsupported_tools:
            extra = []
            if unresolved:
                extra.append(f"unresolved exec_ids: {unresolved}")
            if unsupported_tools:
                extra.append(f"unsupported tools: {sorted(unsupported_tools)}")
            v.notes = (v.notes + "; " if v.notes else "") + "; ".join(extra)
        verdicts.append(v)

    # Aggregate
    rv = RunVerdict(run_dir=str(run_dir))
    rv.total_claims = len(claims)
    for c in claims:
        if   c.tag == "CONFIRMED":  rv.confirmed_count  += 1
        elif c.tag == "INFERRED":   rv.inferred_count   += 1
        elif c.tag == "HYPOTHESIS": rv.hypothesis_count += 1
        elif c.tag == "GAP":        rv.gap_count        += 1
        else:                        rv.other_count      += 1
    for v in verdicts:
        if   v.status == "verified":           rv.verified           += 1
        elif v.status == "partial":            rv.partial            += 1
        elif v.status == "failed":             rv.failed             += 1
        elif v.status == "unverifiable":       rv.unverifiable       += 1
        elif v.status == "exec_id_not_found":  rv.exec_id_not_found  += 1
        elif v.status == "tool_not_supported": rv.tool_not_supported += 1
        elif v.status == "not_confirmed":      rv.not_confirmed      += 1
    if rv.confirmed_count > 0:
        rv.confirmation_score = round(rv.verified / rv.confirmed_count, 3)
    return rv, verdicts


def write_validator_report(
    run_dir: Path,
    rv: RunVerdict,
    verdicts: list[ClaimVerdict],
) -> tuple[Path, Path]:
    """Persist `validator_report.json` + `validator_report.md` in `run_dir`."""
    json_path = run_dir / "validator_report.json"
    md_path   = run_dir / "validator_report.md"

    json_path.write_text(json.dumps({
        "summary":  asdict(rv),
        "verdicts": [v.as_dict() for v in verdicts],
    }, indent=2, default=str))

    lines: list[str] = [
        f"# Validator Report — {run_dir.name}",
        "",
        "## Summary",
        "",
        f"- Total tagged claims:        **{rv.total_claims}**",
        f"  - CONFIRMED:                 {rv.confirmed_count}",
        f"  - INFERRED:                  {rv.inferred_count}",
        f"  - HYPOTHESIS:                {rv.hypothesis_count}",
        f"  - GAP:                       {rv.gap_count}",
        f"  - other:                     {rv.other_count}",
        "",
        "## Verification of CONFIRMED claims",
        "",
        f"- ✅ **verified:**           {rv.verified} (every extracted token found in cited tool's parsed output)",
        f"- ⚠ partial:                {rv.partial} (some tokens found, some missing)",
        f"- ❌ failed:                 {rv.failed} (no tokens found)",
        f"- ❓ unverifiable:           {rv.unverifiable} (claim is prose only, no extractable tokens)",
        f"- 🔍 exec_id_not_found:     {rv.exec_id_not_found} (cited exec_id is not in the audit log)",
        f"- ⛔ tool_not_supported:    {rv.tool_not_supported} (no parser for cited tool)",
        f"- ⚠ not_confirmed:           {rv.not_confirmed} (CONFIRMED-tagged but missing exec_id)",
        "",
        f"**Confirmation score: {rv.confirmation_score:.1%}** "
        f"({rv.verified} verified / {rv.confirmed_count} confirmed)",
        "",
        "## Per-claim verdicts",
        "",
    ]
    for v in verdicts:
        line_marker = f"_(line {v.claim.line_no})_"
        if v.status == "verified":
            icon = "✅"
        elif v.status == "partial":
            icon = "⚠"
        elif v.status == "failed":
            icon = "❌"
        elif v.status == "unverifiable":
            icon = "❓"
        elif v.status in ("exec_id_not_found", "tool_not_supported", "not_confirmed"):
            icon = "🔍"
        else:
            icon = "·"
        snippet = v.claim.text.strip().replace("\n", " ")
        if len(snippet) > 200:
            snippet = snippet[:200] + "…"
        lines.append(f"### {icon} {v.status} {line_marker}")
        if v.tool_names:
            lines.append(f"- tools: {', '.join(f'`{t}`' for t in v.tool_names)}")
        elif v.tool_name:
            lines.append(f"- tool: `{v.tool_name}`")
        if v.claim.exec_ids:
            lines.append(
                f"- exec_ids: "
                + ", ".join(f"`{e[-12:]}`" for e in v.claim.exec_ids[:4])
                + (f" (+{len(v.claim.exec_ids)-4} more)"
                   if len(v.claim.exec_ids) > 4 else "")
            )
        if v.matched:
            lines.append(f"- matched: {', '.join(f'`{t}`' for t in v.matched[:8])}"
                          + (f" (+{len(v.matched)-8} more)" if len(v.matched) > 8 else ""))
        if v.verified_absences:
            lines.append(f"- ✅ verified absences (negated): "
                          + ', '.join(f'`{t}`' for t in v.verified_absences[:6])
                          + (f" (+{len(v.verified_absences)-6} more)"
                             if len(v.verified_absences) > 6 else ""))
        if v.missing:
            lines.append(f"- **missing**: {', '.join(f'`{t}`' for t in v.missing[:8])}"
                          + (f" (+{len(v.missing)-8} more)" if len(v.missing) > 8 else ""))
        if v.negation_violations:
            lines.append(f"- 🚨 negation violations (claimed absent but found): "
                          + ', '.join(f'`{t}`' for t in v.negation_violations[:6]))
        if v.notes:
            lines.append(f"- note: {v.notes}")
        lines.append(f"- claim: > {snippet}")
        lines.append("")

    md_path.write_text("\n".join(lines))
    return json_path, md_path


@app.callback(invoke_without_command=True)
def _run(
    run_dir: str = typer.Option(..., "--run-dir"),
    quiet: bool = typer.Option(False, "--quiet"),
) -> None:
    p = Path(run_dir)
    if not p.exists():
        raise typer.BadParameter(f"run-dir does not exist: {run_dir}")

    rv, verdicts = validate_run(p)
    json_path, md_path = write_validator_report(p, rv, verdicts)

    if not quiet:
        from rich.table import Table
        t = Table(title=f"Validator — {p.name}")
        t.add_column("metric"); t.add_column("count", justify="right")
        for k, v in asdict(rv).items():
            if k == "run_dir":
                continue
            t.add_row(k, f"{v}")
        console.print(t)
        console.print(f"\nReports → [bold]{md_path.name}[/], [bold]{json_path.name}[/]")


def main() -> None:
    """Console-script entry point — invoked by `sift-validate`."""
    app()


if __name__ == "__main__":
    main()
