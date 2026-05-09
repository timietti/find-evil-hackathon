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

from agents.validator.extract import ExtractedTokens, extract_tokens
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
    r"\[(CONFIRMED|INFERRED|HYPOTHESIS|GAP|FAILED)\s*"
    r"(?:[—\-:]\s*exec_id\s*([0-9a-fA-F\-]+))?"
    r"[^\]]*\]",
    re.IGNORECASE,
)


@dataclass
class Claim:
    """A single tagged claim pulled from a final report."""

    tag: str                  # CONFIRMED / INFERRED / HYPOTHESIS / GAP / FAILED
    exec_id: str | None       # exec_id cited (if any)
    text: str                 # the claim's surrounding paragraph
    raw_match: str            # the literal `[CONFIRMED — exec_id ...]` text
    line_no: int              # 1-based line number where the tag appears


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
        for m in _RE_TAG.finditer(para):
            tag = m.group(1).upper()
            exec_id = m.group(2) or None
            # Compute line of the tag inside the paragraph
            offset_lines = para[: m.start()].count("\n")
            claims.append(Claim(
                tag=tag,
                exec_id=exec_id,
                text=para,
                raw_match=m.group(0),
                line_no=start + offset_lines,
            ))
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
    tool_name: str | None = None
    tokens: ExtractedTokens = field(default_factory=ExtractedTokens)
    matched: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
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


def _flatten_to_searchable(parsed: dict[str, Any]) -> str:
    """Render parsed JSON as a single lower-case string for substring search.

    Sufficient for v0. A smarter validator would walk specific fields per
    plugin (e.g. only check `pid` against `processes[].pid`), but the
    flatten-and-search approach gets us 90% of the way and is robust.
    """
    return json.dumps(parsed, default=str).lower()


def verify_claim_against_parsed(
    claim: Claim,
    *,
    parsed: dict[str, Any],
    tool_name: str,
) -> ClaimVerdict:
    """Check `claim` against the parsed JSON of the tool that produced it."""
    tokens = extract_tokens(claim.text)
    if tokens.is_empty():
        return ClaimVerdict(
            claim=claim,
            status="unverifiable",
            tool_name=tool_name,
            tokens=tokens,
            notes="claim has no extractable tokens (prose only)",
        )

    haystack = _flatten_to_searchable(parsed)
    matched: list[str] = []
    missing: list[str] = []

    for tok in tokens.all():
        # Tokens from prose can include trailing punctuation already stripped
        # by the extractor; lower-case substring is the right relation here.
        if tok.lower() in haystack:
            matched.append(tok)
        else:
            missing.append(tok)

    if not missing:
        status = "verified"
    elif matched:
        status = "partial"
    else:
        status = "failed"

    return ClaimVerdict(
        claim=claim,
        status=status,
        tool_name=tool_name,
        tokens=tokens,
        matched=matched,
        missing=missing,
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
        if not claim.exec_id:
            verdicts.append(ClaimVerdict(
                claim=claim,
                status="not_confirmed",
                notes="claim is tagged CONFIRMED but cites no exec_id",
            ))
            continue

        row = audit.lookup_exec(claim.exec_id)
        if row is None:
            verdicts.append(ClaimVerdict(
                claim=claim,
                status="exec_id_not_found",
                notes=f"exec_id {claim.exec_id} not in audit log",
            ))
            continue

        tool_name = row.get("tool")
        parser = _PARSERS.get(tool_name)
        if not parser:
            verdicts.append(ClaimVerdict(
                claim=claim,
                status="tool_not_supported",
                tool_name=tool_name,
                notes=f"no parser registered for tool_name={tool_name}",
            ))
            continue

        raw_path = Path(row.get("raw_output_path") or "")
        if not raw_path.exists():
            verdicts.append(ClaimVerdict(
                claim=claim,
                status="failed",
                tool_name=tool_name,
                notes=f"raw output missing on disk: {raw_path}",
            ))
            continue

        parsed = parser(raw_path.read_text(errors="replace"))
        verdicts.append(verify_claim_against_parsed(
            claim, parsed=parsed, tool_name=tool_name,
        ))

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
        if v.tool_name:
            lines.append(f"- tool: `{v.tool_name}`")
        if v.claim.exec_id:
            lines.append(f"- exec_id: `{v.claim.exec_id[-12:]}`")
        if v.matched:
            lines.append(f"- matched tokens: {', '.join(f'`{t}`' for t in v.matched[:8])}"
                          + (f" (+{len(v.matched)-8} more)" if len(v.matched) > 8 else ""))
        if v.missing:
            lines.append(f"- **missing tokens**: {', '.join(f'`{t}`' for t in v.missing[:8])}"
                          + (f" (+{len(v.missing)-8} more)" if len(v.missing) > 8 else ""))
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
