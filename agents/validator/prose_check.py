"""LLM-based prose check for the validator (v4).

Some agent claims are well-grounded in evidence but unreachable by the
rule-based extractor — descriptions like *"the agent used PsExec for
lateral movement based on PSEXESVC.EXE timing alignment"* have their
specific entity references in surrounding context, not the per-claim
sentence. The rule-based pass marks these `unverifiable`; v4 sends each
to a small Claude (Haiku) along with the cited tool's parsed JSON and
asks: does this data structurally support the claim?

Usage is opt-in via `--llm-check` so the default validator path stays
free of API calls (tests, CI, dry runs).

Cost envelope per run on observed prose-only claims (~15-20):
  ~6K input tokens × $1/M + ~150 output × $5/M ≈ $0.007 per claim
  → ~$0.10-0.15 per validator pass with --llm-check.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any


# Default model. Override per-call or via env.
DEFAULT_MODEL = os.environ.get("SIFT_OWL_PROSE_MODEL", "claude-haiku-4-5-20251001")

# Trim parsed JSON to this byte cap before sending — the parser's full row
# list can be megabytes; we only need a representative slice for the LLM
# to ground its check.
MAX_PARSED_BYTES = 12_000

# Maximum claim text length to include in the prompt (truncate longer).
MAX_CLAIM_BYTES = 2_000


_SYSTEM_PROMPT = """\
You are an evidence-grounded validator for digital-forensic claims.

Given:
  1. A specific CLAIM extracted from a DFIR report.
  2. The TOOL_NAME the claim cites and a slice of that tool's PARSED_DATA.

Decide whether the parsed data structurally supports the claim's specific
factual assertion. Be strict:
  - "VERIFIED" only if a specific factual element (process name, file path,
    timestamp, IP, hash, account name, event ID, etc.) in the claim is
    structurally present in the parsed data, OR the claim's negative
    assertion ("X is NOT in this data") matches what you observe.
  - "UNSUPPORTED" if the claim makes specific factual assertions but the
    parsed data does not contain those elements or contradicts them.
  - "UNRELATED" if the cited tool's data is fundamentally not relevant to
    the claim's assertion (e.g. a claim about network traffic citing a
    process-list tool with no networking fields).
  - Otherwise (genuinely ambiguous, prose-only, no testable assertion):
    "UNCERTAIN".

Respond with a single JSON object:
  {"verdict": "VERIFIED"|"UNSUPPORTED"|"UNRELATED"|"UNCERTAIN",
   "reason": "<one sentence>"}

No prose outside the JSON. No code fences.
"""


@dataclass
class ProseCheckResult:
    """LLM-grounded verdict on a single claim."""

    verdict: str       # VERIFIED | UNSUPPORTED | UNRELATED | UNCERTAIN
    reason: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


def _truncate_parsed_for_prompt(parsed: dict[str, Any]) -> str:
    """Render parsed data to a string, capped at MAX_PARSED_BYTES.

    Strategy: dump full JSON. If oversize, drop the bulky row lists
    (processes / rows / nodes / connections / files / findings /
    services / entries / events) so the aggregate fields (count,
    by_extension, by_event_id, foreign_ip_counts, etc.) remain.
    """
    text = json.dumps(parsed, default=str)
    if len(text) <= MAX_PARSED_BYTES:
        return text
    bulky_keys = (
        "processes", "rows", "nodes", "connections", "files",
        "findings", "services", "entries", "events", "partitions",
    )
    trimmed = {k: v for k, v in parsed.items() if k not in bulky_keys}
    text2 = json.dumps(trimmed, default=str)
    if len(text2) <= MAX_PARSED_BYTES:
        return text2
    # Last resort: hard truncate.
    return text2[:MAX_PARSED_BYTES] + "...<TRUNCATED>"


def _truncate_claim(claim: str) -> str:
    if len(claim) <= MAX_CLAIM_BYTES:
        return claim
    return claim[:MAX_CLAIM_BYTES] + "...<TRUNCATED>"


def check_claim_prose(
    *,
    claim_text: str,
    tool_name: str,
    parsed: dict[str, Any],
    client=None,
    model: str = DEFAULT_MODEL,
) -> ProseCheckResult:
    """Ask the LLM whether `parsed` supports `claim_text`.

    `client` is an Anthropic SDK client; one is constructed from
    ANTHROPIC_API_KEY if not supplied. Tests mock this.
    """
    if client is None:
        from anthropic import Anthropic
        client = Anthropic()

    user = (
        f"TOOL_NAME: {tool_name}\n\n"
        f"PARSED_DATA:\n{_truncate_parsed_for_prompt(parsed)}\n\n"
        f"CLAIM:\n{_truncate_claim(claim_text)}"
    )

    resp = client.messages.create(
        model=model,
        max_tokens=200,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user}],
    )

    # Extract first text block.
    text = ""
    for block in resp.content:
        if getattr(block, "type", None) == "text":
            text = block.text
            break
    text = text.strip()

    # Best-effort JSON parse. Be tolerant: model may emit code-fenced JSON
    # or extra text despite instructions.
    parsed_response = _parse_response(text)
    verdict = parsed_response.get("verdict", "UNCERTAIN").upper()
    if verdict not in ("VERIFIED", "UNSUPPORTED", "UNRELATED", "UNCERTAIN"):
        verdict = "UNCERTAIN"
    reason = str(parsed_response.get("reason", "(no reason given)"))[:300]

    # Pricing (per Anthropic docs as of 2025): Haiku 4.5 is $1/M input + $5/M output.
    in_tok = getattr(resp.usage, "input_tokens", 0) or 0
    out_tok = getattr(resp.usage, "output_tokens", 0) or 0
    cost = in_tok / 1e6 * 1.0 + out_tok / 1e6 * 5.0

    return ProseCheckResult(
        verdict=verdict, reason=reason, model=model,
        input_tokens=in_tok, output_tokens=out_tok, cost_usd=cost,
    )


def _parse_response(text: str) -> dict[str, Any]:
    """Tolerantly parse LLM response into a dict.

    Handles bare JSON, code-fenced JSON, and as-a-last-resort heuristic
    extraction of `verdict: <X>` or `"verdict": "<X>"` from prose.
    """
    if not text:
        return {}
    # Strip code fences
    s = text.strip()
    if s.startswith("```"):
        s = s.lstrip("`").lstrip("json").lstrip("\n").rstrip("`").strip()
    try:
        return json.loads(s)
    except Exception:
        pass
    # Heuristic salvage — accept JSON-like ("verdict": "X"), assignment
    # (verdict = X), or freeform prose ("the verdict is UNRELATED").
    out: dict[str, str] = {}
    import re
    m = re.search(
        r'"?verdict"?\s*(?:[:=]|\bis\b|\bwas\b|->)\s*"?'
        r'(VERIFIED|UNSUPPORTED|UNRELATED|UNCERTAIN)"?',
        s, re.IGNORECASE,
    )
    if m:
        out["verdict"] = m.group(1).upper()
    m = re.search(r'"?reason"?\s*[:=]\s*"([^"]+)"', s)
    if m:
        out["reason"] = m.group(1)
    return out
