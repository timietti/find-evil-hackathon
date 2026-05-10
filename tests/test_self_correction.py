"""Unit tests for the SIFT-OWL v2 self-correction loop's prompt-construction
logic. These are pure-function tests — no Claude or sift-mcp invocation.
"""

from __future__ import annotations

import pytest

from eval.agents.sift_owl_v2.run_loop import (
    _DEMOTED_STATUSES,
    _flagged_verdicts,
    _format_flagged_claim,
    build_followup_prompt,
)


def _vr(status: str, **kw) -> dict:
    """Mini factory for validator verdict dicts (matches validator's JSON shape)."""
    return {
        "claim": {
            "tag":       kw.get("tag", "CONFIRMED"),
            "exec_id":   kw.get("exec_id"),
            "exec_ids":  kw.get("exec_ids", []),
            "text":      kw.get("text", ""),
            "raw_match": kw.get("raw_match", "[CONFIRMED]"),
            "line_no":   kw.get("line_no", 1),
        },
        "status":              status,
        "tool_name":           kw.get("tool_name"),
        "tool_names":          kw.get("tool_names", []),
        "matched":             kw.get("matched", []),
        "missing":             kw.get("missing", []),
        "negation_violations": kw.get("negation_violations", []),
        "verified_absences":   kw.get("verified_absences", []),
        "notes":               kw.get("notes", ""),
    }


# ---- _flagged_verdicts ----------------------------------------------------


def test_flagged_verdicts_picks_up_demoted_statuses() -> None:
    rep = {
        "verdicts": [
            _vr("verified"),
            _vr("partial",       missing=["X"]),
            _vr("failed",        missing=["Y"]),
            _vr("not_confirmed"),
            _vr("unverifiable"),
            _vr("exec_id_not_found"),
            _vr("tool_not_supported"),
        ],
    }
    flagged = _flagged_verdicts(rep)
    statuses = {v["status"] for v in flagged}
    # Only the three demotion-worthy statuses should appear.
    assert statuses == _DEMOTED_STATUSES
    assert _DEMOTED_STATUSES == {"partial", "failed", "not_confirmed"}


def test_flagged_verdicts_handles_empty_report() -> None:
    assert _flagged_verdicts({}) == []
    assert _flagged_verdicts({"verdicts": []}) == []


# ---- _format_flagged_claim ------------------------------------------------


def test_format_flagged_claim_partial_with_tokens() -> None:
    v = _vr(
        "partial",
        tag="CONFIRMED",
        exec_ids=["019eaa-1", "019ebb-2"],
        tool_names=["vol3_psscan", "vol3_netscan"],
        matched=["29440", "MRC.exe"],
        missing=["81.30.144.115"],
        text="MRC.exe (PID 29440) connected to 81.30.144.115. [CONFIRMED — exec_id 019eaa-1]",
    )
    out = _format_flagged_claim(1, v)
    assert "[1]" in out
    assert "partial" in out
    assert "vol3_psscan" in out
    assert "vol3_netscan" in out
    assert "019eaa-1" in out
    assert "missing tokens" in out
    assert "81.30.144.115" in out
    assert "already matched" in out
    assert "29440" in out
    # Snippet is preserved
    assert "MRC.exe" in out


def test_format_flagged_claim_negation_violation() -> None:
    v = _vr(
        "failed",
        exec_ids=["01h"],
        tool_names=["vol3_svcscan"],
        negation_violations=["spinlock"],
        text="No spinlock service was found. [CONFIRMED — exec_id 01h]",
    )
    out = _format_flagged_claim(2, v)
    assert "negation violations" in out
    assert "spinlock" in out


def test_format_flagged_claim_not_confirmed_no_exec_id() -> None:
    v = _vr(
        "not_confirmed",
        exec_ids=[],
        text="Some bullet line. [CONFIRMED]",
        notes="claim is tagged CONFIRMED but cites no exec_id",
    )
    out = _format_flagged_claim(3, v)
    assert "not_confirmed" in out
    assert "(none)" in out  # exec_ids empty
    assert "validator note" in out


# ---- build_followup_prompt -------------------------------------------------


def test_build_followup_prompt_includes_flagged_block() -> None:
    base = "## Case context\nFred Rocba was burgled."
    prev_response = "## Findings\n- Some claim. [CONFIRMED — exec_id 01a]"
    prev_validator = {
        "verdicts": [
            _vr(
                "partial",
                exec_ids=["01a"],
                tool_names=["vol3_psscan"],
                missing=["81.30.144.115"],
                text="Some claim about 81.30.144.115. [CONFIRMED — exec_id 01a]",
            ),
            _vr("verified"),  # not flagged
        ],
    }
    prompt = build_followup_prompt(
        base_prompt=base,
        iteration_n=2,
        prev_response_text=prev_response,
        prev_validator_report=prev_validator,
    )
    # Original case context is preserved
    assert "Fred Rocba" in prompt
    # Prior response is included so the agent can build on it
    assert "Some claim. [CONFIRMED" in prompt
    # The feedback header is present
    assert "Validator feedback from iteration 1" in prompt
    # The flagged claim is rendered
    assert "81.30.144.115" in prompt
    # The three resolution options are explicit
    assert "Re-confirm with multi-cite" in prompt
    assert "Demote to [INFERRED]" in prompt
    assert "Demote to [GAP]" in prompt
    # Number of flagged claims is visible
    assert "1 claims" in prompt or "n_flagged: 1" in prompt or "1 claims" in prompt


def test_build_followup_prompt_zero_flagged_uses_placeholder() -> None:
    base = "## Case"
    prev_response = "Done."
    prev_validator = {"verdicts": [_vr("verified"), _vr("verified")]}
    prompt = build_followup_prompt(
        base_prompt=base,
        iteration_n=2,
        prev_response_text=prev_response,
        prev_validator_report=prev_validator,
    )
    assert "no flagged claims" in prompt


def test_build_followup_prompt_preserves_iteration_numbers() -> None:
    base = "x"
    rep = {"verdicts": [_vr("partial", text="t.", missing=["x"])]}
    p2 = build_followup_prompt(
        base_prompt=base, iteration_n=2,
        prev_response_text="r1", prev_validator_report=rep,
    )
    p3 = build_followup_prompt(
        base_prompt=base, iteration_n=3,
        prev_response_text="r2", prev_validator_report=rep,
    )
    assert "iteration 1" in p2
    assert "iteration 2" in p3
    # The "Iteration N's report" header reflects the right prior iter
    assert "Iteration 1's final report" in p2
    assert "Iteration 2's final report" in p3
