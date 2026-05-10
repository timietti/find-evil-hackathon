"""Tests for the SIFT-OWL validator (rule-based v0)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.validator.extract import (
    extract_tokens,
    is_negated_sentence,
    split_sentences,
    token_is_negated_in,
)
from agents.validator.validate import (
    Claim,
    parse_claims,
    validate_run,
    verify_claim_against_parsed,
)


# ---- token extraction ------------------------------------------------------


def test_extract_pid() -> None:
    t = extract_tokens("MRC.exe at PID 29440 is the smoking gun")
    assert "29440" in t.pids


def test_extract_ipv4() -> None:
    t = extract_tokens("Connections to 81.30.144.115 (59 hits) and 213.202.233.104")
    assert "81.30.144.115" in t.ips
    assert "213.202.233.104" in t.ips


def test_extract_iso_timestamp() -> None:
    t = extract_tokens("Memory captured at 2020-11-16T02:32:38Z")
    assert "2020-11-16T02:32:38Z" in t.timestamps


def test_extract_filename_with_forensic_extension() -> None:
    t = extract_tokens(
        "StarFury.zip on OneDrive; sdelete.exe in Downloads; "
        "backup.pst was deleted; Death_Blossom_attack.png viewed"
    )
    assert "StarFury.zip" in t.filenames
    assert "sdelete.exe" in t.filenames
    assert "backup.pst" in t.filenames
    assert "Death_Blossom_attack.png" in t.filenames


def test_extract_windows_path_variants() -> None:
    text = (
        r"Files at \Users\fredr\OneDrive\StarFury.zip and "
        r"\Device\HarddiskVolume3\Windows\System32\STUN.exe; "
        r"D:\Tools\MRC.exe was the binary."
    )
    t = extract_tokens(text)
    assert any("OneDrive" in p for p in t.paths)
    assert any("STUN.exe" in p for p in t.paths)
    # D:\Tools\MRC.exe is captured as a drive_ref or path; either is fine.
    all_tokens = t.all()
    assert any("MRC.exe" in tok for tok in all_tokens)


def test_extract_email() -> None:
    t = extract_tokens(
        "credential file fred.rocba@outlook.com.lnk recovered"
    )
    assert "fred.rocba@outlook.com" in t.emails


def test_extract_brace_guid() -> None:
    t = extract_tokens(
        "UserAssist subkey {9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}"
    )
    assert any("9E04CAB2" in g for g in t.brace_guids)


def test_extract_ignores_pure_prose() -> None:
    t = extract_tokens(
        "The intruder used the existing Windows session to browse documents."
    )
    assert t.is_empty(), f"expected no tokens; got {t.all()}"


# ---- claim parsing ---------------------------------------------------------


def test_parse_claims_finds_confirmed_tag() -> None:
    md = (
        "# Report\n\n"
        "MRC.exe at PID 29440 launched at 2020-11-16T02:31:13Z.\n"
        "[CONFIRMED — exec_id 019e0dd9-acd5-7651-9a30-ca3ed66e47c7]\n"
    )
    claims = parse_claims(md)
    assert len(claims) == 1
    assert claims[0].tag == "CONFIRMED"
    assert claims[0].exec_id == "019e0dd9-acd5-7651-9a30-ca3ed66e47c7"


def test_parse_claims_handles_all_tags() -> None:
    md = (
        "Confirmed thing.\n[CONFIRMED — exec_id 01abc]\n\n"
        "Inferred thing.\n[INFERRED — exec_id 02def reasoning: ...]\n\n"
        "Speculation.\n[HYPOTHESIS]\n\n"
        "Open question.\n[GAP]\n"
    )
    claims = parse_claims(md)
    tags = {c.tag for c in claims}
    assert tags == {"CONFIRMED", "INFERRED", "HYPOTHESIS", "GAP"}


def test_parse_claims_extracts_paragraph_around_tag() -> None:
    md = (
        "Para A line 1.\nPara A line 2 with [CONFIRMED — exec_id 01x].\n\n"
        "Para B unrelated.\n"
    )
    claims = parse_claims(md)
    assert len(claims) == 1
    assert "Para A line 1" in claims[0].text
    assert "Para A line 2" in claims[0].text
    assert "Para B" not in claims[0].text


def test_parse_claims_handles_dash_variants() -> None:
    """em-dash, hyphen, and colon are all valid separators between the tag
    and `exec_id`. The exec_id itself is restricted to hex+dash (UUIDv7
    format), since that's what the audit log emits."""
    for sep in ("—", "-", ":"):
        md = f"thing happened at PID 29440. [CONFIRMED {sep} exec_id 019eabcd-1234]"
        claims = parse_claims(md)
        assert len(claims) == 1, f"failed for separator '{sep}'"
        assert claims[0].tag == "CONFIRMED"
        assert claims[0].exec_id == "019eabcd-1234"


# ---- per-claim verification ------------------------------------------------


def test_verify_claim_against_parsed_finds_pid() -> None:
    parsed = {
        "count": 5,
        "processes": [
            {"pid": 29440, "image": "MRC.exe", "ppid": 7464},
            {"pid": 1912,  "image": "STUN.exe"},
        ],
    }
    claim = Claim(
        tag="CONFIRMED", exec_id="01x",
        text="MRC.exe runs at PID 29440 [CONFIRMED — exec_id 01x]",
        raw_match="[CONFIRMED — exec_id 01x]", line_no=1,
    )
    v = verify_claim_against_parsed(claim, parsed=parsed, tool_name="vol3_psscan")
    assert v.status == "verified"
    assert "29440" in v.matched
    assert "MRC.exe" in v.matched
    assert v.missing == []


def test_verify_claim_against_parsed_partial_match() -> None:
    parsed = {"processes": [{"pid": 29440, "image": "MRC.exe"}]}
    claim = Claim(
        tag="CONFIRMED", exec_id="01x",
        text="MRC.exe at PID 29440 connected to 81.30.144.115 [CONFIRMED — exec_id 01x]",
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(claim, parsed=parsed, tool_name="vol3_psscan")
    # 29440 + MRC.exe matched; 81.30.144.115 is not in this parsed output.
    assert v.status == "partial"
    assert "29440" in v.matched
    assert "81.30.144.115" in v.missing


def test_verify_claim_against_parsed_failed() -> None:
    parsed = {"processes": [{"pid": 4, "image": "System"}]}
    claim = Claim(
        tag="CONFIRMED", exec_id="01x",
        text="MRC.exe at PID 29440 is malware [CONFIRMED — exec_id 01x]",
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(claim, parsed=parsed, tool_name="vol3_psscan")
    assert v.status == "failed"
    assert v.matched == []
    assert "29440" in v.missing
    assert "MRC.exe" in v.missing


def test_verify_claim_against_parsed_unverifiable() -> None:
    """Claim that's pure prose with no extractable tokens."""
    parsed = {"x": 1}
    claim = Claim(
        tag="CONFIRMED", exec_id="01x",
        text="The attacker used a methodical approach. [CONFIRMED — exec_id 01x]",
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(claim, parsed=parsed, tool_name="vol3_psscan")
    assert v.status == "unverifiable"


# ---- v1: negation detection -----------------------------------------------


@pytest.mark.parametrize(
    "sentence,expected",
    [
        ("No spinlock service was found on DC.",   True),
        ("spinlock.exe was not found in filescan.", True),
        ("The binary is absent from the filesystem.", True),
        ("The agent never connected to the C2.",  True),
        ("This account doesn't exist in psscan.", True),
        # genuine positives shouldn't be flagged
        ("STUN.exe at PID 1912 was found in psscan.", False),
        ("usboesrv.exe is the C2 implant.",       False),
    ],
)
def test_is_negated_sentence(sentence: str, expected: bool) -> None:
    assert is_negated_sentence(sentence) is expected


def test_split_sentences() -> None:
    text = "First fact. Second fact!\nThird fact?"
    sents = split_sentences(text)
    assert len(sents) == 3


def test_token_is_negated_in_negated_sentence() -> None:
    text = "PID 1912 is the smoking gun. No spinlock.exe found in services."
    assert token_is_negated_in(text, "spinlock.exe") is True
    assert token_is_negated_in(text, "1912") is False  # in the positive sentence


def test_verify_claim_negative_assertion_when_token_absent() -> None:
    """Claim says 'no spinlock', token NOT in haystack → verified."""
    parsed = {"services": [{"name": "RpcEptMapper"}, {"name": "Spooler"}]}
    claim = Claim(
        tag="CONFIRMED", exec_id="01x",
        text="No spinlock.exe service was found on DC. [CONFIRMED — exec_id 01x]",
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(claim, parsed=parsed, tool_name="vol3_svcscan")
    assert v.status == "verified"
    assert "spinlock.exe" in v.verified_absences
    assert v.negation_violations == []


def test_verify_claim_negation_violation_when_token_present() -> None:
    """Claim says 'no spinlock.exe', but spinlock.exe IS in haystack → failed."""
    parsed = {"services": [{"name": "spinlock.exe", "binary": "C:\\spinlock.exe"}]}
    claim = Claim(
        tag="CONFIRMED", exec_id="01x",
        text="No spinlock.exe service was found. [CONFIRMED — exec_id 01x]",
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(claim, parsed=parsed, tool_name="vol3_svcscan")
    assert v.status == "failed"
    assert "spinlock.exe" in v.negation_violations


# ---- v1: multi-citation parsing -------------------------------------------


def test_parse_claims_extracts_multiple_exec_ids() -> None:
    md = (
        "PID 29440 connected to 81.30.144.115.\n"
        "[CONFIRMED — exec_id 019eaaaa-1111, exec_id 019ebbbb-2222]\n"
    )
    claims = parse_claims(md)
    assert len(claims) == 1
    c = claims[0]
    assert c.exec_id == "019eaaaa-1111"  # primary kept for back-compat
    assert c.exec_ids == ["019eaaaa-1111", "019ebbbb-2222"]


def test_parse_claims_extracts_semicolon_separated_exec_ids() -> None:
    md = "x. [CONFIRMED — exec_id 019eaaaa-1111; exec_id 019ebbbb-2222]"
    c = parse_claims(md)[0]
    assert c.exec_ids == ["019eaaaa-1111", "019ebbbb-2222"]


def test_parse_claims_extracts_three_exec_ids() -> None:
    md = (
        "x. [CONFIRMED — "
        "exec_id 019eaaaa-1111, "
        "exec_id 019ebbbb-2222, "
        "exec_id 019ecccc-3333]"
    )
    c = parse_claims(md)[0]
    assert len(c.exec_ids) == 3


def test_verify_claim_multi_citation_token_in_second_tool() -> None:
    """Multi-cite: token only in tool B; should still be verified."""
    parsed_psscan = {"processes": [{"pid": 29440, "image": "MRC.exe"}]}
    parsed_netscan = {"connections": [{"foreign_addr": "81.30.144.115"}]}
    claim = Claim(
        tag="CONFIRMED", exec_id="01a",
        exec_ids=["01a", "01b"],
        text=(
            "MRC.exe at PID 29440 connected to 81.30.144.115. "
            "[CONFIRMED — exec_id 01a, exec_id 01b]"
        ),
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(
        claim,
        parsed_by_tool=[
            ("vol3_psscan", parsed_psscan),
            ("vol3_netscan", parsed_netscan),
        ],
    )
    assert v.status == "verified"
    assert "29440" in v.matched
    assert "MRC.exe" in v.matched
    assert "81.30.144.115" in v.matched


def test_verify_claim_multi_citation_token_in_neither_tool() -> None:
    """Multi-cite: token in neither cited tool → missing."""
    parsed_a = {"processes": [{"pid": 4, "image": "System"}]}
    parsed_b = {"connections": [{"foreign_addr": "1.2.3.4"}]}
    claim = Claim(
        tag="CONFIRMED", exec_id="01a", exec_ids=["01a", "01b"],
        text="MRC.exe at PID 29440 to 81.30.144.115 [CONFIRMED — exec_id 01a, exec_id 01b]",
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(
        claim,
        parsed_by_tool=[("vol3_psscan", parsed_a), ("vol3_netscan", parsed_b)],
    )
    assert v.status == "failed"
    assert "29440" in v.missing
    assert "MRC.exe" in v.missing
    assert "81.30.144.115" in v.missing


# ---- v2: validator improvements -------------------------------------------


def test_verify_claim_path_with_backslashes_matches_haystack() -> None:
    """v2 path-prefix matching fix.

    `_flatten_to_searchable` previously JSON-encoded backslashes (`\\` → `\\\\`)
    so single-backslash path tokens couldn't match. v2 normalises both sides
    to single backslashes.
    """
    parsed = {
        "files": [
            {"name": "\\Users\\fredr\\OneDrive - Stark Research Labs\\Research\\foo.docx"}
        ]
    }
    claim = Claim(
        tag="CONFIRMED", exec_id="01x",
        text=(
            "The Adamantium file "
            "\\Users\\fredr\\OneDrive - Stark Research Labs\\Research\\foo.docx "
            "was present [CONFIRMED — exec_id 01x]"
        ),
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(claim, parsed=parsed, tool_name="vol3_filescan")
    assert v.status == "verified", (
        f"path-prefix matching should verify; got {v.status} "
        f"with missing={v.missing}"
    )


def test_token_subject_clause_negation_pattern() -> None:
    """v2 'X: Not Y' subject-clause negation.

    'usboesrv.exe: **Not found on nromanoff**' splits at `:\s+` into
    ['usboesrv.exe', 'Not found on nromanoff']. Clause 1 has no negation
    cue but is a *subject* clause (length ≤ len(token)+5) followed by a
    negated clause. v2 treats clause-1's token as negated.
    """
    text = "usboesrv.exe: Not found on nromanoff."
    assert token_is_negated_in(text, "usboesrv.exe") is True


def test_token_subject_clause_does_not_overshoot() -> None:
    """A token in a long sentence with a following short negated clause
    should NOT be treated as negated by the subject-clause heuristic."""
    text = "Foo.exe is the legitimate binary on this host. Bar.exe was not present."
    # Foo.exe is in a long positive sentence; the next sentence's "not"
    # applies to Bar.exe, not to Foo.exe.
    assert token_is_negated_in(text, "Foo.exe") is False
    assert token_is_negated_in(text, "Bar.exe") is True


def test_validator_falls_back_to_parsed_summary_for_parserless_tools(
    tmp_path: Path,
) -> None:
    """v2 parsed_summary fallback for tsk_icat_extract.

    The audit row for tsk_icat_extract has parsed_summary={size_bytes,
    sha256, inode}. v0 validator marked any claim citing it as
    `tool_not_supported` because there's no text parser. v2 falls back
    to the parsed_summary as the verification haystack.
    """
    from mcp_server.audit import AuditLogger

    # validate_run() expects <run_dir>/audit/exec_log.jsonl + audit/raw/
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    audit = AuditLogger(
        exec_log_path=audit_dir / "exec_log.jsonl",
        raw_output_dir=audit_dir / "raw",
    )
    eid = audit.new_exec_id()
    audit.record(
        exec_id=eid, agent="disk_agent", tool="tsk_icat_extract",
        args={"image": "/cases/x.E01", "inode": 12345},
        raw_output_path=None,  # icat emits raw bytes; no parsed text
        exit_code=0, wall_ms=42,
        summary="extracted inode=12345, 9216 bytes, sha256=598e53b6...1dec",
        parsed_summary={"size_bytes": 9216, "sha256": "598e53b69c71643d", "inode": 12345},
    )

    # Build a final_response.md that cites this exec_id with tokens that
    # ARE in parsed_summary (size, sha256, inode — but NOT a filename like
    # "a.exe", which the agent should multi-cite from the prior fls call).
    final = tmp_path / "final_response.md"
    final.write_text(
        f"Extracted file at inode 12345 is 9216 bytes, sha256 598e53b69c71643d.\n"
        f"[CONFIRMED — exec_id {eid}]\n"
    )

    rv, verdicts = validate_run(tmp_path)
    assert len(verdicts) == 1
    v = verdicts[0]
    # The headline v0→v2 bug: tsk_icat_extract used to return
    # tool_not_supported. v2 falls back to parsed_summary, so the verdict
    # should now be a real verification result (verified / partial / failed).
    assert v.status != "tool_not_supported", (
        f"v2 should fall back to parsed_summary; got {v.status}"
    )
    # The extractor pulls inode (12345) and the sha256 hash from the claim;
    # both are in parsed_summary, so verified.
    assert v.status == "verified", f"expected verified; got {v.status} missing={v.missing}"
    matched_str = " ".join(v.matched)
    assert "12345" in matched_str
    assert "598e53b69c71643d" in matched_str


# ---- v3: per-tag claim segmentation ---------------------------------------


def test_parse_claims_two_confirmed_tags_in_one_paragraph_get_separate_text() -> None:
    """v3 fix #1: when a paragraph has multiple [CONFIRMED] tags, each
    Claim's text should be ONLY its own slice, not the whole paragraph.

    Without this, two claims pollute each other's token lists and the
    validator can't tell which exec_id is supposed to support which token.
    """
    md = (
        "**No a.exe was found in DC MFT TEMP paths** "
        "[CONFIRMED — exec_id 019eaaaa-1111]; "
        "**not present in DC ShimCache TEMP entries** "
        "[CONFIRMED — exec_id 019ebbbb-2222].\n"
    )
    claims = parse_claims(md)
    assert len(claims) == 2
    # Each claim's text is its own slice
    assert "DC MFT TEMP paths" in claims[0].text
    assert "DC ShimCache TEMP entries" in claims[1].text
    # And they don't overlap into each other's content
    assert "DC ShimCache" not in claims[0].text
    assert "DC MFT TEMP paths" not in claims[1].text
    # exec_ids are correctly attributed
    assert claims[0].exec_ids == ["019eaaaa-1111"]
    assert claims[1].exec_ids == ["019ebbbb-2222"]


def test_parse_claims_single_tag_per_paragraph_unchanged() -> None:
    """v3 segmentation must not break the simple case where each
    paragraph has exactly one tag (the most common pattern)."""
    md = "Para 1 with PID 4. [CONFIRMED — exec_id 019eaaaa-1111]\n"
    claims = parse_claims(md)
    assert len(claims) == 1
    # text contains the full paragraph leading up to + including the tag
    assert "PID 4" in claims[0].text


# ---- v3: paren-aware negation ---------------------------------------------


def test_is_negated_sentence_strips_parens_before_check() -> None:
    """v3 fix #2: a 'not' inside a parenthetical exception should NOT
    cause the whole sentence to be classified as negated."""
    # The "not" is inside parens; the main clause is positive.
    assert is_negated_sentence("EXFIL.pst is on tdungan (not DC).") is False
    # Real negation outside parens still classifies as negated.
    assert is_negated_sentence("usboesrv.exe was not found on nromanoff.") is True
    # Negation both inside parens AND outside parens → negated (real negation present).
    assert is_negated_sentence("X is not present (not even on Y).") is True


def test_token_negation_paren_aware_e2e() -> None:
    """End-to-end: a token in a sentence with only a parenthetical 'not'
    should be treated as positive, so its presence in the haystack
    counts as a match (not a negation_violation)."""
    parsed = {
        "rows": [
            {"file_name": "EXFIL.pst", "parent_path": "\\Users\\vibranium\\..."},
        ]
    }
    claim = Claim(
        tag="CONFIRMED", exec_id="01x",
        text="EXFIL.pst is on tdungan (not DC). [CONFIRMED — exec_id 01x]",
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(claim, parsed=parsed, tool_name="ezt_mft_parse")
    assert v.status == "verified", (
        f"paren-isolated 'not' should not cause negation; got {v.status} "
        f"violations={v.negation_violations}"
    )
    assert "EXFIL.pst" in v.matched


# ---- v3: timestamp prefix matching ----------------------------------------


def test_timestamp_prefix_match_minute_precision() -> None:
    """v3 fix #3: claim's 'T23:09Z' (minute precision) should match
    haystack's 'T23:09:14Z' (second precision) via prefix match."""
    parsed = {
        "events": [
            {"time_created": "2012-04-03T23:09:14Z"},
        ]
    }
    claim = Claim(
        tag="CONFIRMED", exec_id="01x",
        text="vibranium first activity at 2012-04-03T23:09Z. [CONFIRMED — exec_id 01x]",
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(claim, parsed=parsed, tool_name="ezt_evtx_parse")
    assert v.status == "verified", (
        f"timestamp prefix should match; got {v.status} missing={v.missing}"
    )


def test_timestamp_full_match_still_works() -> None:
    """v3 prefix match must not break the case where the claim's
    timestamp matches the haystack's timestamp exactly."""
    parsed = {"events": [{"time_created": "2012-04-03T23:09:14Z"}]}
    claim = Claim(
        tag="CONFIRMED", exec_id="01x",
        text="event at 2012-04-03T23:09:14Z [CONFIRMED — exec_id 01x]",
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(claim, parsed=parsed, tool_name="ezt_evtx_parse")
    assert v.status == "verified"


def test_timestamp_prefix_does_not_overshoot_to_unrelated_times() -> None:
    """A claim's timestamp 'T23:09Z' must NOT match haystack's 'T23:08:59Z'
    just because they share a prefix string-wise — they don't (different minute)."""
    parsed = {"events": [{"time_created": "2012-04-03T23:08:59Z"}]}
    claim = Claim(
        tag="CONFIRMED", exec_id="01x",
        text="event at 2012-04-03T23:09Z [CONFIRMED — exec_id 01x]",
        raw_match="...", line_no=1,
    )
    v = verify_claim_against_parsed(claim, parsed=parsed, tool_name="ezt_evtx_parse")
    # The token "2012-04-03T23:09Z" is NOT a prefix of "2012-04-03T23:08:59Z",
    # so the substring/prefix matcher correctly returns False.
    assert v.status == "failed"


# ---- end-to-end against committed ROCBA-001 v1 run ------------------------


REPO_ROOT = Path(__file__).resolve().parents[1]
ROCBA_V1_RUN = REPO_ROOT / "eval" / "results" / "rocba-001" / "sift-owl-v1" / "20260509T174516Z-sonnet"


@pytest.mark.skipif(
    not (ROCBA_V1_RUN / "final_response.md").exists()
    or not (ROCBA_V1_RUN / "audit" / "exec_log.jsonl").exists()
    or not (ROCBA_V1_RUN / "audit" / "raw" / "subprocess").exists(),
    reason="needs the v1 ROCBA run + its audit/raw/ outputs (not committed)",
)
def test_validator_runs_against_real_rocba_v1_run(tmp_path: Path) -> None:
    """Smoke test: the validator runs end-to-end on the real v1 run dir.

    Verifies that:
      - parse_claims pulls a non-zero count of CONFIRMED claims
      - validate_run finds parsers for every cited tool (no
        tool_not_supported entries)
      - the confirmation_score is positive (some claims do verify)
    """
    rv, verdicts = validate_run(ROCBA_V1_RUN)
    assert rv.confirmed_count > 0, "v1 ROCBA report has 0 CONFIRMED claims?!"
    assert rv.tool_not_supported == 0, (
        "v1 cited a tool we don't have a parser for"
    )
    assert rv.confirmation_score > 0.0, (
        "no CONFIRMED claims verified at all — likely a validator bug"
    )
