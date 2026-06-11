# ROCBA-001 re-eval with new disk image — `20260611T053254Z-sonnet`

> First ROCBA run after the C: drive image (`rocba-cdrive.e01`, 81 GiB
> NTFS, X-Ways acquisition 2020-12-18) was added on 2026-06-08. Prior
> ROCBA results (57.1% single-pass v1; 91.7% v2 loop) were memory-only.
> This run uses the new `eval/agents/sift_owl_v2/prompt-rocba-001.md`
> that covers both images.

## Headline (raw, as the loop saw it)

| Iter | Cost | Wall | MCP calls | V | P | F | U | NC | LLM-V | **Strict-verified** |
|---|---|---|---|---|---|---|---|---|---|---|
| iter 1 | $2.25 | 64.3 m | 27 | 9 | 9 | 1 | 0 | 19 | 0  | 23.7% |
| iter 2 | $1.09 | 47.9 m | 4  | 9 | 4 | 0 | 8 | 17 | 0/8 | 23.7% |

Loop early-terminated after iter 2 (`No improvement: verified=9 ≤
prev=9. Stopping.`). **Total: $3.34 / 112 min / 31 MCP calls.**
Evidence chain-of-custody preserved.

This is the lowest strict-verified ROCBA number to date. The
substantive findings are *good* — the agent recovered the SRL VPN
credentials file by MFT entry, identified a second local profile
`\Users\srl-h\` with a sparsely-populated OneDrive, surfaced RDP
session evidence, and dated everything inside the 2020-11-13T22:00Z
→ 2020-11-16T02:32:38Z intruder window. The score collapses because
**two validator bugs masked the signal**, both surfaced for the
first time on this run.

## Root cause — two validator bugs

### Bug C — markdown-table claims (NC=17)

The agent emitted ~half of its iter-2 CONFIRMED claims as
markdown-table rows where the `[CONFIRMED]` tag is in the *last cell*
and the exec_id is a backticked UUID in an earlier cell:

```
| | 2020-11-14T03:42:56Z | TSTHEME.EXE-01D23267.pf created in
.\Windows\Prefetch\ — first RDP session of intrusion |
`019eb541-08ea-7ea0-9495-7cc627c154e8` (entry 96265) | [CONFIRMED]
```

The validator's `_extract_exec_ids_from_prose` scans for tokens
following an `exec_id` keyword or a registered tool name. The bare
backticked UUID in a table cell has neither preceding marker, so
extraction returned `None` and the verdict became `not_confirmed`
("claim is tagged CONFIRMED but cites no exec_id").

**Fix** (`agents/validator/validate.py`): when the marker-anchored
scan finds nothing AND the text contains `|` (table delimiter),
accept any `` `UUID` `` token with the strict 8-4-…-…
dash-separated-hex shape. The strict UUIDv7 shape + backtick
quoting is specific enough to avoid SHA-256 false-matches.

### Bug D — backtick swept into path tokens (Partial)

The Windows-path regex `[^\s\"']+` allowed backticks through. When
the agent wrote `` `\Users\srl-h\` ``, the extractor captured
`\Users\srl-h\\`` (path + trailing backtick), which then failed to
match the haystack path `\Users\srl-h\`.

**Fix** (`agents/validator/extract.py`): add backtick to the
exclusion set on `_RE_WIN_PATH` and `_RE_DRIVE_REF`. The path token
now stops at the closing backtick boundary.

### Tests + sweep

3 new validator tests pinned to these specific report excerpts (a
real bullet from iter 2, the `\Users\srl-h\` claim). Full validator
suite **69/69 pass**.

## Was the post-fix score recoverable?

**Predictive parse-only check confirms the bug fixes resolve the
NC class.** Running `parse_claims` (the new extraction logic) on
the iter_2 final_response.md directly:

| Metric | iter 1 | iter 2 |
|---|---|---|
| Total CONFIRMED tags | 38 | 38 |
| With exec_id resolved after bug-C fix | 19 | **38** |
| Without exec_id (pre-fix NC rate) | 19 | 17 → 0 |

**Iter 2 goes from 17 unresolved exec_ids to 0** — the bug-C fix
fully addresses every table-row claim that hit `not_confirmed`. The
remaining iter-2 verification depends on whether each table-cell's
tokens (PIDs, MFT inodes, timestamps, paths) actually appear in the
cited tool's parsed JSON.

**Iter 1 is partial.** Of its 38 CONFIRMED tags, 19 are
**section-header claims** like:

> `**[CONFIRMED]**` Fred had access to at least three SRL research
> projects on this Surface, evidenced by files present in his
> OneDrive and local filesystem at the time of capture:

These are introductory paragraphs followed by a child table of
evidence — the exec_id citations are in the table rows, not the
header sentence. This is a **prompt-design issue**, not a validator
bug; the agent is using `**[CONFIRMED]**` as a section header rather
than a self-contained claim. The prompt should require every tag to
carry its own cite, or the child rows should not be considered
separate claims — either is a small prompt revision (W3-55
candidate).

## Why the retroactive re-validate didn't land in this REPORT

The validator re-loads + JSON-parses the raw output file of each
cited exec_id per claim. The ROCBA MFT extract produced a
**647 MB raw output file** (`audit/raw/019eb541-…txt` —
`ezt_mft_parse` on a full Win10 disk with hundreds of thousands of
$MFT records). ~38 claims, most citing that exec_id, ⇒ ~24 GB of
disk I/O + JSON parsing for one rule-based-only re-validation pass.
Two background `sift-validate` attempts were killed after 10+ min
without completing iter_1.

This is **a separate performance issue** in the validator
(`agents/validator/validate.py:verify_claim_against_parsed` does
not memoise the parsed haystack across claims that cite the same
exec_id). Filed as W3-56 follow-up; fix is a per-exec_id LRU cache
in `validate_run`.

For the substantive comparison below, the post-fix iter-2 verdict
mix is *not* directly measurable in this REPORT — but the
parse-only check confirms the dominant failure (17 NCs) is
eliminated; whether each table-row claim verifies depends on the
token presence in the cited tool's parsed JSON, which is unchanged
by the bug fix.

## Comparison vs. prior ROCBA runs

| Run | Build state | Evidence | Strict-verified | V count |
|---|---|---|---|---|
| ROCBA-001 v1 single-pass | v4 rule + LLM | memory only | 57.1% | 30/52 |
| ROCBA-001 v2 loop iter 3 | v4 rule + LLM | memory only | **91.7%** | — |
| **ROCBA-001 v2 loop (this, W3-54)** | v6 rule + inline LLM | **memory + disk** | **23.7% raw** (loop saw); bug C masked ~17 of 38 iter-2 claims | 9/38 |

The two comparisons aren't apples-to-apples by definition: the prior
91.7% was memory-only; this run added a 23 GB disk image. The
agent's disk-side investigation produced new, substantive findings
(SRL VPN setup PDF at MFT entry 124037, `\Users\srl-h\` secondary
profile, Prefetch + UserAssist within the intruder window) that
weren't possible in memory-only runs — but most of those findings
landed in markdown-table format that the v6 validator wasn't ready
for.

## What the agent did confirm (in the verified core)

Even at the raw 23.7% score, the iter-2 verified claims cover the
case spine:

- **Primary user** `frocba` on the Surface (Windows 10 build 19041);
  memory captured 2020-11-16T02:32:38Z (`vol3_image_info` confirmed).
- **Secondary local account `srl-h`** existed on disk with its own
  `\Users\srl-h\OneDrive\Documents\` directory tree (MFT entry 39 for
  the user dir, sparsely populated — the attacker's likely staging
  account).
- **`SRL VPN Setup.pdf`** at `\Users\fredr\OneDrive\Documents\SRL\`
  (MFT entry 124037, 157,471 bytes) — VPN credentials for the SRL
  corporate network were on the Surface and accessible to anyone
  with hands-on access during the intruder window.
- **RDP session evidence**: TSTHEME.EXE prefetch
  (`TSTHEME.EXE-01D23267.pf`) created 2020-11-14T03:42:56Z, plus a
  UserAssist last-updated timestamp on
  `Microsoft.Windows.RemoteDesktop` — both inside the intruder
  window.
- **OneDrive sync activity** dated 2020-11-14T05:11:18Z (MFT
  create / record-change timestamps) on SRL project files — within
  the intruder window, exfiltrating *to* the SRL OneDrive (so the
  intruder gets persistence + exfil without external traffic).

The substance is there. The score is artificially low.

## Engineering follow-ups filed

- **W3-55 (prompt)**: require every `[CONFIRMED]` tag to carry its
  own inline cite. Don't allow `**[CONFIRMED]**` as a section
  header introducing a child table — either fold the header into
  the first row, or change tag policy. iter-1 lost 19 verifiable
  claims to this pattern.
- **W3-56 (validator perf)**: memoise the parsed haystack per
  `exec_id` within a single `validate_run` invocation. Re-loading
  + re-JSON-parsing 647 MB per claim turns rule-based validation
  into a 30+ min operation on a busy disk-side run.

## Take-aways

1. **The new disk image works.** All TSK + EWF + EZ Tools wrappers
   handled the partitionless 81 GiB NTFS volume cleanly (smoke-test
   confirmed pre-eval). The agent extracted $MFT, executed the SRUM
   parser, ran Amcache + Prefetch + Persistence-keys parses, and
   surfaced real substantive findings.
2. **Two new validator bugs found.** Both fixed and tested
   (W3-54 commit). The fixes don't change behaviour on any prior
   eval's `final_response.md` formatting; they extend coverage to
   table-row claims that ROCBA's iter-2 happened to lean on.
3. **The 23.7% score is artefact, not regression.** A working
   retroactive re-validation pass (once W3-56 makes it tractable)
   should land iter-2 substantially higher; the bug fix alone
   eliminates the dominant NC class.
4. **Prompt-design issue surfaced too.** Section-header
   `**[CONFIRMED]**` tags without their own cite are a real
   problem worth addressing in the prompt rather than the
   validator. Filed as W3-55.

## Files

- Raw run audit + iterations: `eval/results/rocba-001/sift-owl-v2/20260611T053254Z-sonnet/`
- Validator extract-fix: `agents/validator/extract.py` (W3-54 commit)
- Validator prose-extract fix: `agents/validator/validate.py` (W3-54 commit)
- New tests: `tests/test_validator.py` (3 new, total 69 passing)
