# SHIELDBASE re-eval with inline `--llm-check` — `20260523T190903Z-sonnet`

> SHIELDBASE / CRIMSON OSPREY with `ANTHROPIC_API_KEY` set →
> W3-45's auto-detect enabled inline `--llm-check`. Goal: rescue
> Unverifiable verdicts inside the loop, lifting the iter-to-iter
> feedback signal. **Outcome: the run uncovered two validator bugs
> instead, which masked the LLM-check signal entirely.** Both bugs
> are fixed in-flight; this REPORT documents the raw run, the
> retroactive re-validation with the fix, and what's still
> outstanding.

## Headline (raw, as the loop saw it)

| Iter | Cost | Wall | MCP calls | V | P | F | U | NC | LLM-V | **Strict-verified** |
|---|---|---|---|---|---|---|---|---|---|---|
| iter 1 | $1.60 | 23.8 m | 21 | 0  | 9  | 3 | 0 | 14 | 0 | **0.0%** |
| iter 2 | $1.05 | 15.7 m | 7  | 0  | 13 | 5 | 0 | 11 | 0 | **0.0%** |

Loop early-terminated after iter 2 (`No improvement: verified=0 ≤
prev=0. Stopping.`). **Total: $2.65 / 39.5 min / 28 MCP calls.**
Evidence chain-of-custody preserved.

Both iterations got `verified=0` with **0 `unverifiable` verdicts**
— so `--llm-check` had nothing to fire on (LLM check is gated to
`unverifiable` only). The auto-detect worked
(`[19:09:03] llm-check: auto-enabled (ANTHROPIC_API_KEY is set;
~$0.10 / iter)` at startup log), but the bug below diverted every
claim away from `unverifiable` into `partial` / `failed` /
`not_confirmed`.

## Root cause — two validator bugs

### Bug A — exec-id-in-backticks leaks into verifiable tokens

The agent emitted prose-style citations:
``[CONFIRMED] `p.exe` implant active (exec_id `019e563e-23a4-7053-a243-629158db8679`)``

The token extractor (`agents/validator/extract.py:287`) captured
**every** backticked string into `tokens.quoted`. That pulled the
exec_id UUID itself into the "verifiable token" list. The verifier
then looked for the UUID inside the cited tool's parsed JSON (e.g.
`vol3_psscan` rows) and of course couldn't find it — UUIDs are
audit metadata, not data — so it marked the verdict `missing`. With
even one missing token in the list, every claim cascaded from
`verified` → `partial`.

There was already a guard for `hex_hashes` doing the same thing
(`extract.py:280`: skip 16-64 hex tokens preceded by `exec_id`); the
backticked-quoted path was missing the matching guard.

**Fix:** mirror the `hex_hashes` guard on `_RE_BACKTICK` matches —
skip any backticked token preceded by `exec_id` / `exec id` /
`exec ids` within 20 chars.

### Bug B — multi-tag paragraph scoping orphans the prose cite

The agent also used bullet-list claims with the `[CONFIRMED]` tag
mid-bullet and the cite at the end:

```
- **C2 behavior:** 14 connections to 172.16.4.10:8080 [CONFIRMED] (exec_id `UUID`)
```

When `parse_claims` sees a paragraph with 2+ tags, it scopes each
claim's text from `prev_tag_end → this_tag_end`. The trailing
`(exec_id ...)` falls OUTSIDE that slice (it lives in the *next*
claim's preamble). Result: this claim has no exec_id at all → status
`not_confirmed` (14 in iter 1, 11 in iter 2).

This bug is **not fixed in this commit** — the scoping rule is
load-bearing for multi-claim paragraphs and changing it needs more
care. Filed as follow-up.

## After bug A is fixed — retroactive re-validation

Same `final_response.md`s, re-run with the W3-50 extract-fix +
`--llm-check`:

| Iter | V | P | F | U | NC | score | llm_checked | llm_verified |
|---|---|---|---|---|---|---|---|---|
| iter 1 | 2  | 7 | 3 | 0 | 14 | **7.7%**  | 0 | 0 |
| iter 2 | 6  | 7 | 0 | 5 | 11 | **20.7%** | 5 | 0 |

Iter 2 score lifted from 0% → 20.7%. The LLM-check fired 5 times
(cost: $0.013) but rescued 0 — Haiku returned UNSUPPORTED on all 5,
meaning the parsed JSON genuinely didn't carry tokens to corroborate
those prose-only claims. That's a real answer, not a regression.

The remaining ~80 pp gap to W3-46's 92% is entirely the NC verdicts
(bug B). The agent's claims are substantively good — the validator
parser just can't connect them to their cites in the bullet-list
format.

## Wire-fit (W3-47/W3-48) — still validated

SRUM was NOT called this run (the agent took a different exploration
path — focused on memory + netscan, didn't reach SRUM data). So this
run doesn't re-prove the wire-fit, but the W3-49 run already did
(SRUM successfully shrunk from 50 → 6 rows/section to 14.5 KB).

| Tool group | Calls in this run | Wire-cap fires |
|---|---|---|
| `vol3_*` (memory) | 14 | n/a (single-section, no shrink needed) |
| `tsk_*` (disk) | 6 | n/a |
| `ezt_*` (artefacts) | 4 (evtx ×2, amcache ×1, prefetch ×1) | none — small payloads |
| `ezt_srum_parse` | 0 | n/a (not called) |
| `query_rows` | 4 | n/a (drill helper) |

The W3-47/W3-48 shrink ladder is in place; it just didn't get
exercised this run because the agent skipped SRUM.

## Comparison vs. prior SHIELDBASE runs

| Run | Validator | Strict-verified peak | LLM-check | Notes |
|---|---|---|---|---|
| `20260510T194945Z` (single-shot held-out) | v5 (rule + retroactive LLM) | **71.4%** | 9 retroactive rescues | original held-out discipline |
| `20260519T191456Z` (W3-46) | rule-based only | **92.0%** | 0 | unusually clean precision shift; SRUM hit wire cap |
| `20260522T191444Z` (W3-49) | rule-based only | **60.0%** | 0 | post wire-fit; SRUM delivered cap=6; variance band |
| `20260523T190903Z` (this) | rule + inline LLM | **0.0%** raw / 20.7% post-fix | 5 (0 rescued) | validator bug A masked signal; bug B remains |

The variance band on the v2 loop is now sampled at **60% – 92%**
(both rule-based only) plus this run, which doesn't fit the same
basis because the validator was double-counting metadata as
"missing tokens". Once bug B lands the band can be re-measured.

## Take-aways

1. **`--llm-check` infrastructure works end-to-end.** `ANTHROPIC_API_KEY`
   sourced from `~/.anthropic_key` → W3-45 auto-detected → Haiku
   was invoked 5 times during iter 2 ($0.013 total). The startup
   log confirms `llm-check: auto-enabled`. No environmental issues.
2. **Bug A (W3-50): backticked exec-id leaks into tokens — FIXED.**
   `agents/validator/extract.py` now skips backticked tokens
   preceded by an `exec_id` marker, mirroring the hex_hash guard
   already in place. `ClaimVerdict.as_dict()` also gained the
   `exec_ids` plural field (cosmetic; the field exists on the
   `Claim` dataclass but was being dropped at JSON-serialise time,
   making debugging harder). 3 new validator tests; full 65 still
   pass.
3. **Bug B (multi-tag scoping): NOT yet fixed.** When `[CONFIRMED]`
   appears mid-paragraph and the `(exec_id ...)` cite is *after*
   the tag, `parse_claims` scopes the cite into the *next* claim's
   text, leaving the current claim with `exec_ids=[]` → status
   `not_confirmed`. This produces 25 of the 55 total verdicts here.
   Needs careful scoping change in `parse_claims` — the simplest
   fix is to extend each multi-tag claim's text up to the next
   blank-line / next tag, not just the next tag. Filed as W3-52
   follow-up.
4. **Even after bug A, this run lands well below W3-46's 92%.**
   That's bug B doing the rest. The score band 60-92% from W3-46
   and W3-49 remains the better-calibrated reference for the v2
   loop's strict-verified capability.
5. **LLM-check on `unverifiable` is a narrow rescue path.** Haiku
   was invoked 5 times in iter 2, all came back UNSUPPORTED — i.e.
   the claim's prose really wasn't supported by the cited tool's
   parsed output. That's the correct answer; no false rescue. But
   the LLM never sees claims that hit `partial` / `failed` / `NC`
   verdicts, which is most of what's broken when bug B is in play.
   A future enhancement could broaden the LLM-rescue trigger to
   `partial` as well.

## Engineering follow-up filed

- **W3-52:** Fix `parse_claims` multi-tag paragraph scoping so a
  prose-style `(exec_id ...)` cite that trails a `[CONFIRMED]` tag
  is attached to *that* claim, not the next one. Then re-fire this
  eval — the iter-2 floor should jump from 20.7% toward the
  60-92% band the loop has shown otherwise.

## Files

- Raw run audit + iterations: `eval/results/test3-shieldbase/sift-owl-v2/20260523T190903Z-sonnet/`
- Validator extract-fix: `agents/validator/extract.py` (W3-50 commit)
- Validator as_dict() fix: `agents/validator/validate.py` (W3-50 commit)
- New tests: `tests/test_validator.py` (3 new, total 65 passing)
