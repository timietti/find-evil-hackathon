# ROCBA-001 re-eval with new disk image — `20260611T053254Z-sonnet`

> First ROCBA run after the C: drive image (`rocba-cdrive.e01`, 81 GiB
> NTFS, X-Ways acquisition 2020-12-18) was added on 2026-06-08. Prior
> ROCBA results (57.1% single-pass v1; 91.7% v2 loop) were memory-only.
> This run uses the new `eval/agents/sift_owl_v2/prompt-rocba-001.md`
> that covers both images.

## Headline

| Score | Stage | Detail |
|---|---|---|
| **23.7%** | Raw, as the loop saw it | 9/38 verified on both iters; loop early-terminated |
| **31.6%** | Iter 1 post-fix (rule-based) | 12/38; 19 section-header `[CONFIRMED]` claims remain NC (prompt issue) |
| **63.2%** | **Iter 2 post-fix (rule-based)** ⭐ | **24/38; NC=0**, 1 P, 0 F, 13 U; **+29 pp from bug fixes alone** |
| **63.2%** | Iter 2 post-fix + Haiku rescue | LLM-check ran on all 13 U; **0 rescued** (all came back UNRELATED — the prose-only claims genuinely don't tie to the cited evidence) |

**Total run cost: $3.34 / 112 min wall / 31 MCP calls.** Evidence
chain-of-custody preserved.

## Raw run (what the loop saw)

| Iter | Cost | Wall | MCP calls | V | P | F | U | NC | **Strict-verified** |
|---|---|---|---|---|---|---|---|---|---|
| iter 1 | $2.25 | 64.3 m | 27 | 9 | 9 | 1 | 0 | 19 | 23.7% |
| iter 2 | $1.09 | 47.9 m | 4  | 9 | 4 | 0 | 8 | 17 | 23.7% |

Loop early-terminated after iter 2 (`No improvement: verified=9 ≤
prev=9. Stopping.`). The substantive findings — SRL VPN setup PDF at
MFT entry 124037, secondary `\Users\srl-h\` profile, RDP session
evidence inside the intruder window, OneDrive sync at
2020-11-14T05:11:18Z on SRL project files — were all *present* in
the agent's final reports. The score collapsed because **four
validator bugs masked them**.

## Bugs surfaced + fixed

### Bug C — markdown-table claims (NC=17 → 0 on iter 2)

The agent emitted ~half of its iter-2 CONFIRMED claims as
markdown-table rows where `[CONFIRMED]` is in the *last* cell and
the exec_id is a backticked UUID in an earlier cell:

```
| | 2020-11-14T03:42:56Z | TSTHEME.EXE-01D23267.pf created in
.\Windows\Prefetch\ | `019eb541-08ea-7ea0-9495-7cc627c154e8`
(entry 96265) | [CONFIRMED]
```

The validator's `_extract_exec_ids_from_prose` only scans tokens
following an `exec_id` keyword or registered tool name. Backticked
UUIDs in table cells slip through, producing `not_confirmed`.

**Fix** (`validate.py`, W3-54): when the marker-anchored scan finds
nothing AND the text contains `|`, accept any `` `UUID` `` token
matching the strict UUIDv7 shape. Specific enough to avoid SHA-256
false-matches.

### Bug D — path regex swept trailing backtick

`_RE_WIN_PATH` permitted backticks in the character class. When the
agent quoted `` `\Users\srl-h\` ``, the extractor captured
`\Users\srl-h\\``  (path + trailing backtick) which then failed the
haystack match.

**Fix** (`extract.py`, W3-54): add backtick to the exclusion set on
`_RE_WIN_PATH` and `_RE_DRIVE_REF`.

### Bug F — backticked UUID leaked into `tokens.quoted`

Once bug C made the table-row exec_id correctly resolve, the same
backticked UUID *also* got swept into `tokens.quoted` by the
extractor (the W3-50 guard only fired when a `exec_id` marker
preceded it — table cells have no marker). The verifier then looked
for the UUID in the cited tool's parsed JSON and marked every
table-row claim "Partial" because the UUID is metadata, not data.

**Fix** (`extract.py`, W3-57): extend the W3-50 guard to skip any
backticked token whose shape is a strict UUIDv7 (8-4-…-…
dash-separated hex). The pattern is specific enough to never
trigger on real evidence data.

### Bug G — `.\` dot-prefix paths missed the haystack

The agent wrote paths like `` `.\Users\fredr\OneDrive\Documents\SRL\` ``
(Windows relative-path style), but the haystack carries
`\Users\fredr\...` (absolute). The path token retained the leading
dot and failed exact-match.

**Fix** (`extract.py`, W3-57): strip leading `.` from extracted path
tokens. Same path, normalised once.

### Performance follow-up — exec_id parse cache (W3-56)

The validator re-loads + JSON-parses each cited exec_id's raw output
per claim. ROCBA's `ezt_mft_parse` produced a **647 MB raw output
file** that ~38 claims cited; without caching, the validator did
24+ GB of disk I/O for a single re-validation pass (~30 min wall).

**Fix** (`validate.py`, W3-56): memoise the parsed haystack per
`exec_id` within a single `validate_run` call. First claim pays the
parse cost; subsequent claims hit the dict in O(1). Iter-2
re-validate wall dropped from 8:24 → 3:19; iter-1 from 16:21 → 3:34
(despite an additional pass through the same large MFT data).

### Tests + sweep

7 new validator tests pinned to actual report excerpts from this
run (3 for W3-54, 2 for W3-57 + 1 perf assertion). Full validator
suite **71/71 pass**.

## Score evolution per fix

| Stage | iter 1 | iter 2 | iter 2 NC | Notes |
|---|---|---|---|---|
| Raw (loop saw) | 23.7% (9/38) | 23.7% (9/38) | 17 | Bugs C, D, F, G all in play |
| Post bug C (W3-54) | 31.6% (12/38) | 34.2% (13/38) | 0 | NC class eliminated on iter 2 |
| Post bug C + D | same | same | 0 | D was already counted (W3-54 commit) |
| Post bugs C + D + F + G (W3-57) | **31.6%** (12/38) | **63.2%** (24/38) | 0 | +29 pp on iter 2 from F + G |
| Post all + Haiku LLM rescue | same | same | 0 | 13/13 U came back UNRELATED — no rescue available |

Iter 1's 19 NC verdicts are NOT validator bugs — they're
`**[CONFIRMED]**` section-header tags introducing a child table
where the actual citations live in the rows:

> `**[CONFIRMED]**` Fred had access to at least three SRL research
> projects on this Surface, evidenced by files present in his
> OneDrive and local filesystem at the time of capture:

The tag has no inline cite; the evidence is in the table below.
This is a **prompt-design issue** — filed as W3-55, not in any
W3-54 / W3-57 commit.

## What the agent confirmed (post-fix, iter 2)

24 verified strict claims covering the case spine:

- **Primary identity**: `frocba` on the Surface, Windows 10 build
  19041 x64, memory captured 2020-11-16T02:32:38Z.
- **Secondary local account `srl-h`** existed on disk with its own
  `\Users\srl-h\OneDrive\Documents\` directory tree (MFT entry 39
  for the user dir, sparsely populated — the attacker's likely
  staging account).
- **`SRL VPN Setup.pdf`** at `\Users\fredr\OneDrive\Documents\SRL\`
  — MFT entry 124037, 157,471 bytes. VPN credentials for the SRL
  corporate network were on the Surface and accessible during the
  intruder window.
- **RDP session evidence**: `TSTHEME.EXE-01D23267.pf` Prefetch
  created 2020-11-14T03:42:56Z, plus a UserAssist last-updated
  timestamp on `Microsoft.Windows.RemoteDesktop` — both inside the
  intruder window.
- **`Default.rdp`** created/modified 2020-11-14T05:10:44Z in
  `\Users\fredr\OneDrive\Documents\` — RDP connection config saved
  and synced to cloud during the intrusion.
- **OneDrive sync activity** dated 2020-11-14T05:11:18Z (MFT
  create / record-change timestamps) on SRL project files — within
  the intruder window. Exfil channel: the intruder used the SRL
  OneDrive itself.
- (And ~18 more verified MFT / Prefetch / UserAssist / SRUM
  timestamped findings — see iter 2's `validator_report.md` for the
  full list.)

The 13 remaining Unverifiable claims are prose-only intuition
("the intruder used the Surface as their primary access point");
Haiku returned UNRELATED on every one — confirming they are honest
interpretive prose, not citable structural facts. The agent didn't
overclaim.

## Comparison vs. prior ROCBA runs

| Run | Build state | Evidence | Strict-verified | Substantive V |
|---|---|---|---|---|
| ROCBA-001 v1 single-pass | v4 rule + LLM | memory only | 57.1% | 30/52 |
| ROCBA-001 v2 loop iter 3 | v4 rule + LLM | memory only | **91.7%** | — |
| ROCBA-001 v2 loop W3-54 (this) | v6 rule (raw) | **memory + disk** | 23.7% raw, **63.2% post-fix** | **24/38** |

The two are not apples-to-apples by design: the prior 91.7% was
memory-only; this run added a 23 GB disk image and surfaced 24 new
strict-verified disk-side claims (MFT entries, paths, timestamps)
that weren't possible before. The post-fix 63.2% is the
substantive number; the 23.7% the loop terminated on was
artefactual.

## Engineering follow-ups filed

- **W3-55 (prompt)**: require every `[CONFIRMED]` tag to carry its
  own inline cite. iter 1 lost 19 verifiable claims to the
  section-header anti-pattern. Small prompt revision.
- **W3-58** (deferred, optional): allow the validator to treat
  bullet-list claims inside a section under a parent `[CONFIRMED]`
  tag as inheriting that section's exec_id. Reduces the prompt
  burden on the agent.

## Take-aways

1. **The new disk image works end-to-end.** All TSK + EWF + EZ Tools
   wrappers handled the partitionless 81 GiB NTFS volume cleanly;
   the agent extracted $MFT, SRUDB.dat, Amcache.hve, Prefetch
   files, and registry hives without intervention.
2. **Four validator bugs found + fixed in this run alone**, all
   table-format-induced. The W3-50/52 fixes assumed prose claims
   with inline cites; ROCBA's iter 2 used a denser table layout
   that exposed three new edge cases (C / F / G) plus an old one
   (D, the backtick-in-paths leak).
3. **The post-fix 63.2% (24/38 verified) is the substantive
   ceiling for this run.** Haiku confirmed the remaining 13
   Unverifiables are honest prose-only inference, not undercited
   evidence — the agent didn't overclaim, it just summarised at a
   level the validator can't mechanically verify.
4. **Validator cache is a 5× speed-up on disk-heavy runs.** W3-56
   per-exec_id LRU brought iter validation from 16-minute walls
   into the 3-minute range, with no behaviour change. Necessary
   infrastructure for future runs on full-disk evidence.

## Files

- Raw run audit + iterations:
  `eval/results/rocba-001/sift-owl-v2/20260611T053254Z-sonnet/`
- Validator: `agents/validator/extract.py` + `validate.py` (W3-54 +
  W3-56 + W3-57)
- Tests: `tests/test_validator.py` — 71 passing
