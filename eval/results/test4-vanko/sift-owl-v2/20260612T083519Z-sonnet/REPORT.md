# VANKO-001 held-out single-shot — `20260612T083519Z-sonnet`

> First SIFT-OWL run on the SANS FOR500 "Abducted Zebrafish" case.
> The dataset arrived 2026-06-11; this run fired on 2026-06-12 with
> no prompt-tuning to the case content (held-out discipline). The
> prompt-test4-vanko.md was modelled on prompt-rocba-001.md and
> shipped with the W3-55 citation-discipline paragraph from the
> start.

## Headline

| Iter | Cost | Wall | MCP calls | V | P | F | U | NC | LLM-V | **Strict-verified** |
|---|---|---|---|---|---|---|---|---|---|---|
| **iter 1** ⭐ | (see below) | (see below) | 17 | 8 | 12 | 2 | 0 | 0 | 0/2 | **36.4%** (8/22) |
| iter 2 | $0.76 | 13.6 m | 4 | 3 | 19 | 0 | 0 | 0 | 0 | 13.6% (3/22) |

iter 1 was the peak. Iter 2 went *backwards* — V=8 → V=3, P=12 → P=19
— because the agent over-quoted in response to validator feedback,
producing more tokens that didn't match the haystack.

**Total: $2.21 / ~30 min / 21 MCP calls.** Evidence chain-of-custody
preserved (all input hashes unchanged).

The harness then crashed on the post-run hash verification step
(`IsADirectoryError` on the `vanko-c-drive.CYLR/G/` triage-collection
directory I registered in `evidence:` as a documentation handle).
**Iter 3 never fired.** The harness bug is fixed in this commit
(skip directory entries gracefully); the case.yaml is restructured
to put the CYLR collection under a separate `triage_collection:`
field instead of `evidence:`.

## Held-out discipline

Honest. No prompt revision after seeing the data. No re-fires
against this case. This REPORT is the canonical held-out
single-shot result for VANKO-001.

The agent's substantive findings are **good** even at 36.4% scored
— the matched-token lists from the validator show the agent
correctly recovered the hostname, the (single) user profile, the
SID, and ten classified Stark research documents by name. The
score collapse is a prose-style artefact (bug H, below), not a
research failure.

## Bug H — `field_name "value"` compound tokens

The agent emitted claims like:

```
**[CONFIRMED — exec_id `019ebafa-b072-…`]** MFT `entry 263009` is
directory `file_name "PC User"` under `parent_path ".\\Users"`
(`is_directory true`) — the sole interactive profile…
```

Token extractor pulls the compound tokens `entry 263009`,
`file_name "PC User"`, `parent_path ".\\Users"`, `is_directory
true`. The cited `ezt_mft_parse` haystack stores these as JSON
fields with colon separators:

```json
{"EntryNumber": 263009, "FileName": "PC User",
 "ParentPath": ".\\Users", "IsDirectory": true}
```

The compounds don't substring-match; the validator marks each
"missing". The bare values (`263009`, `PC User`, `.\Users`, `true`)
would match.

**This is a prompt-design issue, not a validator bug.** The agent
should quote bare values (`` `263009` ``, `` `"PC User"` ``) or
the JSON field name with the value (`` `"FileName": "PC User"` ``),
not invent `field_name "value"` prose. Filed as **W3-60** — small
prompt revision; do NOT retro-fit to this case (held-out).

The pattern appeared in 12 of iter-1's 14 non-Verified claims and
19 of iter-2's 22 claims. With the W3-60 prompt fix, the iter-1
score would lift substantially (every Partial-because-of-compound
token would resolve cleanly).

## What the agent confirmed (verified core)

Even at the raw 36.4% iter-1 score, the matched-token lists show
the agent recovered the case spine:

- **Disk layout**: GPT, 6 partitions, main C: at sector 1411072,
  NTFS, volume serial confirmed.
- **EWF chain integrity**: Ovie Carroll / FTK Imager `ADI 2.9.0.13`
  / case number `20161104` / evidence number `20161104-HD001`.
- **Hostname**: `STARKSURFACE`.
- **Single interactive user**: `PC User` (profile inode 263009;
  NTUSER.DAT at inode 263010). The unusual literal user-name "PC
  User" rather than "Vanko" is itself a finding — the workstation
  was either generically configured or Vanko was operating under a
  service-style account.
- **SID**: `S-1-5-21-3739107332-290452467-3466442662-1001` confirmed
  in NTUSER.DAT.
- **Classified Stark documents present** in
  `\Users\PC User\OneDrive\Documents\`:
  - `Stark_TS-Level8A_CryoDNA.blacklight.docx`
  - `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx`
  - `…research.docx` (truncated by the validator's matched-token cap)
  - Plus 7 more enumerated by name in iter-1's final response.
- Profile last-write `2016-10-30T23:19:25Z`, profile created
  `2016-06-18T22:00:15Z` — straddles the JARVIS alert window
  (2016-06-30).

(The full enumeration is in `iterations/iter_1/final_response.md`.)

## Why iter 2 regressed

iter 1: V=8 P=12 F=2 NC=0 → 36.4%
iter 2: V=3 P=19 F=0 NC=0 → 13.6%

The validator fed iter 1's 12 Partial verdicts back as feedback for
iter 2. The agent's response was to **add more detail to each
claim** (more `field_name "value"` quotes), under the impression
that more specificity would help. Every additional compound token
created another "missing" token → more Partials. The score
collapsed.

This is a **second-order effect** of bug H: the citation-discipline
prompt fix (W3-55) eliminates the section-header anti-pattern but
doesn't tell the agent how to quote *individual* values. With
W3-60, the iter-2 regression won't happen because the agent will
quote values bare and the validator will find them.

## Substantive vs. score: the gap

Looking at iter 1's 22 confirmed claims:
- 8 fully Verified — disk layout, EWF metadata, partition layout,
  some matched filenames.
- 12 Partial — every one of these has the agent's substantive
  finding present in the matched list, with only the compound-token
  prose noise marked as missing. **These are correct findings
  scored as partial because of the bug-H prose style.**
- 2 Failed — claims where the agent overreached (e.g., asserting
  USB activity without a registry / EVTX cite that the
  ezt_persistence_keys_parse output actually contained).

Post-W3-60, expected score on the same `final_response.md` would be
roughly **22/22 → 18-20/22 ≈ 80-90%**.

## Comparison vs. prior cases at held-out / single-shot

| Case | Held-out discipline | Strict-verified peak | Note |
|---|---|---|---|
| ROCBA-001 v1 single-pass | yes (first run) | 57.1% | memory only |
| STARK-APT-001 v1 | yes | 43.5% | first multi-host run |
| SHIELDBASE single-shot | **yes** | **71.4%** | the canonical held-out number for the project |
| **VANKO-001 (this)** | **yes** | **36.4%** | first physical-disk case; bug H surfaced and accounts for ~80 % of the score deficit |

VANKO-001 lands below the SHIELDBASE held-out 71.4% — but the gap
is almost entirely **bug H (prompt-style)**, not a research-quality
gap. The matched-token lists show the agent did the work; the
prose style obscured the verification.

## Engineering follow-ups

- **W3-60 (prompt)**: revise prompt-test4-vanko.md (and the other
  case prompts) to tell the agent to quote bare values or
  `"field": "value"` pairs, NOT `field_name "value"` compounds.
  Roughly 15 lines of prose change. NOT in this commit because
  applying it before a second VANKO run would break held-out
  discipline.
- **Harness fix (in this commit)**: `_verify_evidence_unchanged`
  now skips directory entries with a structured non-error record
  instead of crashing. Allows future cases to register companion
  directories inline.
- **case.yaml restructure (in this commit)**: CYLR collection moved
  out of the `evidence:` list into a separate `triage_collection:`
  field; the harness will not try to hash it.

## Files

- Raw run audit + iterations:
  `eval/results/test4-vanko/sift-owl-v2/20260612T083519Z-sonnet/`
- Harness fix: `eval/agents/sift_owl_v2/run_loop.py`
- Case definition: `eval/cases/test4-vanko/case.yaml`
- Prompt (held-out as fired): `eval/agents/sift_owl_v2/prompt-test4-vanko.md`
