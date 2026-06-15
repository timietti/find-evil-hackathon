# SIFT-OWL — Demo Video (5 min max)

Devpost requirement: *Screencast of live terminal execution with audio
narration. Show the agent working against real case data, including at
least one self-correction sequence.*

The video covers two phases, both captured live, spliced in editing:

1. **Setup** — Claude scaffolds a fresh case from a directory of raw
   evidence. Judges write zero YAML / Markdown themselves; Claude
   hashes every file (chain of custody) and writes `case.yaml` +
   `case.md` + `prompt-*.md` from the bundled templates.
2. **Investigator** — the v2 self-correction loop runs against
   VANKO-001 (held-out FOR500 case). The actual demo run
   (`20260615T055412Z-sonnet`) ran the **full 3 iterations** and
   climbed **30.0 % → 52.4 % → 80.0 %** strict-verified, with demoted
   claims falling **14 → 10 → 4** and tool calls dropping
   **52 → 21 → 11**. **$2.71 / 33.8 min** wall. Both the iter-1 → iter-2
   and iter-2 → iter-3 transitions are self-correction sequences — we
   show both.

> **Why it stops at 80 %, not 100 %.** The loop hit the 3-iteration cap
> (`--max-iterations 3`); it did **not** print
> `Convergence: 0 demoted claims. Stopping.` — that line only fires on a
> zero-demotion iteration, which this run never reached. Of the 4 claims
> still demoted at iter 3, three are validator *tokenization* artifacts
> (prose trapped between backticks; a self-referential `[CONFIRMED]`
> token inside the agent's own "addressing demotions" note) and one is a
> genuine validator negation edge on the SRUM SID claim — **not**
> unsupported forensics. We say this on camera. An honest 80 % that
> shows real self-correction beats a staged 100 %.

VO is recorded separately in Audacity and layered over the OBS takes.

---

## What's on screen, scene by scene

| Time | Source | What viewer sees |
|---|---|---|
| 0:00 – 0:10 | terminal | `claude < prompts/setup-new-case.md` — Claude takes over |
| 0:10 – 0:32 | terminal, speed-ramp ~20× | Claude walks the evidence dir + hashes every file |
| 0:32 – 0:50 | freshly-written `case.yaml` | the inventory Claude wrote — paths, SHA-256s, GPT partition offset |
| 0:50 – 1:05 | freshly-written `prompt-vanko-demo.md` | the token-quoting validator contract Claude cloned in |
| 1:05 – 1:18 | terminal | `bash scripts/demo_run.sh vanko-demo` — v2 loop starts |
| 1:18 – 1:55 | terminal, speed-ramp ~22× | iter 1 progress — MCP-call counter, validator running |
| 1:55 – 2:20 | `iter_1/validator_report.md` | header (**30.0 %**, 6 V / 13 P / 1 nc), one **partial** verdict spelled out |
| 2:20 – 2:40 | `iter_2/prompt.md` | the prepended "Iteration 1 — flagged claims + validator notes" block |
| 2:40 – 3:10 | terminal, speed-ramp ~21× | iter 2 progress (**self-correction #1**) |
| 3:10 – 3:30 | `iter_2/validator_report.md` | header (**52.4 %**, 11 V / 8 P) — climbing, not converged |
| 3:30 – 3:55 | `iter_3/prompt.md` | iter-2 feedback — the single- vs double-backslash insight |
| 3:55 – 4:20 | terminal, speed-ramp ~23× | iter 3 progress (**self-correction #2**, only 11 tool calls) |
| 4:20 – 4:45 | `iter_3/validator_report.md` | header (**80.0 %**, 16 V / 2 P / 1 F / 1 nc) |
| 4:45 – 5:00 | `REPORT.md` | progression table + final report top + close |

Every artifact on screen comes from one of the two live takes — nothing is staged.

---

## Pre-record checklist

1. Anthropic key on disk: `~/.anthropic_key` (already there).
2. VANKO evidence at `/cases/find-evil-test4/` (already there).
3. Fresh case-id chosen — recommend `vanko-demo` (the existing
   `test4-vanko` files stay; setup writes a parallel set).
4. OBS profile: 1920×1080 @ 30 fps, H.264 MP4, CRF 18.
5. Terminal: GNOME Terminal full-screen, font ≥ 16 pt, dark theme.
6. Mic level test in Audacity — peaks at ≈ −12 dB.
7. Free disk for raw captures: ~4 GB for ~40 min of CRF-18 video.

---

## Step 1 — Setup capture (one OBS take, ≈ 5–10 min wall)

```bash
# In OBS: load the "SIFT-OWL Demo" profile, hit F9 to start.

bash scripts/demo_setup.sh
```

`scripts/demo_setup.sh` (committed) launches Claude Code with
`prompts/setup-new-case.md` pre-loaded, then types one line:

> *"The evidence is at `/cases/find-evil-test4/`. Briefly: a
> single-host insider IP theft on a Microsoft Surface 3. Call the case
> `vanko-demo`."*

Claude then walks the evidence dir, sha-256s every file, classifies
each, reads the GPT partition table off the disk image, and writes
three files. When Claude prints the summary block ("Case registered:
vanko-demo …"), F9 to stop OBS.

Output: `~/Videos/sift-owl-demo-setup-raw.mp4` (~5–10 min).

## Step 2 — Investigator capture (one OBS take, ≈ 34 min)

```bash
# F9 to start OBS (fresh recording).

bash scripts/demo_run.sh vanko-demo
```

(`demo_run.sh` takes the case-id from step 1 as the first argument;
defaults to `test4-vanko` if omitted. It runs `--model sonnet
--max-budget-usd 5.00 --max-iterations 3`.) The loop runs all three
iterations. **Stop cue:** when the terminal prints

```
iter 3 complete: verified=16/20 (demoted=4) cost=$0.626 wall=9.5m
SIFT-OWL v2 run complete. → eval/results/vanko-demo/sift-owl-v2/<run-id>
```

followed by the JSON summary block and the shell prompt returns, F9 to
stop OBS. (Do **not** wait for "Convergence … Stopping." — that line
does not fire on a capped run.)

Output: `~/Videos/sift-owl-demo-run-raw.mp4` (≈ 33–34 min).

## Step 3 — Cutaway captures (≈ 6 min total)

Eight short OBS clips of the file viewers. F9 / F9 per clip, ~30 s each:

```bash
bash scripts/demo_open_artifacts.sh vanko-demo
```

Opens each markdown / YAML file in `bat --paging=always` in order
(paths relative to the run dir
`eval/results/vanko-demo/sift-owl-v2/<run-id>/`):

1. `eval/cases/vanko-demo/case.yaml`            (scene 3)
2. `eval/agents/sift_owl_v2/prompt-vanko-demo.md` (scene 4)
3. `iterations/iter_1/validator_report.md`      (scene 7)
4. `iterations/iter_2/prompt.md`                (scene 8)
5. `iterations/iter_2/validator_report.md`      (scene 10)
6. `iterations/iter_3/prompt.md`                (scene 11)
7. `iterations/iter_3/validator_report.md`      (scene 13)
8. `REPORT.md`                                  (scene 14)

For each: F9, scroll to the section the table calls out, F9.

## Step 4 — VO take (Audacity, ≈ 10 min)

Open Audacity, mono 48 kHz/24-bit, record the VO script (bottom of
this file) in one pass. Save as `~/Audio/sift-owl-vo.wav`.

## Step 5 — Edit (kdenlive or DaVinci Resolve, ≈ 75 min)

Three tracks:

| Track | Content |
|---|---|
| V1 | setup raw + run raw + 8 cutaway clips, cut and speed-ramped per the scene table above |
| A1 | `sift-owl-vo.wav` aligned to scene boundaries |
| A2 *(optional)* | royalty-free ambient bed at −22 LUFS |

Speed-ramp targets:

```
00:00 - 00:10   setup raw  1×    (the claude invocation + first prompt)
00:10 - 00:32   setup raw 20×    (hashing + classification)
00:32 - 00:50   cut: case.yaml
00:50 - 01:05   cut: prompt-vanko-demo.md
01:05 - 01:18   run raw    1×    (loop start)
01:18 - 01:55   run raw   22×    (iter 1, 13.7 min wall)
01:55 - 02:20   cut: iter_1/validator_report.md
02:20 - 02:40   cut: iter_2/prompt.md
02:40 - 03:10   run raw   21×    (iter 2 — self-correction #1, 10.6 min)
03:10 - 03:30   cut: iter_2/validator_report.md
03:30 - 03:55   cut: iter_3/prompt.md
03:55 - 04:20   run raw   23×    (iter 3 — self-correction #2, 9.5 min)
04:20 - 04:45   cut: iter_3/validator_report.md
04:45 - 05:00   cut: REPORT.md
```

Burn-in subtitles from the VO track.

## Step 6 — Export + verify

```bash
# kdenlive: Project → Render → MP4
#   1920×1080, 30 fps, H.264, target 5 Mbps, AAC 192 kbps
#   → ~90 MB at 5 min duration (under Devpost's 100 MB cap)

ffprobe -i ~/Videos/sift-owl-demo-final.mp4 2>&1 | grep -E "Duration|bitrate"
# Confirm Duration: 00:04:5x.xx (must be ≤ 5:00)

ffmpeg -i ~/Videos/sift-owl-demo-final.mp4 -af loudnorm=print_format=json -f null -
# Target: integrated_loudness ≈ -16 LUFS
```

## Step 7 — Upload

```
# Primary: Devpost direct upload (100 MB limit)
# Backup:  YouTube unlisted
# Both URLs go on the submission form.
```

---

## VO script (one continuous take, ~830 words)

> ### 0:00 — Setup invocation (10 s)
>
> "This is SIFT-OWL — an autonomous DFIR agent running on the SANS
> SIFT Workstation. Before the agent investigates anything, it needs
> a registered case. I'm handing Claude the bundled setup prompt and
> pointing it at a folder of raw evidence."
>
> ### 0:10 — Hashing + scaffolding (22 s, over the timelapse)
>
> "Claude walks the evidence directory, sha-two-fifty-six hashes
> every file — that's the chain-of-custody anchor; the harness
> re-hashes at the end and aborts if any byte drifted — classifies
> each artifact, reads the GPT partition table off the disk image,
> and writes three files: a machine-readable case manifest, a
> human-readable briefing, and an investigator prompt cloned from
> the bundled template. I never wrote a line of YAML."
>
> ### 0:32 — case.yaml on screen (18 s)
>
> "The manifest Claude wrote. A single physical Surface 3 disk image —
> one hundred sixteen gigabytes raw across a twenty-one-segment E-oh-one
> chain — with the MD5, SHA-1, and SHA-256 anchors. Claude read the GPT
> table: six partitions, and the main C: drive is partition three
> starting at sector one-four-one-one-zero-seven-two. The agent's tools
> pass that offset straight to The Sleuth Kit."
>
> ### 0:50 — prompt-vanko-demo.md on screen (15 s)
>
> "And the investigator prompt. Note the token-quoting style block at
> the bottom — it's a non-negotiable validator contract: quote bare
> values, not field-name compounds, so the validator can substring-match
> each token against the cited tool's parsed JSON. That contract is
> exactly what the self-correction loop ends up enforcing."
>
> ### 1:05 — Loop start (13 s)
>
> "Now the investigation. The v2 self-correction loop — three
> iterations max, five-dollar budget cap, Sonnet four-six. The agent
> runs inside a Claude Code subprocess with no shell, no file system,
> and no network — only thirty-eight typed, read-only forensic
> functions are callable."
>
> ### 1:18 — Iter 1 (37 s — over the timelapse)
>
> "Iteration one. Every MCP call gets one row in the audit log with an
> exec-ID, the arguments, and the SHA-two-fifty-six of inputs and
> outputs. The agent fires fifty-two tools — partition stat, MFT,
> Prefetch, SRUM — then writes its report. The validator parses every
> CONFIRMED claim into typed tokens and checks each against the cited
> tool's parsed JSON."
>
> ### 1:55 — Iter 1 validator report (25 s)
>
> "Iteration one: thirty percent strict-verified. Six claims passed
> clean; thirteen came back partial — some tokens matched, some didn't.
> Here's the pattern that bites the whole report: the agent quoted the
> Skype path with double backslashes — `\\Users\\PC User\\...` — but the
> parsed MFT JSON stores `parent_path` with single backslashes. Exact
> token, wrong escaping, no match. The validator notes precisely which
> tokens it couldn't find."
>
> ### 2:20 — Iter 2 prompt (20 s)
>
> "What the loop hands the agent next. The harness prepends the
> iteration-one prompt with each flagged claim, the tokens that
> matched, and the tokens that didn't. The agent picks them up and
> decides, per claim, whether to re-investigate, re-cite, or demote."
>
> ### 2:40 — Iter 2 (30 s — over the timelapse)
>
> "Iteration two — the first self-correction. Notice the tool count
> drops to twenty-one: the agent isn't redoing the investigation, it's
> surgically re-querying the exec-IDs it already has to read back the
> exact stored strings. It re-cites, adds missing fields, and rewrites
> the flagged claims. The validator re-runs."
>
> ### 3:10 — Iter 2 validator report (20 s)
>
> "Iteration two: fifty-two percent — verified jumps from six to eleven,
> demoted claims fall from fourteen to ten. Climbing, not yet
> converged. The loop continues because verified count improved."
>
> ### 3:30 — Iter 3 prompt (25 s)
>
> "The second round of feedback. By now the root cause is clear in the
> agent's own working notes: MFT `parent_path` values are stored with
> single backslashes — the parsed value, not the display form. It also
> spots two of its own artifacts: a planning preamble and a footer line
> the validator mis-read as tagless CONFIRMED claims. It strips both."
>
> ### 3:55 — Iter 3 (25 s — over the timelapse)
>
> "Iteration three — the second self-correction, and the most
> surgical: eleven tool calls. The agent rewrites every path token to
> single-backslash form, multi-cites the volume serial from the
> filesystem stat output, and removes the mis-tokenized text."
>
> ### 4:20 — Iter 3 validator report (25 s)
>
> "Iteration three: eighty percent strict-verified — sixteen of twenty.
> Demoted claims down to four. And I want to be precise about those
> four, because this is an honest demo: three are validator
> *tokenization* edge cases — prose caught between backticks, and a
> `CONFIRMED` token sitting inside the agent's own note explaining a
> previous fix — and one is a genuine negation edge on the SRUM SID
> claim. None of the four is an unsupported forensic finding."
>
> ### 4:45 — Final report + close (15 s)
>
> "The loop stops at the three-iteration cap, thirty to fifty-two to
> eighty percent. Total cost, two dollars seventy-one; total wall,
> thirty-four minutes. The final report reconstructs the IP-theft
> spine — classified docs copied into OneDrive at one shared timestamp,
> a VeraCrypt container built the night before, the mapped Stark drive
> at D — every CONFIRMED claim exec-ID-cited, every exec-ID in the
> audit log, every finding reproducible from raw bytes. Repo:
> github.com/timietti slash find-evil-hackathon. Open, MIT."

---

## Checklists

### Pre-record
- [ ] OBS profile loaded, mic input live, peak −12 dB
- [ ] Terminal full-screen, font ≥ 16 pt
- [ ] `~/.anthropic_key` readable; `/cases/find-evil-test4/` present
- [ ] `scripts/demo_setup.sh`, `scripts/demo_run.sh`, `scripts/demo_open_artifacts.sh` present + executable
- [ ] `bat` and `ffmpeg` installed

### Post-edit
- [ ] Final duration ≤ 5:00 (target 4:55)
- [ ] Subtitles burned in
- [ ] Loudness ≈ −16 LUFS integrated
- [ ] File ≤ 100 MB
- [ ] YouTube unlisted backup uploaded
- [ ] Devpost form has both URLs
</content>
</invoke>
