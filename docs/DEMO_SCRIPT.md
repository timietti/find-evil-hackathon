# SIFT-OWL — Demo Video (5 min max)

Devpost requirement: *Screencast of live terminal execution with audio
narration. Show the agent working against real case data, including at
least one self-correction sequence.*

Recipe is one live OBS take of the agent running on **VANKO-001** (the
held-out FOR500 case). VANKO converges in two iterations
(iter 1 = 65.8 %, iter 2 = 100.0 % / 37 verified) — so a single live
run captures both the working-against-real-case requirement *and* a
clean self-correction sequence inside the time budget. $1.75 / ~26 min
wall.

VO is recorded separately in Audacity and layered over the OBS take
during edit.

---

## What's on screen, scene by scene

| Time | Source on screen | What viewer sees |
|---|---|---|
| 0:00 – 0:15 | terminal | the `run_loop` invocation + first stdout lines |
| 0:15 – 1:30 | terminal, speed-ramp ~10× | iter 1 progress — MCP-call counter, validator running |
| 1:30 – 2:15 | `iter_1/validator_report.md` | header (65.8 %, 25 V / 7 P / 0 F), one **partial** verdict spelled out |
| 2:15 – 2:45 | `iter_2/prompt.md` scroll | "Iteration 1 validator flagged these claims …" section |
| 2:45 – 4:00 | terminal, speed-ramp ~6× | iter 2 progress (the **self-correction**) |
| 4:00 – 4:35 | `iter_2/validator_report.md` | header (100.0 %, 37/37, `Convergence: 0 demoted claims. Stopping.`) |
| 4:35 – 5:00 | `final_response.md` scroll | top of the report + close |

Every cut is a real artifact from the live capture — nothing is staged.

---

## Pre-record checklist

1. Anthropic key on disk: `~/.anthropic_key` (already there).
2. VANKO evidence at `/cases/find-evil-test4/` (already there).
3. OBS profile: 1920×1080 @ 30 fps, H.264 MP4, CRF 18.
4. Terminal: GNOME Terminal full-screen, font ≥ 16 pt, dark theme.
5. Mic level test in Audacity — peaks at ≈ −12 dB.
6. Free disk for raw capture: ~3 GB for 26 min at CRF 18.

---

## Step 1 — Live capture (one OBS take, ≈ 26 min)

```bash
# In OBS: load the "SIFT-OWL Demo" profile, set Display Capture to the
# monitor with the terminal, hit F9 to start.

bash scripts/demo_run.sh
```

`scripts/demo_run.sh` (committed) runs the v2 loop on VANKO with the
canonical settings. When you see `BASELINE RUN COMPLETE` followed by
the validator summary, F9 again to stop OBS.

Output: `~/Videos/sift-owl-demo-raw.mp4` (≈ 25-26 min).

## Step 2 — Cutaway captures (≈ 5 min total)

Three short OBS clips of the file viewers. F9 / F9 per clip, ~30 s each:

```bash
bash scripts/demo_open_artifacts.sh
```

Opens each markdown file in `bat --paging=always` in the order the edit
needs them:

1. `iter_1/validator_report.md`        (scene 3)
2. `iter_2/prompt.md`                  (scene 4 — scroll to "flagged" section)
3. `iter_2/validator_report.md`        (scene 6)
4. `final_response.md`                 (scene 7)

For each: F9, scroll to the section, F9.

## Step 3 — VO take (Audacity, ≈ 10 min)

Open Audacity, mono 48 kHz/24-bit, record the script in one pass. Save
as `~/Audio/sift-owl-vo.wav`. The full VO script is at the bottom of
this file — ~720 words at 2.4 wps fits 5 minutes with room to breathe.

## Step 4 — Edit (kdenlive or DaVinci Resolve, ≈ 45 min)

Three tracks:

| Track | Content |
|---|---|
| V1 | `sift-owl-demo-raw.mp4` (speed-ramp per the scene table above) + 4 cutaway clips inserted at the right cut points |
| A1 | `sift-owl-vo.wav` aligned to scene boundaries |
| A2 *(optional)* | royalty-free ambient bed at −22 LUFS |

Speed-ramp targets (so iter-1 grind doesn't eat the budget):

```
00:00 - 00:15   raw  1×   (intro + invocation)
00:15 - 01:30   raw 10×   (iter 1 progress)
01:30 - 02:15   cut: iter_1/validator_report.md
02:15 - 02:45   cut: iter_2/prompt.md
02:45 - 04:00   raw  6×   (iter 2 progress)
04:00 - 04:35   cut: iter_2/validator_report.md
04:35 - 05:00   cut: final_response.md
```

Burn-in subtitles from the VO track (Resolve: `Edit → Subtitles → from
audio`; kdenlive: install `subtitlecomposer`).

## Step 5 — Export + verify

```bash
# kdenlive: Project → Render → MP4
#   1920×1080, 30 fps, H.264, target 5 Mbps, AAC 192 kbps
#   → ~90 MB at 5 min duration (under Devpost's 100 MB cap)

ffprobe -i ~/Videos/sift-owl-demo-final.mp4 2>&1 | grep -E "Duration|bitrate"
# Confirm Duration: 00:04:5x.xx (must be ≤ 5:00)

# Loudness check
ffmpeg -i ~/Videos/sift-owl-demo-final.mp4 -af loudnorm=print_format=json -f null -
# Target: integrated_loudness ≈ -16 LUFS
```

## Step 6 — Upload

```bash
# Primary: Devpost direct upload (100 MB limit)
# Backup: YouTube unlisted

# Both URLs go on the submission form.
```

---

## VO script (one continuous take, ~720 words)

> ### 0:00 — Invocation (15 s)
>
> "This is SIFT-OWL — an autonomous DFIR agent running on a SANS SIFT
> Workstation. I'm pointing it at VANKO-001, a hundred-and-sixteen-gig
> physical disk from a SANS five-hundred case the agent has never
> been tuned to. Five-dollar budget, three iterations, Sonnet four-six."
>
> ### 0:15 — Iter 1 (75 s — over the timelapse)
>
> "The agent runs inside a Claude Code subprocess with no shell, no
> file system, and no network — its only callable surface is
> thirty-eight typed read-only forensic functions registered by the
> MCP server. You can see the iter-1 banner; underneath, the MCP-call
> counter is climbing. Every call gets one row in
> `audit/exec_log.jsonl` with an exec-ID, the arguments, the SHA-two-fifty-six
> of inputs and outputs, and a parsed summary. The agent decides
> which tools to fire from a high-level briefing — partition tables,
> MFT extraction, EVTX, prefetch, SRUM — and writes its final report
> at the end. Then the validator runs."
>
> ### 1:30 — Iter 1 validator report (45 s)
>
> "Iter one: sixty-five-point-eight percent strict-verified. Twenty-five
> claims passed, seven came back as partial — the validator extracted
> a token, looked it up in the cited tool's parsed JSON, and didn't
> find an exact match. Here's one of them — a quoted compound where
> the agent wrote `is_directory true` as a single token instead of
> the bare value `true`. The validator can't substring-match that
> against the JSON haystack."
>
> ### 2:15 — Iter 2 prompt (30 s)
>
> "This is what the loop hands the agent next. The harness prepends
> the iter-1 prompt with the flagged claims and the validator's notes
> on what exactly didn't match. The agent picks them up and decides
> whether to re-investigate, re-cite, or demote each one."
>
> ### 2:45 — Iter 2 (75 s — over the timelapse)
>
> "Iter two — the self-correction. The agent rephrases the flagged
> claims with bare-value tokens and adds the missing citations.
> Notice the call count is much lower this time: it doesn't redo
> the whole investigation, it surgically addresses the flagged
> claims. The validator re-runs."
>
> ### 4:00 — Iter 2 validator report (35 s)
>
> "Iter two: one hundred percent strict-verified. Thirty-seven of
> thirty-seven testable claims now pass. Validator prints
> 'Convergence: zero demoted claims — stopping.' The loop terminates
> at iter two; iter three doesn't fire. Total cost, a dollar
> seventy-five; total wall, twenty-six minutes; thirteen MCP calls
> across both iterations."
>
> ### 4:35 — Final report + close (25 s)
>
> "Final report. The agent reconstructed the full IP-theft spine:
> fourteen classified documents in OneDrive, all sharing the exact
> timestamp JARVIS detected the transfer; the mapped Stark-research
> drive at letter D since May; the syncing OneDrive hierarchy. Every
> claim is exec-ID-cited, every exec-ID is in the audit log, every
> finding is reproducible. Repo: github.com/timietti slash
> find-evil-hackathon. Open, MIT."

---

## Checklists

### Pre-record
- [ ] OBS profile loaded, mic input live, peak −12 dB
- [ ] Terminal full-screen, font ≥ 16 pt
- [ ] `~/.anthropic_key` readable; `/cases/find-evil-test4/` present
- [ ] `scripts/demo_run.sh` and `scripts/demo_open_artifacts.sh` present + executable
- [ ] `bat` and `ffmpeg` installed

### Post-edit
- [ ] Final duration ≤ 5:00 (target 4:55)
- [ ] Subtitles burned in
- [ ] Loudness ≈ −16 LUFS integrated
- [ ] File ≤ 100 MB
- [ ] YouTube unlisted backup uploaded
- [ ] Devpost form has both URLs
