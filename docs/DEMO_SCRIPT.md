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
   VANKO-001 (held-out FOR500 case). Converges in 2 iterations
   (iter 1 = 65.8 %, iter 2 = 100.0 % / 37 verified). $1.75 / ~26 min
   wall. The iter-1 → iter-2 transition is the self-correction
   sequence.

VO is recorded separately in Audacity and layered over the OBS takes.

---

## What's on screen, scene by scene

| Time | Source | What viewer sees |
|---|---|---|
| 0:00 – 0:10 | terminal | `claude < prompts/setup-new-case.md` — Claude takes over |
| 0:10 – 0:35 | terminal, speed-ramp ~10× | Claude walks the evidence dir + hashes every file |
| 0:35 – 0:55 | freshly-written `case.yaml` | the inventory Claude wrote — paths, SHA-256s, partition offsets |
| 0:55 – 1:10 | freshly-written `prompt-vanko-demo.md` | the investigator prompt Claude wrote |
| 1:10 – 1:25 | terminal | `bash scripts/demo_run.sh` — v2 loop starts |
| 1:25 – 2:15 | terminal, speed-ramp ~10× | iter 1 progress — MCP-call counter, validator running |
| 2:15 – 2:45 | `iter_1/validator_report.md` | header (65.8 %, 25 V / 7 P / 0 F), one **partial** verdict spelled out |
| 2:45 – 3:10 | `iter_2/prompt.md` | "Iteration 1 validator flagged these claims …" section |
| 3:10 – 4:00 | terminal, speed-ramp ~6× | iter 2 progress (the **self-correction**) |
| 4:00 – 4:30 | `iter_2/validator_report.md` | header (100.0 %, 37/37, `Convergence: 0 demoted claims. Stopping.`) |
| 4:30 – 5:00 | `final_response.md` | top of the report + close |

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
7. Free disk for raw captures: ~3 GB for ~30 min of CRF-18 video.

---

## Step 1 — Setup capture (one OBS take, ≈ 5–10 min wall)

```bash
# In OBS: load the "SIFT-OWL Demo" profile, hit F9 to start.

bash scripts/demo_setup.sh
```

`scripts/demo_setup.sh` (committed) launches Claude Code with
`prompts/setup-new-case.md` pre-loaded, then types one line:

> *"The evidence is at `/cases/find-evil-test4/`. Briefly: SANS
> FOR500 'Abducted Zebrafish' — single-host insider IP theft on a
> Microsoft Surface 3. Call the case `vanko-demo`."*

Claude then walks the evidence dir, sha-256s every file (~5 min for
the 116 GiB E01 chain), classifies each, reads the partition table,
and writes three files. When Claude prints the summary block ("Case
registered: vanko-demo …"), F9 to stop OBS.

Output: `~/Videos/sift-owl-demo-setup-raw.mp4` (~5–10 min).

## Step 2 — Investigator capture (one OBS take, ≈ 26 min)

```bash
# F9 to start OBS (fresh recording).

bash scripts/demo_run.sh vanko-demo
```

(`demo_run.sh` takes the case-id from step 1 as the first argument;
defaults to `test4-vanko` if omitted.) When the loop prints
`Convergence: 0 demoted claims. Stopping.` and exits, F9 to stop OBS.

Output: `~/Videos/sift-owl-demo-run-raw.mp4` (≈ 25–26 min).

## Step 3 — Cutaway captures (≈ 5 min total)

Five short OBS clips of the file viewers. F9 / F9 per clip, ~30 s each:

```bash
bash scripts/demo_open_artifacts.sh vanko-demo
```

Opens each markdown / YAML file in `bat --paging=always` in order:

1. `eval/cases/vanko-demo/case.yaml`      (scene 3)
2. `eval/agents/sift_owl_v2/prompt-vanko-demo.md` (scene 4)
3. `iter_1/validator_report.md`           (scene 7)
4. `iter_2/prompt.md`                     (scene 8)
5. `iter_2/validator_report.md`           (scene 10)
6. `final_response.md`                    (scene 11)

For each: F9, scroll to the section the table calls out, F9.

## Step 4 — VO take (Audacity, ≈ 10 min)

Open Audacity, mono 48 kHz/24-bit, record the VO script (bottom of
this file) in one pass. Save as `~/Audio/sift-owl-vo.wav`.

## Step 5 — Edit (kdenlive or DaVinci Resolve, ≈ 60 min)

Three tracks:

| Track | Content |
|---|---|
| V1 | setup raw + run raw + 6 cutaway clips, cut and speed-ramped per the scene table above |
| A1 | `sift-owl-vo.wav` aligned to scene boundaries |
| A2 *(optional)* | royalty-free ambient bed at −22 LUFS |

Speed-ramp targets:

```
00:00 - 00:10   setup raw  1×    (the claude invocation + first prompt)
00:10 - 00:35   setup raw 10×    (hashing + classification)
00:35 - 00:55   cut: case.yaml
00:55 - 01:10   cut: prompt-vanko-demo.md
01:10 - 01:25   run raw    1×    (loop start)
01:25 - 02:15   run raw   10×    (iter 1)
02:15 - 02:45   cut: iter_1/validator_report.md
02:45 - 03:10   cut: iter_2/prompt.md
03:10 - 04:00   run raw    6×    (iter 2 — self-correction)
04:00 - 04:30   cut: iter_2/validator_report.md
04:30 - 05:00   cut: final_response.md
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

## VO script (one continuous take, ~760 words)

> ### 0:00 — Setup invocation (10 s)
>
> "This is SIFT-OWL — an autonomous DFIR agent running on the SANS
> SIFT Workstation. Before the agent investigates anything, it needs
> a registered case. I'm handing Claude the bundled setup prompt and
> pointing it at a folder of evidence."
>
> ### 0:10 — Hashing + scaffolding (25 s, over the timelapse)
>
> "Claude walks the evidence directory, sha-two-fifty-six hashes
> every file — that's the chain of custody anchor; the harness will
> refuse to launch later if any of these hashes drifts — classifies
> each artifact, reads the GPT partition table off the disk image,
> and writes three files: a machine-readable case manifest, a
> human-readable briefing, and an investigator prompt cloned from
> the bundled template. I never wrote a line of YAML."
>
> ### 0:35 — case.yaml on screen (20 s)
>
> "The manifest Claude wrote. Single physical disk, twenty-one E01
> segments, one hundred sixteen gigabytes raw. SHA-256 anchor on the
> first segment. The GPT partition table is read off the disk: six
> partitions, the main C: drive is partition three starting at sector
> one-four-one-one-zero-seven-two. The agent's tools will pass that
> offset to The Sleuth Kit."
>
> ### 0:55 — prompt-vanko-demo.md on screen (15 s)
>
> "And the investigator prompt — case briefing, evidence inventory,
> goals one through four. The token-quoting style block at the
> bottom is verbatim from the template — it's a non-negotiable
> validator contract."
>
> ### 1:10 — Loop start (15 s)
>
> "Now the actual investigation. The v2 self-correction loop, three
> iterations max, five-dollar budget cap, Sonnet four-six. The agent
> runs inside a Claude Code subprocess with no shell, no file
> system, and no network — only thirty-eight typed read-only
> forensic functions are callable."
>
> ### 1:25 — Iter 1 (50 s — over the timelapse)
>
> "Iter one. Every MCP call gets one row in the audit log with an
> exec-ID, the arguments, the SHA-two-fifty-six of inputs and
> outputs, and a parsed summary. The agent decides which tools to
> fire — partition tables, MFT extraction, EVTX, prefetch, SRUM —
> then writes its final report. The validator parses every
> CONFIRMED claim into typed tokens and checks each one against
> the cited tool's parsed JSON."
>
> ### 2:15 — Iter 1 validator report (30 s)
>
> "Iter one: sixty-five-point-eight percent strict-verified.
> Twenty-five claims passed, seven came back as partial — the
> validator extracted a token, looked it up in the cited tool's
> parsed JSON, and didn't find an exact match. Here's one — a
> compound where the agent wrote `is_directory true` as a single
> token instead of the bare value `true`. Can't substring-match
> that against the JSON haystack."
>
> ### 2:45 — Iter 2 prompt (25 s)
>
> "What the loop hands the agent next. The harness prepends the
> iter-1 prompt with the flagged claims and the validator's notes
> on what exactly didn't match. The agent picks them up and decides
> whether to re-investigate, re-cite, or demote each one."
>
> ### 3:10 — Iter 2 (50 s — over the timelapse)
>
> "Iter two — the self-correction. The agent rephrases the flagged
> claims with bare-value tokens and adds the missing citations.
> Notice the call count is much lower this time: it doesn't redo
> the whole investigation, it surgically addresses what the
> validator flagged. The validator re-runs."
>
> ### 4:00 — Iter 2 validator report (30 s)
>
> "Iter two: one hundred percent strict-verified. Thirty-seven of
> thirty-seven claims now pass. Validator prints 'Convergence: zero
> demoted claims — stopping.' The loop terminates at iter two; iter
> three doesn't fire. Total cost, a dollar seventy-five; total
> wall, twenty-six minutes; thirteen MCP calls."
>
> ### 4:30 — Final report + close (30 s)
>
> "Final report. The agent reconstructed the full IP-theft spine:
> fourteen classified documents in OneDrive, all sharing the exact
> timestamp JARVIS detected the transfer; the mapped Stark-research
> drive at letter D since May; the syncing OneDrive hierarchy.
> Every claim is exec-ID-cited, every exec-ID is in the audit log,
> every finding reproducible from raw bytes. Repo:
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
