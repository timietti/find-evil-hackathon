# SIFT-OWL — Demo Video Script (5:00)

> Storyboard for the Devpost-required 5-minute submission video.
> Voice-over (VO) is what the narrator says; the screen column describes
> exactly what's on screen at that moment.
>
> Tooling: 1920×1080 screen capture with `OBS Studio`, mic for VO,
> post-edit in `kdenlive` or `DaVinci Resolve`. Cursor highlights via
> `key-mon`. Audio cleanup in Audacity. Target file: ≤ 100 MB H.264 MP4.
>
> **The Devpost rules require an explicit "self-correction sequence"** —
> covered in scene 5 (3:00 - 4:00).

---

## Beat map

| Time | Scene | Theme |
|---|---|---|
| 0:00 - 0:15 | **Cold open** | Headline numbers, the punch |
| 0:15 - 0:50 | **The baseline problem** | Why Protocol SIFT alone isn't enough |
| 0:50 - 1:30 | **Architecture in 40 sec** | Typed MCP boundary, per-call audit, validator-in-loop |
| 1:30 - 3:00 | **Live run — ROCBA-001** | Fire the loop, watch convergence |
| 3:00 - 4:00 | **Self-correction sequence** | Single claim: flagged in iter 2 → corrected in iter 3 |
| 4:00 - 4:30 | **Audit trail walkthrough** | One claim → exec_id → JSONL row → reproducibility |
| 4:30 - 5:00 | **Results + close** | 3 cases, MITRE coverage, repo link |

---

## Scene 1 — Cold open  (0:00 - 0:15)

**Screen**
- Full-frame card on dark background:
  ```
  SIFT-OWL
  Autonomous DFIR agent on a typed-MCP boundary

  ROCBA-001:        91.7%
  STARK-APT-001:    86.1%
  SHIELDBASE        71.4%        single-shot held-out · $3.50 · 42 min
  SHIELDBASE  ⭐    89.9%        self-correcting loop · 71/79 V · $4.59 · 57 min
  ```
- Bottom: `github.com/timietti/find-evil-hackathon · MIT`

**VO** (12 s)
> "SIFT-OWL is an autonomous DFIR agent that processes raw disk and
> memory images end-to-end — no human in the loop, no shell access for
> the model, and a per-call audit trail every claim has to cite. On a
> held-out 15-host SANS case, three dollars and forty-two minutes of
> compute got us seventy-one percent of claims strictly verified on a
> single shot; the self-correcting loop with libesedb-backed SRUM gets
> us to eighty-nine point nine percent with seventy-one of seventy-nine
> verified. Here's how."

---

## Scene 2 — The baseline problem  (0:15 - 0:50)

**Screen**
- Split screen.
- **Left half**: Protocol SIFT baseline run — `eval/results/test2-stark-apt/baseline-protocol-sift/20260510T183123Z-sonnet/REPORT.md`
  - Highlight: `Cost: $10.99 (37% over budget)`, `Exit code: 1`,
    `Result subtype: error_max_budget_usd`, `Final report on disk: none`
- **Right half**: Protocol SIFT's actual audit file — `/cases/find-evil-test/analysis/forensic_audit.log`. One line only:
  ```
  Sat May  9 05:31:43 UTC 2026:
  ```

**VO** (30 s)
> "Protocol SIFT — the hackathon's published baseline — drives Claude
> Code with an unrestricted Bash allow-list. On a single-host memory
> case it gets thirty-one percent verified. On a four-host case it
> spawns seven parallel sub-agents, blows past its budget, and gets
> cut off mid-report. And the entire forensic audit log is this:
> one line, a timestamp. There is no way to trace a finding back to
> the specific shell command that produced it. Both of those are
> architecturally fixable — we just had to replace the shell with
> something the model can't escape."

---

## Scene 3 — Architecture in 40 seconds  (0:50 - 1:30)

**Screen**
- Open `docs/architecture.svg` in browser.
- Highlight in sequence (cursor zooms or animated focus rings):
  1. The Orchestrator box (top) — "loop, 3 iters, hard budget cap"
  2. The Investigator subprocess — note the red `--disallowed-tools` line
  3. The `sift-mcp · FastMCP stdio server` — note the 4 grouped tool family tiles
  4. The audit log box — the JSON row sample
  5. The Validator column — the 5 numbered steps
  6. The trust boundary callouts — TB1 through TB6

**VO** (40 s)
> "The architecture is one idea: replace the shell with a typed MCP
> server, then make every call audited. The investigator can call
> thirty-eight registered functions — that's it. No Bash. No Read.
> No Write. No web access. Every function validates its arguments,
> runs a forensic tool in a subprocess with argv lists — never
> shell-equals-true — parses the output, and writes one JSON row to
> the audit log with the exec ID, args, both hashes, and a parsed
> summary. After each iteration the validator pulls every CONFIRMED
> claim out of the report, resolves its cited exec ID, and re-checks
> whether the parsed tool output structurally supports it. If not,
> the next iteration's prompt tells the agent which claims to fix.
> Six trust boundaries, all architecturally enforced, all tested."

---

## Scene 4 — Live run on ROCBA-001  (1:30 - 3:00)

**Screen — sub-scene 4a (1:30 - 1:50)**: terminal
```
$ python -m eval.agents.sift_owl_v2.run_loop \
    --case rocba-001 \
    --prompt-file prompt.md \
    --model sonnet \
    --max-budget-usd 5 \
    --max-iterations 3
[12:00:00] Pre-run hashes match. (2 files)
[12:00:01] iter 1: launching claude...
```

**VO** (20 s)
> "Here's the canonical case — ROCBA — a Windows 10 employee laptop,
> eighteen-gig RAM image, single-host break-in. We fire the v2
> self-correction loop with a five-dollar cap, three iterations,
> Sonnet four-six. The loop builds a base prompt, spawns the
> investigator, waits for it to write its tagged report, then runs
> the validator."

**Screen — sub-scene 4b (1:50 - 2:20)**: cut to a sped-up timelapse of `tool_calls.jsonl` filling up. Show the count climb: 30, 60, 80, 110. Then iter-1 `final_response.md` opens — scroll through the tagged claims.

**VO** (30 s)
> "Forty-eight tool calls in this iteration. The agent runs
> vol3 image_info, psscan, pstree, cmdline, netscan, filescan,
> malfind, svcscan, userassist, then drills with query_rows for the
> specific PIDs and IPs it wants to verify. Every call gets one row
> in the audit log. The investigator finishes, the validator runs,
> we get our first score."

**Screen — sub-scene 4c (2:20 - 3:00)**: open `validator_report.md` for ROCBA v2 iter 1.
- Highlight: `Confirmation score: 48.3%`
- Scroll to per-claim verdicts, point at one **partial** verdict.
- Cut to iter 2 prompt (`iter_2/prompt.md`) — scroll to the "validator flagged the following claims" section, show 14 flagged claims.

**VO** (40 s)
> "Forty-eight percent strict-verified at iter one — not the headline
> number yet. The validator flagged fourteen claims as partial — some
> tokens matched, some didn't. The harness builds the next iteration's
> prompt by appending the flagged claims, with the validator's notes
> on *what* didn't match. Iter two doesn't restart — it picks up the
> same audit log, the same exec IDs, and the agent decides which
> claims to re-investigate."

---

## Scene 5 — Self-correction sequence  (3:00 - 4:00)  ⭐ mandatory

**Screen — sub-scene 5a (3:00 - 3:25)**: zoom in on a single flagged claim from `iter_2/prompt.md`. Pick the cleanest one. Example:

```
[3] partial — cited tool: vol3_netscan
- note: 3 tokens matched (PID 1912, foreign IP 81.30.144.115);
  1 missing: timestamp "2020-11-14T03:42:55Z" not in netscan parsed_summary
> [CONFIRMED] STUN.exe (PID 1912) reached out to 81.30.144.115 at
  2020-11-14T03:42:55Z (vol3_netscan exec_id=019e1372-...)
```

**VO** (25 s)
> "Here's a single flagged claim. The agent said STUN-dot-exe
> connected to a specific IP at a specific timestamp, citing the
> network scan. The validator confirmed PID nineteen-twelve and the
> IP are in the netscan output — but the timestamp it cited isn't.
> So it's marked partial. The fix isn't to rerun netscan — netscan
> doesn't carry per-connection wall-clock timestamps. The fix is
> to cite a *different* tool that does."

**Screen — sub-scene 5b (3:25 - 3:50)**: cut to iter 3's `final_response.md`. Find the corrected claim:

```
[CONFIRMED] STUN.exe (PID 1912) reached out to 81.30.144.115
  (vol3_netscan  exec_id=019e1372-d58b-...)
  at 2020-11-14T03:42:55Z
  (vol3_cmdline  exec_id=019e1374-3eba-...)
```

**VO** (25 s)
> "Iter three. Same claim, but now multi-cited: netscan for the
> connection itself, cmdline for the process-start timestamp that
> anchors the wall clock. The validator re-runs, both citations
> resolve, both sets of tokens match, claim verified."

**Screen — sub-scene 5c (3:50 - 4:00)**: validator_report.md for iter 3. Highlight:
```
Confirmation score: 91.7%  (54 verified / 60 testable)
LLM-promoted: 1 (Haiku 4.5 prose check, $0.0013)
```

**VO** (10 s)
> "Final score: ninety-one-point-seven percent strict-verified.
> Three iterations, four dollars sixty-nine cents, twenty-four minutes."

---

## Scene 6 — Audit trail walkthrough  (4:00 - 4:30)

**Screen**
- Terminal. Pick the same exec_id from the corrected claim above
  (`019e1372-d58b-7042-bfd9-849d9fd58cba`).
- Run:
  ```
  $ grep 019e1372-d58b audit/exec_log.jsonl | jq .
  ```
- Show the JSON row inline. Highlight the fields:
  - `tool: "vol3_netscan"`
  - `args: { "image": "/cases/find-evil-test/Rocba-Memory.raw" }`
  - `input_hash` + `output_hash` (sha256)
  - `parsed_summary` (truncated count of connections)
  - `wall_ms: 7820`

**VO** (30 s)
> "Every confirmed claim cites an exec ID. Every exec ID is one row
> in this JSONL file. The row has the tool name, the exact arguments,
> the SHA-256 of the inputs and outputs, the wall time, and a parsed
> summary. The raw output is on disk too, at a content-addressed path,
> so you can re-derive every number in the report. This is what
> traceability means architecturally — not a prompt instruction asking
> the model to be helpful."

---

## Scene 7 — Results + close  (4:30 - 5:00)

**Screen — sub-scene 7a (4:30 - 4:48)**: results table

```
Case                          Strict-verified    Cost      Wall    Hosts
─────────────────────────────────────────────────────────────────────────
ROCBA-001  dev                   91.7%          $4.69     24 min     1
STARK-APT  dev                   86.1%          $1.92     20 min     4
SHIELDBASE held-out single shot  71.4%  (30/42) $3.50     42 min    15+
SHIELDBASE self-correcting ⭐    89.9%  (71/79) $4.59     57 min    15+

MITRE ATT&CK coverage: 20 of 22 target techniques at Full (91%)
                       2 Partial, 0 Missing

vs Protocol SIFT baseline:
   ROCBA      31.0%  →  91.7%       (+60.7 pp)
   STARK-APT  did-not-finish ($10.99) → completed at $1.92
```

**VO** (18 s)
> "Three cases. On the held-out SHIELDBASE, seventy-one percent of
> claims verified on a single shot; the self-correcting loop with
> libesedb-backed SRUM and inline LLM-check pushes that to eighty-nine
> point nine percent — seventy-one of seventy-nine confirmed claims.
> Twenty of twenty-two MITRE techniques at Full coverage. No shell,
> no spoliation, every claim traceable. Sixty-points-of-accuracy lift
> on ROCBA over the baseline; on STARK-APT, where the baseline didn't
> even finish, we landed in twenty minutes for under two dollars."

**Screen — sub-scene 7b (4:48 - 5:00)**: closing card
```
   SIFT-OWL
   Open source · MIT · SANS SIFT 24.x

   github.com/timietti/find-evil-hackathon
   docs/ACCURACY_REPORT.md
   docs/MITRE_COVERAGE.md
```

**VO** (12 s)
> "Repo is open, MIT licensed. Full accuracy report, MITRE coverage
> matrix, audit logs, every claim — committed. Run it on your case."

---

## Production notes

### Audio
- Single-take VO is fine; pace at ~150 words/min averages over the 5
  minutes (~750 words). The script is ~720 words.
- Pause 0.5 s between scenes; lets background-music ducking work.
- Background music: low-key ambient electronic, -22 LUFS, fade in/out
  at scene cuts. Suggested: Suno-generated or royalty-free from
  Pixabay/Bensound. CC-BY required if used.

### Visual style
- Dark terminal background (#0d1117 GitHub dark)
- Cursor highlight: yellow circle outline, 30% opacity
- Code highlights: red underline (3 px) for "flagged" claims, green for
  "verified"
- Architecture diagram: full-screen with animated zooms via Ken-Burns
  effect (Resolve has a preset)

### File targets
- Output: 1920×1080 H.264 MP4, 30 fps, 6 Mbps target → ≤ 100 MB
- Devpost upload limit: 100 MB direct; YouTube unlisted as backup link

### Capture commands
```bash
# Pre-record: capture the ROCBA v2 loop output as the live demo source
ANTHROPIC_API_KEY=$(cat ~/.anthropic_key) \
  python -m eval.agents.sift_owl_v2.run_loop \
    --case rocba-001 --prompt-file prompt.md \
    --model sonnet --max-budget-usd 5 --max-iterations 3 \
  2>&1 | tee /tmp/demo-rocba.log

# We use the EXISTING ROCBA v2 run at
# eval/results/rocba-001/sift-owl-v2/20260510T065909Z-sonnet/
# for the scene-4 cuts, since that's the canonical 91.7% run.
```

### Cuts cheat sheet
The clip uses three asynchronous tracks:
- **Track 1** — terminal/IDE captures (the agent running)
- **Track 2** — VO mic
- **Track 3** — ambient music bed
With overlays for:
- Headline numbers (scene 1, 7a)
- Cursor highlights (scenes 5-6)
- Architecture diagram (scene 3)

---

## Word count check

| Scene | Words (approx) | Seconds | Words/sec |
|---|---|---|---|
| 1 — Cold open | 55 | 15 | 3.7 |
| 2 — Baseline problem | 95 | 35 | 2.7 |
| 3 — Architecture | 130 | 40 | 3.3 |
| 4 — Live run | 195 | 90 | 2.2 |
| 5 — Self-correction | 165 | 60 | 2.8 |
| 6 — Audit trail | 75 | 30 | 2.5 |
| 7 — Results + close | 60 | 30 | 2.0 |
| **Total** | **775** | **300** | **2.6** |

Comfortable narration pace (~150-160 wpm), leaves room for breathing
and on-screen text reading.

---

## Pre-record checklist

- [ ] Microphone gain calibrated; one warm-up take recorded + listened to
- [ ] Screen recorder set to 1920×1080, 30 fps, mouse pointer visible
- [ ] Architecture SVG opens cleanly in browser at full screen
- [ ] Terminal font ≥ 16 pt for legibility at 1080p
- [ ] `audit/exec_log.jsonl` for the rocba-001 v2 run exists at
      `eval/results/rocba-001/sift-owl-v2/20260510T065909Z-sonnet/audit/`
- [ ] `jq` installed
- [ ] All file paths cited in the script exist (per the checklist above)
- [ ] Closing-card URL matches the actual repo URL

---

## Post-edit checklist

- [ ] Final file ≤ 100 MB
- [ ] Captions burned in or as a `.vtt` sidecar
- [ ] Music track credited if not original
- [ ] YouTube unlisted upload as Devpost-failure fallback
- [ ] Devpost submission references the video URL
