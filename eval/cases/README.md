# Cases — DEV / TRAIN / VALIDATE+DEMO split

Three datasets ship with the SIFT-OWL evaluation. Each has its own role; the
discipline of keeping the held-out case off SIFT-OWL's iteration loop is what
makes the final accuracy-report numbers meaningful.

| Case ID | Role | Hosts | Bytes | Threat actor | Why |
|---|---|---|---|---|---|
| **rocba-001** | **DEV** | 1 (memory only) | 18 GB | physical break-in | Single-host memory triage. Fast iteration ($1/run, ~20 min). Heaviest use; safe to point SIFT-OWL at this freely. |
| **test2-stark-apt** | **TRAIN / SECONDARY DEV** | 4 (disk + memory) | ~58 GB | APT1 ("Comment Crew") | Multi-host enterprise from 2012 (XP, Win7×2, Win2008R2 DC). Different scenario from SHIELDBASE → safe to iterate cross-source-correlation work without overfitting the held-out case. |
| **test3-shieldbase** | **VALIDATE + DEMO (held-out)** | 15+ (disk + memory) | ~199 GB | CRIMSON OSPREY (state-level) | Canonical SANS FOR508 lab — the scenario Rob Lee built Protocol SIFT around. The Devpost-shipped Protocol SIFT case template literally describes this dataset. **Used only for: final accuracy numbers + the 5-min demo video.** |

## Discipline

The **only** SIFT-OWL invocations against `/cases/find-evil-test3/` permitted
between now and the hackathon submission are:

1. The final eval run that produces the accuracy-report numbers for the
   Devpost submission.
2. The demo recording (5-min screencast).

Everything else — agent debugging, MCP-fn additions, prompt tuning, validator
tests, harness changes — uses **rocba-001** or **test2-stark-apt**.

## Privileged ground truth

For each held-out case, the eval harness has access to ground-truth labels
that the agent does **not** see at run time:

- `test3-shieldbase/case.yaml.ground_truth_iocs` — STUN.exe / msedge / pssdnsvc /
  atmfd.dll / lateral-movement command / 2023-01-25 timeline. Comes from the
  Protocol SIFT case template, which IS this dataset's briefing.
- `test2-stark-apt/case.md` — APT1 attribution surfaced from
  `precooked/redline/APT1 - IOCS/`. Privileged label, not agent input.

## Layout under each case

```
eval/cases/<case_id>/
├── case.yaml          ← machine-readable: paths, hashes, hosts, ground_truth
├── case.md            ← human-readable narrative + held-out discipline
└── intake/
    ├── hashes/        ← our SHA-256 of every evidence file at intake time
    ├── windows_info/  ← vol windows.info per memory image (captured at intake)
    └── acquisition_md5/  ← original SANS / FTK Imager hashes (chain of custody)
```

## Output destinations (never inside `/cases/...`)

```
eval/results/<case_id>/<harness>/<run_id>/
├── REPORT.md          ← head-to-head metrics + findings comparison
├── summary.json       ← machine-readable
├── run_meta.json      ← invocation, env, pre/post evidence hashes
├── final_response.md  ← agent's text response
├── tool_calls.jsonl   ← parsed tool-use events
├── transcript.jsonl   ← raw stream-json (gitignored — bulky)
└── audit/
    ├── exec_log.jsonl ← per-MCP-call audit log (committed)
    └── raw/           ← raw subprocess outputs (gitignored — bulky)
```

Three harnesses live under `eval/baselines/` and `eval/agents/`:

- `baselines/protocol_sift/` — vanilla Claude Code with Bash unrestricted
- `agents/sift_owl_v0/` — MCP-only with no rehydration
- `agents/sift_owl_v1/` — MCP-only with truncate + query_rows drill
