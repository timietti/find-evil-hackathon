# FIND EVIL! — Master Plan

**Hackathon:** FIND EVIL! (SANS / Devpost)
**Deadline:** 2026-06-15 23:45 EDT
**Prize pool:** $22,000 ($10K first)
**Repo:** `/home/sansforensics/Tools/find-evil-hackathon` (public, MIT)
**Author:** miettinen.timo@gmail.com

---

## 0. Status snapshot (2026-05-10)

| Track | Status |
|---|---|
| MCP server | **20 typed read-only tools** (9 vol3 + 6 disk + 4 EZ Tools + query_rows). 173 unit tests green. |
| Agents | v0 / v1 single-pass + **v2 self-correction loop** all shipped under `eval/agents/`. |
| Validator | v0..v4 shipped. v4 adds LLM-based prose check (Haiku 4.5; opt-in via `--llm-check`). |
| Datasets | ROCBA-001 + STARK-APT-001 in active dev. **SHIELDBASE held out** for the final eval. |
| Headline accuracy | ROCBA v2 loop iter 3 = **91.7% strict-verified** (v4 validator). STARK-APT v2 loop iter 3 = 86.1%. |
| Baselines | Protocol SIFT baselines: ROCBA done (31% verified). STARK-APT *in progress 2026-05-10*. SHIELDBASE runs in held-out session. |
| Architecturally enforced | TB1-TB5 architectural; TB6/TB7 hybrid (rule-based + LLM). See `docs/ARCHITECTURE.md`. |

**Remaining work:** AmcacheParser shipped (W3-15). Next: SHIELDBASE final eval → aggregate accuracy report → architecture SVG → Devpost submission → demo video.

---

## 1. Mission

> *"Make Protocol SIFT a fully autonomous incident response agent."*

Build an autonomous, agentic AI forensics investigator that runs on the SANS SIFT Workstation, processes raw case data (disk images, memory captures, log archives), self-corrects, and produces evidence-grounded findings at machine speed — with **architecturally enforced** evidence integrity and a fully traceable audit trail.

---

## 2. Winning Strategy (decision log)

The judging criteria order is the single most important design input. Re-stated, in priority order:

1. **Autonomous Execution Quality** (tiebreaker) — reason, fail, self-correct
2. **IR Accuracy** — correct findings, caught hallucinations, inference vs. confirmation
3. **Breadth and Depth** — depth-on-few beats shallow-on-many (judge guidance)
4. **Constraint Implementation** — *architectural* guardrails ≫ prompt-based
5. **Audit Trail Quality** — every finding ↔ specific tool execution
6. **Usability and Documentation** — another practitioner can deploy & extend

### Baseline: what Protocol SIFT actually is (recon, 2026-05-08)

Protocol SIFT is **not** an MCP-based agent. It is a Claude Code configuration bundle:

- `~/.claude/CLAUDE.md` — system prompt (operator role, forensic constraints, tool paths, skill routing).
- `~/.claude/settings.json` — permission policy. Allow-list for forensic CLIs + a narrow deny-list (`rm -rf:*`, `dd:*`, `wget:*`, `curl:*`, `ssh:*`, `WebFetch`). Write/Edit scoped to `./analysis|exports|reports`.
- `~/.claude/skills/{memory-analysis,plaso-timeline,sleuthkit,windows-artifacts,yara-hunting}/SKILL.md` — markdown prompt libraries with exact CLI invocations the agent should use.
- `~/.claude/case-templates/CLAUDE.md` — per-case overlay (the shipped template is the FOR508 SRL Crimson Osprey scenario, with known IOCs already documented — useful as a future ground-truth case).
- `Stop` hook → `./analysis/forensic_audit.log` containing only `$CONVERSATION_SUMMARY` per session.
- `analysis-scripts/generate_pdf_report.py` — WeasyPrint helper.

**Concrete weaknesses (these are exactly what our architecture beats):**

| # | Weakness | Why it matters | Our fix |
|---|---|---|---|
| W1 | `Bash(*)` is allow-listed broadly; deny-list is pattern-narrow (e.g. `rm -rf:*` blocks `rm -rf` but not `rm -r` or `rm /cases/foo`) | Agent can spoliate evidence with subtle command variations | MCP server exposes only typed read-only functions — no shell at all |
| W2 | `Bash(mount *)` allow-listed without enforcing `ro` | One missing flag → evidence write-mount | All mounts performed by MCP server with `ro,noatime,noexec` hard-coded; image files set immutable (`chattr +i`) on session start |
| W3 | Evidence-integrity rules live in CLAUDE.md prose only | First model that "thinks for itself" can violate them | Architectural: bind-mount RO + immutable bit + path allow-list at exec time |
| W4 | Audit log is one `$CONVERSATION_SUMMARY` line per session | Findings cannot be traced to specific tool calls (judging criterion 5) | Per-call JSONL: `{exec_id, ts, tool, args, input_hash, output_hash, exit_code, parsed_summary}` |
| W5 | All raw tool output goes back into the LLM context | Massive text dumps overflow context; model paraphrases or fabricates | MCP server *parses* output server-side, returns structured JSON keyed by `exec_id` |
| W6 | Hallucinations are caught only by humans reviewing the log | Loses on criterion 2 (IR accuracy) | Validator agent: every "confirmed" claim must cite an `exec_id` whose parsed output structurally supports the claim, else demoted to "inference" |
| W7 | Single-agent context grows linearly with case size | Long cases → context degradation, lost early findings | Specialist sub-agents per domain; orchestrator only sees structured summaries |

### Architectural choice: **Hybrid (Custom MCP Server + Multi-Agent + Persistent Learning Loop)**

Pick approach #2 (Custom MCP Server) as the **foundation** — judges explicitly call it "the most sound architecture in the evaluation." Layer #3 (Multi-Agent) on top for specialization and context-window protection, and #7 (Persistent Learning Loop / starter-idea) on top of that for self-correction. This stacks the top three judging criteria into a single architecture **and** addresses every recon weakness above.

**Rationale:**

- **Custom MCP Server** → wins criterion 4 (architectural guardrails). The agent *physically cannot* `rm` evidence because the server exposes only typed, read-only forensic functions.
- **Multi-agent specialists** → wins criterion 3 (depth). Domain agents (memory / disk / timeline / registry / network) each go deep without polluting one giant context. Inter-agent message log → wins criterion 5 (audit trail).
- **Persistent learning loop with verifiable success criteria** → wins criterion 1 (autonomous execution quality). Each iteration scores its own output; hallucinations get caught by cross-source correlation; max-iteration cap prevents runaway.
- **Cross-source correlation** (disk ↔ memory) → wins criterion 2 (IR accuracy). The agent's *own* second-line review surfaces contradictions before they reach the report.

Project codename: **`SIFT-OWL`** (Operate, Witness, Learn). Working name only; we can rebrand once we ship the demo video.

### What we are explicitly NOT doing

- **Not** building yet another wrapper around `execute_shell_cmd`. That loses on criterion 4 by design.
- **Not** an alternative-IDE submission (Cursor/Cline/Aider). Prompt-based restrictions only — losing posture on criterion 4.
- **Not** chasing breadth across 200 SIFT tools. Pick ~10 highest-signal tool families, expose them as typed MCP functions, and *go deep*.
- **Not** building a custom LLM. Use Claude (Opus 4.7 for the orchestrator, Sonnet 4.6 / Haiku 4.5 for specialist subagents — see §6.3).

---

## 3. System Architecture (target state)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         SIFT-OWL (Orchestrator)                          │
│  Claude Opus 4.7 · plans, sequences, self-evaluates, terminates          │
└────────────┬─────────────────────────────────────────────────┬───────────┘
             │ A2A messages (logged, timestamped, token-counted)│
   ┌─────────┴──────────┬──────────────┬──────────────┬────────┴────────┐
   │ Memory Agent        │ Disk Agent    │ Timeline     │ Windows-Arts   │
   │ (Vol3, MemBaseline) │ (TSK, EWF)    │ Agent        │ Agent          │
   │                     │               │ (Plaso)      │ (EZ Tools)     │
   └─────────┬───────────┴───────┬──────┴──────┬───────┴────────┬───────┘
             │                   │             │                │
             ▼                   ▼             ▼                ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │                    SIFT-MCP (Custom MCP Server)                  │
   │   Typed, read-only forensic functions. NO shell exec exposed.    │
   │   Every call → execution_id, timestamp, hash of input+output.    │
   │                                                                  │
   │   get_amcache(image)         vol3_pslist(memdump)                │
   │   extract_mft_timeline(img)  vol3_malfind(memdump)               │
   │   parse_evtx(path)           extract_prefetch(image)             │
   │   yara_scan(path, ruleset)   shimcache(image)                    │
   │   ...                                                            │
   └────────┬─────────────────────────────────────────────────────────┘
            │ Subprocess execution (sandboxed, image mounted RO)
            ▼
   ┌─────────────────────────────────────────────────────────┐
   │  SIFT Workstation tools — Vol3, TSK, EZ Tools, Plaso,   │
   │  YARA, bulk_extractor, photorec, ...                    │
   └────────────┬────────────────────────────────────────────┘
                │ Read-only mounts only
                ▼
   ┌──────────────────────────────────────────────────────────┐
   │  Evidence:  /cases/  (RO bind mount, immutable bit set)  │
   │  Outputs:   ./analysis/  ./exports/  ./reports/          │
   │  Audit:     ./audit/{exec_log.jsonl, agent_msgs.jsonl}   │
   └──────────────────────────────────────────────────────────┘
```

**Trust boundaries (must be on the architecture diagram):**

| Boundary | Enforcement | Type |
|---|---|---|
| Agent → tool execution | MCP function whitelist; no shell exposed | **Architectural** |
| Tool → evidence | Bind-mount RO + chattr +i + capability drop | **Architectural** |
| Tool → output dir | All writes confined to `./analysis/` | **Architectural** |
| Finding → claim | Every assertion must cite an `execution_id` | **Architectural** (validated at report-emit time) |
| Inference vs. confirmation | LLM-tagged + post-hoc check that "confirmed" claims have ≥1 tool citation | Hybrid (prompt + validator) |

The hybrid row is the only place we tolerate prompt-based — and we document the failure mode in the accuracy report (criterion 4 explicitly asks for this).

---

## 4. Deliverables Map (8 mandatory items → owners)

| # | Deliverable | Maps to | Notes |
|---|---|---|---|
| 1 | GitHub repo + license | All | Public, MIT. `find-evil-hackathon` is already a git repo on `main`. |
| 2 | Demo video ≤5 min | Criterion 1 | MUST include a self-correction sequence on screen. Record near end of project. |
| 3 | Architecture diagram | Criterion 4 | Show §3 diagram + trust-boundary table. Mermaid or Excalidraw. |
| 4 | Project description (Devpost) | Criteria 1–6 | Devpost format: What/How/Challenges/Learned/Next. |
| 5 | Dataset documentation | Criterion 2 | What we tested on, ground truth, what we found. |
| 6 | Accuracy report | Criteria 2 + 4 | FPs, missed artifacts, hallucinations. Spoliation test results. |
| 7 | Try-it-out instructions | Criterion 6 | One-command `install.sh`-style for SIFT users. |
| 8 | Agent execution logs | Criterion 5 | `audit/exec_log.jsonl` + `audit/agent_msgs.jsonl`, both included in repo. |

Missing any → eliminated. Track all 8 as workstreams from week 1.

---

## 5. Test Data & Ground Truth

All three datasets are intaked as of 2026-05-09. Final split:

| Case ID | Role | Hosts | Bytes | Threat actor | Notes |
|---|---|---|---|---|---|
| `rocba-001` | **DEV** | 1 (memory only) | 18 GB | physical break-in | Single-host memory triage; baselined and v0/v1-evaluated |
| `test2-stark-apt` | **TRAIN / SECONDARY DEV** | 4 (disk + memory) | ~58 GB | APT1 (2012) | Multi-host enterprise; cross-source correlation surface |
| `test3-shieldbase` | **VALIDATE + DEMO (held-out)** | 15+ (disk + memory) | ~199 GB | CRIMSON OSPREY (state-level) | Canonical SANS FOR508 lab — the scenario Protocol SIFT was built around |

Per-case authoring lives in `eval/cases/<case_id>/`:
- `case.yaml` — machine-readable context (loaded by SIFT-OWL at runtime)
- `case.md` — human-readable narrative + held-out discipline notes
- `intake/` — SHA-256 hashes, windows.info captures, acquisition-time MD5 sidecars

**We do not write to `/cases/`.** Auto-mode classifier blocked an attempted update of `/cases/find-evil-test/CLAUDE.md` on day 1 — correct behaviour given the user's global rule. All case authoring stays in version control; SIFT-OWL output goes to `eval/results/<case_id>/`.

### Dataset-split discipline

The **only** SIFT-OWL runs allowed against `test3-shieldbase` between now and submission are:

1. The final accuracy-report eval run.
2. The 5-min demo recording.

Everything else (agent debug, MCP-fn additions, validator tests) uses `rocba-001` or `test2-stark-apt`. The discipline is what makes the final numbers meaningful.

### Privileged ground truth

For each held-out case the eval harness has access to ground-truth labels that the agent does **not** see at run time:

- `test3-shieldbase/case.yaml.ground_truth_iocs` — STUN.exe / msedge masquerade / pssdnsvc / atmfd.dll / `net use H: \\172.16.6.12\c$\Users` / 2023-01-25 timeline. Sourced from the Protocol SIFT case template, which IS this dataset's briefing.
- `test2-stark-apt/case.md` — APT1 attribution from `precooked/redline/APT1 - IOCS/`.

### Tool-path corrections discovered at intake (vs. Protocol SIFT global CLAUDE.md)

| Tool | Protocol SIFT says | Actual on this instance |
|---|---|---|
| Volatility 3 | `python3 /opt/volatility3-2.20.0/vol.py` | `vol` in PATH (`/usr/local/bin/vol` → `/opt/volatility3/bin/vol`), v2.28.0 |

### Tool-path corrections discovered at intake (vs. Protocol SIFT global CLAUDE.md)

| Tool | Protocol SIFT says | Actual on this instance |
|---|---|---|
| Volatility 3 | `python3 /opt/volatility3-2.20.0/vol.py` | `vol` in PATH (`/usr/local/bin/vol` → `/opt/volatility3/bin/vol`), v2.28.0 |

Documented per-case in `eval/cases/<id>/case.md`. Fold into the global CLAUDE.md only after we own the install path.

---

## 6. Workplan — 5.5 weeks

Buffer: deadline is 2026-06-15. Ship-ready target is 2026-06-12 to leave 3 days for video, polish, and Devpost upload. Total: **5 calendar weeks of build, 0.5 week of polish.**

### Week 1 (May 8 – May 14) — Foundation
- Stand up Protocol SIFT on this SIFT instance (`curl ... | bash` per Devpost).
- Run the existing Protocol SIFT agent against a known case end-to-end. **Capture baseline:** what it gets right, what it hallucinates. This baseline is what we beat in the accuracy report.
- Inventory available case data; pick primary test case.
- Repo skeleton: `mcp_server/`, `agents/`, `audit/`, `tests/`, `analysis/` (gitignored), `reports/`, `docs/`.
- Choose MCP SDK (Python `mcp` package) and pin versions.
- Sketch the architecture diagram (will be revised, but having a v1 forces clarity).

### Week 2 (May 15 – May 21) — MCP Server v1 ✅ done early (May 9)

**Shipped 9 days early.** 9 typed read-only memory-forensics functions are live as a FastMCP stdio server, all wired through the same architectural pattern:

| Function | Wraps | E2E status |
|---|---|---|
| `vol3_image_info` | `windows.info` | ✅ MCP wire round-trip |
| `vol3_psscan` | `windows.psscan` | ✅ |
| `vol3_pstree` | `windows.pstree` | ✅ |
| `vol3_cmdline` | `windows.cmdline` | ✅ |
| `vol3_netscan` | `windows.netscan` | ✅ asserts 4 baseline RDP IPs |
| `vol3_filescan` | `windows.filescan` | ✅ slow — asserts StarFury.zip + Vibrainium |
| `vol3_malfind` | `windows.malfind` | ✅ slow |
| `vol3_svcscan` | `windows.svcscan` | ✅ |
| `vol3_userassist` | `windows.registry.userassist` | ✅ |

Each function: validates path → runs Vol3 with `-r jsonl` → parses to structured dict → records audit row with `exec_id`, sha256(args), sha256(raw output), `parsed_summary`, `wall_ms` → returns parsed dict to caller.

55 tests green non-slow + 2 slow (full ~6 min). The MCP server is reachable as `sift-mcp` (entry point in pyproject.toml).

What W2 explicitly deferred to W2.5 / W3:
- Disk-side functions (TSK + EZ Tools + Plaso). STARK-APT-001 needs them.
- `vol3_handles` / `vol3_dlllist` / per-PID-filtered variants of psscan/cmdline.
- Spoliation pytest that exercises a full agent run end-to-end (deferred until orchestrator lands).

### Week 3 (May 22 – May 28) — Self-correction + disk side ✅ done early (May 9-10)

**Pivoted from LangGraph to direct Claude Code subprocess.** A self-correction loop with direct subprocess invocation, validator feedback, and shared audit dir across iterations proved simpler and at least as capable as a LangGraph state machine. Shipped:

- 6 disk-side MCP fns (TSK + EWF) — `tsk_partition_table`, `tsk_fs_stat`, `tsk_fls_list`, `tsk_icat_extract`, `ewf_info`, `ewf_verify`.
- 4 EZ Tools wrappers — `ezt_mft_parse`, `ezt_shimcache_parse`, `ezt_evtx_parse`, `ezt_amcache_parse`. All take `extract_exec_id` (not paths) — TB4.
- Validator v0..v4. v4 ships LLM-based prose check (Haiku 4.5) for unverifiable claims; opt-in via `--llm-check`, ~$0.01 per validator pass.
- `eval/agents/sift_owl_v2/run_loop.py` — N-iteration self-correction loop with budget split and validator-flagged-claims feedback.
- Two cases run through the full v2 loop with measurable convergence: ROCBA-001 (3.8% → 48.3% → 90.0% → **91.7%** across v0→v4), STARK-APT-001 (86.1% with 0 partial, 0 failed).

A2A specialist messaging deferred: single agent per iteration was sufficient.

### Week 4 (May 29 – June 4) — Held-out final eval + polish (in progress)
- Run SIFT-OWL v2 loop on **SHIELDBASE** (held-out, single shot, ~$25-50 budget).
- Aggregate accuracy report (`docs/ACCURACY_REPORT.md`).
- Architecture diagram SVG.
- Devpost submission text.

### Week 5 (June 5 – June 11) — Demo + final polish
- Record 5-min screencast around the **91.7% ROCBA v2 loop** result + an iter-3 surgical-fix moment.
- Final dry-run of INSTALL.md / README.md from a clean shell.
- Submission upload to Devpost.

### Polish (June 12 – June 14)
- Record demo video. Plan the 5 minutes:
  - 0:00–0:30 problem framing + arch diagram on screen
  - 0:30–2:30 live agent run on real case
  - 2:30–3:30 **self-correction sequence** (mandatory) — show a hallucination caught and re-run
  - 3:30–4:30 audit trail walkthrough — pick one finding, trace back to `execution_id`
  - 4:30–5:00 results vs. baseline
- Devpost project description.
- Final dry-run of try-it-out instructions on a clean SIFT VM (or fresh user account).

### June 15 — Submit before 23:45 EDT.

---

## 7. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Protocol SIFT install breaks on this instance | M | H | W1 day-1 task. Have fallback: install in Docker. |
| LangGraph multi-agent loops infinitely | M | H | Hard iteration + wall-clock + token caps from W3 day-1. |
| MCP server is slower than direct shell, agent times out | M | M | Profile in W2. Cache parsed outputs by `(tool, args, evidence_hash)`. |
| Hallucination detector itself produces FPs | H | M | Conservative — only demote when validator can't *prove* support. Document in accuracy report. |
| Ground-truth dataset unavailable / closed | M | H | Build synthetic ground truth in W1 as backup. |
| Demo video runs over 5 min | M | M | Storyboard in W4, dry-run in W5. |
| Scope creep into 6+ specialist agents | H | M | Start with 3. Don't add #4 until #1–3 are passing tests. |
| Single contributor (no team announced) → bus factor 1 | H | H | Aggressive use of CI + docs from W1 so anyone (incl. judges) can reproduce. |

---

## 8. Repo Layout (target)

```
find-evil-hackathon/
├── README.md                  # judge entry point
├── INSTALL.md                 # try-it-out instructions
├── LICENSE                    # already present (verify it's MIT/Apache)
├── plans/
│   ├── Devpost.html
│   └── MASTER_PLAN.md         # this file
├── docs/
│   ├── ARCHITECTURE.md        # detailed arch + trust boundaries
│   ├── ACCURACY_REPORT.md
│   ├── DATASET.md
│   └── architecture.svg       # diagram
├── mcp_server/
│   ├── server.py              # entry
│   ├── tools/                 # one file per typed function
│   ├── parsers/               # raw → structured JSON
│   └── audit.py               # exec_log writer
├── agents/
│   ├── orchestrator.py
│   ├── memory_agent.py
│   ├── disk_agent.py
│   ├── timeline_agent.py
│   ├── correlator.py          # cross-source correlation pass
│   ├── validator.py           # hallucination detector
│   └── prompts/               # all system prompts here
├── audit/                     # gitignored except samples/
│   ├── exec_log.jsonl
│   ├── agent_msgs.jsonl
│   └── samples/               # one redacted sample run, committed
├── tests/
│   ├── test_spoliation.py     # evidence integrity
│   ├── test_mcp_tools.py
│   └── test_validator.py
├── analysis/                  # gitignored
├── reports/                   # gitignored except samples
└── eval/
    ├── ground_truth/          # synthetic case manifests
    └── score.py               # precision/recall/halluc rate
```

---

## 9. Open Questions (to resolve in Week 1, not blocking start)

1. Does the LICENSE file already say MIT/Apache-2.0? (Open and verify on day 1.)
2. Is Protocol SIFT's existing agent loop in Python? (Determines whether we can extend in-process or must subprocess.)
3. Does the SANS team plan to release a "canonical" hackathon case? (Watch Slack + Devpost updates.)
4. Are we entering as solo or recruiting teammates from Slack? (Solo permitted; teams up to 5.)
5. Do we run agents on local Claude Code or via API? (API gives better logging + token telemetry → better audit trail; local gives lower latency. Default: API.)

---

## 10. Day-1 Action List

In execution order:

1. Verify license is MIT/Apache → if not, change.
2. Inventory case data on this instance.
3. Install Protocol SIFT, run baseline against any available case, capture output.
4. Stand up repo skeleton per §8.
5. Pin Python deps: `mcp`, `langgraph`, `anthropic`, `pytest`, parser libs.
6. Open the Protocol SIFT Slack, lurk for case-data and judge guidance signals.
7. Draft v1 of `docs/ARCHITECTURE.md` — forces concrete decisions early.

---

*This plan is living. Update it weekly with what changed and why. Date every major revision.*
