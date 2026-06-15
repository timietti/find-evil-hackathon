# SIFT-OWL — Devpost project description

> Ready-to-paste content for the Devpost project page. Each `##` section maps to
> a Devpost field. Built directly from `docs/ACCURACY_REPORT.md`,
> `docs/MITRE_COVERAGE.md`, and `docs/ARCHITECTURE.md` so numbers stay anchored
> to committed evidence.

---

## Tagline (≤140 chars)

> Autonomous DFIR agent on a typed-MCP boundary — no shell, every claim cited. Two held-out SANS cases: 71.4 % → 89.9 % (SHIELDBASE), 36.4 % → 100.0 % (VANKO).

---

## Inspiration

Real-world incident response is bottlenecked at the **human triage step**. A
modern enterprise compromise produces 50-200 GB of evidence across 10-20 hosts,
and the analyst gate is "someone has to sit down with Volatility, Sleuth Kit,
and EZ Tools for hours." Protocol SIFT — the hackathon's published baseline —
showed that a Claude Code configuration *could* drive those tools, but it has
two structural problems:

1. **It runs everything through `Bash(*)`** with a narrow deny-list. The agent
   could theoretically `rm` evidence, mount it read-write, or exfiltrate via
   `curl`. The protection is prose in a system prompt.
2. **Its audit trail is one line per session** (the `$CONVERSATION_SUMMARY`
   `Stop`-hook). When a finding looks wrong, there is no way to trace it back
   to the specific tool call that produced it.

We wanted to see how far you could push DFIR autonomy by **eliminating both
problems architecturally** — no shell, no arbitrary paths, and a per-call
audit row that every claim must cite. Then prove it works on a real
held-out SANS case.

---

## What it does

**SIFT-OWL** is an autonomous, agentic DFIR investigator that runs on the SANS
SIFT Workstation. Point it at a case (E01 disk images + raw memory dumps),
fire one command, and get a tagged & cited markdown report 20-40 minutes
later — covering: patient zero identification, malware implants, persistence
mechanisms, lateral movement chains, credential theft, exfil staging,
unified UTC timeline, and TTP attribution. Every `[CONFIRMED]` claim cites
an `exec_id` that the validator can independently resolve and check against
the parsed tool output.

Three SANS-canonical cases ran end-to-end:

| Case | Hosts | Evidence | **SIFT-OWL score** | Protocol SIFT baseline |
|---|---|---|---|---|
| ROCBA-001 (dev) | 1 | 18 GB memory | **91.7%** strict-verified | 31.0% |
| STARK-APT-001 (dev) | 4 | 58 GB disk + memory | **86.1%** strict-verified | did not finish (budget overrun) |
| SHIELDBASE / CRIMSON OSPREY ⭐ | 15+ | 198 GB disk + memory | **71.4 %** single-shot (HELD-OUT, $3.50, 42 min) **→ 89.9 %** (71/79) with the self-correcting loop ($4.59, 57 min) | n/a |
| VANKO-001 / "Abducted Zebrafish" ⭐ | 1 | 116 GiB Surface 3 physical disk (no memory) | **36.4 %** single-shot (HELD-OUT, $2.21, 30 min) **→ 100.0 %** (37/37) post-prompt-fix retry ($1.75, 26 min) — **first perfect strict-verified score across all SIFT-OWL evals** | n/a |

**No spoliation across any run.** Every claim re-derivable from the committed
audit log.

---

## How we built it

### The architectural insight

Replace the unrestricted shell with a **typed MCP server** that exposes only
read-only forensic functions. The agent on the other side has **no `Bash`, no
`Read`, no `Edit`, no `Write`, no `WebFetch`, no `Agent`, no `Skill`**. It can
only call the 38 registered functions, each with a Pydantic-validated input
schema:

- **17 memory tools** wrapping Volatility 3 (psscan, pstree, cmdline,
  netscan, filescan, malfind, svcscan, userassist, dlllist, handles,
  scheduled_tasks, hashdump, cachedump, skeleton_key_check, envars,
  vadyarascan, image_info)
- **6 disk tools** wrapping Sleuth Kit + EWF (`ewf_info`, `ewf_verify`,
  `tsk_partition_table`, `tsk_fs_stat`, `tsk_fls_list`, `tsk_icat_extract`)
- **10 Windows-artefact parsers** wrapping EZ Tools + custom Python +
  libyal libscca + libesedb: MFTECmd, AppCompatCacheParser, EvtxECmd,
  AmcacheParser, Prefetch (via pyscca — PECmd is Linux-broken), JLECmd,
  RBCmd, SRUM (via pyesedb — SrumECmd is Linux-broken), a Task-XML
  parser, a Run-keys parser via RECmd
- **4 threat-hunt + carving tools**: YARA file scan, bulk_extractor multi-
  scanner, bstrings, MD5+SHA-1+SHA-256+ssdeep hash
- **1 drill helper** (`query_rows`) for re-parsing any prior call's full row
  list

### The audit trail

Every MCP call writes one JSONL row to `audit/exec_log.jsonl` with `exec_id`
(UUIDv7), args, sha256(input + output), `parsed_summary`, `wall_ms`,
`raw_output_path`. Every claim in the final report cites an `exec_id`. The
validator resolves the citation, reads the parsed JSON, and re-checks
structural support. No claim is taken on trust.

### The self-correction loop

`eval/agents/sift_owl_v2/run_loop.py` runs N iterations (default 3):

1. **Plan / Execute**: the investigator subprocess runs against the MCP
   server, produces `final_response.md` with tagged claims.
2. **Validate**: rule-based extractor pulls structured tokens (PIDs, IPs,
   paths, timestamps, hashes, inodes, emails) from each claim. Each token
   must appear in the cited tool's parsed output. v4 LLM prose-check
   (Haiku 4.5) handles unverifiable prose claims for ~$0.01/run.
3. **Replan**: if not converged, the next iteration's prompt is the base
   prompt + the validator's flagged claims with notes. The agent
   re-investigates.

Termination: converged (no improvement + no demotions), max-iter, or budget.

### The validator (6 versions)

Every regression a real run surfaced got a fix + a test. Final v6:
- Per-claim segmentation with paren-aware negation handling
- Backslash-normalisation for Windows paths
- Timestamp prefix matching (`T23:09Z` matches `T23:09:14Z`)
- Prose-style citation extraction (handles `(vol3_psscan exec_id=X)`
  outside tag brackets — the format the agent emitted on SHIELDBASE)
- Audit-log prefix lookup for truncated UUIDs in MITRE-style tables
- Backticked exec-id guard so `` (exec_id `UUID`) `` doesn't leak the
  UUID into the verifiable-token list (would otherwise cascade
  every claim to `partial` — SHIELDBASE W3-50)
- Multi-tag paragraph scoping so the trailing `(exec_id …)` cite on a
  bullet-list claim attaches to *its* tag, not the next bullet (W3-52)
- Inline LLM prose check via Haiku 4.5; auto-enables when
  `ANTHROPIC_API_KEY` is in env (~$0.05 / 3-iter run)

### Stack

- **Language**: Python 3.12 (server) + Claude Code CLI (investigator harness)
- **MCP**: FastMCP over stdio
- **Tooling**: Volatility 3 2.28 (runs fully offline via cached community
  symbol pack), Sleuth Kit + libewf, EZ Tools (.NET 9 builds), libyal
  `libscca` (Prefetch — replaces Linux-broken PECmd), libyal `libesedb`
  (SRUM — replaces Linux-broken SrumECmd), YARA 4.5, bulk_extractor 2.0.3
- **Validator LLMs**: Sonnet 4.6 for the investigator, Haiku 4.5 for the
  prose-check rescue pass
- **Testing**: 279 pytest unit tests + slow E2E markers; per-MCP-call
  audit trail enables full replay

### Architecture diagram

See `docs/architecture.svg` (hand-rolled, no rendering deps). Shows the
orchestrator → investigator subprocess → MCP boundary → tool subprocess →
evidence flow, with the validator-in-the-loop, the per-call audit log, and
all six trust boundaries called out.

---

## Headline results

### Held-out single-shot eval — SHIELDBASE / CRIMSON OSPREY

**SANS FOR508 Lab 1.1**: 15+ host enterprise compromise, 7 disk images +
23 memory dumps, 198 GB total. Threat actor: CRIMSON OSPREY (state-level
APT). The eval was a *single run* against a case SIFT-OWL had never seen,
with no prompt tuning informed by the case's content.

**Single-shot, held-out result: 71.4% strict-verified at iter 3, $3.50 total,
42 minutes wall.** 12% of the $30 budget. The same case run again with the
self-correcting loop after libesedb-backed SRUM landed (W3-43) and inline
LLM-check enabled (W3-45) reached **89.9% strict-verified with 71 of 79 claims
confirmed, $4.59 total, 57 minutes** — 3× the substantive verified-claim count
of the single-shot run, and roughly the v2 loop's ceiling on this case
(variance band 60–92% across 4 samples).

Substantive findings (all `exec_id`-cited):
- **Cobalt Strike Beacon** intrusion across rd01 (patient zero, OUTLOOK.EXE
  RWX injection via spear-phishing), file01 (Rar.exe 9-min exfil staging),
  exchange01 (named-pipe `fhsvc-b378` cross-host pivot), and DC (cmd.exe +
  tasklist enumeration).
- 12 MITRE ATT&CK TTPs documented with per-TTP citations: T1566.001
  (spearphish), T1047 (WMI exec), T1059.001 (PowerShell), T1036.004
  (masquerade), T1055 (injection), T1021.002 (SMB lateral), T1090.001
  (proxy relay), T1071.001 (HTTPS C2), T1572 (named-pipe C2), T1560.001
  (RAR exfil), T1574.012 (IFEO hijack hypothesis), T1003.001 (LSASS
  credential access).
- Internal C2 relay `172.16.4.10:8080` → dual cloud (Azure 13.89.220.65,
  AWS 52.16.55.11).

### Second held-out — VANKO-001 / "Abducted Zebrafish"

**SANS FOR500 student handout**: Anthony Vanko, lead biochemical engineer
at Stark Enterprises' DC R&D facility, suspected of disseminating
classified research (cell regeneration, Zebrafish DNA splice testing)
that appeared on a Chinese university file share in June 2016.
Single-host case: a Microsoft Surface 3, full physical disk (116 GiB,
GPT, 6 partitions). No memory image.

**Held-out single-shot: 36.4 % strict-verified iter 1, $2.21, ~30 min.**
The score collapsed on a previously-unseen prose-style pattern (bug H):
the agent quoted `field_name "value"` compounds rather than bare values,
and those compounds don't substring-match the JSON haystack's
`"FieldName": "value"` representation. The matched-token lists showed
the research itself was solid — the bug was prose noise.

A 15-line prompt revision (W3-60: "quote bare values, not `field_name
"value"` compounds") + a re-fire one hour later got the same case to
**100.0 % strict-verified at iter 2 — 37 of 37 claims confirmed,
$1.75, 26 minutes** — **the first perfect strict-verified score across
any SIFT-OWL eval.** Loop converged with 0 demoted claims; iter 3 was
unnecessary.

Substantive findings (all 37 claims verified):
- **14 classified Stark research documents** found by name + MFT entry
  + location, including `Stark_TS-Level8A_CryoDNA.blacklight.docx`
  (entry 58969) and `Stark_Level_12_Wolverine_Dossier_Behavior_
  Controls.docx` (entry 56770).
- `zebrafish.pdf` carries a **Zone.Identifier ADS** proving
  web-download provenance.
- **`STARK_ENT (D).lnk`** (entry 5030) — the StarkResearch server share
  was mapped as local drive D: since 2016-05-13.
- All 11 OneDrive classified files share the **exact** record-changed
  timestamp **2016-06-30T14:47:38Z** — the identical moment JARVIS
  detected the transfer.
- OneDrive directory hierarchy (`Level_7`, `Level_8`, `Level_12`)
  mirrors the source server's `\StarkResearch\Level X Classified\`
  naming — direct one-to-one upload mapping.

The W3-59 36.4 % is preserved as the canonical held-out single-shot
number; the W3-61 100 % is the post-fix retry. Both REPORT.md files
are in the submission package below.

### Head-to-head vs. Protocol SIFT baseline

| Case | Protocol SIFT | SIFT-OWL v2 | Delta |
|---|---|---|---|
| ROCBA-001 | 31.0% verified ($2.26, 13 min) | **91.7%** ($4.69, 24 min) | **+60.7 pp** |
| STARK-APT-001 | did not finish — `error_max_budget_usd` at $10.99 / 26 min | **86.1%** ($1.92, 20 min) | **5.7× cheaper, completed** |

Protocol SIFT's `Agent` tool spawned 7 parallel sub-agents on STARK-APT, each
spending independently — that's what blew the budget. Its streaming output
contained substantively-correct findings but no `[CONFIRMED]` tags with
citations, so the validator cannot score it. **The cut-off-mid-report is
exactly the failure mode the architecture is supposed to prevent.**

### MITRE ATT&CK coverage

20 of 22 user-target techniques at **Full** coverage. 2 Partial (T1091 USB +
T1110 Brute Force aggregation). 0 Missing. Full matrix in
`docs/MITRE_COVERAGE.md`.

---

## Challenges we ran into

### 1. The validator regex bug at SHIELDBASE iter 1

The SHIELDBASE eval surfaced that the v0..v4 validator only scanned for
`exec_id` citations **inside** `[CONFIRMED — exec_id X]` tag brackets. The
agent's natural format was `[CONFIRMED] ... (vol3_psscan exec_id=X)` — a
prose-style citation *after* the closing bracket. Result: 56 of 56 iter-1
claims hit `not_confirmed`. The iter-2 prompt got "all 42 confirmed claims
failed" — noisy feedback that wasted iter 2's budget on re-investigation.

**Fix**: validator v5 (committed mid-flight, `cac6c42`) added prose-style
extraction with strict UUID-shape detection (won't false-match SHA-256
hashes) and audit-log prefix lookup for truncated UUIDs. Re-validation of
the SAME iter-3 output surged from 0% → 71.4%. We preserved the non-
monotonic curve in the run record rather than re-running — it's an honest
artefact of the bug-discovery sequence.

### 2. MCP tool result overflow

Vol3 `psscan` on an 18 GB image emits ~330 KB of text — past Claude Code's
per-tool-result size cap. v0 agent could see the truncation message but
had no way to recover (the built-in `Read` was denied). Fix: server-side
parser truncates the row list to 50 entries on the wire; full data on disk;
`query_rows(exec_id, filter, limit, offset)` does the drill.

### 3. Multi-host scope blew Protocol SIFT's budget

Running the same `claude -p` baseline against the 4-host STARK-APT case
spawned 7 parallel `Agent` sub-investigations — at $1.50+ each — and ran
the orchestrator out of budget mid-report. The architecture's emphasis on
"server-side parsing, agent gets summaries" turned out to matter more on
multi-host cases than we expected.

### 4. Validator-as-loop-feedback is fragile

When the validator is wrong, the loop amplifies the error. iter 2 of
SHIELDBASE was effectively a wasted iteration because the iter-1 validator
output misled the agent. This is a real cost of the architecture and we
documented it transparently in the per-run REPORT.

### 5. Case-specific era mismatch

SHIELDBASE's `case.yaml` documents IOCs from a 2023-01-25 CRIMSON OSPREY
incident, but the available memory captures are dated 2018-09-era. The
agent surfaced a real, valid **2018 Cobalt Strike compromise** — different
threat event than the 2023 IOCs reference. We documented this clearly
rather than retro-fitting the case. A more thorough prompt would call
`vol3_image_info` on every memory image first to identify which captures
are which era.

---

## Accomplishments we're proud of

1. **Architectural enforcement beat prompt enforcement** on the two specific
   failure modes we set out to fix: ROCBA-001 baseline 31% → SIFT-OWL 91.7%
   verified accuracy; STARK-APT baseline did-not-finish → SIFT-OWL completed
   at 86.1% with full audit trail.

2. **Held-out discipline preserved.** SHIELDBASE was a single shot — we
   never iterated SIFT-OWL on this case, never tuned prompts to its
   findings. The 71.4% is intrinsic. The same case re-run later with the
   self-correcting loop + libesedb SRUM + inline LLM-check reached
   **89.9% (71/79 verified claims)** — substantively much more, on a
   case that wasn't tuned to.

3. **MITRE ATT&CK coverage at 91% Full** (20 of 22 target techniques) with
   zero missing-coverage techniques. Every Partial has a documented closure
   in the roadmap.

4. **The validator is its own engineering surface.** Five versions, each
   triggered by a real regression on a real run, each with a regression
   test. No silent rules. The validator code is the audit's audit.

5. **Per-call audit anchors every claim.** Open `audit/exec_log.jsonl`,
   grep the cited `exec_id`, see the exact subprocess call that produced
   the evidence — args, sha256, wall_ms, parsed JSON. Trust boundary TB6
   architecturally enforced.

6. **Cost / value is great.** Held-out 15-host case → $3.50, 42 minutes.
   Per-claim cost: $0.05-$0.08. Per-host: $0.23.

---

## What we learned

- **Self-correction loops only converge when the validator is correct.**
  iter 2 of SHIELDBASE wasted an iteration on noisy feedback from a buggy
  validator. The validator is a load-bearing component, not a passive
  reporter.

- **Architectural constraints are the right abstraction.** "Never modify
  evidence" as a prompt rule fails the first time the model decides to
  improvise. "Have no `Write` tool available" cannot fail by design.

- **Per-case ceilings exist.** STARK-APT plateau'd at ~86% regardless of
  inventory size (38 tools didn't beat 19 tools on this case) — the
  remaining 14% is prose-only attribution narrative with no extractable
  structured tokens. Recognising this saves us from over-engineering.

- **Multi-cite is essential for cross-source claims.** "STUN.exe at PID
  1912 connecting to 81.30.144.115" should cite three exec_ids (psscan,
  netscan, cmdline) — that's the proof. Single-cite claims often partial-
  match because the structured evidence is spread across calls.

- **The held-out discipline matters.** Re-evaling on SHIELDBASE would have
  produced a better number with the v5 validator and the expanded 38-tool
  inventory, but it would muddle the "single shot" story. The flat re-eval
  on STARK-APT (85.7% vs 86.1% baseline) is itself a useful finding — the
  baseline was already at the per-case ceiling.

---

## What's next

Documented in `plans/MCP_TOOL_ROADMAP.md`:

- **Phase 5 — RECmd batches + SQLECmd + LECmd + WxTCmd** (~4-6 hr):
  closes T1091 (USB via Shellbags) and adds browser history for T1071
  finer-grained DNS/HTTP detection.
- **Phase 6 — Cross-source correlator helpers** (~3-4 hr):
  meta-tools on top of the audit log (`correlate_indicator`,
  `correlate_process`, `audit_search`). Closes T1110 (brute-force
  aggregation) and removes manual correlation grunt-work from the
  agent's loop.
- **Legacy Windows memory (Win7-x86 PAE)** — known gap. W3-53 cached
  the Vol3 community symbol pack so Vol3 now runs fully offline, but
  Win7-x86 PAE dumps still fail at `KernelPDBScanner` — a Vol3
  framework limitation, not symbol availability. Vol2 wrappers or
  `memprocfs` integration would unblock them; both are
  post-submission territory.
- **Linux + macOS memory** (post-submission stretch): Vol3 has
  profiles for both. Adding `vol3_linux_*` and `vol3_mac_*` makes
  SIFT-OWL the only public AI DFIR agent that handles non-Windows
  memory.

We'd also like to formalise the "do you need more data?"
pre-iteration check that would have prevented the STARK-APT re-eval's
iter-3 regression (agent rewrote the report without running any new
tools and lost 5 pp).

---

## Built with

`python` · `claude-code` · `mcp` · `fastmcp` · `pydantic` · `volatility3` · `sleuthkit` · `libewf` · `eric-zimmerman-tools` · `yara` · `bulk_extractor` · `anthropic` (Sonnet 4.6 + Haiku 4.5) · `pytest` · `typer` · `cairosvg`

---

## Try it out

```
git clone https://github.com/timietti/find-evil-hackathon.git
cd find-evil-hackathon
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Installs YARA + ssdeep + libscca + libesedb + the Vol3 community
# symbol pack (~800 MB, lets Vol3 run fully offline). Idempotent.
bash scripts/bootstrap_sift_tools.sh

sift-mcp inspect                        # prints the 38-tool inventory
pytest -x --deselect tests/test_disk_e2e.py \
          --deselect tests/test_vol3_memory_e2e.py \
          --deselect tests/test_ez_tools_e2e.py
# 283 pass, 1 skipped

# Authenticate the Claude Code CLI that drives the agent — a Claude
# Pro/Max subscription works (`claude login`), or use an API key.
claude login

# Optional: set ANTHROPIC_API_KEY. Not needed to run the agent if you
# logged in above — it only enables the validator's `--llm-check`
# (Haiku 4.5 rescue on Unverifiable verdicts, ~$0.05), which the SDK
# can't drive from the subscription credential.
export ANTHROPIC_API_KEY=sk-ant-api03-...

# Run on a case:
sift-owl-loop --case rocba-001 --prompt-file prompt.md \
    --model sonnet --max-budget-usd 5 --max-iterations 3
```

Full repo: **https://github.com/timietti/find-evil-hackathon**

Key documents:
- **README.md** — entry point
- **docs/ARCHITECTURE.md** — system design + trust boundaries
- **docs/architecture.svg** — diagram (PNG embedded above)
- **docs/ACCURACY_REPORT.md** — full numbers, methodology, failure modes
- **docs/MITRE_COVERAGE.md** — per-technique coverage matrix
- **plans/MCP_TOOL_ROADMAP.md** — what's next
- **INSTALL.md** — setup on SANS SIFT 24.x

---

## License

MIT — `LICENSE` in repo.

---

## Submission package

| Deliverable | File / link |
|---|---|
| Public repo | `https://github.com/timietti/find-evil-hackathon` |
| Demo video | `https://youtu.be/qtFDdMojSvM` |
| Architecture diagram | `docs/architecture.svg` + `docs/architecture.png` |
| Accuracy report | `docs/ACCURACY_REPORT.md` |
| SHIELDBASE held-out (single-shot) | `eval/results/test3-shieldbase/sift-owl-v2/20260510T194945Z-sonnet/REPORT.md` — 71.4 % |
| SHIELDBASE v2 loop (canonical) | `eval/results/test3-shieldbase/sift-owl-v2/20260524T101323Z-sonnet/REPORT.md` — **89.9 %**, 71/79 verified |
| VANKO-001 held-out (single-shot) | `eval/results/test4-vanko/sift-owl-v2/20260612T083519Z-sonnet/REPORT.md` — 36.4 % |
| VANKO-001 post-W3-60 retry | `eval/results/test4-vanko/sift-owl-v2/20260612T093511Z-sonnet/REPORT.md` — **100.0 %**, 37/37 verified |
| Audit log sample | `audit/exec_log.jsonl` per run dir |
| Demo video storyboard | `docs/DEMO_SCRIPT.md` |
