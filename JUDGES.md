# SIFT-OWL — Run It Locally (judges)

Self-contained step-by-step for running the agent against your own
evidence. No public deployment URL — SIFT-OWL is a local, read-only
forensic agent that runs on the SANS SIFT Workstation against an
evidence directory you point it at.

> **Evidence accessibility.** The four bundled cases were all run
> against **hackathon-provided evidence** — supplied by the FIND
> EVIL! organisers and downloaded from the official distribution
> link to `/cases/find-evil-test*/`. No proprietary or
> examiner-only datasets are involved, so a judge with the same
> hackathon access can drop those images at the same paths and
> reproduce any run exactly (per-file SHA-256 anchors live in
> each `eval/cases/<id>/case.yaml`; full provenance in
> [`EVIDENCE.md`](EVIDENCE.md)). To run against fresh evidence
> instead, point the agent at your own directory per the steps
> below.

| Setting | Value |
|---|---|
| Target OS | SANS SIFT Workstation (Ubuntu 22.04 / 24.x, x86-64) |
| Python | 3.12 |
| LLM access | The investigator runs via the Claude Code CLI — authenticate with **either** a Claude Pro/Max subscription (`claude login`) **or** an Anthropic API key. An API key is needed *only* for the optional validator LLM-rescue (`--llm-check`, Step 7); the agent itself runs fine on a subscription. |
| Typical cost / run | $1.75 – $4.69 |
| Typical wall time | 15 min – 1 h depending on case size |
| Network egress | None — Vol3 runs fully offline after step 4 |

---

## Step 1 — Install Claude Code CLI

```bash
curl -fsSL https://claude.ai/install.sh | bash
claude --version    # confirm
claude login        # authenticate — a Claude Pro/Max subscription works here
```

The agent drives Claude through this CLI, so it uses whatever credential
the CLI is logged in with. A **Claude Pro/Max subscription is sufficient**;
an Anthropic API key (Step 7) is an alternative and is only *required* for
the optional validator rescue.

## Step 2 — Clone the repo

```bash
cd ~
git clone https://github.com/timietti/find-evil-hackathon.git
cd find-evil-hackathon
```

## Step 3 — Python environment + package

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Step 4 — Bootstrap SIFT-side tools (one-off, ~5 min, idempotent)

```bash
bash scripts/bootstrap_sift_tools.sh
```

Installs/confirms: YARA, ssdeep, libscca (Prefetch), libesedb
(SRUM), and caches the Volatility 3 community Windows symbol pack
to `/opt/sift-owl/vol3-symbols/` so Vol3 runs **fully offline**
for every supported kernel GUID.

## Step 5 — Smoke-test the install (optional, ~30 s)

```bash
sift-mcp inspect            # prints the 38-tool inventory
pytest -x --deselect tests/test_disk_e2e.py \
          --deselect tests/test_vol3_memory_e2e.py \
          --deselect tests/test_ez_tools_e2e.py
```

Expect: 283 pass, 1 skipped.

## Step 6 — Scaffold your case with Claude (no YAML to write)

Run Claude Code in the repo root, in plain-assistant mode (not
the locked-down agent), and hand it the bundled setup prompt:

```bash
cd find-evil-hackathon
claude < prompts/setup-new-case.md
```

Then tell Claude where your evidence lives in one line, e.g.:

> *"The evidence is at `/cases/my-case/`. Briefly: a single-host
> Windows 10 laptop, suspected data-theft incident."*

Claude will walk the evidence directory, sha-256 hash every file
(5–10 min on a large image — it will warn before starting),
classify each file (memory image, disk image, registry hive,
etc.), read partition tables on disk images, and write three
files for you:

```
eval/cases/<case-id>/case.yaml              evidence inventory
eval/cases/<case-id>/case.md                human briefing
eval/agents/sift_owl_v2/prompt-<case-id>.md investigator prompt
```

It will then print the `<case-id>` and the exact `run_loop`
command for step 8. The setup prompt (`prompts/setup-new-case.md`)
spells out exactly which sections Claude must fill in vs. copy
verbatim from the bundled templates — especially the
token-quoting style block, which must not be edited.

## Step 7 — (Optional) Anthropic API key for the validator rescue

**Skip this if you authenticated with a subscription in Step 1** — the
agent already has what it needs. This key only powers the *optional*
validator LLM-rescue.

```bash
export ANTHROPIC_API_KEY=sk-ant-api03-...
```

When set, the v2 loop auto-enables the Haiku 4.5 LLM-rescue on
unverifiable prose claims (~$0.05/run extra). Without it, pure
rule-based validation still runs — the loop completes either way.
(The validator calls the Anthropic SDK directly, which does **not**
read the Claude Code subscription credential, so this rescue
specifically needs the API key.)

## Step 8 — Run the agent

```bash
python -m eval.agents.sift_owl_v2.run_loop \
    --case            <your-case-id> \
    --prompt-file     eval/agents/sift_owl_v2/prompt-<your-case-id>.md \
    --model           sonnet \
    --max-budget-usd  5.00 \
    --max-iterations  3
```

The loop terminates on convergence (0 demoted claims),
no-improvement, or the budget / iteration cap.

Add `--dry-run` to verify case.yaml + prompt + evidence hashes
without spawning the investigator (recommended first pass).

## Step 9 — Read the output

All artefacts land under a timestamped directory:

```
eval/results/<your-case-id>/sift-owl-v2/<UTC>-sonnet/
├── final_response.md             best report across iterations
├── iterations/
│   └── iter_N/
│       ├── prompt.md             what the agent saw this iter
│       │                         (incl. flagged claims from N-1)
│       ├── final_response.md     the iter-N report
│       ├── validator_report.md   per-claim verdicts + score
│       └── validator_report.json machine-readable verdicts
├── audit/
│   ├── exec_log.jsonl            every MCP call (exec_id, args,
│   │                             sha256 input/output,
│   │                             parsed_summary, wall_ms)
│   └── raw/<sha256>              content-addressed raw output
└── run_meta.json                 cmdline, model, total cost, wall
```

The **strict-verified percentage** at the top of
`validator_report.md` is the headline accuracy number for that
iteration.

> **Full raw transcript:** every run keeps the structured tool-execution
> log (`audit/exec_log.jsonl`) + per-iteration `tool_calls.jsonl`; the
> published **`vanko-demo`** run additionally ships the complete raw
> turn-by-turn `transcript.jsonl` (agent reasoning + `tool_use` /
> `tool_result` stream) under each `iterations/iter_N/`, so the entire
> agent communication for the demo case is reviewable from the repo alone.

## Step 10 — Re-validate any prior run (optional, no cost)

```bash
sift-validate eval/results/<your-case-id>/sift-owl-v2/<run-dir>/
```

Rule-based only. Add `--llm-check` to enable the Haiku rescue
pass.

---

## Further reading

| Doc | What's in it |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design + the 7 trust boundaries + validator versions |
| [`docs/ACCURACY_REPORT.md`](docs/ACCURACY_REPORT.md) | Full per-case strict-verified scores against our development evidence |
| [`docs/MITRE_COVERAGE.md`](docs/MITRE_COVERAGE.md) | Per-ATT&CK-technique coverage of the 38-tool inventory |
| [`docs/DEVPOST.md`](docs/DEVPOST.md) | Project description as submitted to Devpost |
| [`INSTALL.md`](INSTALL.md) | Long-form install + troubleshooting |
