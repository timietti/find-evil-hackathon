# Install / Try-It-Out

> Target: any SANS SIFT Workstation (Ubuntu x86-64) with the standard SIFT toolset already installed. Tested on SIFT 24.x with Python 3.12.

## Prerequisites

| Requirement | Notes |
|---|---|
| SANS SIFT Workstation | Volatility 3, Sleuth Kit, EZ Tools, Plaso, YARA, bulk_extractor pre-installed at SIFT-default paths |
| Python 3.12+ | `python3 --version` |
| Anthropic API key | `export ANTHROPIC_API_KEY=...` |
| Disk space | ≥ 5 GB free in `./analysis/` for one full run on a typical SRL-sized case |

If you have not already installed Protocol SIFT (baseline), this submission is independent — install it only if you want to run the baseline for comparison.

## Install

```bash
git clone https://github.com/timietti/find-evil-hackathon.git
cd find-evil-hackathon
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Run on a case

The agent expects a case directory containing one or more E01 disk images and/or one memory image. It writes all output under `./<case>/analysis/`, `./<case>/exports/`, and `./<case>/reports/` — never to evidence files.

```bash
export ANTHROPIC_API_KEY=...

# 1. Verify image integrity (MUST pass before agent starts)
ewfverify /cases/<CASENAME>/*.E01

# 2. Launch the agent (default: 3 iterations, 15-min wall-clock cap)
sift-owl --case /cases/<CASENAME>

# 3. Inspect the audit trail
cat /cases/<CASENAME>/audit/exec_log.jsonl   | jq .
cat /cases/<CASENAME>/audit/agent_msgs.jsonl | jq .

# 4. Final report
ls /cases/<CASENAME>/reports/
```

## Verify evidence was not modified

```bash
# Original hashes (recorded at session start)
cat /cases/<CASENAME>/audit/evidence_hashes.json

# Re-hash and diff
sift-owl verify-spoliation --case /cases/<CASENAME>
```

If the agent ever produces a non-empty diff, that is a critical finding — open an issue.

## Architectural enforcement (what the MCP server prevents)

The `sift-mcp` server exposes typed read-only forensic functions only. The orchestrator and sub-agents have no shell access. This means an LLM cannot:

- delete, overwrite, or rename evidence files,
- mount evidence read-write (all mounts are forced `ro,noatime,noexec` by the server),
- exfiltrate evidence (no network egress tools exposed),
- run arbitrary binaries.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full trust-boundary table.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `volatility3 symbols not found` | First run downloads Microsoft PDB symbols; ensure outbound HTTPS to `downloads.volatilityfoundation.org`, or pre-populate `/opt/volatility3-2.20.0/volatility3/symbols/windows/` |
| `dotnet: command not found` | EZ Tools require `dotnet` runtime v6 — `apt install dotnet-runtime-6.0` |
| `permission denied` mounting EWF | The MCP server uses `sudo` for mount operations; ensure the running user is in `sudoers` for `mount`, `umount`, `ewfmount` |
| Long wall-clock on large memory images | Default cap is 15 min; bump with `--wall-clock-min 30` |
