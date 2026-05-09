# SIFT-OWL — Autonomous DFIR Agent for SANS SIFT

> **Submission for [FIND EVIL!](https://find-evil.devpost.com/)** — SANS hackathon, Jun 15 2026.
>
> Codename: **SIFT-OWL** — *Operate, Witness, Learn*.

## Status

🚧 Under active development. See [`plans/MASTER_PLAN.md`](plans/MASTER_PLAN.md) for the full strategy and weekly milestones.

### What's working today

- **`sift-mcp`** — FastMCP stdio server with 9 typed read-only memory-forensics functions (`vol3_image_info`, `vol3_psscan`, `vol3_pstree`, `vol3_cmdline`, `vol3_netscan`, `vol3_filescan`, `vol3_malfind`, `vol3_svcscan`, `vol3_userassist`). Any MCP client (Claude Code, custom agent, test harness) can connect and discover the inventory via `sift-mcp inspect`.
- **Architectural trust boundaries** — agent-side has no shell. Path validation rejects anything outside `/cases/` (or `$SIFT_OWL_EVIDENCE_ROOT`). Subprocess invocations are argv-list, never `shell=True`.
- **Per-call audit trail** — every MCP call writes one JSONL row to `audit/exec_log.jsonl` with `exec_id`, args, input/output sha256, parsed_summary, wall_ms. Every "confirmed" claim in a final report cites an `exec_id` for traceability.
- **55 tests green** (parsers + path validation + subprocess + 6-plugin E2E + 3 MCP wire-protocol round-trip).

## What this is

An autonomous, agentic AI forensics investigator that runs on the SANS SIFT Workstation and processes raw case data (disk images, memory captures, log archives) end-to-end without human checkpoints. It improves on the baseline [Protocol SIFT](https://github.com/teamdfir/protocol-sift) configuration along every judging axis:

| Concern | Protocol SIFT (baseline) | SIFT-OWL |
|---|---|---|
| Tool surface | `Bash(*)` allow-list with narrow deny-list | Custom MCP server exposing only typed read-only forensic functions |
| Evidence integrity | Prompt-based ("Never modify `/cases/`") | Architectural — RO bind mount + immutable bit + path allow-list |
| Audit trail | Single `$CONVERSATION_SUMMARY` line per session | Per-call JSONL with `exec_id`, hashes, parsed summary |
| Hallucinations | Caught only by humans | Validator agent — every "confirmed" claim must cite an `exec_id` |
| Context bloat | Single agent reads all raw output | Specialist sub-agents per domain; orchestrator sees structured summaries only |
| Self-correction | None | Persistent learning loop with cross-source correlation pass |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the system design and trust boundaries.

## Quick start

```bash
git clone https://github.com/timietti/find-evil-hackathon.git
cd find-evil-hackathon
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Inspect the MCP tool inventory (no Vol3 / evidence required)
sift-mcp inspect

# Run the MCP server (stdio transport — for an MCP client to connect)
sift-mcp --audit-dir ./audit --evidence-root /cases

# Once the orchestrator lands (W3), point it at a case:
# sift-owl --case /cases/<CASENAME> --max-iterations 3
```

Full installation / setup: [`INSTALL.md`](INSTALL.md).

## Repo layout

```
find-evil-hackathon/
├── plans/MASTER_PLAN.md     # strategy + weekly plan
├── docs/ARCHITECTURE.md     # system design + trust boundaries
├── mcp_server/              # custom MCP server (typed forensic functions)
│   ├── server.py
│   ├── tools/               # one module per typed function
│   ├── parsers/             # raw tool output → structured JSON
│   └── audit.py             # per-call JSONL writer
├── agents/                  # LangGraph orchestrator + specialists
│   ├── orchestrator.py
│   ├── memory_agent.py
│   ├── disk_agent.py
│   ├── timeline_agent.py
│   ├── correlator.py        # cross-source correlation pass
│   └── validator.py         # hallucination detector
├── audit/                   # per-run logs (gitignored except samples/)
├── tests/                   # pytest — incl. spoliation tests
├── eval/                    # ground truth + scoring harness
└── scripts/                 # one-off helpers
```

## License

MIT — see [LICENSE](LICENSE).
