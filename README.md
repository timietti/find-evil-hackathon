# SIFT-OWL — Autonomous DFIR Agent for SANS SIFT

> **Submission for [FIND EVIL!](https://find-evil.devpost.com/)** — SANS hackathon, Jun 15 2026.
>
> Codename: **SIFT-OWL** — *Operate, Witness, Learn*.

## Status

🚧 Under active development. See [`plans/MASTER_PLAN.md`](plans/MASTER_PLAN.md) for the full strategy and weekly milestones.

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

> **Not yet runnable.** First runnable build target: end of W2 (May 21, 2026).

```bash
git clone https://github.com/timietti/find-evil-hackathon.git
cd find-evil-hackathon
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Point at a case directory containing E01 + memory image
sift-owl --case /cases/<CASENAME> --max-iterations 3
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
