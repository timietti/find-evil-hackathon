# Protocol SIFT baseline prompt — ROCBA-001

> Injected as the **first user message** to vanilla Claude Code (Protocol SIFT global
> config + skill files installed). Working directory at launch: `/cases/find-evil-test/`.
> The agent has full Protocol SIFT permissions: shell access, allow-listed forensic CLIs,
> deny-list for `rm -rf:* / dd:* / wget:* / curl:* / ssh:* / WebFetch`.

---

You are operating as a Principal DFIR Orchestrator on the SANS SIFT Workstation.

## Case ROCBA-001 — Fred Rocba / SRL break-in & IP theft

Fred Rocba is a technical engineer hired by Stark Research Labs (SRL) on **2020-10-24** and
shipped a Microsoft Surface for remote work. He used it from home with O365, OneDrive,
Dropbox, Google Drive, iCloud, and Zoom. Browsers installed: Edge, Firefox, Chrome.
Personal identities: `fred.rocba@gmail.com`, `fred.rocba@outlook.com`, iPhone +1-339-223-3317.
Corporate email: `frocba@stark-research-labs.com`.

On **2020-11-10 morning EST** Fred and his family flew to Disney World on a planned vacation.
On the evening of **2020-11-13 EST** his residence was broken into. The intruders accessed
his SRL Surface (left logged in). Fred returned **2020-11-15 PM EST**, did not touch the
laptop, and SRL captured RAM at **2020-11-15 21:32:38 EST** (`2020-11-16T02:32:38Z`).

**Temporal alibi:** any user-driven activity inside `2020-11-13T22:00Z .. 2020-11-16T02:32Z`
that is not iCloud / Dropbox / OneDrive / GoogleDrive / O365 sync is the intruder.

## Evidence (read-only, do not modify)

- `/cases/find-evil-test/Rocba-Memory.raw` — 18 GB Windows 10 build 19041 (x64) RAM capture
- `/cases/find-evil-test/ROCBA-BACKGROUND.pptx` — case briefing (you have already received the relevant context above; you do not need to open the PPTX)

## Your task

Conduct a full memory-only investigation and answer all five goals:

1. **G1** What key projects did Fred have access to?
2. **G2** What was stolen?
3. **G3** Where was it transferred to (cloud / USB / network share / etc.)?
4. **G4** How was it stolen (tooling / technique)?
5. **G5** When did the activity occur (correlate with break-in window)?

Use the SIFT-installed memory-analysis toolset (Volatility 3 + Memory Baseliner). Consult
`~/.claude/skills/memory-analysis/SKILL.md` and `~/.claude/skills/yara-hunting/SKILL.md`
for tool guidance.

Note: on this instance Volatility 3 is in `$PATH` as `vol` (the global CLAUDE.md path
`/opt/volatility3-2.20.0/vol.py` is stale). Use `vol -f <image> <plugin>` directly.

Write all output to `./analysis/`, `./exports/`, and `./reports/` (relative to this
directory). Final report: `./reports/rocba_findings.md`.

For every claim in the final report, **tag it explicitly** as one of:

- `[CONFIRMED]` — directly observed in tool output (cite the exact tool + plugin + line)
- `[INFERRED]` — derived from observed evidence with explicit reasoning
- `[HYPOTHESIS]` — plausible but not yet supported

If you encounter ambiguity, do not hallucinate — flag the gap instead.

When you are done, print a one-line summary `BASELINE RUN COMPLETE` to stdout so the
harness knows to stop streaming.
