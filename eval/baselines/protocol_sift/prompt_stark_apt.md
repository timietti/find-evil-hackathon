# Protocol SIFT baseline prompt — STARK-APT-001

> Injected as the **first user message** to vanilla Claude Code (Protocol SIFT global
> config + skill files installed). Working directory at launch: `/cases/find-evil-test2/`.
> The agent has full Protocol SIFT permissions: shell access, allow-listed forensic CLIs,
> deny-list for `rm -rf:* / dd:* / wget:* / curl:* / ssh:* / WebFetch`.

---

You are operating as a Principal DFIR Orchestrator on the SANS SIFT Workstation.

## Case STARK-APT-001 — SANS FOR508 Stark Research Labs Data Breach (legacy)

This is the canonical SANS FOR508 v3-v4 multi-host APT case. Acquisition: FTK Imager
**2012-04-06 → 2012-04-09**. Four hosts on subnet **10.3.58.0/24**:

| Host dir | OS | Role | Persona |
|---|---|---|---|
| `win2008R2-controller-c-drive` + `-memory` | Windows Server 2008 R2 x64 | Domain Controller | (DC) — `10.3.58.4` |
| `win7-32-nromanoff-c-drive` + `-memory` | Windows 7 x86 SP1 | Workstation | Natasha Romanoff — `10.3.58.5` |
| `win7-64-nfury-c-drive` + `-memory` | Windows 7 x64 | Workstation | Nick Fury |
| `xp-tdungan-c-drive` + `-memory` | Windows XP SP3 (build `2600.xpsp_sp3_gdr.111025-1629`) | Workstation | Tom Dungan |

Each host has both a paired E01 disk image and a `.001` raw memory dump.

The `precooked/` directories under each disk contain analyst-validated outputs
(Volatility, Plaso super-timelines, Redline). **Do NOT read `precooked/` — it is
ground truth, not agent input.** If you accidentally open something from that path,
discard the finding.

## Working hypothesis

External attacker reached one of the workstations, pivoted into the domain
(credential theft on the workstation → DC compromise), then propagated to the
remaining workstations to harvest documents / credentials. Expected APT-class TTPs:

- HTRAN / WEBC2 / BACKDOOR.BARKIOFORK family implants
- Manticore / GREENCAT-style C2
- DCSync / hash-dumping, then Kerberos abuse from a workstation
- Targeted document exfil (defense / R&D themes — "Stark Research Labs")

Specific implants, exfil paths, and entry vector are the case to solve.

## Evidence (read-only, do not modify)

All under `/cases/find-evil-test2/`. Memory `.001` files are raw RAM dumps. Disk
`.E01` files are FTK Imager E01 segments — Vol3 reads them directly with
`-f path/to/disk.E01`; Sleuth Kit reads E01 with `-i ewf`.

```
/cases/find-evil-test2/win2008R2-controller-c-drive/win2008R2-controller-c-drive.E01     14 GB
/cases/find-evil-test2/win2008R2-controller-memory/win2008R2-controller-memory-raw.001    3 GB
/cases/find-evil-test2/win7-32-nromanoff-c-drive/win7-32-nromanoff-c-drive.E01           11 GB
/cases/find-evil-test2/win7-32-nromanoff-memory/win7-32-nromanoff-memory-raw.001          4 GB
/cases/find-evil-test2/win7-64-nfury-c-drive/win7-64-nfury-c-drive.E01                   12 GB
/cases/find-evil-test2/win7-64-nfury-memory/win7-64-nfury-memory-raw.001                  2 GB
/cases/find-evil-test2/xp-tdungan-c-drive/xp-tdungan-c-drive.E01                          7 GB
/cases/find-evil-test2/xp-tdungan-memory/xp-tdungan-memory-raw.001                        4 GB
```

Note: Vol3 fails on `win7-32-nromanoff-memory` because the Win7-x86 PAE PDB symbol
table (`ntkrpamp.pdb` GUID `CE18EBF87B6A4C5CBF77806534BD9478`) is not auto-downloadable.
Document this as `[GAP]` and proceed with disk-side analysis on that host.

## Your task

Conduct a full multi-host investigation and answer all six goals:

1. **G1** Initial compromise vector and patient-zero host.
2. **G2** Lateral movement across the four hosts.
3. **G3** Implants / persistence mechanisms (process, service, scheduled task, registry).
4. **G4** Exfiltration: what was staged, packaged, and where it went.
5. **G5** Unified incident timeline (UTC) across all four hosts.
6. **G6** Credential-theft mechanism and which accounts were compromised.

Use the SIFT-installed toolset (Volatility 3, Memory Baseliner, Sleuth Kit + EWF,
Plaso, EZ Tools, bulk_extractor, YARA). Consult the relevant skill files in
`~/.claude/skills/`.

Note: on this instance Volatility 3 is in `$PATH` as `vol` (the global CLAUDE.md
path `/opt/volatility3-2.20.0/vol.py` is stale). Use `vol -f <image> <plugin>`.

Write all output to `./analysis/`, `./exports/`, and `./reports/` (relative to
the cwd `/cases/find-evil-test2/`). Final report:
`./reports/stark_apt_findings.md`.

For every claim in the final report, **tag it explicitly** as one of:

- `[CONFIRMED]` — directly observed in tool output (cite the exact tool + plugin + line)
- `[INFERRED]` — derived from observed evidence with explicit reasoning
- `[HYPOTHESIS]` — plausible but not yet supported

If you encounter ambiguity, do not hallucinate — flag the gap with `[GAP]` instead.

When you are done, print a one-line summary `BASELINE RUN COMPLETE` to stdout so
the harness knows to stop streaming.
