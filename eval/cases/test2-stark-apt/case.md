# Case STARK-APT-001 — SANS FOR508 Stark Research Labs Data Breach (legacy)

## Briefing

This is the classic SANS FOR508 v3-v4 lab dataset — the **Stark Research Labs (SRL)
Data Breach Intrusion** scenario. Acquisition occurred 2012-04-06 → 2012-04-09 with
FTK Imager 3.1 (memory) and 3.3 (disk). The scenario predates the current "Crimson
Osprey / SHIELDBASE" iteration but is the canonical multi-host APT case the FOR508
course was built around for years.

Evidence covers four hosts on subnet **10.3.58.0/24**:

| Host | OS | Role | Persona |
|---|---|---|---|
| `win2008R2-controller` | Windows Server 2008 R2 x64 | Domain Controller | (DC) |
| `win7-32-nromanoff` | Windows 7 x86 SP1 | Workstation | Natasha Romanoff |
| `win7-64-nfury` | Windows 7 x64 | Workstation | Nick Fury |
| `xp-tdungan` | Windows XP SP3 | Workstation | (Tom Dungan?) — XP build lab `2600.xpsp_sp3_gdr.111025-1629`, captured `2012-04-06 20:14:10 UTC`, 1 CPU |

Each host has both a paired E01 disk image and a `.001` raw memory dump, plus a
Mandiant Redline `.mans` session (pre-existing memory analysis). Several disks ship
with `precooked/` directories containing Volatility output, Plaso super-timelines,
VSS extracts, and bulk_extractor output — these are SANS course solutions and
serve as **ground truth** for our accuracy report.

## Scope vs. ROCBA-001

| Aspect | ROCBA-001 | STARK-APT-001 |
|---|---|---|
| Hosts | 1 (Surface) | 4 (DC + 2 Win7 + XP) |
| Evidence | Memory only (18 GB) | Memory + disk (8 files, ~58 GB) |
| Scenario | Physical break-in + IP theft | Multi-stage APT intrusion + lateral movement |
| Cross-source correlation surface | None — no disk | High — 4 disk+memory pairs, lateral movement |
| Ground truth available | Briefing PPTX only | `precooked/` Volatility/Plaso/Redline solutions |
| Difficulty | Single-pass triage | Multi-host correlation, AD compromise, persistence hunt |

These two cases exercise complementary parts of SIFT-OWL. ROCBA-001 is fast and
cheap (good for iteration). STARK-APT-001 stresses the cross-source correlator and
multi-host orchestration.

## Threat actor

The `precooked/redline/APT1 - IOCS/` directory shipped with the dataset confirms
the scenario's threat actor is **APT1** (Mandiant's designation for the PLA Unit
61398 / "Comment Crew" — the canonical Chinese state actor of the 2012-2013 era).
Treat this as a privileged ground-truth label, not as agent input. The agent must
identify APT1 (or at least APT1-class TTPs) from the evidence, not from the
folder name.

## Working hypothesis

External attacker reached one of the workstations, pivoted into the domain
(credential theft on the workstation → DC compromise), then propagated to the
remaining workstations to harvest documents / credentials. Given the APT1 label,
expect TTPs like:

- HTRAN / WEBC2 / BACKDOOR.BARKIOFORK family implants
- Manticore / GREENCAT-style C2 to PLA infrastructure
- DCSync / hash-dumping, then Kerberos abuse from a workstation
- Targeted document exfil (defense / R&D themes — fits "Stark Research Labs")

Exact entry vector, specific implants, and exfil paths are the case to solve.

## Investigation goals

1. **G1** Identify the initial compromise vector and the patient-zero host.
2. **G2** Map lateral movement across the four hosts.
3. **G3** Identify implants / persistence mechanisms (process, service, scheduled task, registry).
4. **G4** Identify exfiltration: what was staged, packaged, and where it went.
5. **G5** Build the unified incident timeline (UTC) across all four hosts.
6. **G6** Identify credential-theft mechanism and which accounts were compromised.

## Strong signals to mine

- **Domain Controller events** — Kerberos-related authentications, golden-ticket / silver-ticket residue, replication anomalies (DCSync), Event IDs 4624/4625/4768/4769/4770/4776.
- **Cross-host process tree** — common C2 implant / RAT names recurring across hosts. Look for the same parent-orphaned process across `nromanoff`, `nfury`, `tdungan`.
- **Workstation → DC SMB/RPC** — `net.exe`, `wmic.exe`, `psexec`, `winrm`, `Service.exe` artefacts on the workstation, paired with logon events on the DC.
- **Persistence** — Run keys, services, scheduled tasks, WMI subscriptions, sticky-key replacement (XP era).
- **Credential theft** — Mimikatz residue (sekurlsa cache, lsass dump artifacts), ntds.dit reads on DC.
- **Exfiltration staging** — `*.7z`, `*.rar`, `*.zip` in temp paths; large network transfers in netscan.

## Held-out vs dev split (revised after dataset 2 intake)

| Case | Status | Why |
|---|---|---|
| ROCBA-001 | **DEV** | Single host, fast iteration. Use freely; case context already in `case.yaml`. |
| STARK-APT-001 | **VALIDATE** (provisional) | Rich ground truth via `precooked/`. Best candidate for the accuracy-report numbers. May reassign to DEMO if dataset 3 turns out to be a better validate target. |
| Dataset 3 | TBD | When it lands. |

The full split is not finalised until dataset 3 is on disk. Lock in `eval/cases/README.md` then.

## Evidence integrity

- All 8 evidence files SHA-256-hashed at intake (`intake/hashes/*.sha256`).
- FTK Imager-recorded MD5/SHA1 from acquisition time preserved in `case.yaml.acquisition_hashes` and the original `.E01.txt` / `.raw.001.txt` sidecars.
- This repo never writes to `/cases/find-evil-test2/`. SIFT-OWL output goes to `eval/results/test2-stark-apt/`.

## Pre-cooked extras (do NOT feed to the agent)

The `precooked/` and `baseline-memory/` directories contain analyst-validated reference output:

- `win7-32-nromanoff-c-drive/precooked/volatility/` — Vol2 plugin output captured by SANS instructors.
- `win7-32-nromanoff-c-drive/precooked/timeline/` — Plaso super-timeline.
- `win7-32-nromanoff-c-drive/precooked/redline/` — Mandiant Redline `.mans` analysis session.
- `win7-32-nromanoff-c-drive/precooked/volume-shadow/` — VSS extracts + super-timeline.
- `xp-tdungan-c-drive/precooked/volatility/` — Vol output.
- `xp-tdungan-c-drive/precooked/redline/` — Redline session + Mandiant whitelist.
- `xp-tdungan-memory/baseline-memory/XPSP3x86-baseline.img` — clean XP baseline for Memory Baseliner diff.
- `*-memory/*.mans` — Mandiant Redline pre-existing analysis sessions for each host.

These are the closest thing to ground truth the dataset provides. Used **only** for
post-run scoring; never as agent input.

## Open questions

1. Are the `precooked/` Volatility outputs from Vol2 (legacy) or Vol3? (Likely Vol2 given 2012/2017 dates — output format will differ.)
2. Does the `win7-32-nromanoff-memory/` raw image have an integrity issue, or did parallel symbol downloads collide on first vol run? (Re-running serially.)
3. What is `tdungan`'s full first name? The username alone will not tell us.

## Vol3 image profiles (after intake)

| Host | OS | Build | Arch | CPUs | SystemTime (UTC) | Vol3 status |
|---|---|---|---|---|---|---|
| **dc** | Windows Server 2008 R2 SP1 | 7601 | x64 | 1 | 2012-04-06T23:19:12Z | ✅ resolved |
| **nfury** | Windows 7 SP1 | 7601 | x64 | 1 | 2012-04-06T21:28:39Z | ✅ resolved |
| **tdungan** | Windows XP SP3 | 2600 | x86 | 1 | 2012-04-06T20:14:10Z | ✅ resolved (NTBuildLab `2600.xpsp_sp3_gdr.111025-1629`) |
| **nromanoff** | Windows 7 SP1 (x86 PAE) | 7601 | x86 | ? | n/a | ⚠️ **Vol3 PDB symbol download failing** (`ntkrpamp.pdb`/`CE18EBF87B6A4C5CBF77806534BD9478`) |

**nromanoff Vol3 issue:**
- `vol banners.Banners` succeeds and reports `ntkrpamp.pdb|CE18EBF87B6A4C5CBF77806534BD9478|2`, so the image itself is readable.
- Translation-layer auto-detection fails because Vol3 cannot fetch / convert that specific PDB. Microsoft Symbol Server availability is intermittent for old Win7 SP1 x86 PAE kernels.
- **Workarounds available**:
  - **(b) confirmed**: `precooked/redline/nromanoff.mans` is a Mandiant Redline session pre-recorded against this image — usable as ground-truth memory artefacts for nromanoff post-run scoring.
  - (a) manually download the PDB and run `pdbconv.py`.
  - (c) Vol2 fallback for that host only.
- For SIFT-OWL: this is a tool-level failure, not an MCP-server bug. The agent's specialist will see a `ToolError` and should pivot to disk-side analysis for nromanoff and the Redline ground-truth file.
