# Evidence dataset documentation

Documentation of every evidence set SIFT-OWL was developed,
evaluated, and reported against. All datasets were either
provided by the FIND EVIL! hackathon organisers (delivered to
`/cases/find-evil-test*/` on the SIFT Workstation) or originate
from SANS DFIR course labs that the agent was pointed at on the
same paths.

The agent itself is evidence-agnostic. Anyone running SIFT-OWL
against their own evidence registers a new case via the
walkthrough in `JUDGES.md` (Claude scaffolds `case.yaml` from
hashed evidence — no schema authoring required).

> **Accessibility for judges.** Every evidence set listed here is
> **first-party hackathon material** — supplied by the FIND EVIL!
> organisers and downloaded from the official distribution link
> to a fixed `/cases/find-evil-test*/` path tree on the SIFT
> Workstation. Nothing is privately sourced, paywalled, or
> examiner-only. A judge with the same hackathon access can pull
> the identical images and reproduce every run bit-for-bit — the
> SHA-256 anchors pinned in each `eval/cases/<id>/case.yaml`
> confirm an exact match before the agent will launch.

---

## Per-case integrity

Every evidence file has a SHA-256 anchor pinned in the matching
`eval/cases/<case-id>/case.yaml`. The v2 self-correction loop
re-hashes each entry at start-up and refuses to launch the
investigator if any hash drifts (`audit/pre_run_hashes.json` +
`audit/post_run_hashes.json`). Evidence is mounted read-only at
the MCP-tool boundary — see `docs/ARCHITECTURE.md` trust
boundaries TB2 and TB3.

---

## 1. ROCBA-001 — Fred Rocba / SRL break-in

| | |
|---|---|
| Source | FIND EVIL! hackathon — organiser-provided |
| Path on SIFT | `/cases/find-evil-test/` |
| Scenario | Single-host Windows 10 employee laptop (Microsoft Surface); residential break-in during family vacation; suspected IP theft from a Stark Research Labs–issued device |
| Hosts | 1 |
| Total size | ~100 GiB (memory + disk) |
| Case briefing | `ROCBA-BACKGROUND.pptx` ships alongside the evidence |
| Manifest | [`eval/cases/rocba-001/case.yaml`](eval/cases/rocba-001/case.yaml) + [`case.md`](eval/cases/rocba-001/case.md) |
| Investigator prompt | [`eval/agents/sift_owl_v2/prompt-rocba-001.md`](eval/agents/sift_owl_v2/prompt-rocba-001.md) |
| Role in submission | **Development case** (iterated on during build) |

Evidence items:

| File | Kind | SHA-256 | Notes |
|---|---|---|---|
| `Rocba-Memory.raw` | memory_image | `eb33bdf6…282e10563` | 18.7 GiB, captured 2020-11-16T02:32:38Z |
| `rocba-cdrive.e01` | disk_image | `f2eb856d…d81b5c67` | 81 GiB raw (EnCase L1); X-Ways Forensics 20.1 acquisition 2020-12-18; disk dropped by organisers 2026-06-08 (mid-hackathon) |
| `ROCBA-BACKGROUND.pptx` | case_briefing | `44a12c54…d8980834` | Organiser-provided context deck |

---

## 2. STARK-APT-001 — SANS FOR508 Stark Research Labs APT

| | |
|---|---|
| Source | FIND EVIL! hackathon — organiser-provided (SANS FOR508 lab) |
| Path on SIFT | `/cases/find-evil-test2/` |
| Scenario | 4-host enterprise compromise; APT-style intrusion 2012-04-06 → 2012-04-09; Domain Controller + 3 workstations |
| Hosts | 4 (DC + nromanoff + nfury + tdungan) |
| Total size | ~80 GiB across paired disk + memory per host |
| Manifest | [`eval/cases/test2-stark-apt/case.yaml`](eval/cases/test2-stark-apt/case.yaml) + [`case.md`](eval/cases/test2-stark-apt/case.md) |
| Investigator prompt | [`eval/agents/sift_owl_v2/prompt-test2-stark-apt-v3.md`](eval/agents/sift_owl_v2/prompt-test2-stark-apt-v3.md) |
| Role in submission | **Development case** (multi-host shakedown) — also used as a Protocol SIFT baseline comparison (the baseline failed at $10.99 over budget) |

Evidence items (8 files; per-host paired disk + memory):

| Host | Role | OS | IP | Disk E01 sha256 | Memory raw sha256 |
|---|---|---|---|---|---|
| dc | Domain Controller | WS 2008 R2 SP1 x64 | 10.3.58.4 | `389ea6b4…fd6db4e7e` | `0980b543…ae770edd` |
| nromanoff | Workstation | Win 7 SP1 x86 PAE | 10.3.58.5 | `f9266213…5a5a1e5b6` | `f40af394…25517d728` |
| nfury | Workstation | Win 7 SP1 x64 | 10.3.58.6 | `a5df0b38…cf06d1589c7` | `0b53c169…96a27c9f5b` |
| tdungan | Workstation | Win XP SP3 x86 | 10.3.58.7 | `11751184…825e402eb0` | `bf5c4740…b9b9775cc` |

---

## 3. SHIELDBASE / CRIMSON OSPREY — SANS FOR508 Lab 1.1

| | |
|---|---|
| Source | FIND EVIL! hackathon — organiser-provided (SANS FOR508 Lab 1.1; canonical Protocol-SIFT scenario by Rob Lee) |
| Path on SIFT | `/cases/find-evil-test3/evidence/` |
| Scenario | 15+ host Active-Directory enterprise compromise by a state-level APT designated "CRIMSON OSPREY"; declared 2023-01-24; external IR consultant engagement |
| Hosts | 15+ across 6 subnets (services, R&D, business, management, DMZ, VPN) |
| Total size | ~198 GiB (7 disk E01s + 23 memory raws) |
| Manifest | [`eval/cases/test3-shieldbase/case.yaml`](eval/cases/test3-shieldbase/case.yaml) + [`case.md`](eval/cases/test3-shieldbase/case.md) |
| Investigator prompt | [`eval/agents/sift_owl_v2/prompt-test3-shieldbase.md`](eval/agents/sift_owl_v2/prompt-test3-shieldbase.md) |
| Role in submission | **Held-out final-evaluation case.** SIFT-OWL was *not* iterated on against this dataset during development; the v2 loop's strict-verified score (89.9 % verified, 71/79 claims) was produced after the agent was locked. |

Per-host breakdown in `case.yaml` (`disk_images:` and
`memory_images:` blocks); each file has a `size_bytes` anchor.
SHA-256 anchors were captured at acquisition into the
case.yaml at lock-in.

---

## 4. VANKO-001 — SANS FOR500 "Abducted Zebrafish"

| | |
|---|---|
| Source | FIND EVIL! hackathon — organiser-provided (SANS FOR500 case) |
| Path on SIFT | `/cases/find-evil-test4/` |
| Scenario | Single-host insider-threat IP theft; Anthony Vanko, lead biochemical engineer at Stark Enterprises DC R&D facility; JARVIS automated monitoring flagged a transfer 2016-06-30; suspected exfil of classified research |
| Hosts | 1 (Microsoft Surface 3 physical disk) |
| Total size | 116 GiB raw / 21-segment E01 chain |
| Manifest | [`eval/cases/test4-vanko/case.yaml`](eval/cases/test4-vanko/case.yaml) + [`case.md`](eval/cases/test4-vanko/case.md) |
| Investigator prompt | [`eval/agents/sift_owl_v2/prompt-test4-vanko.md`](eval/agents/sift_owl_v2/prompt-test4-vanko.md) |
| Role in submission | **Held-out final-evaluation case.** Organiser-dropped late in the build window; SIFT-OWL was not iterated against the content. Held-out single-shot scored 36.4 %; a prompt-side token-quoting-style fix (W3-60) raised the next run to 100.0 % strict-verified (37/37) — see `docs/ACCURACY_REPORT.md` §2.4 for the gap analysis. |

Evidence items:

| File | Kind | SHA-256 | Notes |
|---|---|---|---|
| `surface_physical.E01` (chain `.E01..E21`) | disk_image | `0a44ad8d…c7aa3b1c` | 116 GiB raw; FTK Imager 2.9.0.1385; acquired 2016-11-04T17:47:41Z; examiner Ovie Carroll; GPT, 6 partitions; main C: at slot 3, sector 1411072, length 230883328 sectors; EWF-embedded MD5 `4032d556…0e95603c`, SHA-1 `e0e72dfc…35bc85ce7` |
| `Vanko Student Scenario_D01_01.docx` | case_briefing | (not hash-pinned — non-evidentiary) | Organiser-provided briefing |
| `cylr_collection/` | triage_collection | (directory, not hash-pinned) | Companion CyLR rapid-triage collection of Windows critical artefacts from the same disk; not load-bearing for the eval but available for cross-check |

---

## Held-out vs development discipline

| Case | Status | Why |
|---|---|---|
| ROCBA-001 | development | First end-to-end case; the agent's prompt was iterated against it. Disk image dropped mid-hackathon (2026-06-08) and re-evaluated under W3-58. |
| STARK-APT-001 | development | Multi-host shakedown; prompt iterated. |
| SHIELDBASE | **held-out** | Canonical Protocol-SIFT scenario. Locked at v1 of the prompt; never tuned to its content. |
| VANKO-001 | **held-out** | Organiser drop, late in the build. Held-out single-shot at 36.4 % surfaced bug H; W3-60 prompt-side fix (not validator code) lifted the next run to 100.0 %. Both runs are preserved verbatim. |

Per-iteration validator reports for every run live under
`eval/results/<case-id>/sift-owl-v2/<UTC>-sonnet/` (audit log
+ iterations/ + final_response.md + validator_report.{md,json}).

---

## Provenance + integrity summary

- **All evidence sets were delivered to a fixed path tree** on
  the SIFT Workstation (`/cases/find-evil-test{,2,3,4}/`) and
  treated strictly read-only by the agent.
- **SHA-256 anchors** for every evidence file are pinned in
  the per-case `eval/cases/<id>/case.yaml`. The harness
  re-hashes at start-up and at finish; mismatches abort the run.
- **EWF-embedded acquisition hashes** (MD5 + SHA-1, surfaced
  by `ewfinfo`) were preserved into the case.yaml `media_md5:`
  / `media_sha1:` fields where available — these correspond to
  the raw decompressed disk image inside each E01 chain and
  predate any SIFT-OWL handling.
- **No evidence file was modified, copied, mounted with write
  access, or otherwise altered** at any point. The architecture
  (`docs/ARCHITECTURE.md` §Trust Boundaries) makes spoliation
  structurally unreachable — the MCP boundary exposes only
  typed read-only forensic functions; no `open(..., "w")`,
  no shell, no FUSE write layer.

---

## See also

- [`README.md`](README.md) — project overview + headline accuracy
- [`JUDGES.md`](JUDGES.md) — self-contained runbook to run the agent
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — trust boundaries TB1-TB7
- [`docs/ACCURACY_REPORT.md`](docs/ACCURACY_REPORT.md) — full per-case strict-verified scores + variance analysis
- [`docs/MITRE_COVERAGE.md`](docs/MITRE_COVERAGE.md) — per-ATT&CK-technique coverage of the 38-tool inventory
