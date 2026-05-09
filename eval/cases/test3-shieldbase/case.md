# Case SHIELDBASE-CRIMSON-OSPREY — SANS FOR508 Lab 1.1

## ⚠ Held-out validation + demo case

This is the canonical scenario the Protocol SIFT lab was built around. **Do not
iterate SIFT-OWL on this dataset during development.** It is reserved for:

1. Final accuracy-report numbers — SIFT-OWL findings vs. the documented IOCs.
2. The 5-minute demo video for the hackathon submission.

Use **ROCBA-001** (DEV — fast iteration, ~$1/run) or **STARK-APT-001** (TRAIN —
multi-host APT1 from 2012, exercises cross-source correlation) for everything else.

## Briefing

Stark Research Labs (SRL) — domain `SHIELDBASE` (Windows Server 2022, 2022 DFL)
declared an incident on **2023-01-24** under attack from a state-level APT named
**CRIMSON OSPREY**. SIFT-OWL is engaged as external IR consultant alongside
Roger Sydow (IT Admin, `rsydow-a`) and Clint Barton (IT Security Analyst, `cbarton-a`).

### Network topology

| Network | Subnet | Hosts |
|---|---|---|
| Management | `172.16.8.0/24` | log01, assess01/02, sft01, trust01, adusa01 |
| Services | `172.16.4.0/24` | dc01, file01, exchange01, proxy01, dev01, sql01 |
| Business Line | `172.16.7.0/24` | wksta01–10 (Win11) |
| **R&D** | `172.16.6.0/24` | **rd01–rd10 — lateral movement target: 172.16.6.12** |
| DMZ | `172.16.19.0/24` | dns01, ftp01, smtp01 |
| VPN | `172.16.30.0/24` | Remote workers |

**External attacker IP**: `172.15.1.20`.

## Evidence inventory — substantial scope vs. the prior two cases

| | ROCBA-001 | STARK-APT-001 | **SHIELDBASE-CRIMSON-OSPREY** |
|---|---|---|---|
| Hosts | 1 | 4 | **15+** |
| Disk images | 0 | 4 | **7** |
| Memory images | 1 | 4 | **22** |
| Total bytes | 18 GB | ~58 GB | **≈ 199 GB** |
| Capture year | 2020 | 2012 | 2018 + 2021 + 2023 |
| Threat actor | physical break-in | APT1 | **CRIMSON OSPREY (state-level)** |

### Disk images (7, ≈ 101 GB)

```
base-dc-cdrive.E01            12.3 GB   Domain Controller (dc01)
base-file-cdrive.E01          16.4 GB   File Server
base-rd-01-cdrive.E01         17.8 GB   RD-01 — PRIMARY COMPROMISE HOST
base-rd-02-cdrive.E01         17.2 GB   RD-02
base-wkstn-01-c-drive.E01     16.9 GB   Workstation 01
base-wkstn-05-cdrive.E01      14.8 GB   Workstation 05
dmz-ftp-cdrive.E01            12.8 GB   DMZ FTP server
```

### Memory images (22, ≈ 98 GB) — multi-tier coverage

Each `*.img` ships with a `*.md5` sidecar carrying the acquisition-time MD5 (a
chain-of-custody anchor independent of our SHA-256 intake hashes).

**Servers:** dc, file (×2 incl. snapshot 5), mail (Exchange — 18 GB!), av,
hunt (forensic wkstn), elf (Event Log Forwarder), sp (SharePoint), admin.

**RD farm (6 hosts):** rd01, rd-02, rd-03, rd-04, rd-05, rd-06.

**Workstations (6 + a re-capture):** wkstn-01 (2018-era + a separate 2021 capture
named `base-wkstn-01-mem.img`), wkstn-02..06.

The 2018 acquisition timestamps + 2023 incident date suggests the lab was
recorded against a system clock advanced to early 2023 — the *content* of the
memory images reflects the 2023-01-25 SHIELDBASE intrusion.

## Privileged ground truth

The case CLAUDE.md (sha256 `f248a36b...`) shipped at all three case roots is
**identical** to Protocol SIFT's `case-templates/CLAUDE.md`. That file documents
the lab's known IOCs:

| IOC | Detail |
|---|---|
| `STUN.exe` | `C:\Windows\System32\STUN.exe`, **PID 1912**, parent `svchost.exe (PID 1244)` — on **rd01** |
| `msedge.exe` (masquerading) | 7 instances spawned from STUN.exe + explorer.exe; classified `Trojan:Win32/PowerRunner.A` |
| `pssdnsvc.exe` | suspicious service in `C:\Windows\` — name/path mismatch for PsShutdown |
| `atmfd.dll` | missing driver — present in Autoruns but absent from filesystem |
| Lateral movement | `net use H: \\172.16.6.12\c$\Users` via `net.exe (PID 9128)` |
| Execution chain | STUN.exe (scheduled task) → svchost.exe → taskhostw.exe |
| Evasion | msedge.exe masquerading; Defender detected + terminated repeatedly |

**Timeline anchors (UTC):**

- `2023-01-24` — incident declared, F-Response agents deployed
- `2023-01-25T14:52:04Z` — lateral movement to `172.16.6.12`
- `2023-01-25T14:56:42Z..15:04:43Z` — msedge.exe PIDs spawned
- `2023-01-25T15:00:56Z` — msedge.exe PID 2524 active at memory capture
- `2023-01-29T12:23:16Z` — Kansa post-intrusion collection (Autorunsc timestamp)

These are **privileged ground-truth labels** — kept *out* of the agent's input
when SIFT-OWL runs. They are read only at scoring time, by the eval harness,
to compute precision / recall / hallucination rate.

## Investigation goals (final)

1. **G1** Primary compromise host + initial access vector.
2. **G2** All malware implants + their persistence mechanisms.
3. **G3** Lateral movement map across SHIELDBASE — hosts in order.
4. **G4** Credentials stolen / abused, and from which host.
5. **G5** Data staged / exfiltrated, and how.
6. **G6** Unified UTC timeline across evidence sources.
7. **G7** TTP attribution (CRIMSON OSPREY signal).

## What this case tests in SIFT-OWL

| Capability | Why this case stresses it |
|---|---|
| Multi-host orchestration | 15+ hosts; agent must triage, not exhaustively analyse every host |
| Cross-source correlation | 7 disk + 23 memory pairs — disk artifacts (MFT, EVTX, AmCache, Prefetch) must agree with memory artifacts |
| Identifier resolution | "rd01" disk vs "base-rd01-memory.img" memory — agent must pair them and disambiguate from rd-02..06 |
| Token / context economics | A naive 9-call-per-host pattern explodes into 135 forensic calls; SIFT-OWL needs strategy to focus where evil lives |
| Hallucination defense at scale | More hosts → more chances to confabulate; the validator agent must hold up |

## Held-out vs dev split (final, with all 3 datasets in)

| Case | Status | Reason |
|---|---|---|
| **ROCBA-001** | **DEV** | Single host, 18 GB, fast iteration. Already in heavy use. |
| **STARK-APT-001** | **TRAIN / SECONDARY DEV** | 4 hosts, ~58 GB, APT1 lab. Different scenario from SHIELDBASE → useful for testing cross-source correlation without overfitting. |
| **SHIELDBASE-CRIMSON-OSPREY** | **VALIDATE + DEMO (held-out)** | 15+ hosts, ~199 GB, canonical SANS lab the hackathon was built around. Touched only at the end for accuracy numbers + demo video. |

Discipline: **never** point SIFT-OWL at `/cases/find-evil-test3/` during W3-W4
development. Only the final eval run + demo recording are permitted.

## Pre/post-run hash protocol (when this case is used)

1. Compute SHA-256 of every E01 + .img at intake — already done in
   `intake/hashes/{disk,memory}.sha256`.
2. After every SIFT-OWL run that touches this case, re-hash and diff. Any diff
   = critical spoliation finding.
3. Match against `*.md5` sidecars (acquisition-time hashes) on initial intake
   only — those are independent chain-of-custody anchors from SANS.

## Output destination

All SIFT-OWL output (analysis, exports, reports, audit) goes to
`./eval/results/test3-shieldbase/`. Nothing is written to
`/cases/find-evil-test3/`.
