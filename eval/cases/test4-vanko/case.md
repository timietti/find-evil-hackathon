# Case VANKO-001 — SANS FOR500 "Abducted Zebrafish" / Anthony Vanko IP theft

## Briefing

This is the SANS FOR500 student-handout scenario: **"The Case of the
Abducted Zebrafish."** The subject is Anthony Vanko, a lead
biochemical engineer at Stark Enterprises' DC Research and
Development Facility, whose work centres on rapid cell regeneration
and Zebrafish DNA splice testing.

In **June 2016** internal Stark Enterprises documents (including
calculations of cell regrowth, rapid cell regeneration research, and
ZF DNA splice test notes) appeared on a Chinese university research
file share. The Stark Intelligence Division identified Vanko —
working on those exact topics — as a person of interest.

On **2016-06-30** the JARVIS automated network-monitoring AI
detected a large volume of data transferred from the Stark Research
server to Vanko's workstation. The directories sourced from
`\StarkResearch\Level 5..8 Classified\` were flagged. JARVIS
suspended Vanko's network account and emailed him a notice that his
activity scored 82.3 % likelihood of attempted IP theft.

On **2016-11-04** Vanko's Microsoft Surface 3 was forensically
imaged by Ovie Carroll using FTK Imager. SIFT-OWL's job is to
investigate whether Vanko was involved in the dissemination, and if
so, what happened to the data.

## Evidence available

| File / path | Description |
|---|---|
| `surface_physical.E01..E21` | Full physical Surface 3 disk, EWF chain (21 segments). 116 GiB raw / ~42 GB compressed. MD5 `4032d556…` + SHA-1 `e0e72df…` embedded in the EWF metadata. **GPT-partitioned** — 6 partitions; the main C: drive is **partition 003 starting at sector 1411072** — pass `offset=1411072` to `tsk_fs_stat` / `tsk_fls_list` / `tsk_icat_extract`. |
| `vanko-c-drive.CYLR/G/` | CyLR rapid triage collection: pre-extracted `$LogFile`, `$MFT`, `ProgramData`, `Users`, `Windows`. Same disk; smaller and faster but **lacks $UsnJrnl + slack/freelist**. |
| `Vanko Student Scenario_D01_01.docx` | Case briefing (this document). |

**No memory image** for this case. Disk-side investigation only.

> Note: the CYLR directory also contains a `FOR500HANDOUT_Vanko
> Master Scenario Solution.pdf` (the student exercise's answer key).
> The MCP boundary exposes no tool that can read PDFs, so the
> solution is unreachable from inside the agent loop and does not
> contaminate the investigation. Flagged here for human review only.

## Investigation goals

1. **G1** Was Vanko involved with the dissemination of classified
   information?
2. **G2** Validate whether Vanko copied a large volume of classified
   data from the StarkResearch server.
3. **G3** What was done with the data afterwards (cloud / USB /
   network share / external transfer)?

## Strong signals to mine

- **Mapped network drives** to `\StarkResearch\` — registry
  `\NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\
  MountPoints2` for mapped UNC paths; `LinkFiles` cited under
  `Recent`.
- **Document references**: filenames or folder names containing
  `cell regeneration`, `Zebrafish`, `ZF DNA`, `Level 5..8 Classified`
  in Recent JumpLists, ShellBags, Office MRUs, Edge / IE history.
- **Outbound exfil channels**: USB-mass-storage device arrival
  events (`Microsoft-Windows-DriverFrameworks-UserMode/Operational`
  + `setupapi.dev.log`); cloud-sync clients (Dropbox / OneDrive /
  Google Drive) installed and active; webmail / browser uploads;
  upload-tool prefetches (FileZilla, WinSCP, PuTTY pscp, curl,
  wget).
- **File copying tooling**: `robocopy`, `xcopy`, `7z`, `rar`
  invocations in Prefetch or in `consolehost_history.txt`.
- **Volume Shadow Copy** snapshots (vssadmin output is typically
  not on a workstation, but VSS volumes if exposed contain
  point-in-time copies — useful when the live FS has been wiped).
- **Anti-forensic activity** if any: SDelete, CCleaner, Eraser,
  bleachbit prefetches; recent timestomping.
- **Browser / email artefacts**: posting URLs (Chinese-language
  domains), anonymous file-share services (mega, anonfiles, etc.).
- **JumpLists** for File Explorer, Edge, Word, Excel, PowerPoint —
  surfaces "what files the user opened" with timestamps.

## Held-out vs dev split

ROCBA-001 was promoted to **VALIDATE** (dev): we've iterated on it.
STARK-APT-001 was **DEV** until SHIELDBASE arrived. SHIELDBASE was
the **HELD-OUT** single-shot for accuracy-report numbers.

**VANKO-001 is the second held-out case.** As of 2026-06-12 no
SIFT-OWL run has been fired on this data. The first run should be
done **without prompt-tuning to the case's specifics**, so the
score is intrinsic.

## Evidence integrity

- Evidence files at `/cases/find-evil-test4/`, hashed at intake (see
  `case.yaml`).
- This repo NEVER writes to `/cases/find-evil-test4/`. All SIFT-OWL
  output goes to `eval/results/test4-vanko/{analysis,exports,reports,
  audit}/`.
- Pre-run and post-run hash checks are enforced by the v2 loop
  harness; multi-segment EWF chains are anchored by their `.E01`
  SHA-256 (`0a44ad8d…`).
