# Case ROCBA-001 — Fred Rocba / SRL break-in & IP theft

## Briefing

Fred Rocba is a technical engineer recently hired (2020-10-24) by Stark Research Labs (SRL),
a high-tech R&D firm focused on biotech, metals research, and advanced alloy generation —
a long-standing target of nation-state cyber operations. SRL shipped Fred a new Microsoft
Surface for remote work; he used it from home with O365, OneDrive, Dropbox, Google Drive,
iCloud, and Zoom. Browsers installed: Edge, Firefox, Chrome.

On **2020-11-10** Fred and his family flew to Disney World on a planned vacation pre-dating
his job. On the evening of **2020-11-13** Fred's residence was broken into. Nothing physical
was stolen, but on returning Sunday afternoon **2020-11-15** Fred saw signs his SRL Surface
had been used. He left it powered on per SRL incident-team instructions, and memory was
captured at **2020-11-15 21:32:38 EST** (`2020-11-16T02:32:38Z`).

The C: drive was imaged later — **`rocba-cdrive.e01`**, X-Ways Forensics
acquisition on **2020-12-18** (81 GiB EnCase 1 raw, 23 GB compressed; EWF-
embedded MD5 / SHA-1 captured in `case.yaml`). The disk image landed
mid-development on **2026-06-08**; prior ROCBA runs (single-pass v1 →
v2 loop 91.7%) were memory-only.

## Working hypothesis

A physical adversary with hands-on access to a logged-in SRL workstation, with ≈ 36–48
hours of unmonitored use during which the legitimate user was provably absent
(Disney World, with photos syncing via iCloud).

## Investigation goals

1. **G1** What key projects did Fred have access to?
2. **G2** What was stolen?
3. **G3** Where was it transferred to (cloud / USB / network share / etc.)?
4. **G4** How was it stolen (tooling / technique)?
5. **G5** When did the activity occur (correlate with break-in window)?

## Strong signals to mine

- **Temporal**: anything user-driven inside `2020-11-13T22:00Z..2020-11-16T02:32Z`
  that is *not* photo / cloud sync is highly suspicious.
- **Network**: `windows.netscan` for exfil destinations during that window — flag any
  non-O365/Dropbox/iCloud/Google/Zoom endpoints.
- **Process tree**: console-attached processes (`conhost.exe` children), LOLBins
  (`net.exe`, `wmic.exe`, `mshta.exe`, `certutil.exe`, `powershell.exe -enc ...`),
  and any RDP / remote-management tools spawned outside the existing user session.
- **Removable media**: USB-mass-storage device arrival events, Volume Shadow Copy
  manipulation, robocopy / xcopy / 7z to non-default paths.
- **In-memory registry hives**: UserAssist (GUI execution), MUICache (binary path),
  TypedURLs (browser history residue).
- **Process working dirs / handles**: open File handles to project directories.

## Held-out vs dev split

This is the **first** of three datasets the user provided. **Mark this one DEV**:
we iterate on it; the orchestrator can read this `case.md` and `case.yaml` freely.

The two not-yet-arrived datasets:

- One → **VALIDATE** (held out; touched only at the end for accuracy-report numbers).
- One → **DEMO** (used to record the 5-minute screencast).

Final assignment is decided in `eval/cases/README.md` once all three are on disk.

## Evidence integrity

- Evidence files live at `/cases/find-evil-test/`, hashed at intake (see `case.yaml`).
- This repo NEVER writes to `/cases/find-evil-test/`. All SIFT-OWL output goes to
  `eval/results/rocba-001/{analysis,exports,reports,audit}/`.
- Pre-run and post-run hash checks must match — enforced by `scripts/verify_spoliation.sh`
  (W2 deliverable).

## Baseline plan

Before SIFT-OWL is built, capture **Protocol SIFT baseline** on this case:

1. Launch vanilla Claude Code from `/cases/find-evil-test/` (Protocol SIFT global config + skill files, untouched case CLAUDE.md placeholder still SRL-themed).
2. Give it the goals G1..G5 verbatim.
3. Capture: time-to-first-finding, time-to-final-report, hallucination rate, FPs, missed artifacts.
4. Save full session transcript to `eval/results/rocba-001/baseline-protocol-sift/`.

That number is what SIFT-OWL beats in the accuracy report.
