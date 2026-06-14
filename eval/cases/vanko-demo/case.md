# vanko-demo — FOR500 "Abducted Zebrafish" / Insider IP Theft

## What we know

Anthony Vanko is the lead biochemical engineer at Stark Enterprises' DC
Research and Development Facility. His research areas include rapid cell
regeneration and Zebrafish DNA splice testing — classified R&D at Levels 5–8.

In June 2016 a Chinese university research file share began hosting internal
Stark documents that match Vanko's research domains. In late June, Stark's
JARVIS network-monitoring AI detected a large-volume data transfer from the
Stark Research server into Vanko's Microsoft Surface 3 workstation. The source
directories were `\StarkResearch\Level 5 Classified\` through `Level 8 Classified\`.
JARVIS suspended Vanko's network account on 2016-06-30 and sent him an alert
(82.3% likelihood of attempted IP theft).

On 2016-11-04, Ovie Carroll acquired a full physical disk image of the Surface 3
using FTK Imager (21-segment EWF chain, 116 GiB raw). A companion CyLR triage
collection is also available for fast artefact access.

## What we want to find out

- **G1** Was Vanko the person who accessed and staged the classified documents?
- **G2** Did he copy a large volume of data from the StarkResearch server onto
  his workstation, and what is the forensic evidence for that transfer?
- **G3** How was the data exfiltrated — USB, cloud sync, email, web upload, or
  a direct network share — and is there evidence pointing to the Chinese recipient?
- **G4** Can forensic artefacts (MFT timestamps, Prefetch, NTUSER.DAT, SRUM)
  attribute the actions specifically to Vanko's Windows account on this machine?

## Evidence on hand

| File | Kind | Size | SHA-256 |
|---|---|---|---|
| `surface_physical.E01..E21` | disk_image (EWF, 21 segments) | 116 GiB raw | E01 segment: `0a44ad8d…` |
| `Vanko Student Scenario_D01_01.docx` | case briefing | 23 KB | `7c7950ba…` |
| `vanko-c-drive.CYLR/G/` | triage_collection (CyLR) | — | — |

No memory image exists for this case. All conclusions must be drawn from
disk-side artefacts: MFT, registry hives, Prefetch, JumpLists, SRUM, EVTX,
browser artefacts, and Recycle Bin records.
