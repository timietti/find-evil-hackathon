# Validator Report — iter_1

## Summary

- Total tagged claims:        **34**
  - CONFIRMED:                 26
  - INFERRED:                  4
  - HYPOTHESIS:                0
  - GAP:                       4
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           1 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                22 (some tokens found, some missing)
- ❌ failed:                 3 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 3.8%** (1 verified / 26 confirmed)

## Per-claim verdicts

### ⚠ partial _(line 39)_
- tools: `vol3_image_info`
- exec_ids: `482594d77c2f`
- matched: `2020-11-16T02:32:38Z`
- **missing**: `2020-11-13T22:00Z`, `ntuser.dat`, `\Users\fredr\ntuser.dat``, `C:\Users\fredr\ntuser.dat``, `C:\Users\fredr\ntuser.dat`, `2020-11-13T22:00Z – 2020-11-16T02:32:38Z`, `019e10af-5c21-7842-b611-482594d77c2f`
- claim: > # CASE ROCBA-001 — FINAL INVESTIGATION REPORT ## Memory-Only Analysis of Rocba-Memory.raw **Analyst:** SIFT-OWL v2 — Principal DFIR Orchestrator **Capture anchor:** `2020-11-16T02:32:38Z` [CONFIRMED —…

### ❌ failed _(line 47)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- **missing**: `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`
- claim: > The following SRL project directories were present in pool-memory file objects [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`]:

### ⚠ partial _(line 62)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `stark-research-labs.com.ost`, `frocba@stark-research-labs.com`, `frocba@stark-research-labs.com.ost`
- **missing**: `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`
- claim: > Email archive `frocba@stark-research-labs.com.ost` was also present in memory pool, confirming full corporate mailbox access [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`].

### ⚠ partial _(line 70)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `Starfury.docx`, `StarFury.zip`
- **missing**: `\Users\fredr\OneDrive\Desktop\SA-23E`, `\Users\fredr\OneDrive\StarFury.zip``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\OneDrive\Desktop\SA-23E Mitchell-Hyundyne Starfury.docx`, `\Users\fredr\OneDrive\StarFury.zip`
- 🚨 negation violations (claimed absent but found): `OneDrive - Stark Research Labs`
- claim: > - `\Users\fredr\OneDrive\StarFury.zip` [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`] — a compressed archive of StarFury material placed inside the OneDrive sync folder, meaning it would…

### ⚠ partial _(line 71)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `Starfury.docx`, `StarFury.zip`
- **missing**: `\Users\fredr\OneDrive\Desktop\SA-23E`, `\Users\fredr\OneDrive\StarFury.zip``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\OneDrive\Desktop\SA-23E Mitchell-Hyundyne Starfury.docx`, `\Users\fredr\OneDrive\StarFury.zip`
- 🚨 negation violations (claimed absent but found): `OneDrive - Stark Research Labs`
- claim: > - `\Users\fredr\OneDrive\StarFury.zip` [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`] — a compressed archive of StarFury material placed inside the OneDrive sync folder, meaning it would…

### ❌ failed _(line 83)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- **missing**: `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`
- claim: > [CONFIRMED files in memory — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`; INFERRED copying from concurrent process activity]

### ⚠ partial _(line 86)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `sdelete.exe`, `SDelete.lnk`, `SDelete.zip`, `sdelete64.exe`, `srl-h`
- **missing**: `\Users\fredr\Downloads\SDelete\sdelete.exe``, `\Users\srl-h\Downloads\``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\Downloads\SDelete\sdelete.exe`, `\Users\srl-h\Downloads\`
- claim: > **Anti-forensics applied to scope of theft:** - `\Users\fredr\Downloads\SDelete\sdelete.exe` and `SDelete.zip` present in pool memory; `SDelete.lnk` in Recent [CONFIRMED — exec_id `019e10ba-06c7-70c0-…

### ⚠ partial _(line 87)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `sdelete.exe`, `SDelete.lnk`, `SDelete.zip`, `sdelete64.exe`, `srl-h`
- **missing**: `\Users\fredr\Downloads\SDelete\sdelete.exe``, `\Users\srl-h\Downloads\``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\Downloads\SDelete\sdelete.exe`, `\Users\srl-h\Downloads\`
- claim: > **Anti-forensics applied to scope of theft:** - `\Users\fredr\Downloads\SDelete\sdelete.exe` and `SDelete.zip` present in pool memory; `SDelete.lnk` in Recent [CONFIRMED — exec_id `019e10ba-06c7-70c0-…

### ⚠ partial _(line 94)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `StarFury.zip`
- **missing**: `\Users\fredr\OneDrive\StarFury.zip``, `13.107.*`, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `52.114.*`, `52.167.*`, `019e10b2-33c8-71f0-b971-f1487a706533`, `\Users\fredr\OneDrive\StarFury.zip`
- claim: > **Channel 1 — Microsoft OneDrive cloud sync (primary confirmed exfil vector):** `\Users\fredr\OneDrive\StarFury.zip` placed in the OneDrive sync root [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590a…

### ❌ failed _(line 106)_
- tools: `vol3_netscan`
- exec_ids: `f1487a706533`
- **missing**: `019e10b2-33c8-71f0-b971-f1487a706533`
- claim: > [CONFIRMED connections — exec_id `019e10b2-33c8-71f0-b971-f1487a706533`]. RDP supports clipboard and drive-share redirection as built-in file transfer mechanisms. [INFERRED: files transferred via RDP …

### ⚠ partial _(line 114)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `fighter_starfury.jpg`, `StarFuryHeader.jpg`
- **missing**: `\Users\fredr\iCloudDrive\``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\iCloudDrive\`
- claim: > **Channel 4 — iCloud (possible pre-existing personal sync):** StarFury images `StarFuryHeader.jpg` and `fighter_starfury.jpg` were found at `\Users\fredr\iCloudDrive\` [CONFIRMED — exec_id `019e10ba-0…

### ⚠ partial _(line 121)_
- tools: `vol3_cmdline`
- exec_ids: `4c58ee0e06b2`
- matched: `MRC.exe`, `Tools\`
- **missing**: `D:\Tools\MRC.exe`, `019e10b2-2a45-70f1-933d-4c58ee0e06b2`
- claim: > **Step 1 — Physical break-in and USB deployment:** On the evening of 2020-11-13 EST, the intruder physically entered Fred's residence. The SRL Surface was left logged in (Fred on vacation). The intrud…

### ⚠ partial _(line 124)_
- tools: `vol3_pstree`, `vol3_cmdline`
- exec_ids: `dbe94c39f245`, `4c58ee0e06b2`
- matched: `7464`, `29440`, `explorer.exe`, `MRC.exe`
- **missing**: `019e10b0-a4a8-73c3-a0be-dbe94c39f245`, `019e10b2-2a45-70f1-933d-4c58ee0e06b2`
- claim: > **Step 2 — DameWare Mini Remote Control deployment:** `MRC.exe` (DameWare Mini Remote Control, a commercial remote admin tool, WOW64/32-bit) was launched by double-clicking it through Windows Explorer…

### ⚠ partial _(line 127)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-14T12:43:01Z`, `cmd.exe`
- **missing**: `2020-11-14T13:50Z`, `2020-11-13T22:09Z`, `019e10b3-343f-7270-b730-d532b6046c33`
- claim: > **Step 3 — File reconnaissance and staging (hands-on-keyboard, 2020-11-13T22:09Z – 2020-11-14T13:50Z):** The intruder browsed the filesystem using Windows Explorer (13 launches, 1:18:28 total focus [C…

### ⚠ partial _(line 127)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-14T12:43:01Z`, `cmd.exe`
- **missing**: `2020-11-14T13:50Z`, `2020-11-13T22:09Z`, `019e10b3-343f-7270-b730-d532b6046c33`
- claim: > **Step 3 — File reconnaissance and staging (hands-on-keyboard, 2020-11-13T22:09Z – 2020-11-14T13:50Z):** The intruder browsed the filesystem using Windows Explorer (13 launches, 1:18:28 total focus [C…

### ⚠ partial _(line 130)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `StarFury.zip`
- ✅ verified absences (negated): `019e10b2-2a45-70f1-933d-4c58ee0e06b2`
- **missing**: `\Users\fredr\OneDrive\``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\OneDrive\`
- claim: > **Step 4 — Archive creation and cloud staging:** `StarFury.zip` was created and placed in `\Users\fredr\OneDrive\` for automatic cloud exfiltration [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4…

### ⚠ partial _(line 133)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-14T04:39:15Z`, `regedit.exe`
- **missing**: `019e10b3-343f-7270-b730-d532b6046c33`
- claim: > **Step 5 — Registry manipulation:** `regedit.exe` was opened at `2020-11-14T04:39:15Z` [CONFIRMED UserAssist — exec_id `019e10b3-343f-7270-b730-d532b6046c33`]. [GAP: purpose unknown; possible modifica…

### ⚠ partial _(line 136)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-14T13:50:02Z`, `DropboxUninstaller.exe`
- **missing**: `SDelete.zip`, `\Users\fredr\Downloads\SDelete\``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\Downloads\SDelete\`, `019e10b3-343f-7270-b730-d532b6046c33`
- claim: > **Step 6 — Anti-forensic cleanup:** - `DropboxUninstaller.exe` run at `2020-11-14T13:50:02Z` — Dropbox removed, likely to prevent sync-based artifact trail [CONFIRMED UserAssist — exec_id `019e10b3-34…

### ⚠ partial _(line 137)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `SDelete.zip`
- **missing**: `2020-11-14T13:50:02Z`, `DropboxUninstaller.exe`, `\Users\fredr\Downloads\SDelete\``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\Downloads\SDelete\`, `019e10b3-343f-7270-b730-d532b6046c33`
- claim: > **Step 6 — Anti-forensic cleanup:** - `DropboxUninstaller.exe` run at `2020-11-14T13:50:02Z` — Dropbox removed, likely to prevent sync-based artifact trail [CONFIRMED UserAssist — exec_id `019e10b3-34…

### ⚠ partial _(line 140)_
- tools: `vol3_userassist`, `vol3_pstree`
- exec_ids: `d532b6046c33`, `dbe94c39f245`
- matched: `2020-11-16T02:31:13Z`, `MRC.exe`, `02:31:15Z`
- **missing**: `81.30.144.115`, `213.202.233.104`, `2020-11-16T02:30Z`, `02:32:38Z`, `019e10b2-33c8-71f0-b971-f1487a706533`, `019e10b0-a4a8-73c3-a0be-dbe94c39f245`, `019e10b3-343f-7270-b730-d532b6046c33`
- claim: > **Step 7 — Persistent remote re-entry (2020-11-16T02:30Z onwards):** RDP connections began at ~02:30Z from four external IPs. MRC.exe was re-launched at `2020-11-16T02:31:13Z` (UserAssist) / `02:31:15…

### ⚠ partial _(line 140)_
- tools: `vol3_netscan`
- exec_ids: `f1487a706533`
- matched: `81.30.144.115`, `213.202.233.104`
- **missing**: `2020-11-16T02:31:13Z`, `2020-11-16T02:30Z`, `MRC.exe`, `02:32:38Z`, `019e10b2-33c8-71f0-b971-f1487a706533`, `019e10b0-a4a8-73c3-a0be-dbe94c39f245`, `019e10b3-343f-7270-b730-d532b6046c33`, `02:31:15Z`
- claim: > **Step 7 — Persistent remote re-entry (2020-11-16T02:30Z onwards):** RDP connections began at ~02:30Z from four external IPs. MRC.exe was re-launched at `2020-11-16T02:31:13Z` (UserAssist) / `02:31:15…

### ⚠ partial _(line 142)_
- tools: `vol3_malfind`
- exec_ids: `8cf7c7432210`
- ✅ verified absences (negated): `019e10b3-6ee6-7a31-9132-8cf7c7432210`, `019e10b3-3b9b-74e2-9fdf-503d754fe7e0`
- **missing**: `MRC.exe`, `vol3_malfind`
- claim: > **No malware/code injection detected:** `vol3_malfind` returned 16 findings, all attributable to legitimate processes (Windows Defender, SearchApp, LockApp, RuntimeBroker, Teams, SmartScreen) with no …

### ⚠ partial _(line 142)_
- tools: `vol3_svcscan`
- exec_ids: `503d754fe7e0`
- ✅ verified absences (negated): `019e10b3-6ee6-7a31-9132-8cf7c7432210`, `019e10b3-3b9b-74e2-9fdf-503d754fe7e0`
- **missing**: `MRC.exe`, `vol3_malfind`
- claim: > **No malware/code injection detected:** `vol3_malfind` returned 16 findings, all attributable to legitimate processes (Windows Defender, SearchApp, LockApp, RuntimeBroker, Teams, SmartScreen) with no …

### ✅ verified _(line 152)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-13T22:09:17Z`
- claim: > ``` 2020-11-13T22:09:17Z  Xbox Gaming Overlay triggered — first post-22:00 UserAssist hit                        [CONFIRMED UA exec_id 019e10b3-343f-7270-b730-d532b6046c33]

### ⚠ partial _(line 179)_
- tools: `vol3_userassist`, `vol3_pstree`
- exec_ids: `d532b6046c33`, `dbe94c39f245`
- matched: `29440`, `2020-11-16T02:31:15Z`, `2020-11-16T02:31:13Z`, `MRC.exe`
- **missing**: `81.30.144.115`, `201.193.188.114`, `213.202.233.104`, `2020-11-16T02:30:05Z`, `2020-11-16T02:31:26Z`, `2020-11-16T02:31:18Z`
- claim: > 2020-11-16T02:30:05Z  First RDP connection from 201.193.188.114 (CLOSED) 2020-11-16T02:31:13Z  MRC.exe launched via Explorer (UserAssist timestamp) 2020-11-16T02:31:15Z  MRC.exe process created (PID 2…

### ⚠ partial _(line 188)_
- tools: `vol3_netscan`
- exec_ids: `f1487a706533`
- matched: `81.30.144.115`, `213.202.233.104`
- **missing**: `2020-11-16T02:32:38Z`
- claim: > 2020-11-16T02:32:38Z  *** SRL RAM CAPTURE ***                        At capture: 81.30.144.115 and 213.202.233.104 both ESTABLISHED                        Intruder was actively connected during acquis…
