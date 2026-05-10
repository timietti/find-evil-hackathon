# Validator Report — iter_2

## Summary

- Total tagged claims:        **56**
  - CONFIRMED:                 43
  - INFERRED:                  7
  - HYPOTHESIS:                1
  - GAP:                       5
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           9 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                29 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           1 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           2 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 20.9%** (9 verified / 43 confirmed)

## Per-claim verdicts

### ⚠ partial _(line 17)_
- tools: `vol3_image_info`
- exec_ids: `482594d77c2f`
- matched: `2020-11-16T02:32:38Z`
- **missing**: `2020-11-13T22:00Z`, `ntuser.dat`, `\Users\fredr\ntuser.dat``, `C:\Users\fredr\ntuser.dat``, `2020-11-13T22:00Z – 2020-11-16T02:32:38Z`, `C:\Users\fredr\ntuser.dat`, `019e10b3-343f-7270-b730-d532b6046c33`, `019e10af-5c21-7842-b611-482594d77c2f` (+1 more)
- claim: > **Analyst:** SIFT-OWL v2 — Principal DFIR Orchestrator   **Capture anchor:** `2020-11-16T02:32:38Z` [CONFIRMED — exec_id `019e10af-5c21-7842-b611-482594d77c2f`]   **OS:** Windows 10 Build 19041 x64   …

### ⚠ partial _(line 19)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `ntuser.dat`, `hive_name`
- **missing**: `2020-11-13T22:00Z`, `2020-11-16T02:32:38Z`, `\Users\fredr\ntuser.dat``, `C:\Users\fredr\ntuser.dat``, `2020-11-13T22:00Z – 2020-11-16T02:32:38Z`, `C:\Users\fredr\ntuser.dat`, `019e10b3-343f-7270-b730-d532b6046c33`, `019e10af-5c21-7842-b611-482594d77c2f`
- claim: > **Analyst:** SIFT-OWL v2 — Principal DFIR Orchestrator   **Capture anchor:** `2020-11-16T02:32:38Z` [CONFIRMED — exec_id `019e10af-5c21-7842-b611-482594d77c2f`]   **OS:** Windows 10 Build 19041 x64   …

### 🔍 not_confirmed _(line 36)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[6]** "[CONFIRMED files in memory]" — no data tokens. → **Resolved**: individual file names are now included in the G2 section per-file, each citing exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`.

### 🔍 not_confirmed _(line 42)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[10]** "[CONFIRMED connections]" — no data tokens beyond exec_id UUID. → **Resolved**: specific IPs and ports now included in connection claim: `81.30.144.115:51048 ESTABLISHED`, `213.202.233.104:45…

### ❓ unverifiable _(line 58)_
- exec_ids: `d532b6046c33`, `dbe94c39f245`, `f1487a706533`
- note: claim has no extractable tokens (prose only)
- claim: > **[20]** [21] Step-7 re-entry claim: each cited tool missing other tools' tokens. → **Resolved**: multi-cite `[CONFIRMED — exec_id 019e10b3-343f-7270-b730-d532b6046c33, exec_id 019e10b0-a4a8-73c3-a0be…

### ❌ failed _(line 70)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- **missing**: `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`
- claim: > The following SRL project files were present as pool-memory file objects at capture time [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`]:

### ⚠ partial _(line 83)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `stark-research-labs.com.ost`, `frocba@stark-research-labs.com`, `frocba@stark-research-labs.com.ost`
- **missing**: `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`
- claim: > Corporate email archive `frocba@stark-research-labs.com.ost` was present in pool memory, confirming full corporate mailbox access [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`].

### ⚠ partial _(line 91)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `fighter_starfury.jpg`, `Starfury.docx`, `StarFuryHeader.jpg`, `StarFury.zip`
- **missing**: `\Users\fredr\iCloudDrive\fighter_starfury.jpg``, `\Users\fredr\iCloudDrive\StarFuryHeader.jpg``, `\Users\fredr\OneDrive\Desktop\SA-23E`, `\Users\fredr\OneDrive\StarFury.zip``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\iCloudDrive\StarFuryHeader.jpg`, `\Users\fredr\iCloudDrive\fighter_starfury.jpg`, `\Users\fredr\OneDrive\Desktop\SA-23E Mitchell-Hyundyne Starfury.docx` (+1 more)
- claim: > - `\Users\fredr\OneDrive\StarFury.zip` — compressed archive placed in the personal OneDrive sync root for automatic cloud upload [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`]. - `\Users…

### ⚠ partial _(line 92)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `fighter_starfury.jpg`, `Starfury.docx`, `StarFuryHeader.jpg`, `StarFury.zip`
- **missing**: `\Users\fredr\iCloudDrive\fighter_starfury.jpg``, `\Users\fredr\iCloudDrive\StarFuryHeader.jpg``, `\Users\fredr\OneDrive\Desktop\SA-23E`, `\Users\fredr\OneDrive\StarFury.zip``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\iCloudDrive\StarFuryHeader.jpg`, `\Users\fredr\iCloudDrive\fighter_starfury.jpg`, `\Users\fredr\OneDrive\Desktop\SA-23E Mitchell-Hyundyne Starfury.docx` (+1 more)
- claim: > - `\Users\fredr\OneDrive\StarFury.zip` — compressed archive placed in the personal OneDrive sync root for automatic cloud upload [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`]. - `\Users…

### ⚠ partial _(line 93)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `fighter_starfury.jpg`, `Starfury.docx`, `StarFuryHeader.jpg`, `StarFury.zip`
- **missing**: `\Users\fredr\iCloudDrive\fighter_starfury.jpg``, `\Users\fredr\iCloudDrive\StarFuryHeader.jpg``, `\Users\fredr\OneDrive\Desktop\SA-23E`, `\Users\fredr\OneDrive\StarFury.zip``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\iCloudDrive\StarFuryHeader.jpg`, `\Users\fredr\iCloudDrive\fighter_starfury.jpg`, `\Users\fredr\OneDrive\Desktop\SA-23E Mitchell-Hyundyne Starfury.docx` (+1 more)
- claim: > - `\Users\fredr\OneDrive\StarFury.zip` — compressed archive placed in the personal OneDrive sync root for automatic cloud upload [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`]. - `\Users…

### ❌ failed _(line 105)_
- tools: `vol3_filescan`, `vol3_filescan`
- exec_ids: `590aa4c55cf2`, `590aa4c55cf2`
- **missing**: `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`
- claim: > [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`; INFERRED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`; reasoning: pool-memory presence indicates open file handles; actual copying is i…

### ⚠ partial _(line 109)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `sdelete.exe`, `SDelete.lnk`, `SDelete.zip`, `sdelete64.exe`, `srl-h`
- **missing**: `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk``, `\Users\fredr\Downloads\SDelete\sdelete.exe``, `\Users\srl-h\Downloads\sdelete64.exe``, `\Users\fredr\Downloads\SDelete.zip``, `\Users\fredr\Downloads\SDelete.zip`, `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk`, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\srl-h\Downloads\sdelete64.exe` (+1 more)
- claim: > - `\Users\fredr\Downloads\SDelete\sdelete.exe` and `\Users\fredr\Downloads\SDelete.zip` were present in pool memory; `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk` confirms SDelet…

### ⚠ partial _(line 110)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `sdelete.exe`, `SDelete.lnk`, `SDelete.zip`, `sdelete64.exe`, `srl-h`
- **missing**: `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk``, `\Users\fredr\Downloads\SDelete\sdelete.exe``, `\Users\srl-h\Downloads\sdelete64.exe``, `\Users\fredr\Downloads\SDelete.zip``, `\Users\fredr\Downloads\SDelete.zip`, `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk`, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\srl-h\Downloads\sdelete64.exe` (+1 more)
- claim: > - `\Users\fredr\Downloads\SDelete\sdelete.exe` and `\Users\fredr\Downloads\SDelete.zip` were present in pool memory; `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk` confirms SDelet…

### ⚠ partial _(line 117)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `OneDrive.exe`, `StarFury.zip`
- **missing**: `52.179.224.121`, `13.107.136.9`, `2020-11-16T02:32:45Z`, `\Users\fredr\OneDrive\StarFury.zip``, `13.107.136.9:443`, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `019e10b2-33c8-71f0-b971-f1487a706533`, `52.179.224.121:443` (+1 more)
- claim: > **Channel 1 — Microsoft OneDrive cloud sync (primary confirmed exfil vector):** `\Users\fredr\OneDrive\StarFury.zip` was placed in the personal OneDrive sync root [CONFIRMED — exec_id `019e10ba-06c7-7…

### ⚠ partial _(line 117)_
- tools: `vol3_netscan`
- exec_ids: `f1487a706533`
- matched: `52.179.224.121`, `13.107.136.9`, `2020-11-16T02:32:45Z`, `OneDrive.exe`
- **missing**: `StarFury.zip`, `\Users\fredr\OneDrive\StarFury.zip``, `13.107.136.9:443`, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `019e10b2-33c8-71f0-b971-f1487a706533`, `52.179.224.121:443`, `\Users\fredr\OneDrive\StarFury.zip`
- claim: > **Channel 1 — Microsoft OneDrive cloud sync (primary confirmed exfil vector):** `\Users\fredr\OneDrive\StarFury.zip` was placed in the personal OneDrive sync root [CONFIRMED — exec_id `019e10ba-06c7-7…

### ⚠ partial _(line 119)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `SRL.docx`, `Vibrainium - SRL.docx`
- **missing**: `\Users\fredr\OneDrive`, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\OneDrive - Stark Research Labs\`
- claim: > Note: The corporate OneDrive share (`\Users\fredr\OneDrive - Stark Research Labs\`) is a distinct path also present in pool memory with research files including `Vibrainium - SRL.docx` [CONFIRMED — ex…

### ⚠ partial _(line 130)_
- tools: `vol3_netscan`
- exec_ids: `f1487a706533`
- matched: `81.30.144.115`, `213.202.233.104`, `created`
- **missing**: `02:32:38Z`, `019e10b2-33c8-71f0-b971-f1487a706533`
- claim: > [CONFIRMED — exec_id `019e10b2-33c8-71f0-b971-f1487a706533`]. Note: some connection `created` timestamps exceed the RAM capture time (`02:32:38Z`) — this is a known Volatility pool-tag scan artifact; …

### ⚠ partial _(line 135)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `MRC.exe`
- **missing**: `D:\Tools\MRC.exe``, `D:\Tools):**`, `019e10b3-343f-7270-b730-d532b6046c33`, `D:\Tools\MRC.exe`
- claim: > **Channel 3 — USB drive (D:\Tools):** `D:\Tools\MRC.exe` is the only confirmed D: drive artifact in process space [CONFIRMED — exec_id `019e10b3-343f-7270-b730-d532b6046c33`]. [INFERRED: additional fi…

### ⚠ partial _(line 138)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `fighter_starfury.jpg`, `StarFuryHeader.jpg`
- **missing**: `\Users\fredr\iCloudDrive\fighter_starfury.jpg``, `\Users\fredr\iCloudDrive\StarFuryHeader.jpg``, `\Users\fredr\iCloudDrive\StarFuryHeader.jpg`, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\iCloudDrive\fighter_starfury.jpg`
- claim: > **Channel 4 — iCloud:** `\Users\fredr\iCloudDrive\StarFuryHeader.jpg` and `\Users\fredr\iCloudDrive\fighter_starfury.jpg` present in pool memory [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4c55…

### ⚠ partial _(line 145)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `MRC.exe`, `name`
- **missing**: `D:\Tools\MRC.exe`].`, `019e10b3-343f-7270-b730-d532b6046c33`, `D:\Tools\MRC.exe`
- claim: > **Step 1 — Physical break-in and USB deployment:** The intruder inserted a USB drive containing `D:\Tools\MRC.exe` [CONFIRMED — exec_id `019e10b3-343f-7270-b730-d532b6046c33`, field `name`, value `D:\…

### ⚠ partial _(line 148)_
- tools: `vol3_pstree`
- exec_ids: `dbe94c39f245`
- matched: `29440`, `2020-11-16T02:31:15Z`, `explorer.exe`, `MRC.exe`
- **missing**: `2020-11-16T02:31:13Z`, `D:\Tools\MRC.exe``, `wow64=true`, `create_time=2020-11-16T02:31:15Z`, `count=1`, `019e10b0-a4a8-73c3-a0be-dbe94c39f245`, `D:\Tools\MRC.exe`, `last_updated=2020-11-16T02:31:13Z` (+2 more)
- claim: > **Step 2 — DameWare Mini Remote Control deployment:** `MRC.exe` (DameWare Mini Remote Control, 32-bit WOW64) was launched from Windows Explorer: PPID 7464 (`explorer.exe`) → PID 29440 (`MRC.exe`), `wo…

### ⚠ partial _(line 148)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-16T02:31:13Z`, `explorer.exe`, `MRC.exe`
- **missing**: `29440`, `2020-11-16T02:31:15Z`, `D:\Tools\MRC.exe``, `wow64=true`, `create_time=2020-11-16T02:31:15Z`, `count=1`, `019e10b0-a4a8-73c3-a0be-dbe94c39f245`, `D:\Tools\MRC.exe` (+3 more)
- claim: > **Step 2 — DameWare Mini Remote Control deployment:** `MRC.exe` (DameWare Mini Remote Control, 32-bit WOW64) was launched from Windows Explorer: PPID 7464 (`explorer.exe`) → PID 29440 (`MRC.exe`), `wo…

### ⚠ partial _(line 151)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-14T12:43:01Z`, `2020-11-13T22:09:17Z`, `2020-11-14T13:50:02Z`, `cmd.exe`, `Microsoft.XboxGamingOverlay_8wekyb3d8bbwe!App`
- **missing**: `last_updated=2020-11-13T22:09:17Z`, `019e10b3-343f-7270-b730-d532b6046c33`
- claim: > **Step 3 — File reconnaissance and staging (hands-on-keyboard, `2020-11-13T22:09:17Z` – `2020-11-14T13:50:02Z`):** First post-break-in UserAssist hit: `Microsoft.XboxGamingOverlay_8wekyb3d8bbwe!App` a…

### ⚠ partial _(line 151)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-14T12:43:01Z`, `2020-11-13T22:09:17Z`, `2020-11-14T13:50:02Z`, `cmd.exe`, `Microsoft.XboxGamingOverlay_8wekyb3d8bbwe!App`
- **missing**: `last_updated=2020-11-13T22:09:17Z`, `019e10b3-343f-7270-b730-d532b6046c33`
- claim: > **Step 3 — File reconnaissance and staging (hands-on-keyboard, `2020-11-13T22:09:17Z` – `2020-11-14T13:50:02Z`):** First post-break-in UserAssist hit: `Microsoft.XboxGamingOverlay_8wekyb3d8bbwe!App` a…

### ⚠ partial _(line 154)_
- tools: `vol3_filescan`
- exec_ids: `590aa4c55cf2`
- matched: `StarFury.zip`
- **missing**: `\Users\fredr\OneDrive\StarFury.zip``, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\OneDrive\StarFury.zip`
- claim: > **Step 4 — Archive creation and cloud staging:** `\Users\fredr\OneDrive\StarFury.zip` placed in the personal OneDrive root for automatic cloud sync [CONFIRMED — exec_id `019e10ba-06c7-70c0-b1e3-590aa4…

### ⚠ partial _(line 157)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-14T04:39:15Z`, `regedit.exe`, `0:03:40.124000`
- **missing**: `%windir%\regedit.exe`, `019e10b3-343f-7270-b730-d532b6046c33`
- claim: > **Step 5 — Registry manipulation:** `%windir%\regedit.exe` last_updated `2020-11-14T04:39:15Z`, count 1, focus_count 2, time_focused `0:03:40.124000` [CONFIRMED — exec_id `019e10b3-343f-7270-b730-d532…

### ⚠ partial _(line 160)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-14T13:50:02Z`, `sdelete.exe`, `DropboxUninstaller.exe`
- **missing**: `SDelete.lnk`, `SDelete.zip`, `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk``, `\Users\fredr\Downloads\SDelete\sdelete.exe``, `\Users\fredr\Downloads\SDelete.zip``, `\Users\fredr\Downloads\SDelete.zip`, `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk`, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2` (+3 more)
- claim: > **Step 6 — Anti-forensic cleanup:** - `%ProgramFiles%\Dropbox\Client\DropboxUninstaller.exe` last_updated `2020-11-14T13:50:02Z`, count 1 — Dropbox uninstalled to remove sync artifact trail [CONFIRMED…

### ⚠ partial _(line 161)_
- tools: `vol3_filescan`, `vol3_userassist`
- exec_ids: `590aa4c55cf2`, `d532b6046c33`
- matched: `2020-11-14T13:50:02Z`, `sdelete.exe`, `DropboxUninstaller.exe`, `SDelete.lnk`, `SDelete.zip`
- **missing**: `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk``, `\Users\fredr\Downloads\SDelete\sdelete.exe``, `\Users\fredr\Downloads\SDelete.zip``, `\Users\fredr\Downloads\SDelete.zip`, `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk`, `019e10ba-06c7-70c0-b1e3-590aa4c55cf2`, `\Users\fredr\Downloads\SDelete\sdelete.exe`, `019e10b3-343f-7270-b730-d532b6046c33` (+1 more)
- claim: > **Step 6 — Anti-forensic cleanup:** - `%ProgramFiles%\Dropbox\Client\DropboxUninstaller.exe` last_updated `2020-11-14T13:50:02Z`, count 1 — Dropbox uninstalled to remove sync artifact trail [CONFIRMED…

### ⚠ partial _(line 164)_
- tools: `vol3_netscan`
- exec_ids: `f1487a706533`
- matched: `81.30.144.115`, `201.193.188.114`, `213.202.233.104`, `2020-11-16T02:30:05Z`
- **missing**: `29440`, `2020-11-16T02:31:15Z`, `2020-11-16T02:31:13Z`, `MRC.exe`, `D:\Tools\MRC.exe``, `019e10b2-33c8-71f0-b971-f1487a706533`, `D:\Tools\MRC.exe`, `019e10b3-343f-7270-b730-d532b6046c33` (+1 more)
- claim: > **Step 7 — Persistent remote re-entry (`2020-11-16T02:30:05Z` onwards):** First RDP from `201.193.188.114` port 63385 at `2020-11-16T02:30:05Z` [CONFIRMED — exec_id `019e10b2-33c8-71f0-b971-f1487a7065…

### ⚠ partial _(line 164)_
- tools: `vol3_userassist`, `vol3_pstree`
- exec_ids: `d532b6046c33`, `dbe94c39f245`
- matched: `29440`, `2020-11-16T02:31:15Z`, `2020-11-16T02:31:13Z`, `MRC.exe`
- **missing**: `81.30.144.115`, `201.193.188.114`, `213.202.233.104`, `2020-11-16T02:30:05Z`, `D:\Tools\MRC.exe``, `019e10b2-33c8-71f0-b971-f1487a706533`, `D:\Tools\MRC.exe`, `019e10b3-343f-7270-b730-d532b6046c33` (+1 more)
- claim: > **Step 7 — Persistent remote re-entry (`2020-11-16T02:30:05Z` onwards):** First RDP from `201.193.188.114` port 63385 at `2020-11-16T02:30:05Z` [CONFIRMED — exec_id `019e10b2-33c8-71f0-b971-f1487a7065…

### ⚠ partial _(line 164)_
- tools: `vol3_netscan`
- exec_ids: `f1487a706533`
- matched: `81.30.144.115`, `201.193.188.114`, `213.202.233.104`, `2020-11-16T02:30:05Z`
- **missing**: `29440`, `2020-11-16T02:31:15Z`, `2020-11-16T02:31:13Z`, `MRC.exe`, `D:\Tools\MRC.exe``, `019e10b2-33c8-71f0-b971-f1487a706533`, `D:\Tools\MRC.exe`, `019e10b3-343f-7270-b730-d532b6046c33` (+1 more)
- claim: > **Step 7 — Persistent remote re-entry (`2020-11-16T02:30:05Z` onwards):** First RDP from `201.193.188.114` port 63385 at `2020-11-16T02:30:05Z` [CONFIRMED — exec_id `019e10b2-33c8-71f0-b971-f1487a7065…

### ⚠ partial _(line 167)_
- tools: `vol3_malfind`
- exec_ids: `8cf7c7432210`
- matched: `dllhost.exe`, `LockApp.exe`, `Teams.exe`, `MsMpEng.exe`, `SearchApp.exe`, `RuntimeBroker.`, `smartscreen.ex`
- ✅ verified absences (negated): `29440`, `MRC.exe`, `019e10b3-3b9b-74e2-9fdf-503d754fe7e0`
- **missing**: `019e10b3-6ee6-7a31-9132-8cf7c7432210`, `vol3_malfind`
- claim: > **No code injection detected:** `vol3_malfind` returned 16 findings totaling: 5 × `MsMpEng.exe` (RWX, Windows Defender), 4 × `SearchApp.exe` (RWX), 1 × `dllhost.exe`, 1 × `LockApp.exe` (RWX), 1 × `Run…

### ⚠ partial _(line 167)_
- tools: `vol3_svcscan`
- exec_ids: `503d754fe7e0`
- matched: `dllhost.exe`, `MsMpEng.exe`
- ✅ verified absences (negated): `29440`, `MRC.exe`, `019e10b3-3b9b-74e2-9fdf-503d754fe7e0`
- **missing**: `LockApp.exe`, `Teams.exe`, `SearchApp.exe`, `019e10b3-6ee6-7a31-9132-8cf7c7432210`, `RuntimeBroker.`, `vol3_malfind`, `smartscreen.ex`
- claim: > **No code injection detected:** `vol3_malfind` returned 16 findings totaling: 5 × `MsMpEng.exe` (RWX, Windows Defender), 4 × `SearchApp.exe` (RWX), 1 × `dllhost.exe`, 1 × `LockApp.exe` (RWX), 1 × `Run…

### ✅ verified _(line 178)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-13T22:09:17Z`
- claim: > ``` 2020-11-13T22:09:17Z  Microsoft.XboxGamingOverlay app triggered (first post-22:00Z UserAssist                        hit — intruder's first keyboard/mouse event on the logged-in session)          …

### ✅ verified _(line 181)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-14T04:39:15Z`, `regedit.exe`
- claim: > 2020-11-14T04:39:15Z  %windir%\regedit.exe opened (count 1, focus 3:40)                        [CONFIRMED — exec_id 019e10b3-343f-7270-b730-d532b6046c33]

### ✅ verified _(line 184)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-14T12:43:01Z`, `cmd.exe`
- claim: > 2020-11-14T12:43:01Z  cmd.exe last active (~6:42 session)                        [CONFIRMED — exec_id 019e10b3-343f-7270-b730-d532b6046c33]

### ✅ verified _(line 188)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-14T13:50:02Z`, `DropboxUninstaller.exe`
- claim: > 2020-11-14T13:50:02Z  %ProgramFiles%\Dropbox\Client\DropboxUninstaller.exe run (count 1)                        Dropbox removed — anti-forensics                        [CONFIRMED — exec_id 019e10b3-34…

### ✅ verified _(line 193)_
- tools: `vol3_netscan`
- exec_ids: `f1487a706533`
- matched: `201.193.188.114`, `2020-11-16T02:30:05Z`
- claim: > 2020-11-16T02:30:05Z  First RDP from 201.193.188.114 port 63385 (CLOSED)                        [CONFIRMED — exec_id 019e10b2-33c8-71f0-b971-f1487a706533]

### ⚠ partial _(line 196)_
- tools: `vol3_userassist`
- exec_ids: `d532b6046c33`
- matched: `2020-11-16T02:31:13Z`, `MRC.exe`
- **missing**: `D:\Tools\MRC.exe`
- claim: > 2020-11-16T02:31:13Z  D:\Tools\MRC.exe last_updated (UserAssist, count 1, focus_count 1)                        [CONFIRMED — exec_id 019e10b3-343f-7270-b730-d532b6046c33]

### ✅ verified _(line 199)_
- tools: `vol3_pstree`
- exec_ids: `dbe94c39f245`
- matched: `29440`, `2020-11-16T02:31:15Z`, `explorer.exe`, `MRC.exe`
- claim: > 2020-11-16T02:31:15Z  MRC.exe process created (PID 29440, PPID 7464/explorer.exe, WOW64, 20 threads)                        [CONFIRMED — exec_id 019e10b0-a4a8-73c3-a0be-dbe94c39f245]

### ✅ verified _(line 202)_
- tools: `vol3_netscan`
- exec_ids: `f1487a706533`
- matched: `81.30.144.115`, `2020-11-16T02:31:26Z`
- claim: > 2020-11-16T02:31:26Z  First confirmed 81.30.144.115 RDP connection (port 53145)                        [CONFIRMED — exec_id 019e10b2-33c8-71f0-b971-f1487a706533]

### ✅ verified _(line 205)_
- tools: `vol3_image_info`
- exec_ids: `482594d77c2f`
- matched: `2020-11-16T02:32:38Z`
- claim: > 2020-11-16T02:32:38Z  *** SRL RAM CAPTURE ***                        [CONFIRMED — exec_id 019e10af-5c21-7842-b611-482594d77c2f]

### ✅ verified _(line 210)_
- tools: `vol3_netscan`
- exec_ids: `f1487a706533`
- matched: `81.30.144.115`, `213.202.233.104`, `2020-11-16T02:34:45`
- claim: > 2020-11-16T02:34:45–58Z  81.30.144.115 port 5067 ESTABLISHED; port 51048 ESTABLISHED                           213.202.233.104 port 45753 ESTABLISHED; port 40876 ESTABLISHED                           …
