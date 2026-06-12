# Validator Report — iter_1

## Summary

- Total tagged claims:        **43**
  - CONFIRMED:                 38
  - INFERRED:                  4
  - HYPOTHESIS:                0
  - GAP:                       1
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           25 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                7 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           6 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 65.8%** (25 verified / 38 confirmed)

## Per-claim verdicts

### ✅ verified _(line 40)_
- tools: `ewf_info`
- exec_ids: `e745b5054501`
- matched: `4032d556cc866c23f1e797410e95603c`, `Fri Nov  4 17:47:41 2016`, `Ovie Carroll`, `20161104-HD001`, `Surface 3`
- claim: > **[CONFIRMED — exec_id `019ebb2f-b3aa-7783-898f-e745b5054501`]** Examiner field is `Ovie Carroll`, evidence number `20161104-HD001`, description `Surface 3`, acquisition date `Fri Nov  4 17:47:41 2016…

### ✅ verified _(line 42)_
- tools: `tsk_partition_table`
- exec_ids: `68d5306eacf9`
- matched: `003`, `1411072`, `230883328`
- claim: > **[CONFIRMED — exec_id `019ebb2f-b58c-7062-82ad-68d5306eacf9`]** GPT disk; C: drive is partition slot `003` starting at sector `1411072`, length `230883328` sectors.

### ✅ verified _(line 44)_
- tools: `tsk_fs_stat`
- exec_ids: `8bf2bf8efade`
- matched: `A420A4D720A4B1AA`, `4096`, `Windows`
- claim: > **[CONFIRMED — exec_id `019ebb2f-d48a-7a20-b5f1-8bf2bf8efade`]** Filesystem: NTFS, volume name `Windows`, serial `A420A4D720A4B1AA`, cluster size `4096` bytes.

### ✅ verified _(line 46)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `\Users\PC`, `S-1-5-21-3739107332-290452467-3466442662-1001`, `263009`, `\Users\PC User`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** Subject profile: single primary user directory `\Users\PC User` (MFT parent entry `263009`). SRUM confirms user SID `S-1-5-21-373910733…

### ✅ verified _(line 58)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-18T22:00:15Z`, `notes.docx`, `\Users\PC`, `\Users\PC User\Documents`, `168425`, `ZF DNA splice test notes.docx`, `13367`
- claim: > | File | Location | MFT Entry | Size | Record Changed | exec_id | |---|---|---|---|---|---| | `ZF DNA splice test notes.docx` | `\Users\PC User\Documents` | `13367` | `168425` | `2016-06-18T22:00:15Z`…

### ✅ verified _(line 59)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-18T22:00:15Z`, `research.docx`, `\Users\PC`, `Rapid cell regeneration research.docx`, `\Users\PC User\Documents`, `31868`, `480110`
- claim: > | | `Rapid cell regeneration research.docx` | `\Users\PC User\Documents` | `31868` | `480110` | `2016-06-18T22:00:15Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 60)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-19T01:32:02Z`, `zebrafish.pdf`, `\Users\PC`, `\Users\PC User\Documents`, `708591`, `68394`
- claim: > | | `zebrafish.pdf` | `\Users\PC User\Documents` | `68394` | `708591` | `2016-06-19T01:32:02Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 61)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `research.docx`, `\Users\PC`, `Rapid cell regeneration research.docx`, `6361`, `493466`, `\Users\PC User\OneDrive\Documents`
- claim: > | | `Rapid cell regeneration research.docx` | `\Users\PC User\OneDrive\Documents` | `6361` | `493466` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 62)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Inventory.docx`, `\Users\PC`, `2193`, `STARK-TS-Level7-CryoDNA Storage Inventory.docx`, `20124`, `\Users\PC User\OneDrive\Documents`
- claim: > | | `STARK-TS-Level7-CryoDNA Storage Inventory.docx` | `\Users\PC User\OneDrive\Documents` | `2193` | `20124` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 63)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `sample-Alpha_Experiment.docx`, `\Users\PC`, `58405`, `\Users\PC User\OneDrive\Documents`, `Cryo-regeneration of DNA sample-Alpha_Experiment.docx`, `494629`
- claim: > | | `Cryo-regeneration of DNA sample-Alpha_Experiment.docx` | `\Users\PC User\OneDrive\Documents` | `58405` | `494629` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 64)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `attempts.xlsx`, `\Users\PC`, `12382`, `cryoregeneration x-alpha attempts.xlsx`, `\Users\PC User\OneDrive\Documents`, `58966`
- claim: > | | `cryoregeneration x-alpha attempts.xlsx` | `\Users\PC User\OneDrive\Documents` | `58966` | `12382` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 65)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Stark_TS-Level8A_CryoDNA.blacklight.docx`, `\Users\PC`, `58969`, `20000293`, `\Users\PC User\OneDrive\Documents\Level_8`
- claim: > | | `Stark_TS-Level8A_CryoDNA.blacklight.docx` | `\Users\PC User\OneDrive\Documents\Level_8` | `58969` | `20000293` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 66)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Marriage.docx`, `\Users\PC`, `17251`, `58971`, `Stark_TS-Level8a_DNA Marriage.docx`, `\Users\PC User\OneDrive\Documents\Level_8`
- claim: > | | `Stark_TS-Level8a_DNA Marriage.docx` | `\Users\PC User\OneDrive\Documents\Level_8` | `58971` | `17251` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 67)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Information.docx`, `\Users\PC`, `59216`, `23187`, `\Users\PC User\OneDrive\Documents\Level_8`, `Level 8 Indoc Information.docx`
- claim: > | | `Level 8 Indoc Information.docx` | `\Users\PC User\OneDrive\Documents\Level_8` | `59216` | `23187` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 68)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `samples.docx`, `\Users\PC`, `Observations on regenerative DNA samples.docx`, `59031`, `\Users\PC User\OneDrive\Documents\Level_12`, `129214`
- claim: > | | `Observations on regenerative DNA samples.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `59031` | `129214` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 69)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Cryo-DNA_DraftStandards_lab_results.docx`, `\Users\PC`, `Reverse Cryo-DNA_DraftStandards_lab_results.docx`, `59034`, `21469`, `\Users\PC User\OneDrive\Documents\Level_12`
- claim: > | | `Reverse Cryo-DNA_DraftStandards_lab_results.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `59034` | `21469` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 70)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx`, `\Users\PC`, `178280`, `56770`, `\Users\PC User\OneDrive\Documents\Level_12`
- claim: > | | `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `56770` | `178280` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CON…

### ✅ verified _(line 71)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `4.docx`, `\Users\PC`, `213302`, `59190`, `Stark TS-Level 12_Project_Nehemiah 4.docx`, `\Users\PC User\OneDrive\Documents\Level_12`
- claim: > | | `Stark TS-Level 12_Project_Nehemiah 4.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `59190` | `213302` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 73)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-19T01:32:02Z`, `zebrafish.pdf`, `Zone.Identifier`, `68394`, `zebrafish.pdf:Zone.Identifier`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** `zebrafish.pdf` (entry `68394`) carries a `Zone.Identifier` ADS (`zebrafish.pdf:Zone.Identifier`, 106 bytes), indicating it was downloa…

### ✅ verified _(line 75)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-29T16:20:43Z`, `2016-06-29T16:20:16Z`, `2016-06-29T20:21:28Z`, `2016-06-30T02:02:43Z`, `DNA_replication_en.png`, `490px-Nulcear_radiation-LEVEL7.jpg`, `research.docx`, `notes.docx` (+8 more)
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** Recent Item links confirm active opening of research files on June 29–30, 2016: - `ZF DNA splice test notes.docx.lnk` (entry `8408`), m…

### 🔍 not_confirmed _(line 81)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **G1 Finding:** [CONFIRMED] The workstation of "PC User" (Anthony Vanko) contained the exact research topics cited in the JARVIS alert — zebrafish DNA splice research, rapid cell regeneration, and Lev…

### ✅ verified _(line 89)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-05-13T19:15:07Z`, `\Windows\Recent`, `\Users\PC`, `\Users\PC User\AppData\Roaming\Microsoft\Windows\Recent\`, `STARK_ENT (D).lnk`, `D:`, `5030`, `(D)`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** A Recent Items link file `STARK_ENT (D).lnk` (entry `5030`) exists at `\Users\PC User\AppData\Roaming\Microsoft\Windows\Recent\`, creat…

### ⚠ partial _(line 93)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `\Users\PC`, `58969`, `59034`, `2193`, `58971`, `Level_8`, `59031` (+3 more)
- **missing**: `copied: true`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** All eleven classified files in `\Users\PC User\OneDrive\Documents\` and its subdirectories (`Level_8`, `Level_12`) share the same MFT r…

### ✅ verified _(line 95)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:25:38Z`, `STARKSURFACE-20160630-1025.log`, `395`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** A Stark network monitoring log `STARKSURFACE-20160630-1025.log` (entry `395`) was created at `2016-06-30T14:25:38Z` — 22 minutes before…

### ⚠ partial _(line 97)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `STARKSURFACE-20160621-0643.log`, `\Windows\Temp`, `38`, `160752`, `\Windows\Temp\`
- **missing**: `STARKSURFACE-*.log`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** The MFT shows a series of `STARKSURFACE-*.log` files in `\Windows\Temp\` covering dates from March 2016 through November 4, 2016, demon…

### 🔍 not_confirmed _(line 110)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **G2 Finding:** [CONFIRMED] Vanko copied a large volume of Stark classified research data to his workstation on 2016-06-30 between approximately 14:25–14:47 UTC, exploiting the `D:` mapped drive conne…

### ⚠ partial _(line 118)_
- tools: `ezt_prefetch_parse`
- exec_ids: `0a1ac717beaf`
- matched: `2016-10-30T23:11:20Z`, `2016-07-02T23:02:23Z`, `2016-08-08T18:51:07Z`, `2016-09-30T11:54:59Z`, `2016-08-08T18:49:23Z`, `2016-09-30T11:52:25Z`, `2016-11-04T13:24:58Z`, `2016-08-08T12:15:02Z` (+2 more)
- **missing**: `2016-06-30T14:47:38Z`, `2016-06-30T14:46:54Z`, `-CA84A5C1.pf`, `10575`, `ONEDRIVE.EXE-CA84A5C1.pf`
- claim: > **[CONFIRMED — exec_id `019ebb3b-e922-7b73-9e2c-0a1ac717beaf`]** OneDrive Prefetch (`ONEDRIVE.EXE-CA84A5C1.pf`, inode `10575`) shows the Prefetch file was **created `2016-06-30T14:46:54Z`** — 44 secon…

### ⚠ partial _(line 120)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `3a15e8f457fe`
- matched: `OneDrive.exe`, `\Users\PC`, `C:\Users\PC`, `OneDrive`
- **missing**: `NTUSER.DAT`, `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`
- claim: > **[CONFIRMED — exec_id `019ebb3b-b1b4-7490-b112-3a15e8f457fe`]** NTUSER.DAT HKCU Run key confirms OneDrive was configured to autostart at every login: value name `OneDrive`, value data `"C:\Users\PC U…

### ✅ verified _(line 122)_
- tools: `ezt_prefetch_parse`
- exec_ids: `0a1ac717beaf`
- matched: `SYNCENGINE-2016-10-30`, `SYNCENGINE-2016-8-8`, `SYNCENGINE-2016-7-2`, `SYNCENGINE-2016-9-30`
- claim: > **[CONFIRMED — exec_id `019ebb3b-e922-7b73-9e2c-0a1ac717beaf`]** The Prefetch files_loaded list references sync log files dated `SYNCENGINE-2016-7-2` (July 2, 2016), `SYNCENGINE-2016-8-8` (multiple Au…

### ✅ verified _(line 126)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `3a15e8f457fe`
- matched: `iCloudServices.exe`, `Backup.exe`, `ApplePhotoStreams.exe`, `iCloudDrive.exe`, `iCloudPhotos.exe`, `\Users\PC`, `C:\Users\PC`, `C:\Program` (+4 more)
- claim: > **[CONFIRMED — exec_id `019ebb3b-b1b4-7490-b112-3a15e8f457fe`]** The following additional cloud-sync clients are configured to autostart via HKCU Run: - `iCloudServices.exe` — `C:\Program Files (x86)\…

### ⚠ partial _(line 137)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-07-07T01:44:54Z`, `Dropbox.exe`, `\Users\PC`, `\Users\PC User\Dropbox\`, `16968`, `32909`
- **missing**: `\Users\PC User\Dropbox\.dropbox.cache\prefetch_cache`, `\Program Files (x86)\Dropbox\Client_12.4.22\Dropbox.exe`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** Dropbox client is installed at `\Program Files (x86)\Dropbox\Client_12.4.22\Dropbox.exe` (entry `16968`) and a user Dropbox folder exis…

### ⚠ partial _(line 139)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-10-14T22:42:42Z`, `-8DACDCF4.pf`, `DROPBOX.EXE`, `149508`, `DROPBOX.EXE-8DACDCF4.pf`
- **missing**: `in_use: false`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** `DROPBOX.EXE-8DACDCF4.pf` (entry `149508`) has `in_use: false` — the Dropbox Prefetch entry is marked as deleted, with a timestamp of `…

### ⚠ partial _(line 141)_
- tools: `tsk_fls_list`
- exec_ids: `4e71f7d8f70a`
- matched: `DropboxUpdate.log`
- **missing**: `DropboxUpdate.log-*`, `ProgramData\Dropbox\Update\Log\`
- claim: > **[CONFIRMED — exec_id `019ebb30-b3fc-71b3-92d5-4e71f7d8f70a`]** Multiple `DropboxUpdate.log-*` files appear in `ProgramData\Dropbox\Update\Log\` with dates spanning August 2015 through November 4, 20…

### ✅ verified _(line 145)_
- tools: `tsk_fls_list`
- exec_ids: `4e71f7d8f70a`
- matched: `5.1.0.34`, `5.2.1.69`, `4.1.1.53`, `306815`, `iCloud Control Panel 5.1.0.34`, `46785`, `iCloud Control Panel 5.2.1.69`, `21263` (+1 more)
- claim: > **[CONFIRMED — exec_id `019ebb30-b3fc-71b3-92d5-4e71f7d8f70a`]** Multiple versions of the iCloud installer are cached: - `iCloud Control Panel 4.1.1.53` (inode `306815`) - `iCloud Control Panel 5.1.0.…

### 🔍 not_confirmed _(line 156)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **G3 Finding:** [CONFIRMED] The primary exfiltration channel was **Microsoft OneDrive**, which began syncing the classified documents at `2016-06-30T14:47:38Z` — verified by the simultaneous Prefetch …

### 🔍 not_confirmed _(line 164)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | Investigation Goal | Finding | Confidence | |---|---|---| | G1: Vanko involved in dissemination | All three JARVIS-flagged research topics (zebrafish, cell regeneration, ZF DNA splice) plus Level 7–…

### 🔍 not_confirmed _(line 165)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | G2: Large-volume data copy from StarkResearch | Mapped drive `D:` to Stark server from May 2016; 14 classified files bulk-copied on `2016-06-30T14:47:38Z` matching JARVIS alert; `copied` MFT flag …

### 🔍 not_confirmed _(line 166)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | G3: Post-transfer data disposition | Microsoft OneDrive (primary, confirmed by Prefetch/autostart/sync logs); Dropbox (installed, active, Prefetch deleted); iCloud Drive + Google Photos Backup (au…
