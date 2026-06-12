# Validator Report — iter_2

## Summary

- Total tagged claims:        **42**
  - CONFIRMED:                 37
  - INFERRED:                  4
  - HYPOTHESIS:                0
  - GAP:                       1
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           37 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                0 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 100.0%** (37 verified / 37 confirmed)

## Per-claim verdicts

### ✅ verified _(line 24)_
- tools: `ewf_info`
- exec_ids: `e745b5054501`
- matched: `4032d556cc866c23f1e797410e95603c`, `Fri Nov  4 17:47:41 2016`, `Ovie Carroll`, `20161104-HD001`, `Surface 3`
- claim: > **[CONFIRMED — exec_id `019ebb2f-b3aa-7783-898f-e745b5054501`]** Examiner field is `Ovie Carroll`, evidence number `20161104-HD001`, description `Surface 3`, acquisition date `Fri Nov  4 17:47:41 2016…

### ✅ verified _(line 26)_
- tools: `tsk_partition_table`
- exec_ids: `68d5306eacf9`
- matched: `003`, `1411072`, `230883328`
- claim: > **[CONFIRMED — exec_id `019ebb2f-b58c-7062-82ad-68d5306eacf9`]** GPT disk; C: drive is partition slot `003` starting at sector `1411072`, length `230883328` sectors.

### ✅ verified _(line 28)_
- tools: `tsk_fs_stat`
- exec_ids: `8bf2bf8efade`
- matched: `A420A4D720A4B1AA`, `4096`, `Windows`
- claim: > **[CONFIRMED — exec_id `019ebb2f-d48a-7a20-b5f1-8bf2bf8efade`]** Filesystem: NTFS, volume name `Windows`, serial `A420A4D720A4B1AA`, cluster size `4096` bytes.

### ✅ verified _(line 30)_
- tools: `ezt_mft_parse`, `ezt_srum_parse`
- exec_ids: `daf567387d3d`, `93a5dc3e7321`
- matched: `\Users\PC`, `S-1-5-21-3739107332-290452467-3466442662-1001`, `263009`, `\Users\PC User`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`, exec_id `019ebb37-8282-7ad1-8315-93a5dc3e7321`]** Subject profile: single primary user directory `\Users\PC User` (MFT parent entry `2630…

### ✅ verified _(line 42)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-18T22:00:15Z`, `notes.docx`, `\Users\PC`, `\Users\PC User\Documents`, `168425`, `ZF DNA splice test notes.docx`, `13367`
- claim: > | File | Location | MFT Entry | Size | Record Changed | exec_id | |---|---|---|---|---|---| | `ZF DNA splice test notes.docx` | `\Users\PC User\Documents` | `13367` | `168425` | `2016-06-18T22:00:15Z`…

### ✅ verified _(line 43)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-18T22:00:15Z`, `research.docx`, `\Users\PC`, `Rapid cell regeneration research.docx`, `\Users\PC User\Documents`, `31868`, `480110`
- claim: > | | `Rapid cell regeneration research.docx` | `\Users\PC User\Documents` | `31868` | `480110` | `2016-06-18T22:00:15Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 44)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-19T01:32:02Z`, `zebrafish.pdf`, `\Users\PC`, `\Users\PC User\Documents`, `708591`, `68394`
- claim: > | | `zebrafish.pdf` | `\Users\PC User\Documents` | `68394` | `708591` | `2016-06-19T01:32:02Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 45)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `research.docx`, `\Users\PC`, `Rapid cell regeneration research.docx`, `6361`, `493466`, `\Users\PC User\OneDrive\Documents`
- claim: > | | `Rapid cell regeneration research.docx` | `\Users\PC User\OneDrive\Documents` | `6361` | `493466` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 46)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Inventory.docx`, `\Users\PC`, `2193`, `STARK-TS-Level7-CryoDNA Storage Inventory.docx`, `20124`, `\Users\PC User\OneDrive\Documents`
- claim: > | | `STARK-TS-Level7-CryoDNA Storage Inventory.docx` | `\Users\PC User\OneDrive\Documents` | `2193` | `20124` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 47)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `sample-Alpha_Experiment.docx`, `\Users\PC`, `58405`, `\Users\PC User\OneDrive\Documents`, `Cryo-regeneration of DNA sample-Alpha_Experiment.docx`, `494629`
- claim: > | | `Cryo-regeneration of DNA sample-Alpha_Experiment.docx` | `\Users\PC User\OneDrive\Documents` | `58405` | `494629` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 48)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `attempts.xlsx`, `\Users\PC`, `12382`, `cryoregeneration x-alpha attempts.xlsx`, `\Users\PC User\OneDrive\Documents`, `58966`
- claim: > | | `cryoregeneration x-alpha attempts.xlsx` | `\Users\PC User\OneDrive\Documents` | `58966` | `12382` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 49)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Stark_TS-Level8A_CryoDNA.blacklight.docx`, `\Users\PC`, `58969`, `20000293`, `\Users\PC User\OneDrive\Documents\Level_8`
- claim: > | | `Stark_TS-Level8A_CryoDNA.blacklight.docx` | `\Users\PC User\OneDrive\Documents\Level_8` | `58969` | `20000293` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 50)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Marriage.docx`, `\Users\PC`, `17251`, `58971`, `Stark_TS-Level8a_DNA Marriage.docx`, `\Users\PC User\OneDrive\Documents\Level_8`
- claim: > | | `Stark_TS-Level8a_DNA Marriage.docx` | `\Users\PC User\OneDrive\Documents\Level_8` | `58971` | `17251` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 51)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Information.docx`, `\Users\PC`, `59216`, `23187`, `\Users\PC User\OneDrive\Documents\Level_8`, `Level 8 Indoc Information.docx`
- claim: > | | `Level 8 Indoc Information.docx` | `\Users\PC User\OneDrive\Documents\Level_8` | `59216` | `23187` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 52)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `samples.docx`, `\Users\PC`, `Observations on regenerative DNA samples.docx`, `59031`, `\Users\PC User\OneDrive\Documents\Level_12`, `129214`
- claim: > | | `Observations on regenerative DNA samples.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `59031` | `129214` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 53)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Cryo-DNA_DraftStandards_lab_results.docx`, `\Users\PC`, `Reverse Cryo-DNA_DraftStandards_lab_results.docx`, `59034`, `21469`, `\Users\PC User\OneDrive\Documents\Level_12`
- claim: > | | `Reverse Cryo-DNA_DraftStandards_lab_results.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `59034` | `21469` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 54)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx`, `\Users\PC`, `178280`, `56770`, `\Users\PC User\OneDrive\Documents\Level_12`
- claim: > | | `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `56770` | `178280` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CON…

### ✅ verified _(line 55)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `4.docx`, `\Users\PC`, `213302`, `59190`, `Stark TS-Level 12_Project_Nehemiah 4.docx`, `\Users\PC User\OneDrive\Documents\Level_12`
- claim: > | | `Stark TS-Level 12_Project_Nehemiah 4.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `59190` | `213302` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED]

### ✅ verified _(line 57)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-19T01:32:02Z`, `zebrafish.pdf`, `Zone.Identifier`, `68394`, `zebrafish.pdf:Zone.Identifier`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** `zebrafish.pdf` (entry `68394`) carries a `Zone.Identifier` ADS (`zebrafish.pdf:Zone.Identifier`, 106 bytes), indicating it was downloa…

### ✅ verified _(line 59)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-29T16:20:43Z`, `2016-06-29T16:20:16Z`, `2016-06-29T20:21:28Z`, `2016-06-30T02:02:43Z`, `DNA_replication_en.png`, `490px-Nulcear_radiation-LEVEL7.jpg`, `research.docx`, `notes.docx` (+8 more)
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** Recent Item links confirm active opening of research files on June 29–30, 2016: - `ZF DNA splice test notes.docx.lnk` (entry `8408`), m…

### ✅ verified _(line 65)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-18T22:00:15Z`, `2016-06-30T14:47:38Z`, `Stark_TS-Level8A_CryoDNA.blacklight.docx`, `research.docx`, `zebrafish.pdf`, `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx`, `notes.docx`, `Inventory.docx` (+3 more)
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** The workstation of "PC User" (Anthony Vanko) contained all three JARVIS-flagged research topics — zebrafish DNA splice research (`ZF DN…

### ✅ verified _(line 73)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-05-13T19:15:07Z`, `\Windows\Recent`, `\Users\PC`, `\Users\PC User\AppData\Roaming\Microsoft\Windows\Recent\`, `STARK_ENT (D).lnk`, `D:`, `5030`, `(D)`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** A Recent Items link file `STARK_ENT (D).lnk` (entry `5030`) exists at `\Users\PC User\AppData\Roaming\Microsoft\Windows\Recent\`, creat…

### ✅ verified _(line 77)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `\Users\PC`, `58969`, `58971`, `Level_8`, `56770`, `true`, `Level_12` (+2 more)
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** All eleven classified files in `\Users\PC User\OneDrive\Documents\` and its subdirectories (`Level_8`, `Level_12`) share the same MFT r…

### ✅ verified _(line 79)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-30T14:47:38Z`, `2016-06-30T14:25:38Z`, `STARKSURFACE-20160630-1025.log`, `395`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** A Stark network monitoring log `STARKSURFACE-20160630-1025.log` (entry `395`) was created at `2016-06-30T14:25:38Z` — 22 minutes before…

### ✅ verified _(line 81)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-21T10:43:37Z`, `STARKSURFACE-20160621-0643.log`, `\Windows\Temp`, `38`, `160752`, `\Windows\Temp\`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** The MFT confirms an earlier anomalously large Stark monitoring log: `STARKSURFACE-20160621-0643.log` (entry `38`, `160752` bytes, creat…

### ✅ verified _(line 94)_
- tools: `ezt_mft_parse`, `ezt_persistence_keys_parse`
- exec_ids: `daf567387d3d`, `3a15e8f457fe`
- matched: `2016-05-13T19:15:07Z`, `2016-06-30T14:47:38Z`, `58969`, `copied`, `STARK_ENT (D).lnk`, `58971`, `D:`, `true` (+2 more)
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`, exec_id `019ebb3b-b1b4-7490-b112-3a15e8f457fe`]** Vanko copied a large volume of Stark classified research data to his workstation on 201…

### ✅ verified _(line 102)_
- tools: `ezt_mft_parse`, `ezt_prefetch_parse`
- exec_ids: `daf567387d3d`, `0a1ac717beaf`
- matched: `2016-06-30T14:46:54Z`, `2016-06-30T14:47:38Z`, `2016-07-02T23:02:23Z`, `2016-11-04T13:24:58Z`, `ONEDRIVE.EXE`, `-CA84A5C1.pf`, `10575`, `ONEDRIVE.EXE-CA84A5C1.pf` (+2 more)
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`, exec_id `019ebb3b-e922-7b73-9e2c-0a1ac717beaf`]** The MFT shows the Prefetch file `ONEDRIVE.EXE-CA84A5C1.pf` (entry `10575`) was created …

### ✅ verified _(line 104)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `3a15e8f457fe`
- matched: `OneDrive.exe`, `\Users\PC`, `C:\Users\PC`, `C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe`, `OneDrive`
- claim: > **[CONFIRMED — exec_id `019ebb3b-b1b4-7490-b112-3a15e8f457fe`]** HKCU Run key confirms OneDrive was configured to autostart at every login: value name `OneDrive`, value data `C:\Users\PC User\AppData\…

### ✅ verified _(line 106)_
- tools: `ezt_prefetch_parse`
- exec_ids: `0a1ac717beaf`
- matched: `SYNCENGINE-2016-9-30.1154.6044.1.AODL`, `SYNCENGINE-2016-7-2.232.6860.1.AODL`, `SYNCENGINE-2016-8-8.1851.6300.1.AODL`, `SYNCENGINE-2016-10-30.2311.7980.1.AODL`
- claim: > **[CONFIRMED — exec_id `019ebb3b-e922-7b73-9e2c-0a1ac717beaf`]** The Prefetch files_loaded list references sync log files `SYNCENGINE-2016-7-2.232.6860.1.AODL` (July 2, 2016), `SYNCENGINE-2016-8-8.185…

### ✅ verified _(line 110)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `3a15e8f457fe`
- matched: `iCloudServices.exe`, `Backup.exe`, `ApplePhotoStreams.exe`, `iCloudDrive.exe`, `iCloudPhotos.exe`, `\Users\PC`, `C:\Users\PC`, `C:\Program` (+4 more)
- claim: > **[CONFIRMED — exec_id `019ebb3b-b1b4-7490-b112-3a15e8f457fe`]** The following additional cloud-sync clients are configured to autostart via HKCU Run: - `iCloudServices.exe` — `C:\Program Files (x86)\…

### ✅ verified _(line 121)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-10-14T22:42:03Z`, `2016-07-07T01:44:54Z`, `Dropbox.exe`, `\Users\PC`, `Program Files (x86)\Dropbox`, `\Users\PC User\Dropbox\`, `16968`, `32909` (+2 more)
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** Dropbox client is installed at `Client_12.4.22` under `Program Files (x86)\Dropbox` (MFT entry `16968`, `Dropbox.exe`, record_changed `…

### ✅ verified _(line 123)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-10-14T22:42:42Z`, `-8DACDCF4.pf`, `DROPBOX.EXE`, `\Windows\Prefetch`, `false`, `in_use`, `149508`, `DROPBOX.EXE-8DACDCF4.pf`
- claim: > **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** `DROPBOX.EXE-8DACDCF4.pf` (entry `149508`, `\Windows\Prefetch`) has the MFT `in_use` field set to `false` — this Prefetch entry is unal…

### ✅ verified _(line 125)_
- tools: `tsk_fls_list`
- exec_ids: `4e71f7d8f70a`
- matched: `DropboxUpdate.log`, `DropboxUpdate.log-2016-02-18-02-09-43-432-6996`, `303485`, `20866`, `DropboxUpdate.log-2015-08-26-22-23-59-490-3772`, `ProgramData/Dropbox/Update/Log`
- claim: > **[CONFIRMED — exec_id `019ebb30-b3fc-71b3-92d5-4e71f7d8f70a`]** Multiple DropboxUpdate log files exist in `ProgramData/Dropbox/Update/Log` spanning August 2015 through 2016, including `DropboxUpdate.…

### ✅ verified _(line 129)_
- tools: `tsk_fls_list`
- exec_ids: `4e71f7d8f70a`
- matched: `5.1.0.34`, `5.2.1.69`, `4.1.1.53`, `306815`, `iCloud Control Panel 5.1.0.34`, `46785`, `iCloud Control Panel 5.2.1.69`, `21263` (+1 more)
- claim: > **[CONFIRMED — exec_id `019ebb30-b3fc-71b3-92d5-4e71f7d8f70a`]** Multiple versions of the iCloud installer are cached: - `iCloud Control Panel 4.1.1.53` (inode `306815`) - `iCloud Control Panel 5.1.0.…

### ✅ verified _(line 146)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-06-29T16:20:43Z`, `2016-06-30T14:47:38Z`
- claim: > | Investigation Goal | Finding | exec_id(s) | Confidence | |---|---|---|---| | G1: Vanko involved in dissemination | All three JARVIS-flagged research topics (zebrafish, cell regeneration, ZF DNA spli…

### ✅ verified _(line 147)_
- tools: `ezt_mft_parse`
- exec_ids: `daf567387d3d`
- matched: `2016-05-13T19:15:07Z`, `2016-06-30T14:47:38Z`, `58969`, `copied`, `STARK_ENT (D).lnk`, `58971`, `D:`, `true` (+2 more)
- claim: > | | G2: Large-volume data copy from StarkResearch | Mapped drive `D:` (`STARK_ENT (D).lnk`, entry `5030`) to Stark server from `2016-05-13T19:15:07Z`; 14 classified files bulk-copied at `2016-06-30T14…

### ✅ verified _(line 148)_
- tools: `ezt_mft_parse`, `ezt_prefetch_parse`, `ezt_persistence_keys_parse`
- exec_ids: `daf567387d3d`, `0a1ac717beaf`, `3a15e8f457fe`
- matched: `2016-06-30T14:46:54Z`, `2016-07-07T01:44:54Z`, `OneDrive.exe`, `10575`
- claim: > | | G3: Post-transfer data disposition | OneDrive (primary): Prefetch file created `2016-06-30T14:46:54Z` (entry `10575`), HKCU autostart `OneDrive.exe`, sync logs through October 2016; Dropbox (insta…
