# Validator Report — iter_2

## Summary

- Total tagged claims:        **30**
  - CONFIRMED:                 22
  - INFERRED:                  4
  - HYPOTHESIS:                0
  - GAP:                       4
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           3 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                19 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 13.6%** (3 verified / 22 confirmed)

## Per-claim verdicts

### ⚠ partial _(line 53)_
- tools: `ewf_info`
- exec_ids: `4c95c580e3cd`
- matched: `2.9.0.13`, `20161104-HD001`, `20161104`
- **missing**: `2016-11-04T17:47:02Z`, `SRUDB.dat`, `Live Physical / fixed disk`, `2016-11-04`, `modified 2016-11-04T17:47:02Z`, `ADI 2.9.0.13`
- claim: > **[CONFIRMED — exec_id `019ebaf9-01b0-7552-9311-4c95c580e3cd`]** EWF metadata confirms acquisition by Ovie Carroll using FTK Imager `ADI 2.9.0.13`, case number `20161104`, evidence number `20161104-HD…

### ⚠ partial _(line 55)_
- tools: `tsk_partition_table`
- exec_ids: `cfeafe68f55f`
- matched: `230883328`, `Basic data partition`, `003`
- **missing**: `start_sector 1411072`
- claim: > **[CONFIRMED — exec_id `019ebaf9-026a-7542-b2a6-cfeafe68f55f`]** GPT partition table parsed. Slot `003` (`Basic data partition`) starts at `start_sector 1411072`, length `230883328` sectors — the Wind…

### ✅ verified _(line 57)_
- tools: `tsk_fs_stat`
- exec_ids: `eaa8b74fe21f`
- matched: `A420A4D720A4B1AA`, `Windows`
- claim: > **[CONFIRMED — exec_id `019ebaf9-1802-7af1-8976-eaa8b74fe21f`]** NTFS volume confirmed on partition slot 003. Volume name `Windows`, serial `A420A4D720A4B1AA`, cluster size 4096 bytes.

### ⚠ partial _(line 63)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `STARKSURFACE`
- **missing**: `file_name "PC User"`, `parent_path ".\\Users"`, `entry 263009`, `is_directory true`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** MFT `entry 263009` is directory `file_name "PC User"` under `parent_path ".\\Users"` (`is_directory true`) — the sole interactive profi…

### ⚠ partial _(line 65)_
- tools: `ezt_mft_parse`, `ezt_srum_parse`
- exec_ids: `458c571e8c0b`, `4d07dbeacf5c`
- matched: `2016-06-18T22:00:15Z`, `2016-10-30T23:19:25Z`, `NTUSER.DAT`, `S-1-5-21-3739107332-290452467-3466442662-1001`, `modified`, `PC User`, `push_notifications`, `record_changed`
- **missing**: `parent_path ".\\Users\\PC User"`, `entry 263010`, `file_name NTUSER.DAT`, `file_size 4194304`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`, exec_id `019ebb02-8e6e-7de2-96db-4d07dbeacf5c`]** The subject's Windows SID is `S-1-5-21-3739107332-290452467-3466442662-1001` (confirmed…

### ⚠ partial _(line 88)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `Stark_TS-Level8A_CryoDNA.blacklight.docx`, `4.docx`, `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx`, `research.docx`, `Inventory.docx`, `zebrafish.pdf`, `OneDrive\Documents`, `56770` (+8 more)
- **missing**: `parent_path ".\\Users\\PC User\\Documents"`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** Ten classified Stark Enterprises documents confirmed present in `OneDrive\Documents` by MFT. File names include `STARK-TS-Level7-CryoDN…

### ⚠ partial _(line 90)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `2016-06-29T16:20:16Z`, `research.docx`, `modified`, `Rapid cell regeneration research.docx.lnk`, `record_changed`
- **missing**: `parent_path ".\\Users\\PC User\\AppData\\Roaming\\Microsoft\\Windows\\Recent"`, `entry 2232`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** Recent-item LNK `Rapid cell regeneration research.docx.lnk` MFT `entry 2232`, `parent_path ".\\Users\\PC User\\AppData\\Roaming\\Micros…

### ⚠ partial _(line 92)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `2016-06-19T01:32:02Z`, `zebrafish.pdf`, `68394`, `zebrafish.pdf:Zone.Identifier`, `record_changed`
- **missing**: `is_ads true`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** `zebrafish.pdf` at entry `68394` carries NTFS ADS `zebrafish.pdf:Zone.Identifier` (106 bytes, `is_ads true`), indicating it was downloa…

### ⚠ partial _(line 102)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `2016-06-30T14:47:38Z`, `Inventory.docx`, `research.docx`, `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx`, `Stark_TS-Level8A_CryoDNA.blacklight.docx`, `STARK-TS-Level7-CryoDNA Storage Inventory.docx`, `56770`, `2193` (+4 more)
- **missing**: `copied true`, `.\\Users\\PC User\\OneDrive\\Documents`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** Every classified document in `.\\Users\\PC User\\OneDrive\\Documents` carries `record_changed` `2016-06-30T14:47:38Z`. This single atom…

### ⚠ partial _(line 104)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `2016-06-30T14:46:54Z`, `2016-06-30T14:47:38Z`, `ONEDRIVE.EXE`, `-CA84A5C1.pf`, `ONEDRIVE.EXE-CA84A5C1.pf`, `created`, `record_changed`
- **missing**: `entry 10575`, `parent_path ".\\Windows\\Prefetch"`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** Prefetch file `ONEDRIVE.EXE-CA84A5C1.pf`, MFT `entry 10575`, `parent_path ".\\Windows\\Prefetch"`, `created` `2016-06-30T14:46:54Z` — *…

### ⚠ partial _(line 106)_
- tools: `ezt_persistence_keys_parse`, `ezt_mft_parse`
- exec_ids: `8936940e6e65`, `458c571e8c0b`
- matched: `OneDrive.exe`, `\Users\PC`, `C:\Users\PC`, `OneDrive`, `C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe`
- **missing**: `entry 429`, `parent_path ".\\Users\\PC User\\AppData\\Local\\Microsoft\\OneDrive"`, `file_name "OneDrive.exe"`
- claim: > **[CONFIRMED — exec_id `019ebaff-f908-7cc3-b810-8936940e6e65`, exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** The HKCU Run key contains value name `OneDrive` with data path `C:\Users\PC User\AppDat…

### ⚠ partial _(line 110)_
- tools: `ezt_srum_parse`, `ezt_mft_parse`
- exec_ids: `4d07dbeacf5c`, `458c571e8c0b`
- matched: `2016-11-04T17:47:02Z`, `SRUDB.dat`, `network_usage`, `2016-09-29`
- **missing**: `file_name SRUDB.dat`, `modified 2016-11-04T17:47:02Z`, `parent_path ".\\Windows\\System32\\sru"`, `entry 114124`, `file_size 23003136`
- claim: > **[CONFIRMED — exec_id `019ebb02-8e6e-7de2-96db-4d07dbeacf5c`, exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** SRUDB.dat MFT `entry 114124`, `file_name SRUDB.dat`, `parent_path ".\\Windows\\System32…

### ⚠ partial _(line 126)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `2016-06-30T14:46:54Z`, `OneDrive.exe`, `56770`, `58405`, `58966`, `58971`, `2193`, `58969` (+3 more)
- **missing**: `.\\Users\\PC User\\OneDrive\\Documents`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** All classified Stark documents in `.\\Users\\PC User\\OneDrive\\Documents` (10 confirmed files, entries `6361`, `2193`, `58405`, `58966…

### ⚠ partial _(line 128)_
- tools: `ezt_persistence_keys_parse`, `ezt_mft_parse`
- exec_ids: `8936940e6e65`, `458c571e8c0b`
- matched: `OneDrive.exe`, `\Users\PC`, `C:\Users\PC`, `OneDrive`, `C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe`
- **missing**: `entry 429`, `parent_path ".\\Users\\PC User\\AppData\\Local\\Microsoft\\OneDrive"`, `file_name "OneDrive.exe"`
- claim: > **[CONFIRMED — exec_id `019ebaff-f908-7cc3-b810-8936940e6e65`, exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** HKCU Run key value `OneDrive` data `C:\Users\PC User\AppData\Local\Microsoft\OneDrive\O…

### ⚠ partial _(line 134)_
- tools: `ezt_prefetch_parse`
- exec_ids: `1ff41e383eeb`
- matched: `2016-06-29T20:32:27Z`, `2016-06-30T01:12:53Z`, `2016-06-29T16:12:13Z`, `2016-06-30T01:40:51Z`, `2016-06-29T20:25:57Z`, `2016-06-30T01:56:46Z`, `VeraCrypt.exe`, `VERACRYPT.EXE` (+1 more)
- **missing**: `run_count 6`, ` and `, `executable_name "VERACRYPT.EXE"`, `last_run 2016-06-30T01:56:46Z`
- claim: > **[CONFIRMED — exec_id `019ebb05-f629-78d2-aff8-1ff41e383eeb`]** VeraCrypt.exe Prefetch: `executable_name "VERACRYPT.EXE"`, hash `9E1B0240`, `run_count 6`, `last_run 2016-06-30T01:56:46Z`, previous ru…

### ⚠ partial _(line 136)_
- tools: `ezt_mft_parse`, `ezt_shimcache_parse`
- exec_ids: `458c571e8c0b`, `7a02c46d08e8`
- matched: `2016-06-29T15:51:16Z`, `VeraCrypt.exe`, `1.17.exe`, `Format.exe`, `\Users\PC`, `C:\Users\PC`, `C:\Program`
- **missing**: `path "C:\Program Files\VeraCrypt\VeraCrypt.exe"`, `file_name "VeraCrypt Setup 1.17.exe"`, `path "C:\Program Files\VeraCrypt\VeraCrypt Format.exe"`, `parent_path ".\\Users\\PC User\\Downloads"`, `executed "Yes"`, `path "C:\Users\PC User\Downloads\VeraCrypt Setup 1.17.exe"`, `entry 32010`, `has_ads true` (+1 more)
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`, exec_id `019ebb07-bc98-7522-8fdd-7a02c46d08e8`]** VeraCrypt Setup 1.17 downloaded: MFT `entry 32010`, `file_name "VeraCrypt Setup 1.17.ex…

### ⚠ partial _(line 144)_
- tools: `ezt_persistence_keys_parse`, `ezt_mft_parse`
- exec_ids: `8936940e6e65`, `458c571e8c0b`
- matched: `NTUSER.DAT`, `iCloudDrive.exe`, `iCloudServices.exe`, `ApplePhotoStreams.exe`, `iCloudPhotos.exe`, `iCloudPhotos`, `ApplePhotoStreams`, `iCloudServices` (+1 more)
- **missing**: `parent_path ".\\Users\\PC User"`, `entry 263010`
- claim: > **[CONFIRMED — exec_id `019ebaff-f908-7cc3-b810-8936940e6e65`, exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** Persistence_keys parse (exec_id `019ebaff-f908-7cc3-b810-8936940e6e65`) confirms HKCU R…

### ⚠ partial _(line 146)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `2016-11-04T17:41:23Z`, `-E72FEFE1.pf`, `DROPBOXUPDATE.EXE`, `DROPBOXUPDATE.EXE-E72FEFE1.pf`, `3100`
- **missing**: `modified 2016-11-04T17:41:23Z`, `.\\Program Files (x86)\\Dropbox\\Client_12.4.22`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** Dropbox Client 12.4.22 binary directory confirmed in MFT under `.\\Program Files (x86)\\Dropbox\\Client_12.4.22`. Prefetch `DROPBOXUPDA…

### ✅ verified _(line 150)_
- tools: `ezt_shimcache_parse`
- exec_ids: `7a02c46d08e8`
- matched: `SIGN.MEDIA`
- claim: > **[CONFIRMED — exec_id `019ebb07-bc98-7522-8fdd-7a02c46d08e8`]** Shimcache contains entries from removable media identified by `SIGN.MEDIA` tokens, indicating USB devices that were connected and brows…

### ✅ verified _(line 162)_
- tools: `ezt_shimcache_parse`
- exec_ids: `7a02c46d08e8`
- matched: `SIGN.MEDIA`
- claim: > Each row is **[CONFIRMED — exec_id `019ebb07-bc98-7522-8fdd-7a02c46d08e8`]** with its respective `SIGN.MEDIA` value and path token from the shimcache AppCompatCache output.

### ⚠ partial _(line 166)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `2016-07-01T23:26:46Z`, `2016-07-01T23:29:41Z`, `2016-07-01T23:24:22Z`, `IMAGER.EXE`, `-9A323C93.pf`, `FTK IMAGER.EXE-9A323C93.pf`, `388`, `6422` (+1 more)
- **missing**: `created 2016-07-01T23:26:46Z`, `created 2016-07-01T23:24:22Z`, `created 2016-07-01T23:29:41Z`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** FTK Imager Prefetch (entry `3874`, `FTK IMAGER.EXE-9A323C93.pf`) `created 2016-07-01T23:24:22Z`; Magnet RAM Capture Prefetch (entry `64…

### ⚠ partial _(line 172)_
- tools: `ezt_mft_parse`, `ezt_prefetch_parse`
- exec_ids: `458c571e8c0b`, `1ff41e383eeb`
- matched: `2016-06-29T16:03:13Z`, `2016-06-30T01:56:46Z`, `2016-06-29T16:12:33Z`, `2016-06-30T01:14:52Z`, `VeraCrypt.exe`, `1.17.EXE`, `-6EA86AF5.pf`, `-9CE5E690.pf` (+6 more)
- **missing**: `created 2016-06-29T16:03:13Z`, `modified 2016-06-30T01:14:52Z`, `created 2016-06-29T16:12:33Z`
- 🚨 negation violations (claimed absent but found): `4397`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`, exec_id `019ebb05-f629-78d2-aff8-1ff41e383eeb`]** VeraCrypt installed `2016-06-29T16:03:13Z` (MFT entry `30644`, `VERACRYPT SETUP 1.17.EX…
