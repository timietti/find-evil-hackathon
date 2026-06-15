# Validator Report — iter_3

## Summary

- Total tagged claims:        **28**
  - CONFIRMED:                 20
  - INFERRED:                  4
  - HYPOTHESIS:                2
  - GAP:                       2
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           16 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                2 (some tokens found, some missing)
- ❌ failed:                 1 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           1 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 80.0%** (16 verified / 20 confirmed)

## Per-claim verdicts

### 🔍 not_confirmed _(line 43)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[10] not_confirmed** — Removed the footer line beginning "All `[CONFIRMED]`…" which contained the tag without an exec_id.

### ⚠ partial _(line 49)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `\Users\PC`, `"PC User"`, `108`, `parent_path`
- **missing**: `, placing `, ` (confirmed via SRUM, exec_id `, ` squarely under the `, ` profile. The active user SID is `
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The Windows user account on this device is named `"PC User"`. MFT entry `108` has `parent_path` `.\Users\PC User\AppData\Roaming\Skype\…

### ✅ verified _(line 51)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `\Users\PC`, `\Users\PC User\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** Classified Stark Enterprises research files were present on Vanko's workstation at imaging time. The following files were identified un…

### ✅ verified _(line 62)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-29T16:20:43Z`, `2016-06-29T16:20:16Z`, `2016-06-19T01:32:02Z`, `notes.docx`, `zebrafish.pdf`, `research.docx`, `Inventory.docx`, `2232` (+7 more)
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** Recent-folder LNK files corroborate that the user personally opened these files. MFT returns: `zebrafish.pdf.lnk` (entry `51827`, modif…

### ✅ verified _(line 64)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-05-13T19:15:07Z`, `D:`, `5030`, `STARK_ENT (D).lnk`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** A mapped-drive Recent link `STARK_ENT (D).lnk` (entry `5030`, created `2016-05-13T19:15:07Z`) confirms Vanko had a drive letter `D:` po…

### ✅ verified _(line 72)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:25:38Z`, `STARKSURFACE-20160630-1025.log`, `\Windows\Temp`, `\Users\PC`, `395`, `.\Users\PC User\AppData\Local\Temp\`, `.\Windows\Temp\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The device contains STARKSURFACE IT-monitoring agent log files in `.\Windows\Temp\` and `.\Users\PC User\AppData\Local\Temp\` spanning …

### ✅ verified _(line 74)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:47:38Z`, `research.docx`, `Inventory.docx`, `\Users\PC`, `usec_zeros`, `Rapid cell regeneration research.docx`, `copied`, `.\Users\PC User\OneDrive\Documents` (+6 more)
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** Entries `2193` and `6361` — both classified documents in `.\Users\PC User\OneDrive\Documents` — share an identical `record_changed` tim…

### ✅ verified _(line 84)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:47:38Z`, `\Users\PC`, `copied`, `.\Users\PC User\OneDrive\Documents`, `parent_path`, `2193`, `true`, `record_changed` (+1 more)
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** All confirmed classified documents with `record_changed` timestamp `2016-06-30T14:47:38Z` (entries `2193` and `6361`) are physically st…

### ✅ verified _(line 86)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-10-30T23:12:56Z`, `\Users\PC`, `.\Users\PC User\AppData\Local\Microsoft\OneDrive\logs\Personal`, `file_name`, `parent_path`, `47`, `TraceArchive.6390.0509-79.etl`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** OneDrive client activity logs exist at `parent_path` `.\Users\PC User\AppData\Local\Microsoft\OneDrive\logs\Personal`. The trace archiv…

### ✅ verified _(line 90)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-29T16:03:13Z`, `2016-06-29T15:51:16Z`, `1.17.exe`, `\Users\PC`, `VeraCrypt Setup 1.17.exe`, `Zone.Identifier`, `parent_path`, `.\Program Files` (+4 more)
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** `VeraCrypt Setup 1.17.exe` (entry `32010`) was downloaded from the internet to `parent_path` `.\Users\PC User\Downloads` on `2016-06-29…

### ✅ verified _(line 92)_
- tools: `ezt_prefetch_parse`
- exec_ids: `e76f6210c4b7`
- matched: `2016-06-29T16:32:16Z`, `2016-06-29T20:32:30Z`, `2016-06-29T16:32:41Z`, `2016-06-30T01:14:42Z`, `2016-06-29T16:34:32Z`, `2016-06-29T16:12:23Z`, `FORMAT.EXE`, `6` (+1 more)
- claim: > **[CONFIRMED — exec_id `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`]** `VERACRYPT FORMAT.EXE` — the volume creation tool — ran `6` times with run history: `2016-06-29T16:12:23Z`, `2016-06-29T16:32:16Z`, `20…

### ✅ verified _(line 94)_
- tools: `ezt_prefetch_parse`
- exec_ids: `43bf884db914`
- matched: `2016-06-30T01:12:53Z`, `2016-06-29T16:12:13Z`, `2016-06-30T01:56:46Z`, `2016-06-29T20:32:27Z`, `2016-06-30T01:40:51Z`, `2016-06-29T20:25:57Z`, `VERACRYPT.EXE`, `6`
- claim: > **[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`]** `VERACRYPT.EXE` — the main mounting executable — ran `6` times: `2016-06-29T16:12:13Z`, `2016-06-29T20:25:57Z`, `2016-06-29T20:32:27Z`,…

### ✅ verified _(line 96)_
- tools: `ezt_prefetch_parse`, `ezt_mft_parse`
- exec_ids: `43bf884db914`, `173ab081dfe2`
- matched: `2016-06-29T20:32:56Z`, `2016-06-29T20:37:00Z`, `2016-06-29T20:11:03Z`, `\Users\PC`, `History.xml`, `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\CONFIGURATION.XML`, `29963`, `.\Users\PC User\AppData\Roaming` (+5 more)
- claim: > **[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The VeraCrypt Prefetch references `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\HISTORY.XML` and `\…

### ✅ verified _(line 102)_
- tools: `ezt_prefetch_parse`
- exec_ids: `c7b2630cb6bc`
- matched: `2016-06-18T22:02:05Z`, `SMALLFTPD.EXE`, `\USERS\DEFAULTPRINTER\SMALLFTPD.EXE`
- claim: > **[CONFIRMED — exec_id `019ec9e1-27ec-7e61-999c-c7b2630cb6bc`]** `SMALLFTPD.EXE` — a small Windows FTP server — last ran on `2016-06-18T22:02:05Z`, launched from `\USERS\DEFAULTPRINTER\SMALLFTPD.EXE`.…

### ✅ verified _(line 106)_
- tools: `ezt_prefetch_parse`, `ezt_mft_parse`
- exec_ids: `7b41cecaf0ea`, `173ab081dfe2`
- matched: `2016-06-29T16:01:38Z`, `2016-06-29T20:26:29Z`, `7ZFM.EXE`, `-44040917.pf`, `7Z1602-X64.EXE`, `7ZFM.EXE-44040917.pf`, `19841`, `\USERS\PC USER\DOWNLOADS\7Z1602-X64.EXE`
- claim: > **[CONFIRMED — exec_id `019ec9e1-2a33-7200-bd91-7b41cecaf0ea`, `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** `7Z1602-X64.EXE` (7-Zip v16.02 installer) ran once at `2016-06-29T16:01:38Z` from `\USERS\PC US…

### ⚠ partial _(line 116)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `\Users\PC`, `parent_path`, `108`
- **missing**: `, confirming the `, ` Windows account is Anthony Vanko's personal Microsoft Live/Skype account (`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** MFT entry `108` resides at `parent_path` `.\Users\PC User\AppData\Roaming\Skype\live#3aanthony.vanko\media_messaging\emo_cache_v2`, con…

### ❌ failed _(line 118)_
- tools: `ezt_srum_parse`
- exec_ids: `1bdeb4b613aa`
- 🚨 negation violations (claimed absent but found): `S-1-5-21-3739107332-290452467-3466442662-1001`
- claim: > **[CONFIRMED — exec_id `019ec9de-f970-7dd1-8413-1bdeb4b613aa`]** The SRUM push_notifications provider associates SID `S-1-5-21-3739107332-290452467-3466442662-1001` with personal consumer application …

### ✅ verified _(line 120)_
- tools: `ezt_prefetch_parse`, `ezt_prefetch_parse`, `tsk_fs_stat`
- exec_ids: `43bf884db914`, `e76f6210c4b7`, `97cb61c3bc07`
- matched: `\Users\PC`, `A420A4D720A4B1AA`, `CONFIGURATION.XML`, `volume_serial`, `HISTORY.XML`, `20A4B1AA`, `\Users\PC User\AppData\Roaming\VeraCrypt\`
- claim: > **[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`, `019ec9d8-e644-7e40-a146-97cb61c3bc07`]** VeraCrypt configuration data (`HISTORY.XML`, `CONFIGURA…

### ✅ verified _(line 122)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:25:38Z`, `STARKSURFACE-20160630-1025.log`, `395`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** STARKSURFACE IT-monitoring logs show the machine regularly connecting to the Stark network during business hours. Log `STARKSURFACE-201…

### ✅ verified _(line 128)_
- tools: `ezt_mft_parse`, `ezt_prefetch_parse`, `ezt_prefetch_parse`
- exec_ids: `173ab081dfe2`, `43bf884db914`, `e76f6210c4b7`
- matched: `2016-06-30T01:14:42Z`, `2016-06-30T01:56:46Z`, `research.docx`, `Format.exe`, `VeraCrypt.exe`, `Rapid cell regeneration research.docx`, `timestomped`, `true` (+1 more)
- ✅ verified absences (negated): `2016-11-04T17:47:41Z`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`, `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`]** The VeraCrypt encrypted container file is absent from a…
