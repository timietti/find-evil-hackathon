# Validator Report — iter_2

## Summary

- Total tagged claims:        **30**
  - CONFIRMED:                 21
  - INFERRED:                  5
  - HYPOTHESIS:                2
  - GAP:                       2
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           11 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                8 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           2 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 52.4%** (11 verified / 21 confirmed)

## Per-claim verdicts

### 🔍 not_confirmed _(line 30)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > 3. Entry 2193 has `"copied":true`, `"usec_zeros":true` (not timestomped); entry 6361 has `"timestomped":true` — fix compound tokens to bare `true` 4. Same issue — `record_changed: X` and `copied: true…

### ⚠ partial _(line 46)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `"PC User"`, `108`, `live#3aanthony.vanko`, `S-1-5-21-3739107332-290452467-3466442662-1001`
- **missing**: `. This ties the `
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The Windows user account on this device is named `"PC User"`. The Skype application data path in the MFT confirms this account belongs …

### ✅ verified _(line 48)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `\Users\PC`, `\Users\PC User\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** Classified Stark Enterprises research files were present on Vanko's workstation at the time of imaging. The following files were found …

### ✅ verified _(line 59)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-29T16:20:43Z`, `2016-06-29T16:20:16Z`, `2016-06-19T01:32:02Z`, `notes.docx`, `zebrafish.pdf`, `research.docx`, `Inventory.docx`, `2232` (+7 more)
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** Recent-folder LNK files corroborate that the user personally opened these files: `"zebrafish.pdf.lnk"` (entry `51827`, modified `2016-0…

### ✅ verified _(line 61)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-05-13T19:15:07Z`, `5030`, `"STARK_ENT (D).lnk"`, `D:`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** A mapped drive Recent link `"STARK_ENT (D).lnk"` (entry `5030`, created `2016-05-13T19:15:07Z`) confirms Vanko had a mapped drive lette…

### ✅ verified _(line 69)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:25:38Z`, `STARKSURFACE-20160630-1025.log`, `\Windows\Temp`, `\Users\PC`, `395`, `.\Users\PC User\AppData\Local\Temp\`, `.\Windows\Temp\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The device contains a pattern of regular STARKSURFACE IT-monitoring agent log files in `.\Windows\Temp\` and `.\Users\PC User\AppData\L…

### ✅ verified _(line 71)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:47:38Z`, `research.docx`, `Inventory.docx`, `usec_zeros`, `Rapid cell regeneration research.docx`, `copied`, `STARK-TS-Level7-CryoDNA Storage Inventory.docx`, `timestomped` (+4 more)
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The three classified documents stored in OneDrive share an identical `record_changed` timestamp of `2016-06-30T14:47:38Z`. The `STARK-T…

### ⚠ partial _(line 81)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:47:38Z`, `Inventory.docx`, `copied`, `STARK-TS-Level7-CryoDNA Storage Inventory.docx`, `2193`, `true`, `record_changed`
- **missing**: `.\\Users\\PC User\\OneDrive\\Documents`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** All three classified documents with `record_changed` timestamp `2016-06-30T14:47:38Z` are physically stored inside `.\\Users\\PC User\\…

### ⚠ partial _(line 83)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-10-30T23:12:56Z`, `TraceArchive.6390.0509-79.etl`, `47`
- **missing**: `.\\Users\\PC User\\AppData\\Local\\Microsoft\\OneDrive\\logs\\Personal`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** OneDrive client activity logs exist under `.\\Users\\PC User\\AppData\\Local\\Microsoft\\OneDrive\\logs\\Personal`, with the trace arch…

### ⚠ partial _(line 87)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-29T16:03:13Z`, `2016-06-29T15:51:16Z`, `1.17.exe`, `VeraCrypt Setup 1.17.exe`, `33215`, `32010`
- **missing**: `.\\Users\\PC User\\Downloads`, `.\\Program Files\\VeraCrypt`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** `VeraCrypt Setup 1.17.exe` was downloaded from the internet to `.\\Users\\PC User\\Downloads` on `2016-06-29T15:51:16Z` (entry `32010`,…

### ✅ verified _(line 89)_
- tools: `ezt_prefetch_parse`
- exec_ids: `e76f6210c4b7`
- matched: `2016-06-29T16:32:16Z`, `2016-06-29T20:32:30Z`, `2016-06-29T16:32:41Z`, `2016-06-30T01:14:42Z`, `2016-06-29T16:34:32Z`, `2016-06-29T16:12:23Z`, `FORMAT.EXE`, `6` (+1 more)
- claim: > **[CONFIRMED — exec_id `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`]** `VERACRYPT FORMAT.EXE` — the volume creation tool — ran `6` times. Run history: `2016-06-29T16:12:23Z`, `2016-06-29T16:32:16Z`, `2016-0…

### ✅ verified _(line 91)_
- tools: `ezt_prefetch_parse`
- exec_ids: `43bf884db914`
- matched: `2016-06-30T01:12:53Z`, `2016-06-29T16:12:13Z`, `2016-06-30T01:56:46Z`, `2016-06-29T20:32:27Z`, `2016-06-30T01:40:51Z`, `2016-06-29T20:25:57Z`, `VERACRYPT.EXE`, `6`
- claim: > **[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`]** `VERACRYPT.EXE` — the main VeraCrypt executable for mounting containers — also ran `6` times: `2016-06-29T16:12:13Z`, `2016-06-29T20:25…

### ⚠ partial _(line 93)_
- tools: `ezt_prefetch_parse`, `ezt_mft_parse`
- exec_ids: `43bf884db914`, `173ab081dfe2`
- matched: `2016-06-29T20:32:56Z`, `2016-06-29T20:37:00Z`, `2016-06-29T20:11:03Z`, `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\CONFIGURATION.XML`, `29963`, `4397`, `33344`, `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\HISTORY.XML`
- **missing**: `.\\Users\\PC User\\AppData\\Roaming\\VeraCrypt`
- claim: > **[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The VeraCrypt Prefetch references `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\HISTORY.XML` and `\…

### ✅ verified _(line 99)_
- tools: `ezt_prefetch_parse`
- exec_ids: `c7b2630cb6bc`
- matched: `2016-06-18T22:02:05Z`, `SMALLFTPD.EXE`, `\USERS\DEFAULTPRINTER\SMALLFTPD.EXE`, `defaultprinter`
- claim: > **[CONFIRMED — exec_id `019ec9e1-27ec-7e61-999c-c7b2630cb6bc`]** `SMALLFTPD.EXE` — a small Windows FTP server — last ran on `2016-06-18T22:02:05Z`, launched from the `defaultprinter` account's home di…

### ✅ verified _(line 103)_
- tools: `ezt_prefetch_parse`, `ezt_mft_parse`
- exec_ids: `7b41cecaf0ea`, `173ab081dfe2`
- matched: `2016-06-29T16:01:38Z`, `2016-06-29T20:26:29Z`, `7ZFM.EXE`, `-44040917.pf`, `7Z1602-X64.EXE`, `7ZFM.EXE-44040917.pf`, `19841`, `\USERS\PC USER\DOWNLOADS\7Z1602-X64.EXE`
- claim: > **[CONFIRMED — exec_id `019ec9e1-2a33-7200-bd91-7b41cecaf0ea`, `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** `7Z1602-X64.EXE` (7-Zip v16.02 installer) ran once at `2016-06-29T16:01:38Z` from `\USERS\PC US…

### ⚠ partial _(line 113)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `108`, `live#3aanthony.vanko`, `PC User`
- **missing**: `.\\Users\\PC User\\AppData\\Roaming\\Skype\\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The Skype data path for MFT entry `108` has parent_path `live#3aanthony.vanko` under `.\\Users\\PC User\\AppData\\Roaming\\Skype\\`, ty…

### ⚠ partial _(line 115)_
- tools: `ezt_srum_parse`
- exec_ids: `1bdeb4b613aa`
- matched: `S-1-5-21-3739107332-290452467-3466442662-1001`
- **missing**: `SRUDB.dat`
- claim: > **[CONFIRMED — exec_id `019ec9de-f970-7dd1-8413-1bdeb4b613aa`]** The SRUDB.dat push_notifications provider associates SID `S-1-5-21-3739107332-290452467-3466442662-1001` with personal consumer applica…

### ⚠ partial _(line 117)_
- tools: `ezt_prefetch_parse`, `ezt_prefetch_parse`
- exec_ids: `43bf884db914`, `e76f6210c4b7`
- matched: `\Users\PC`, `CONFIGURATION.XML`, `volume_serial`, `HISTORY.XML`, `20A4B1AA`, `\Users\PC User\AppData\Roaming\VeraCrypt\`
- **missing**: `A420A4D720A4B1AA`
- claim: > **[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`]** VeraCrypt configuration data (`HISTORY.XML`, `CONFIGURATION.XML`) is stored under `\Users\PC Us…

### ✅ verified _(line 119)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:25:38Z`, `STARKSURFACE-20160630-1025.log`, `\Windows\Temp`, `\Users\PC`, `395`, `.\Users\PC User\AppData\Local\Temp\`, `.\Windows\Temp\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The STARKSURFACE IT-monitoring logs in `.\Windows\Temp\` and `.\Users\PC User\AppData\Local\Temp\` show the machine regularly connectin…

### ✅ verified _(line 125)_
- tools: `ezt_mft_parse`, `ezt_prefetch_parse`, `ezt_prefetch_parse`
- exec_ids: `173ab081dfe2`, `43bf884db914`, `e76f6210c4b7`
- matched: `2016-06-30T01:14:42Z`, `2016-06-30T01:56:46Z`, `research.docx`, `Format.exe`, `VeraCrypt.exe`, `Rapid cell regeneration research.docx`, `timestomped`, `true` (+1 more)
- ✅ verified absences (negated): `2016-11-04T17:47:41Z`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`, `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`]** The VeraCrypt encrypted container file is absent from a…

### 🔍 not_confirmed _(line 149)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > All `[CONFIRMED]
