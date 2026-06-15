# Validator Report — iter_1

## Summary

- Total tagged claims:        **27**
  - CONFIRMED:                 20
  - INFERRED:                  3
  - HYPOTHESIS:                2
  - GAP:                       2
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           6 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                13 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           1 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 30.0%** (6 verified / 20 confirmed)

## Per-claim verdicts

### ⚠ partial _(line 49)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `"PC User"`, `S-1-5-21-3739107332-290452467-3466442662-1001`
- **missing**: `.\\Users\\PC User\\AppData\\Roaming\\Skype\\live#3aanthony.vanko\\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The Windows user account on this device is named `"PC User"`, but the Skype application data path confirms this is Anthony Vanko's acco…

### ✅ verified _(line 51)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `\Users\PC`, `\Users\PC User\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** Classified Stark Enterprises research files were present on Vanko's workstation at the time of imaging. The following files were found …

### ✅ verified _(line 62)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-29T16:20:43Z`, `2016-06-29T16:20:16Z`, `2016-06-19T01:32:02Z`, `notes.docx`, `zebrafish.pdf`, `research.docx`, `Inventory.docx`, `2232` (+7 more)
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** Recent-folder LNK files corroborate that the user personally opened these files: `"zebrafish.pdf.lnk"` (entry `51827`, modified `2016-0…

### ⚠ partial _(line 64)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-05-13T19:15:07Z`, `5030`, `D:`, `"STARK_ENT (D).lnk"`
- **missing**: `\\StarkResearch\Level`, `\\StarkResearch\Level 5–8 Classified\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** A mapped drive Recent link `"STARK_ENT (D).lnk"` (entry `5030`, created `2016-05-13T19:15:07Z`) confirms Vanko had a mapped drive lette…

### ✅ verified _(line 70)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:25:38Z`, `STARKSURFACE-20160630-1025.log`, `\Windows\Temp`, `\Users\PC`, `395`, `.\Users\PC User\AppData\Local\Temp\`, `.\Windows\Temp\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The device contains a pattern of regular STARKSURFACE IT-monitoring agent log files in `.\Windows\Temp\` and `.\Users\PC User\AppData\L…

### ⚠ partial _(line 72)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:47:38Z`, `research.docx`, `Inventory.docx`, `Rapid cell regeneration research.docx`, `STARK-TS-Level7-CryoDNA Storage Inventory.docx`, `2193`, `record_changed`, `6361`
- **missing**: `timestomped: true`, `usec_zeros: true`, `copied: true`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The three classified documents stored in OneDrive (Level 7 CryoDNA, Rapid cell regeneration, and ZF formula) all share an identical `re…

### ⚠ partial _(line 82)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:47:38Z`, `Inventory.docx`, `\Users\PC`, `STARK-TS-Level7-CryoDNA Storage Inventory.docx`, `.\Users\PC User\OneDrive\Documents\`, `2193`
- **missing**: `record_changed: 2016-06-30T14:47:38Z`, `copied: true`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** All three classified documents with `record_changed: 2016-06-30T14:47:38Z` are physically stored inside `.\Users\PC User\OneDrive\Docum…

### ⚠ partial _(line 84)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-10-30T23:12:56Z`, `\Users\PC`, `TraceArchive.6390.0509-79.etl`, `47`
- **missing**: `.\Users\PC User\AppData\Local\Microsoft\OneDrive\logs\Personal\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** OneDrive client activity logs exist under `.\Users\PC User\AppData\Local\Microsoft\OneDrive\logs\Personal\`, with entries dated through…

### ⚠ partial _(line 88)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-29T16:03:13Z`, `2016-06-29T15:51:16Z`, `1.17.exe`, `\Users\PC`, `VeraCrypt Setup 1.17.exe`, `.\Users\PC User\Downloads\`, `33215`, `32010`
- **missing**: `.\Program Files\VeraCrypt\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** `VeraCrypt Setup 1.17.exe` was downloaded from the internet to `.\Users\PC User\Downloads\` on `2016-06-29T15:51:16Z` (Zone.Identifier …

### ✅ verified _(line 90)_
- tools: `ezt_prefetch_parse`
- exec_ids: `e76f6210c4b7`
- matched: `2016-06-29T16:32:16Z`, `2016-06-29T20:32:30Z`, `2016-06-29T16:32:41Z`, `2016-06-30T01:14:42Z`, `2016-06-29T16:34:32Z`, `2016-06-29T16:12:23Z`, `FORMAT.EXE`, `6` (+1 more)
- claim: > **[CONFIRMED — exec_id `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`]** `VERACRYPT FORMAT.EXE` — the volume creation tool — ran `6` times. Run history: `2016-06-29T16:12:23Z`, `2016-06-29T16:32:16Z`, `2016-0…

### ⚠ partial _(line 92)_
- tools: `ezt_prefetch_parse`
- exec_ids: `43bf884db914`
- matched: `2016-06-30T01:12:53Z`, `2016-06-29T16:12:13Z`, `2016-06-30T01:56:46Z`, `2016-06-29T20:32:27Z`, `2016-06-30T01:40:51Z`, `2016-06-29T20:25:57Z`, `VERACRYPT.EXE`, `6`
- **missing**: `01:56 UTC on June 30`
- claim: > **[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`]** `VERACRYPT.EXE` — the main VeraCrypt executable for mounting containers — also ran `6` times: `2016-06-29T16:12:13Z`, `2016-06-29T20:25…

### ⚠ partial _(line 94)_
- tools: `ezt_prefetch_parse`
- exec_ids: `43bf884db914`
- matched: `\Users\PC`, `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\CONFIGURATION.XML`, `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\HISTORY.XML`
- **missing**: `2016-06-29T20:32:56Z`, `2016-06-29T20:37:00Z`, `2016-06-29T20:11:03Z`, `.\Users\PC User\AppData\Roaming\VeraCrypt\`, `29963`, `33344`, `4397`
- claim: > **[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`]** The VeraCrypt Prefetch references `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\HISTORY.XML` and `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\…

### ⚠ partial _(line 100)_
- tools: `ezt_prefetch_parse`
- exec_ids: `c7b2630cb6bc`
- matched: `2016-06-18T22:02:05Z`
- **missing**: `run_count: 1`
- 🚨 negation violations (claimed absent but found): `SMALLFTPD.EXE`, `defaultprinter`, `\USERS\DEFAULTPRINTER\SMALLFTPD.EXE`
- claim: > **[CONFIRMED — exec_id `019ec9e1-27ec-7e61-999c-c7b2630cb6bc`]** `SMALLFTPD.EXE` — a small Windows FTP server — ran once on `2016-06-18T22:02:05Z`. It was launched from `\USERS\DEFAULTPRINTER\SMALLFTP…

### ⚠ partial _(line 104)_
- tools: `ezt_prefetch_parse`
- exec_ids: `7b41cecaf0ea`
- matched: `2016-06-29T16:01:38Z`, `7Z1602-X64.EXE`, `\USERS\PC USER\DOWNLOADS\7Z1602-X64.EXE`
- **missing**: `2016-06-29T20:26:29Z`, `7ZFM.EXE`, `19841`
- claim: > **[CONFIRMED — exec_id `019ec9e1-2a33-7200-bd91-7b41cecaf0ea`]** `7Z1602-X64.EXE` (7-Zip v16.02 installer) ran once at `2016-06-29T16:01:38Z` from `\USERS\PC USER\DOWNLOADS\7Z1602-X64.EXE` — immediate…

### ✅ verified _(line 114)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `\Users\PC`, `108`, `live#3aanthony.vanko`, `PC User`, `.\Users\PC User\AppData\Roaming\Skype\live#3aanthony.vanko\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The Skype data path `.\Users\PC User\AppData\Roaming\Skype\live#3aanthony.vanko\` (MFT entry `108`) ties the `PC User` Windows account …

### ⚠ partial _(line 116)_
- tools: `ezt_srum_parse`
- exec_ids: `1bdeb4b613aa`
- ✅ verified absences (negated): `SRUDB.dat`
- 🚨 negation violations (claimed absent but found): `S-1-5-21-3739107332-290452467-3466442662-1001`
- claim: > **[CONFIRMED — exec_id `019ec9de-f970-7dd1-8413-1bdeb4b613aa`]** The SRUDB.dat push_notifications provider associates SID `S-1-5-21-3739107332-290452467-3466442662-1001` with multiple personal applica…

### ⚠ partial _(line 118)_
- tools: `ezt_prefetch_parse`, `ezt_prefetch_parse`
- exec_ids: `43bf884db914`, `e76f6210c4b7`
- matched: `\Users\PC`, `CONFIGURATION.XML`, `HISTORY.XML`, `20A4B1AA`, `\Users\PC User\AppData\Roaming\VeraCrypt\`
- **missing**: `A420A4D720A4B1AA`
- claim: > **[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`]** VeraCrypt configuration data (`HISTORY.XML`, `CONFIGURATION.XML`) is stored under `\Users\PC Us…

### ✅ verified _(line 120)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `2016-06-30T14:25:38Z`, `STARKSURFACE-20160630-1025.log`, `\Windows\Temp`, `\Users\PC`, `395`, `.\Users\PC User\AppData\Local\Temp\`, `.\Windows\Temp\`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The STARKSURFACE IT-monitoring logs in `.\Windows\Temp\` and `.\Users\PC User\AppData\Local\Temp\` show the machine regularly connectin…

### ⚠ partial _(line 126)_
- tools: `ezt_mft_parse`
- exec_ids: `173ab081dfe2`
- matched: `research.docx`, `Rapid cell regeneration research.docx`, `6361`
- ✅ verified absences (negated): `2016-06-30T01:14:42Z`
- **missing**: `timestomped: true`
- 🚨 negation violations (claimed absent but found): `2016-06-30T01:56:46Z`, `Format.exe`, `VeraCrypt.exe`
- claim: > **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The VeraCrypt encrypted container file is not present in any user-visible directory at imaging time. Given that Format.exe ran as late …

### 🔍 not_confirmed _(line 152)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > *All `[CONFIRMED]
