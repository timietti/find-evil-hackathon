# Validator Report — iter_2

## Summary

- Total tagged claims:        **46**
  - CONFIRMED:                 40
  - INFERRED:                  5
  - HYPOTHESIS:                0
  - GAP:                       1
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           27 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                3 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           6 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           2 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 67.5%** (27 verified / 40 confirmed)

## Per-claim verdicts

### 🔍 not_confirmed _(line 15)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > The key fixes needed are: - **[1], [3], [6], [8], [9], [10], [12], [13], [14], [15]**: Multi-cite with tsk_fls_list/psscan exec_ids alongside hash/YARA exec_ids to supply missing path/inode/PID tokens…

### 🔍 not_confirmed _(line 19)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > `; keep hash/PID claims `[CONFIRMED]

### ✅ verified _(line 43)_
- tools: `tsk_fls_list`
- exec_ids: `3d973993f499`
- matched: `23296`, `AdbeRdr910_en_US.exe`
- claim: > [CONFIRMED] `AdbeRdr910_en_US.exe` (trojanized Adobe Reader 9.1.0 installer) confirmed present in Dropbox cache on tdungan disk, deleted but recoverable: path `Documents and Settings/tdungan/My Docume…

### ✅ verified _(line 45)_
- tools: `tsk_fls_list`
- exec_ids: `3d973993f499`
- matched: `23294`, `-2CFF2AE5.pf`, `ADBERDR910_EN_US.EXE`, `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf`
- claim: > [CONFIRMED] Execution confirmed by Prefetch artifact `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf`, inode 23294, on tdungan disk (tsk_fls_list exec_id=019e3cce-2345-7761-b338-3d973993f499).

### ✅ verified _(line 53)_
- tools: `tsk_fls_list`, `hash_file`
- exec_ids: `0e825ccdaaa3`, `39be292a3b81`
- matched: `71488`, `71670`, `usboesrv.exe`, `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`, `fd05be1a86af4b6328f161ec2d9f22cd`, `Program Files/USB over Ethernet/usboesrv.exe`, `Windows/System32/usboesrv.exe`
- claim: > **FIX FOR [1]** — [CONFIRMED] `usboesrv.exe` (C2 implant) installed as a Windows service on the DC with two disk copies: the legitimate `Program Files/USB over Ethernet/usboesrv.exe` (inode 71488) and…

### ✅ verified _(line 55)_
- tools: `vol3_psscan`
- exec_ids: `54ed19ecbf3d`
- matched: `27304`, `2012-03-20T17:58:12Z`, `services.exe`, `usboesrv.exe`
- claim: > **FIX FOR [2]** — [CONFIRMED] Service execution confirmed: PID 27304 (`usboesrv.exe`), PPID 556 (`services.exe`/SCM), Session 0, created 2012-03-20T17:58:12Z — establishing T1543.003 persistence (Crea…

### ✅ verified _(line 57)_
- tools: `vol3_psscan`
- exec_ids: `54ed19ecbf3d`
- matched: `27144`, `2012-03-20T18:54:16Z`, `usboe.exe`
- claim: > [CONFIRMED] Companion process `usboe.exe` (PID 27144, PPID 8512, Session 2) running concurrently on DC as interactive USB-over-Ethernet relay, created 2012-03-20T18:54:16Z (vol3_psscan exec_id=019e3cc…

### ❌ failed _(line 59)_
- tools: `vol3_psscan`, `vol3_vadyarascan`
- exec_ids: `54ed19ecbf3d`, `4e84ac7cafe3`
- 🚨 negation violations (claimed absent but found): `27304`, `usboesrv.exe`
- claim: > **FIX FOR [13]** — [CONFIRMED — negative] vol3_vadyarascan on PID 27304 (usboesrv.exe, vol3_psscan exec_id=019e3ccc-df9a-7c13-a478-54ed19ecbf3d) returned 0 YARA matches across all bundled signatures —…

### ✅ verified _(line 61)_
- tools: `tsk_fls_list`, `yara_scan_extract`
- exec_ids: `0e825ccdaaa3`, `b745ed0ccfbd`
- matched: `71670`, `usboesrv.exe`, `Windows/System32/usboesrv.exe`
- claim: > **FIX FOR [14]** — [CONFIRMED — negative] yara_scan_extract on the DC disk `Windows/System32/usboesrv.exe` (inode 71670, tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3) returned 0 matches a…

### ✅ verified _(line 63)_
- tools: `tsk_fls_list`
- exec_ids: `0e825ccdaaa3`
- matched: `spinlock.exe`
- claim: > [CONFIRMED] `spinlock.exe` (email harvester) executed on the DC — confirmed by Windows Error Reporting crash artifacts at `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbf…

### ✅ verified _(line 65)_
- tools: `vol3_scheduled_tasks`
- exec_ids: `c03dc71f93a5`
- matched: `2012-04-04T17:45:36Z`, `2012-04-04T17:49:59Z`, `At2`
- claim: > [CONFIRMED] DC scheduled task `At2` created during active attack period: creation_time 2012-04-04T17:49:59Z, last_run_time 2012-04-04T17:45:36Z, enabled, Time trigger (vol3_scheduled_tasks exec_id=019…

### ❓ unverifiable _(line 67)_
- exec_ids: `9f05050a8500`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] DC HKLM SOFTWARE Run keys contain only legitimate entries (VMware Tools, McAfee HIP, DWTRIG20) — no attacker-planted Run key on DC (ezt_persistence_keys_parse exec_id=019e3cd0-9f4a-7cb0-a7…

### ⚠ partial _(line 71)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `98b6bf517a89`
- matched: `svchost.exe`, `dllhost`
- **missing**: `c:\windows\system32\dllhost\svchost.exe``, `svchost = c:\windows\system32\dllhost\svchost.exe`
- claim: > **FIX FOR [2] / [4]** — [CONFIRMED] Malicious HKLM Run key `svchost = c:\windows\system32\dllhost\svchost.exe` extracted from nromanoff SOFTWARE hive, establishing T1547.001 (Boot/Logon Autostart: Reg…

### ✅ verified _(line 73)_
- tools: `tsk_fls_list`, `tsk_icat_extract`, `hash_file`
- exec_ids: `b5ec1f9c4c24`, `b8ecb7bc1bce`, `dd65397189c1`
- matched: `60768`, `svchost.exe`, `4c7906e2f2a82fdfad74b47c90350771`, `f293fdb96e6ed7e4ede7a173e5e47dd69a30edc6216e550787e7481d2df43cef`, `Windows/System32/dllhost/svchost.exe`
- claim: > **FIX FOR [3]** — [CONFIRMED] Implant binary physically present on nromanoff disk: `Windows/System32/dllhost/svchost.exe`, inode 60768, 102,400 bytes, SHA-256 `f293fdb96e6ed7e4ede7a173e5e47dd69a30edc6…

### ✅ verified _(line 75)_
- tools: `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `b5ec1f9c4c24`, `4fd7714db555`
- matched: `60919`, `winclient.reg`, `4e742cf456299787349fe85958fcb62f106f6ed2d3b916bac0cbbc720491154f`, `Windows/System32/dllhost/winclient.reg`
- claim: > **FIX FOR [6]** — [CONFIRMED] Registry installer `Windows/System32/dllhost/winclient.reg`, inode 60919, 348 bytes, SHA-256 `4e742cf456299787349fe85958fcb62f106f6ed2d3b916bac0cbbc720491154f` also prese…

### ✅ verified _(line 77)_
- tools: `tsk_fls_list`, `yara_scan_extract`
- exec_ids: `b5ec1f9c4c24`, `4d2b2767f1f6`
- matched: `60768`, `svchost.exe`, `Windows/System32/dllhost/svchost.exe`
- claim: > **FIX FOR [5]** — [CONFIRMED — negative] yara_scan_extract on extracted `Windows/System32/dllhost/svchost.exe` (inode 60768, nromanoff — tsk_fls_list exec_id=019e3ccd-e5ab-7fb2-975e-b5ec1f9c4c24) retu…

### ⚠ partial _(line 81)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `dc30946ed02a`
- matched: `svchost.exe`
- **missing**: `c:\windows\system32\dllhost\svchost.exe``, `svchost = c:\windows\system32\dllhost\svchost.exe`
- claim: > **FIX FOR [6]** — [CONFIRMED] Identical malicious HKLM Run key `svchost = c:\windows\system32\dllhost\svchost.exe` extracted from tdungan SOFTWARE hive — same implant toolkit as nromanoff (ezt_persist…

### ✅ verified _(line 83)_
- tools: `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `3d973993f499`, `63360b30dace`
- matched: `3023`, `3022`, `winclient.reg`, `svchost.exe`, `WINDOWS/system32/dllhost/svchost.exe`, `WINDOWS/system32/dllhost/winclient.reg`
- claim: > [CONFIRMED] Implant binary `WINDOWS/system32/dllhost/svchost.exe` (inode 3022) and registry installer `WINDOWS/system32/dllhost/winclient.reg` (inode 3023, 342 bytes) both present on tdungan disk (tsk…

### ❓ unverifiable _(line 87)_
- exec_ids: `9db909b1101c`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] No attacker-planted HKLM Run keys found in nfury SOFTWARE hive — only VMware Tools, McAfee HIP, and WerFault (ezt_persistence_keys_parse exec_id=019e3cd0-aee9-7721-91ee-9db909b1101c).

### ❌ failed _(line 89)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `2e6287026874`
- **missing**: `NTUSER.DAT`
- 🚨 negation violations (claimed absent but found): `Sidebar.exe`, `mctadmin.exe`
- claim: > **FIX FOR [7]** — [CONFIRMED] vibranium NTUSER.DAT HKCU RunOnce entries on nfury are limited to Windows defaults: Sidebar.exe and mctadmin.exe — the attacker's personal user hive contains only these t…

### ✅ verified _(line 91)_
- tools: `tsk_fls_list`, `hash_file`
- exec_ids: `be000ac80c15`, `a3825d9c37ae`
- matched: `540`, `spinlock.exe`, `6bff2aebb8852fc2658b9768d2166ece`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`, `Windows/System32/spinlock.exe`
- claim: > **FIX FOR [8]** — [CONFIRMED] `spinlock.exe` (PyInstaller-packed email harvester) present at `Windows/System32/spinlock.exe`, inode 540, 2,271,885 bytes, SHA-256 `6eef2381040cd38ce5974ef954121e136bd93…

### ✅ verified _(line 93)_
- tools: `tsk_fls_list`, `yara_scan_extract`
- exec_ids: `be000ac80c15`, `da2b564ab871`
- matched: `540`, `spinlock.exe`, `SIFTOWL_PyInstaller_Packed`, `_MEIPASS2`, `_MEIPASS`, `Windows/System32/spinlock.exe`
- claim: > **FIX FOR [9]** — [CONFIRMED] PyInstaller packing confirmed on `Windows/System32/spinlock.exe` (inode 540) via YARA rule `SIFTOWL_PyInstaller_Packed` at offsets 0x14400 (`_MEIPASS2`) and 0x14468 (`_ME…

### ✅ verified _(line 103)_
- tools: `tsk_fls_list`
- exec_ids: `be000ac80c15`
- matched: `80342`, `NTUSER.DAT`, `Users/vibranium/`, `vibranium`
- claim: > [CONFIRMED] `vibranium` domain account (SHIELDBASE domain) has an active user profile on nfury disk, confirming interactive domain logon: `Users/vibranium/` directory containing NTUSER.DAT (inode 8034…

### ✅ verified _(line 105)_
- tools: `tsk_fls_list`
- exec_ids: `be000ac80c15`
- matched: `44732`, `43082`, `VIBRANIUM.docx`, `VIBRANIUM.LNK`, `Users/nfury/AppData/Roaming/Microsoft/Office/Recent/VIBRANIUM.LNK`, `Users/nfury/Documents/VIBRANIUM.docx`
- claim: > **FIX FOR [16]** — [CONFIRMED] Targeted document `VIBRANIUM.docx` accessed on nfury: file present at `Users/nfury/Documents/VIBRANIUM.docx` (inode 44732) with Office Recent LNK at `Users/nfury/AppData…

### ✅ verified _(line 109)_
- tools: `vol3_psscan`
- exec_ids: `54ed19ecbf3d`
- matched: `27144`, `27304`, `usboesrv.exe`, `usboe.exe`
- claim: > [CONFIRMED] Two USB-over-Ethernet processes on DC confirm a relay architecture: `usboesrv.exe` (PID 27304, Session 0, service) as the server-side C2 listener and `usboe.exe` (PID 27144, Session 2) as …

### ✅ verified _(line 113)_
- tools: `tsk_fls_list`, `tsk_icat_extract`, `hash_file`, `yara_scan_extract`
- exec_ids: `be000ac80c15`, `ea472a34ddd4`, `aea2c91ee3b3`, `8e10b670b2d7`
- matched: `80517`, `a.exe`, `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`, `c4b0458c04abdaa773348c2668212b45`, `Users/vibranium/AppData/Local/Temp/a.exe`
- claim: > **FIX FOR [10]** — [CONFIRMED] `a.exe` (HTTPPUMP stub/loader) present in vibranium's Temp folder: `Users/vibranium/AppData/Local/Temp/a.exe`, inode 80517, 9,216 bytes, SHA-256 `598e53b69c71643db559c19…

### ❓ unverifiable _(line 121)_
- exec_ids: `ccd-80e2-730`, `487df9f78dfb`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] vol3_cachedump on nfury extracted 6 domain accounts' DCC2/MSCASH hashes confirming credential theft across all victim accounts and the attacker-controlled vibranium account (vol3_cachedump…

### ❓ unverifiable _(line 136)_
- exec_ids: `c0019b711c80`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] DC vol3_hashdump returned only Administrator and Guest with null NT hashes — SAM database locked/inaccessible in DC memory at acquisition time (vol3_hashdump exec_id=019e3ccc-c920-7c43-af4…

### ❓ unverifiable _(line 138)_
- exec_ids: `83adcaebb615`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] DC vol3_cachedump returned 0 cached credentials — expected behavior as domain controllers do not cache domain credentials locally (vol3_cachedump exec_id=019e3ccc-d04e-7cc3-aea6-83adcaebb6…

### ❓ unverifiable _(line 140)_
- exec_ids: `3e08bfb253cb`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] nfury vol3_hashdump returned Administrator, Guest, SRL-Helpdesk with null NT hashes — SAM locked at acquisition (vol3_hashdump exec_id=019e3ccd-7b48-7b61-b1c2-3e08bfb253cb).

### ✅ verified _(line 148)_
- tools: `tsk_fls_list`
- exec_ids: `be000ac80c15`
- matched: `44732`, `43082`, `VIBRANIUM.docx`, `Users/nfury/Documents/VIBRANIUM.docx`
- claim: > [CONFIRMED] `VIBRANIUM.docx` is the primary targeted document: resident at `Users/nfury/Documents/VIBRANIUM.docx` (inode 44732), with Office Recent LNK at inode 43082 confirming access (tsk_fls_list e…

### ✅ verified _(line 152)_
- tools: `tsk_fls_list`
- exec_ids: `0e825ccdaaa3`
- ✅ verified absences (negated): `EXFIL.pst`
- claim: > [CONFIRMED — negative] `EXFIL.pst` (email staging container) not found on DC disk — search across 125,362 file entries returned 0 matches (tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3). F…

### ✅ verified _(line 156)_
- tools: `tsk_fls_list`
- exec_ids: `0e825ccdaaa3`
- matched: `spinlock.exe`, `hMailServer.ex`
- claim: > [CONFIRMED] spinlock.exe executed on the DC and crashed, confirmed by WER artifacts: `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab…

### ✅ verified _(line 160)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `0e825ccdaaa3`, `be000ac80c15`
- ✅ verified absences (negated): `hotcorewin2k.sys`, `hydrakatz.exe`
- claim: > **FIX FOR [11]** — [CONFIRMED — negative] `hydrakatz.exe` not found on DC disk (tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3, 0 matches across 125,362 entries) or nfury disk (tsk_fls_list…

### ✅ verified _(line 168)_
- tools: `vol3_psscan`, `tsk_fls_list`, `hash_file`
- exec_ids: `54ed19ecbf3d`, `0e825ccdaaa3`, `39be292a3b81`
- matched: `27304`, `71670`, `2012-03-20T17:58:12Z`, `services.exe`, `usboesrv.exe`, `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`, `Windows/System32/usboesrv.exe`
- claim: > **FIX FOR [12]** — [CONFIRMED] `usboesrv.exe` on DC (PID 27304, PPID 556/services.exe, Session 0, created 2012-03-20T17:58:12Z) is the primary C2 implant: binary at `Windows/System32/usboesrv.exe` ino…

### ✅ verified _(line 174)_
- tools: `tsk_fls_list`, `vol3_cachedump`
- exec_ids: `be000ac80c15`, `487df9f78dfb`
- matched: `vibranium.dat`, `ProgramData/Microsoft/User Account Pictures/SHIELDBASE+vibranium.dat`, `vibranium`, `7b 3b 37 91 3c b0 68 08 b6 79 3d 8d f3 5b 15 78`, `SHIELDBASE`
- claim: > **FIX FOR [15]** — [CONFIRMED] `vibranium` account belongs to domain `SHIELDBASE`: profile file `ProgramData/Microsoft/User Account Pictures/SHIELDBASE+vibranium.dat` present on nfury disk (tsk_fls_li…

### ✅ verified _(line 182)_
- tools: `vol3_scheduled_tasks`
- exec_ids: `c03dc71f93a5`
- matched: `2012-04-04T17:45:36Z`, `2012-04-04T17:49:59Z`, `At2`
- claim: > [CONFIRMED] `At2` scheduled task on DC created 2012-04-04T17:49:59Z (during active attack period), last_run_time 2012-04-04T17:45:36Z, enabled, Time trigger (vol3_scheduled_tasks exec_id=019e3ccc-d648…

### ✅ verified _(line 188)_
- tools: `vol3_scheduled_tasks`
- exec_ids: `29e640699c2b`
- matched: `2011-08-15T14:19:06Z`, `2012-04-06T04:49:00Z`, `GoogleUpdateTaskUserS-1-5-21-2036804247-3058324640-2116585241-1105Core`
- claim: > [CONFIRMED] `GoogleUpdateTaskUserS-1-5-21-2036804247-3058324640-2116585241-1105Core` task on nfury has creation_time 2012-04-06T04:49:00Z (within attack window) but last_run_time 2011-08-15T14:19:06Z …

### ✅ verified _(line 210)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `19e3ccd-1f7f`, `19e3ccd-e5ab`
- matched: `60768`, `usboesrv.exe`, `svchost.exe`
- claim: > | Item | Demotion Type | Resolution | |---|---|---| | [1] usboesrv.exe two copies | partial | Added tsk_fls_list exec_id=019e3ccd-1f7f (has inodes 71488/71670 and paths) | | [2] Service execution sent…

### ⚠ partial _(line 218)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `19e3cce-2345`, `19e3ccd-91fc`
- matched: `3023`, `540`, `80517`, `spinlock.exe`, `winclient.reg`, `mctadmin.exe`, `a.exe`, `Sidebar.exe` (+1 more)
- **missing**: `usboesrv.exe`
- claim: > Run-key sentence with persistence_keys exec_id | | [5] YARA nromanoff svchost.exe | failed | Multi-cite: tsk_fls_list for path/inode + yara_scan_extract for 0 matches | | [6] winclient.reg tdungan | p…
