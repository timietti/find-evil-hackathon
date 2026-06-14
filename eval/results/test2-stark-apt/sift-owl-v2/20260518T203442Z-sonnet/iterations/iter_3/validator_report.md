# Validator Report — iter_3

## Summary

- Total tagged claims:        **47**
  - CONFIRMED:                 37
  - INFERRED:                  8
  - HYPOTHESIS:                0
  - GAP:                       2
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           28 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                0 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           7 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           2 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 75.7%** (28 verified / 37 confirmed)

## Per-claim verdicts

### 🔍 not_confirmed _(line 12)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > ` 4. **[6]**: Make a positive `[CONFIRMED]

### ✅ verified _(line 37)_
- tools: `tsk_fls_list`
- exec_ids: `3d973993f499`
- matched: `23296`, `AdbeRdr910_en_US.exe`
- claim: > [CONFIRMED] `AdbeRdr910_en_US.exe` (trojanized Adobe Reader 9.1.0 installer) confirmed present in Dropbox cache on tdungan disk, deleted but recoverable: path `Documents and Settings/tdungan/My Docume…

### ✅ verified _(line 39)_
- tools: `tsk_fls_list`
- exec_ids: `3d973993f499`
- matched: `23294`, `-2CFF2AE5.pf`, `ADBERDR910_EN_US.EXE`, `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf`
- claim: > [CONFIRMED] Execution confirmed by Prefetch artifact `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf`, inode 23294, on tdungan disk (tsk_fls_list exec_id=019e3cce-2345-7761-b338-3d973993f499).

### ✅ verified _(line 47)_
- tools: `tsk_fls_list`, `hash_file`
- exec_ids: `0e825ccdaaa3`, `39be292a3b81`
- matched: `71488`, `71670`, `usboesrv.exe`, `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`, `fd05be1a86af4b6328f161ec2d9f22cd`, `Program Files/USB over Ethernet/usboesrv.exe`, `Windows/System32/usboesrv.exe`
- claim: > [CONFIRMED] `usboesrv.exe` (C2 implant) installed as a Windows service on the DC with two disk copies: the legitimate `Program Files/USB over Ethernet/usboesrv.exe` (inode 71488) and the trojanized `W…

### ✅ verified _(line 49)_
- tools: `vol3_psscan`
- exec_ids: `54ed19ecbf3d`
- matched: `27304`, `2012-03-20T17:58:12Z`, `services.exe`, `usboesrv.exe`
- claim: > [CONFIRMED] Service execution confirmed: `usboesrv.exe` running as PID 27304, PPID 556 (`services.exe`/SCM), Session 0, created 2012-03-20T17:58:12Z — T1543.003 (Create or Modify System Process: Windo…

### ✅ verified _(line 51)_
- tools: `vol3_psscan`
- exec_ids: `54ed19ecbf3d`
- matched: `27144`, `2012-03-20T18:54:16Z`, `usboe.exe`
- claim: > [CONFIRMED] Companion process `usboe.exe` (PID 27144, PPID 8512, Session 2) running concurrently on DC as interactive USB-over-Ethernet relay, created 2012-03-20T18:54:16Z (vol3_psscan exec_id=019e3cc…

### ❓ unverifiable _(line 53)_
- exec_ids: `4e84ac7cafe3`
- note: claim has no extractable tokens (prose only)
- claim: > **[FIX FOR DEMOTION 3]** — [CONFIRMED — negative] vol3_vadyarascan returned 0 YARA matches for the DC C2 implant process — no bundled signatures matched in the scanned virtual address space (vol3_vady…

### ✅ verified _(line 55)_
- tools: `yara_scan_extract`, `tsk_fls_list`
- exec_ids: `b745ed0ccfbd`, `0e825ccdaaa3`
- matched: `71670`, `usboesrv.exe`, `Windows/System32/usboesrv.exe`
- claim: > [CONFIRMED — negative] yara_scan_extract on the DC disk `Windows/System32/usboesrv.exe` (inode 71670) returned 0 matches across all 38 bundled signature sets — consistent with a custom or proprietary …

### ✅ verified _(line 57)_
- tools: `tsk_fls_list`
- exec_ids: `0e825ccdaaa3`
- matched: `spinlock.exe`
- claim: > [CONFIRMED] `spinlock.exe` (email harvester) executed on the DC — confirmed by Windows Error Reporting crash artifacts at `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbf…

### ✅ verified _(line 59)_
- tools: `vol3_scheduled_tasks`
- exec_ids: `c03dc71f93a5`
- matched: `2012-04-04T17:45:36Z`, `2012-04-04T17:49:59Z`, `At2`
- claim: > [CONFIRMED] DC scheduled task `At2` created during active attack period: creation_time 2012-04-04T17:49:59Z, last_run_time 2012-04-04T17:45:36Z, enabled, Time trigger (vol3_scheduled_tasks exec_id=019…

### ❓ unverifiable _(line 61)_
- exec_ids: `9f05050a8500`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] DC HKLM SOFTWARE Run keys contain only legitimate entries (VMware Tools, McAfee HIP, DWTRIG20) — no attacker-planted Run key on DC (ezt_persistence_keys_parse exec_id=019e3cd0-9f4a-7cb0-a7…

### ✅ verified _(line 65)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `98b6bf517a89`
- matched: `svchost.exe`, `dllhost`, `svchost`
- claim: > **[FIX FOR DEMOTION 4]** — [CONFIRMED] Malicious HKLM Run key with ValueName `svchost` extracted from nromanoff SOFTWARE hive, pointing to an executable within a `dllhost` subdirectory named `svchost.…

### ✅ verified _(line 69)_
- tools: `tsk_fls_list`, `tsk_icat_extract`, `hash_file`
- exec_ids: `b5ec1f9c4c24`, `b8ecb7bc1bce`, `dd65397189c1`
- matched: `60768`, `svchost.exe`, `4c7906e2f2a82fdfad74b47c90350771`, `f293fdb96e6ed7e4ede7a173e5e47dd69a30edc6216e550787e7481d2df43cef`, `Windows/System32/dllhost/svchost.exe`
- claim: > [CONFIRMED] Implant binary physically present on nromanoff disk: `Windows/System32/dllhost/svchost.exe`, inode 60768, 102,400 bytes, SHA-256 `f293fdb96e6ed7e4ede7a173e5e47dd69a30edc6216e550787e7481d2d…

### ✅ verified _(line 71)_
- tools: `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `b5ec1f9c4c24`, `4fd7714db555`
- matched: `60919`, `winclient.reg`, `4e742cf456299787349fe85958fcb62f106f6ed2d3b916bac0cbbc720491154f`, `Windows/System32/dllhost/winclient.reg`
- claim: > [CONFIRMED] Registry installer `Windows/System32/dllhost/winclient.reg`, inode 60919, 348 bytes, SHA-256 `4e742cf456299787349fe85958fcb62f106f6ed2d3b916bac0cbbc720491154f` also present on nromanoff di…

### ✅ verified _(line 73)_
- tools: `tsk_fls_list`, `yara_scan_extract`
- exec_ids: `b5ec1f9c4c24`, `4d2b2767f1f6`
- matched: `60768`, `svchost.exe`, `Windows/System32/dllhost/svchost.exe`
- claim: > [CONFIRMED — negative] yara_scan_extract on extracted `Windows/System32/dllhost/svchost.exe` (inode 60768, nromanoff) returned 0 matches across all bundled YARA rules (tsk_fls_list exec_id=019e3ccd-e5…

### ✅ verified _(line 77)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `dc30946ed02a`
- matched: `svchost.exe`, `dllhost`, `svchost`
- claim: > **[FIX FOR DEMOTION 5]** — [CONFIRMED] Malicious HKLM Run key with ValueName `svchost` extracted from tdungan SOFTWARE hive, pointing to `svchost.exe` within the `dllhost` subdirectory — same implant …

### ✅ verified _(line 81)_
- tools: `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `3d973993f499`, `63360b30dace`
- matched: `3023`, `3022`, `winclient.reg`, `svchost.exe`, `WINDOWS/system32/dllhost/svchost.exe`, `WINDOWS/system32/dllhost/winclient.reg`
- claim: > [CONFIRMED] Implant binary `WINDOWS/system32/dllhost/svchost.exe` (inode 3022) and registry installer `WINDOWS/system32/dllhost/winclient.reg` (inode 3023, 342 bytes) both present on tdungan disk (tsk…

### ❓ unverifiable _(line 85)_
- exec_ids: `9db909b1101c`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] No attacker-planted HKLM Run keys found in nfury SOFTWARE hive — only VMware Tools, McAfee HIP, and WerFault (ezt_persistence_keys_parse exec_id=019e3cd0-aee9-7721-91ee-9db909b1101c).

### 🔍 not_confirmed _(line 87)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[FIX FOR DEMOTION 6]** — [CONFIRMED]

### ✅ verified _(line 89)_
- tools: `tsk_fls_list`, `hash_file`
- exec_ids: `be000ac80c15`, `a3825d9c37ae`
- matched: `540`, `spinlock.exe`, `6bff2aebb8852fc2658b9768d2166ece`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`, `Windows/System32/spinlock.exe`
- claim: > [CONFIRMED] `spinlock.exe` (PyInstaller-packed email harvester) present at `Windows/System32/spinlock.exe`, inode 540, 2,271,885 bytes, SHA-256 `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92…

### ✅ verified _(line 91)_
- tools: `tsk_fls_list`, `yara_scan_extract`
- exec_ids: `be000ac80c15`, `da2b564ab871`
- matched: `540`, `spinlock.exe`, `SIFTOWL_PyInstaller_Packed`, `_MEIPASS2`, `_MEIPASS`, `Windows/System32/spinlock.exe`
- claim: > [CONFIRMED] PyInstaller packing confirmed on `Windows/System32/spinlock.exe` (inode 540) via YARA rule `SIFTOWL_PyInstaller_Packed` at offsets 0x14400 (`_MEIPASS2`) and 0x14468 (`_MEIPASS`) — T1027.00…

### ✅ verified _(line 101)_
- tools: `tsk_fls_list`
- exec_ids: `be000ac80c15`
- matched: `80342`, `NTUSER.DAT`, `Users/vibranium/`, `vibranium`
- claim: > [CONFIRMED] `vibranium` domain account (SHIELDBASE domain) has an active user profile on nfury disk, confirming interactive domain logon: `Users/vibranium/` directory containing NTUSER.DAT (inode 8034…

### ✅ verified _(line 103)_
- tools: `tsk_fls_list`
- exec_ids: `be000ac80c15`
- matched: `44732`, `43082`, `VIBRANIUM.docx`, `VIBRANIUM.LNK`, `Users/nfury/AppData/Roaming/Microsoft/Office/Recent/VIBRANIUM.LNK`, `Users/nfury/Documents/VIBRANIUM.docx`
- claim: > [CONFIRMED] Targeted document `VIBRANIUM.docx` accessed on nfury: file present at `Users/nfury/Documents/VIBRANIUM.docx` (inode 44732) with Office Recent LNK at `Users/nfury/AppData/Roaming/Microsoft/…

### ✅ verified _(line 107)_
- tools: `vol3_psscan`
- exec_ids: `54ed19ecbf3d`
- matched: `27144`, `27304`, `usboesrv.exe`, `usboe.exe`
- claim: > [CONFIRMED] Two USB-over-Ethernet processes on DC confirm a relay architecture: `usboesrv.exe` (PID 27304, Session 0, service) as the server-side C2 listener and `usboe.exe` (PID 27144, Session 2) as …

### ✅ verified _(line 111)_
- tools: `tsk_fls_list`, `tsk_icat_extract`, `hash_file`, `yara_scan_extract`
- exec_ids: `be000ac80c15`, `ea472a34ddd4`, `aea2c91ee3b3`, `8e10b670b2d7`
- matched: `80517`, `a.exe`, `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`, `c4b0458c04abdaa773348c2668212b45`, `Users/vibranium/AppData/Local/Temp/a.exe`
- claim: > [CONFIRMED] `a.exe` (HTTPPUMP stub/loader) present in vibranium's Temp folder: `Users/vibranium/AppData/Local/Temp/a.exe`, inode 80517, 9,216 bytes, SHA-256 `598e53b69c71643db559c197db757363c48a30bb26…

### ❓ unverifiable _(line 119)_
- exec_ids: `e3ccd-80e2-7`, `487df9f78dfb`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] vol3_cachedump on nfury extracted 6 domain accounts' DCC2/MSCASH hashes — confirming credential theft across all victim accounts and the attacker-controlled vibranium account (vol3_cachedu…

### ❓ unverifiable _(line 134)_
- exec_ids: `c0019b711c80`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] DC vol3_hashdump returned only Administrator and Guest with null NT hashes — SAM database locked/inaccessible in DC memory at acquisition time (vol3_hashdump exec_id=019e3ccc-c920-7c43-af4…

### ❓ unverifiable _(line 136)_
- exec_ids: `83adcaebb615`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] DC vol3_cachedump returned 0 cached credentials — expected behavior as domain controllers do not cache domain credentials locally (vol3_cachedump exec_id=019e3ccc-d04e-7cc3-aea6-83adcaebb6…

### ❓ unverifiable _(line 138)_
- exec_ids: `3e08bfb253cb`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] nfury vol3_hashdump returned Administrator, Guest, SRL-Helpdesk with null NT hashes — SAM locked at acquisition (vol3_hashdump exec_id=019e3ccd-7b48-7b61-b1c2-3e08bfb253cb).

### ✅ verified _(line 146)_
- tools: `tsk_fls_list`
- exec_ids: `be000ac80c15`
- matched: `44732`, `43082`, `VIBRANIUM.docx`, `Users/nfury/Documents/VIBRANIUM.docx`
- claim: > [CONFIRMED] `VIBRANIUM.docx` is the primary targeted document: resident at `Users/nfury/Documents/VIBRANIUM.docx` (inode 44732), with Office Recent LNK at inode 43082 confirming access (tsk_fls_list e…

### ✅ verified _(line 150)_
- tools: `tsk_fls_list`
- exec_ids: `0e825ccdaaa3`
- ✅ verified absences (negated): `EXFIL.pst`
- claim: > [CONFIRMED — negative] `EXFIL.pst` (email staging container) not found on DC disk — search across 125,362 file entries returned 0 matches (tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3). F…

### ✅ verified _(line 154)_
- tools: `tsk_fls_list`
- exec_ids: `0e825ccdaaa3`
- matched: `spinlock.exe`, `hMailServer.ex`
- claim: > [CONFIRMED] spinlock.exe executed on the DC and crashed, confirmed by WER artifacts: `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab…

### ✅ verified _(line 158)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `0e825ccdaaa3`, `be000ac80c15`
- ✅ verified absences (negated): `hotcorewin2k.sys`, `hydrakatz.exe`
- claim: > [CONFIRMED — negative] `hydrakatz.exe` not found on DC disk (tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3, 0 matches across 125,362 entries) or nfury disk (tsk_fls_list exec_id=019e3ccd-9…

### ✅ verified _(line 166)_
- tools: `vol3_psscan`, `tsk_fls_list`, `hash_file`
- exec_ids: `54ed19ecbf3d`, `0e825ccdaaa3`, `39be292a3b81`
- matched: `27304`, `71670`, `2012-03-20T17:58:12Z`, `services.exe`, `usboesrv.exe`, `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`, `Windows/System32/usboesrv.exe`
- claim: > [CONFIRMED] `usboesrv.exe` on DC (PID 27304, PPID 556/services.exe, Session 0, created 2012-03-20T17:58:12Z) is the primary C2 implant: binary at `Windows/System32/usboesrv.exe` inode 71670, SHA-256 `…

### ✅ verified _(line 172)_
- tools: `tsk_fls_list`, `vol3_cachedump`
- exec_ids: `be000ac80c15`, `487df9f78dfb`
- matched: `vibranium.dat`, `ProgramData/Microsoft/User Account Pictures/SHIELDBASE+vibranium.dat`, `vibranium`, `7b 3b 37 91 3c b0 68 08 b6 79 3d 8d f3 5b 15 78`, `SHIELDBASE`
- claim: > [CONFIRMED] `vibranium` account belongs to domain `SHIELDBASE`: profile file `ProgramData/Microsoft/User Account Pictures/SHIELDBASE+vibranium.dat` present on nfury disk (tsk_fls_list exec_id=019e3ccd…

### ✅ verified _(line 180)_
- tools: `vol3_scheduled_tasks`
- exec_ids: `c03dc71f93a5`
- matched: `2012-04-04T17:45:36Z`, `2012-04-04T17:49:59Z`, `At2`
- claim: > [CONFIRMED] `At2` scheduled task on DC created 2012-04-04T17:49:59Z (during active attack period), last_run_time 2012-04-04T17:45:36Z, enabled, Time trigger (vol3_scheduled_tasks exec_id=019e3ccc-d648…

### ✅ verified _(line 186)_
- tools: `vol3_scheduled_tasks`
- exec_ids: `29e640699c2b`
- matched: `2011-08-15T14:19:06Z`, `2012-04-06T04:49:00Z`, `GoogleUpdateTaskUserS-1-5-21-2036804247-3058324640-2116585241-1105Core`
- claim: > [CONFIRMED] `GoogleUpdateTaskUserS-1-5-21-2036804247-3058324640-2116585241-1105Core` task on nfury has creation_time 2012-04-06T04:49:00Z (within attack window) but last_run_time 2011-08-15T14:19:06Z …
