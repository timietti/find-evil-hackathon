# Validator Report — iter_1

## Summary

- Total tagged claims:        **45**
  - CONFIRMED:                 38
  - INFERRED:                  2
  - HYPOTHESIS:                0
  - GAP:                       5
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           16 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                9 (some tokens found, some missing)
- ❌ failed:                 3 (no tokens found)
- ❓ unverifiable:           6 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           4 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 42.1%** (16 verified / 38 confirmed)

## Per-claim verdicts

### ✅ verified _(line 51)_
- tools: `tsk_fls_list`
- exec_ids: `3d973993f499`
- matched: `23296`, `AdbeRdr910_en_US.exe`
- claim: > [CONFIRMED] `AdbeRdr910_en_US.exe` (trojanized Adobe Reader 9.1.0 installer) confirmed present in Dropbox cache on tdungan disk, deleted but still recoverable: path `Documents and Settings/tdungan/My …

### ✅ verified _(line 53)_
- tools: `tsk_fls_list`
- exec_ids: `3d973993f499`
- matched: `23294`, `-2CFF2AE5.pf`, `ADBERDR910_EN_US.EXE`, `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf`
- claim: > [CONFIRMED] Execution confirmed by Prefetch artifact: `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf`, inode 23294 (exec_id=019e3cce-2345-7761-b338-3d973993f499).

### ⚠ partial _(line 61)_
- tools: `hash_file`
- exec_ids: `39be292a3b81`
- matched: `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`, `fd05be1a86af4b6328f161ec2d9f22cd`
- **missing**: `71488`, `71670`, `usboesrv.exe`, `Program Files/USB over Ethernet/usboesrv.exe`, `Windows/System32/usboesrv.exe`
- claim: > [CONFIRMED] `usboesrv.exe` (C2 implant) installed as a Windows service on the DC. Two copies of the binary found on disk:   - **Legitimate:** `Program Files/USB over Ethernet/usboesrv.exe` inode 71488…

### ✅ verified _(line 65)_
- tools: `vol3_psscan`
- exec_ids: `54ed19ecbf3d`
- matched: `27304`, `2012-03-20T17:58:12Z`, `services.exe`, `usboesrv.exe`
- claim: > [CONFIRMED] Service execution confirmed in memory: PID 27304 (`usboesrv.exe`) with PPID 556 (`services.exe`/SCM), Session 0, started 2012-03-20T17:58:12Z (vol3_psscan exec_id=019e3ccc-df9a-7c13-a478-5…

### 🔍 not_confirmed _(line 67)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > [CONFIRMED]

### ✅ verified _(line 69)_
- tools: `vol3_psscan`
- exec_ids: `54ed19ecbf3d`
- matched: `27144`, `2012-03-20T18:54:16Z`, `usboe.exe`
- claim: > [CONFIRMED] Companion process `usboe.exe` (PID 27144, PPID 8512, Session 2) running on DC as interactive component of the USB-over-Ethernet C2 relay, started 2012-03-20T18:54:16Z (vol3_psscan exec_id=…

### ✅ verified _(line 71)_
- tools: `tsk_fls_list`
- exec_ids: `0e825ccdaaa3`
- matched: `74152`, `spinlock.exe`
- claim: > [CONFIRMED] `spinlock.exe` (email harvester) executed on the DC — confirmed by Windows Error Reporting crash artifacts: `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbffa…

### ✅ verified _(line 73)_
- tools: `vol3_scheduled_tasks`
- exec_ids: `c03dc71f93a5`
- matched: `2012-04-04T17:45:36Z`, `2012-04-04T17:49:59Z`, `At2`
- claim: > [CONFIRMED] DC scheduled task `At2` created during attack window: creation_time 2012-04-04T17:49:59Z, last_run_time 2012-04-04T17:45:36Z, enabled, Time trigger (vol3_scheduled_tasks exec_id=019e3ccc-d…

### ❓ unverifiable _(line 75)_
- exec_ids: `9f05050a8500`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] DC HKLM SOFTWARE Run keys contain only legitimate entries (VMware Tools, McAfee HIP, DWTRIG20) — no implant Run key on DC (ezt_persistence_keys_parse exec_id=019e3cd0-9f4a-7cb0-a712-9f0505…

### ✅ verified _(line 79)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `98b6bf517a89`
- matched: `svchost.exe`, `\Windows\CurrentVersion\Run`, `c:\windows\system32\dllhost\svchost.exe`, `dllhost`
- claim: > [CONFIRMED] Malicious HKLM Run key extracted from nromanoff SOFTWARE hive (exec_id=019e3cd0-bfaf-70f0-9960-98b6bf517a89):   ``` Key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run Value name: svch…

### ⚠ partial _(line 87)_
- tools: `hash_file`, `tsk_icat_extract`
- exec_ids: `dd65397189c1`, `b8ecb7bc1bce`
- matched: `60768`, `4c7906e2f2a82fdfad74b47c90350771`, `f293fdb96e6ed7e4ede7a173e5e47dd69a30edc6216e550787e7481d2df43cef`
- **missing**: `svchost.exe`, `Windows/System32/dllhost/svchost.exe`
- claim: > [CONFIRMED] Binary `Windows/System32/dllhost/svchost.exe` physically present on nromanoff disk: inode 60768, 102,400 bytes, SHA-256 `f293fdb96e6ed7e4ede7a173e5e47dd69a30edc6216e550787e7481d2df43cef`, …

### 🔍 not_confirmed _(line 89)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > [CONFIRMED]

### ❌ failed _(line 91)_
- tools: `yara_scan_extract`
- exec_ids: `4d2b2767f1f6`
- **missing**: `svchost.exe`, `dllhost/svchost.exe`
- claim: > [CONFIRMED] YARA on nromanoff `dllhost/svchost.exe`: 0 rule matches (yara_scan_extract exec_id=019e3cd2-0903-7842-9190-4d2b2767f1f6).

### ✅ verified _(line 95)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `dc30946ed02a`
- matched: `svchost.exe`, `\Windows\CurrentVersion\Run`, `c:\windows\system32\dllhost\svchost.exe`
- claim: > [CONFIRMED] Malicious HKLM Run key extracted from tdungan SOFTWARE hive (exec_id=019e3cd0-cc5e-7413-af03-dc30946ed02a):   ``` Key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run Value name: svchos…

### ✅ verified _(line 103)_
- tools: `tsk_fls_list`
- exec_ids: `3d973993f499`
- matched: `3022`, `svchost.exe`, `WINDOWS/system32/dllhost/svchost.exe`
- claim: > [CONFIRMED] Binary `WINDOWS/system32/dllhost/svchost.exe` physically present on tdungan disk: inode 3022 (tsk_fls_list exec_id=019e3cce-2345-7761-b338-3d973993f499).

### ⚠ partial _(line 105)_
- tools: `tsk_icat_extract`
- exec_ids: `63360b30dace`
- matched: `3023`
- **missing**: `winclient.reg`, `WINDOWS/system32/dllhost/winclient.reg`
- claim: > [CONFIRMED] Companion installer `WINDOWS/system32/dllhost/winclient.reg` present on tdungan disk: inode 3023, 342 bytes (tsk_icat_extract exec_id=019e3cd1-b97f-7de1-86ef-63360b30dace).

### ❓ unverifiable _(line 109)_
- exec_ids: `9db909b1101c`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] No malicious HKLM Run keys in nfury SOFTWARE hive — only VMware Tools, McAfee HIP, and WerFault (ezt_persistence_keys_parse exec_id=019e3cd0-aee9-7721-91ee-9db909b1101c).

### ⚠ partial _(line 111)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `2e6287026874`
- ✅ verified absences (negated): `NTUSER.DAT`, `vibranium`
- 🚨 negation violations (claimed absent but found): `Sidebar.exe`, `mctadmin.exe`
- claim: > [CONFIRMED] No malicious HKCU Run keys in `vibranium` NTUSER.DAT on nfury — only legitimate Sidebar.exe and mctadmin.exe RunOnce (ezt_persistence_keys_parse exec_id=019e3cd1-a962-7d92-a2b3-2e628702687…

### ⚠ partial _(line 113)_
- tools: `hash_file`
- exec_ids: `a3825d9c37ae`
- matched: `6bff2aebb8852fc2658b9768d2166ece`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`
- **missing**: `540`, `spinlock.exe`, `Windows/System32/spinlock.exe`
- claim: > [CONFIRMED] `spinlock.exe` (PyInstaller email harvester) installed at `Windows/System32/spinlock.exe` on nfury: inode 540, 2,271,885 bytes, SHA-256 `6eef2381040cd38ce5974ef954121e136bd93ec4039d4992543…

### ⚠ partial _(line 115)_
- tools: `yara_scan_extract`
- exec_ids: `da2b564ab871`
- matched: `SIFTOWL_PyInstaller_Packed`, `_MEIPASS`, `_MEIPASS2`
- **missing**: `spinlock.exe`
- claim: > [CONFIRMED] PyInstaller packing confirmed on spinlock.exe via YARA rule `SIFTOWL_PyInstaller_Packed` (T1027.002 — Software Packing), hit at offsets 0x14400 and 0x14468 on strings `_MEIPASS2` and `_MEI…

### ✅ verified _(line 125)_
- tools: `tsk_fls_list`
- exec_ids: `be000ac80c15`
- matched: `80342`, `NTUSER.DAT`, `Users/vibranium/`, `vibranium`
- claim: > [CONFIRMED] `vibranium` domain account (SHIELDBASE domain) has an active user profile on the nfury disk, confirming interactive logon: `Users/vibranium/` directory containing NTUSER.DAT (inode 80342),…

### ✅ verified _(line 127)_
- tools: `tsk_fls_list`
- exec_ids: `be000ac80c15`
- matched: `44732`, `43082`, `VIBRANIUM.docx`, `VIBRANIUM.LNK`, `Users/nfury/AppData/Roaming/Microsoft/Office/Recent/VIBRANIUM.LNK`, `Users/nfury/Documents/VIBRANIUM.docx`
- claim: > [CONFIRMED] Attacker accessed `VIBRANIUM.docx` on nfury's nfury account: `Users/nfury/Documents/VIBRANIUM.docx` (inode 44732) and jump list artifact `Users/nfury/AppData/Roaming/Microsoft/Office/Recen…

### ✅ verified _(line 131)_
- tools: `vol3_psscan`
- exec_ids: `54ed19ecbf3d`
- matched: `27144`, `27304`, `usboesrv.exe`, `usboe.exe`
- claim: > [CONFIRMED] Two USB-over-Ethernet C2 processes on DC demonstrate relay architecture:   - `usboesrv.exe` (PID 27304, service, Session 0) = server-side C2 listener   - `usboe.exe` (PID 27144, Session 2)…

### ⚠ partial _(line 138)_
- tools: `tsk_icat_extract`, `hash_file`, `yara_scan_extract`
- exec_ids: `ea472a34ddd4`, `aea2c91ee3b3`, `8e10b670b2d7`
- matched: `80517`, `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`, `c4b0458c04abdaa773348c2668212b45`
- **missing**: `a.exe`, `Users/vibranium/AppData/Local/Temp/a.exe`
- claim: > [CONFIRMED] `a.exe` (HTTPPUMP dropper/tool) present in vibranium's Temp folder: `Users/vibranium/AppData/Local/Temp/a.exe`, inode 80517, 9,216 bytes, SHA-256 `598e53b69c71643db559c197db757363c48a30bb2…

### ❓ unverifiable _(line 146)_
- exec_ids: `487df9f78dfb`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] vol3_cachedump on nfury extracted 6 domain accounts' DCC2/MSCASH hashes — all are offline cracking targets (exec_id=019e3ccd-80e2-7302-9cc6-487df9f78dfb):

### ❓ unverifiable _(line 161)_
- exec_ids: `c0019b711c80`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] DC vol3_hashdump returned only Administrator and Guest with null NT hashes (exec_id=019e3ccc-c920-7c43-af40-c0019b711c80) — SAM database locked/inaccessible in the memory image at acquisit…

### ❓ unverifiable _(line 163)_
- exec_ids: `83adcaebb615`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] DC vol3_cachedump returned 0 cached credentials (exec_id=019e3ccc-d04e-7cc3-aea6-83adcaebb615) — expected behavior; domain controllers do not cache domain credentials locally.

### ❓ unverifiable _(line 167)_
- exec_ids: `3e08bfb253cb`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED] nfury vol3_hashdump returned Administrator, Guest, SRL-Helpdesk with null NT hashes (exec_id=019e3ccd-7b48-7b61-b1c2-3e08bfb253cb) — SAM locked at acquisition.

### ✅ verified _(line 175)_
- tools: `tsk_fls_list`
- exec_ids: `be000ac80c15`
- matched: `44732`, `43082`, `VIBRANIUM.docx`, `VIBRANIUM.LNK`, `Users/nfury/AppData/Roaming/Microsoft/Office/Recent/VIBRANIUM.LNK`, `Users/nfury/Documents/VIBRANIUM.docx`
- claim: > [CONFIRMED] `VIBRANIUM.docx` is the targeted document, resident at `Users/nfury/Documents/VIBRANIUM.docx` (inode 44732) on nfury. Access evidenced by Office Recent LNK: `Users/nfury/AppData/Roaming/Mi…

### ✅ verified _(line 179)_
- tools: `tsk_fls_list`
- exec_ids: `0e825ccdaaa3`
- ✅ verified absences (negated): `EXFIL.pst`
- claim: > [CONFIRMED — negative] `EXFIL.pst` (email staging container) not found on DC disk (FLS search returned 0 matches, exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3). File was likely deleted after exfiltrat…

### 🔍 not_confirmed _(line 183)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > [CONFIRMED — negative] Neither `hydrakatz.exe` nor `hotcorewin2k.sys` found in FLS for any host disk image. These were staged and executed transiently, consistent with a live-off-the-land / run-and-de…

### ✅ verified _(line 187)_
- tools: `tsk_fls_list`
- exec_ids: `0e825ccdaaa3`
- matched: `spinlock.exe`, `hMailServer.ex`
- claim: > [CONFIRMED] spinlock.exe WER crash report on DC confirms execution on the domain controller. The email harvester ran on DC (targeting hMailServer — `hMailServer.ex` process visible in DC psscan) befor…

### ⚠ partial _(line 195)_
- tools: `hash_file`
- exec_ids: `39be292a3b81`
- matched: `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`
- **missing**: `27304`, `96.255.98.154`, `2012-03-20T17:58:12Z`, `usboesrv.exe`, `96.255.98.154:29932`
- claim: > [CONFIRMED] `usboesrv.exe` on DC (PID 27304, started 2012-03-20T17:58:12Z) is the primary C2 implant communicating to `96.255.98.154:29932` (from prior netscan analysis; not re-confirmed this iteratio…

### ❌ failed _(line 197)_
- tools: `vol3_vadyarascan`
- exec_ids: `4e84ac7cafe3`
- **missing**: `27304`, `usboesrv.exe`
- claim: > [CONFIRMED — negative] YARA on usboesrv.exe in-memory (PID 27304): 0 rule matches — no Mimikatz, Cobalt Strike, PyInstaller, or other bundled signatures detected in memory (vol3_vadyarascan exec_id=01…

### ❌ failed _(line 199)_
- tools: `yara_scan_extract`
- exec_ids: `b745ed0ccfbd`
- **missing**: `usboesrv.exe`
- claim: > [CONFIRMED — negative] YARA on usboesrv.exe binary (disk): 0 rule matches (yara_scan_extract exec_id=019e3ccf-eacd-7e51-9a48-b745ed0ccfbd). The binary does not match any of the 38 bundled signature se…

### ⚠ partial _(line 205)_
- tools: `tsk_fls_list`, `vol3_cachedump`
- exec_ids: `be000ac80c15`, `487df9f78dfb`
- matched: `vibranium.dat`, `ProgramData/Microsoft/User Account Pictures/SHIELDBASE+vibranium.dat`, `vibranium`, `SHIELDBASE`
- **missing**: `7b3b37913cb06808b6793d8df35b1578`
- claim: > [CONFIRMED] `vibranium` account belongs to domain `SHIELDBASE` (confirmed from `ProgramData/Microsoft/User Account Pictures/SHIELDBASE+vibranium.dat` on nfury, exec_id=019e3ccd-91fc-7053-b4d8-be000ac8…

### 🔍 not_confirmed _(line 213)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > [CONFIRMED]

### ✅ verified _(line 217)_
- tools: `vol3_scheduled_tasks`
- exec_ids: `29e640699c2b`
- matched: `2011-08-15T14:19:06Z`, `2012-04-06T04:49:00Z`, `GoogleUpdateTaskUserS-1-5-21-2036804247-3058324640-2116585241-1105Core`
- claim: > [CONFIRMED] `GoogleUpdateTaskUserS-1-5-21-2036804247-3058324640-2116585241-1105Core` task on nfury has creation_time 2012-04-06T04:49:00Z (attack window), last_run_time 2011-08-15T14:19:06Z. The creat…
