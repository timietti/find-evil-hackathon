# Validator Report — iter_2

## Summary

- Total tagged claims:        **51**
  - CONFIRMED:                 35
  - INFERRED:                  4
  - HYPOTHESIS:                0
  - GAP:                       12
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           30 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                0 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           2 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           1 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 85.7%** (30 verified / 35 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **7** (cost: $0.0074)
  - ✅ VERIFIED:    5 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 0 (downgraded to failed)
  - ❓ UNRELATED:   0 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   2 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### ✅ verified _(line 38)_
- tools: `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `88680ed9ce0d`, `f79aabdffa14`
- matched: `48869`, `adberdr813.exe`, `8e0fd39907d9086201affa2da9f29a95f347981254ee9a348071f20fd8c31e33`
- claim: > [CONFIRMED] adberdr813.exe (trojanized Adobe Reader 8.1.3 installer) is present at path Users/nromanoff/Downloads/adberdr813.exe (inode 48869, SHA256: 8e0fd39907d9086201affa2da9f29a95f347981254ee9a348…

### ✅ verified _(line 40)_
- tools: `tsk_fls_list`
- exec_ids: `88680ed9ce0d`
- matched: `48244`
- claim: > [CONFIRMED] A WER crash report at path ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e/Report.wer (inode 48244) is archived on t…

### ❓ unverifiable _(line 42)_
- exec_ids: `20499b3bcb73`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim is a metadata tag (exec_id confirmation) with no testable factual assertion about forensic evidence; the empty YARA scan result neither supports nor contradicts it.
- claim: > [CONFIRMED — exec_id=019e18b3-e5e7-7653-9ec4-20499b3bcb73]

### ✅ verified _(line 46)_
- tools: `tsk_fls_list`
- exec_ids: `1427e5156b6e`
- matched: `23296`, `23294`, `AdbeRdr910_en_US.exe`, `-2CFF2AE5.pf`, `ADBERDR910_EN_US.EXE`
- claim: > [CONFIRMED] AdbeRdr910_en_US.exe was delivered via Dropbox. Path Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-02/AdbeRdr910_en_US (deleted 4f799e4f-1980380-08f01636).exe …

### ✅ verified _(line 56)_
- tools: `tsk_fls_list`, `tsk_icat_extract`, `tsk_icat_extract`, `hash_file`, `hash_file`
- exec_ids: `1427e5156b6e`, `c7a5a5ba77c5`, `0912c9194691`, `8b3-e50a-76e` (+1 more)
- matched: `7793`, `540`, `spinlock.exe`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`
- claim: > [CONFIRMED] spinlock.exe (SHA256: 6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead, 2,271,885 bytes) is present at path WINDOWS/system32/spinlock.exe (inode 7793) on tdungan and at ino…

### ✅ verified _(line 58)_
- tools: `ezt_shimcache_parse`
- exec_ids: `2bf2356f4b15`
- matched: `2012-04-04T17:06:37Z`, `spinlock.exe`, `C:\WINDOWS\system32\spinlock.exe`
- claim: > [CONFIRMED] tdungan ShimCache records path C:\WINDOWS\system32\spinlock.exe at position 0 (last_modified 2012-04-04T17:06:37Z), confirming spinlock.exe was placed on tdungan and registered in the appl…

### ✅ verified _(line 60)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-03T22:53:39Z`, `spinlock.exe`, `\Windows\system32\spinlock.exe`, `C:\Windows\system32\spinlock.exe`
- claim: > [CONFIRMED] nromanoff ShimCache records path C:\Windows\system32\spinlock.exe at position 7 (last_modified 2012-04-03T22:53:39Z, executed: Yes), confirming spinlock.exe ran on nromanoff (ezt_shimcache…

### ✅ verified _(line 62)_
- tools: `vol3_psscan`
- exec_ids: `64adf4b8db89`
- matched: `spinlock.exe`
- claim: > [CONFIRMED] tdungan memory shows spinlock.exe running at PIDs 12244 and 3648 at acquisition time (vol3_psscan exec_id=019e18b0-2df3-7880-b651-64adf4b8db89).

### ✅ verified _(line 64)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `1427e5156b6e`, `4ee1c05ec445`
- matched: `7958`, `74152`, `8465`, `spinlock.exe`
- claim: > [CONFIRMED] PyInstaller runtime extraction directories for spinlock.exe are present on tdungan at paths Documents and Settings/vibranium/Local Settings/Temp/_MEI122362/spinlock.exe.manifest (inode 846…

### ✅ verified _(line 66)_
- tools: `tsk_fls_list`
- exec_ids: `88680ed9ce0d`
- matched: `spinlock.exe`
- claim: > [CONFIRMED] Multiple PyInstaller _MEI extraction directories for spinlock.exe under path Users/vibranium/AppData/Local/Temp/ are present on nromanoff disk (including _MEI111242, _MEI138842, _MEI25602,…

### ✅ verified _(line 68)_
- tools: `vol3_vadyarascan`, `vol3_vadyarascan`
- exec_ids: `8bca82447c94`, `91d40757a443`
- ✅ verified absences (negated): `spinlock.exe`
- claim: > [CONFIRMED — exec_id=019e18b2-3a3e-7350-94d6-8bca82447c94, exec_id=019e18b2-482b-7131-9921-91d40757a443] No YARA matches in spinlock.exe memory (PIDs 12244, 3648 on tdungan). File-level scan also retu…

### ✅ verified _(line 72)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T00:44:11Z`, `2012-04-04T00:14:13Z`, `a.exe`, `\Windows\TEMP\a.exe`, `C:\Windows\TEMP\a.exe`
- claim: > [CONFIRMED] nromanoff ShimCache contains 110 entries for path C:\Windows\TEMP\a.exe (all executed: Yes), with last_modified timestamps incrementing by exactly 1 minute beginning 2012-04-04T00:14:13Z a…

### ✅ verified _(line 74)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `a.exe`, `\Windows\TEMP`, `C:\Windows\TEMP`
- claim: > [CONFIRMED] C:\Windows\TEMP accounts for 102 ShimCache entries on nromanoff (all a.exe executions), making a.exe responsible for approximately 15% of all ShimCache entries on that host (ezt_shimcache_…

### ✅ verified _(line 80)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T01:00:45Z`, `hydrakatz.exe`, `C:\windows\system32\hydrakatz.exe`
- claim: > [CONFIRMED] nromanoff ShimCache records path C:\windows\system32\hydrakatz.exe at position 14 (last_modified 2012-04-04T01:00:45Z, executed: Yes), confirming credential dumping activity on nromanoff (…

### ✅ verified _(line 82)_
- tools: `ezt_shimcache_parse`
- exec_ids: `96ec8c79a7bd`
- ✅ verified absences (negated): `hydrakatz.exe`
- claim: > [CONFIRMED — exec_id=019e18b3-c8ca-7280-90f2-96ec8c79a7bd] hydrakatz.exe does NOT appear in the DC ShimCache (962-entry search returned 0 matches), suggesting the tool was not executed directly on the…

### 🔍 not_confirmed _(line 88)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > [CONFIRMED]

### ✅ verified _(line 96)_
- tools: `vol3_svcscan`, `tsk_fls_list`, `hash_file`
- exec_ids: `f6f6d5caa3d4`, `4ee1c05ec445`, `648c64e48b4f`
- matched: `71488`, `71670`, `usboesrv.exe`, `\Windows\system32\usboesrv.exe`, `C:\Windows\system32\usboesrv.exe`, `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`
- claim: > [CONFIRMED] Service usboesrv ("KernelPro USB over Ethernet Service") is configured SERVICE_AUTO_START and is SERVICE_RUNNING with binary path C:\Windows\system32\usboesrv.exe (vol3_svcscan exec_id=019…

### ❌ failed _(line 98)_
- tools: `strings_extract`, `yara_scan_extract`
- exec_ids: `e1fe7c48962c`, `3bd4adc63c72`
- **missing**: `usboesrv.exe`
- claim: > [CONFIRMED] Strings extraction on the malicious Windows/System32/usboesrv.exe returned only 1 string: "input from stdin or file" (strings_extract exec_id=019e18b3-e45f-7f70-ae56-e1fe7c48962c). This is…

### ✅ verified _(line 100)_
- tools: `vol3_psscan`
- exec_ids: `fc074bf1df17`
- matched: `27304`, `2012-03-20T17:58:12Z`
- claim: > [CONFIRMED] The usboesrv service was alive at acquisition time with PID 27304, created 2012-03-20T17:58:12Z — the C2 implant has been running since at least March 20, 2012 (vol3_psscan exec_id=019e18a…

### ✅ verified _(line 102)_
- exec_ids: `05616ddaacbe`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed Run keys data confirms the presence of exactly the four legitimate entries cited in the claim (DWPersistentQueuedReporting, VMware Tools, VMware User Process, McAfee Host Intrusion Prevention Tray), all with expected legitimate executable paths, supporting the assertion that these specifi
- claim: > [CONFIRMED — exec_id=019e18b3-ce36-78e3-9420-05616ddaacbe] DC HKLM SOFTWARE Run keys contain no malicious entries (DWPersistentQueuedReporting, VMware Tools, VMware User Process, McAfee HIP Tray — all…

### ✅ verified _(line 106)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `49e5c81c22f9`
- matched: `svchost.exe`, `c:\windows\system32\dllhost\svchost.exe`
- claim: > [CONFIRMED] tdungan SOFTWARE hive HKLM Run key contains the entry "svchost" with value c:\windows\system32\dllhost\svchost.exe — a malicious binary placed in a fabricated subdirectory path dllhost\svc…

### ❌ failed _(line 112)_
- tools: `vol3_scheduled_tasks`
- exec_ids: `194d4d580db1`
- 🚨 negation violations (claimed absent but found): `2012-04-04T17:49:59Z`
- claim: > [CONFIRMED — exec_id=019e18b0-5de1-7bb0-b1ca-194d4d580db1] DC scheduled tasks contain 53 tasks (45 enabled), all standard Windows operating system tasks except one: task "At2" was created 2012-04-04T1…

### ❓ unverifiable _(line 114)_
- exec_ids: `8b4f49ab6f02`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim consists only of a confirmation marker and execution ID with no testable factual assertion about scheduled tasks, their properties, or presence/absence in the data.
- claim: > [CONFIRMED — exec_id=019e18b0-663a-73a3-9062-8b4f49ab6f02]

### ✅ verified _(line 124)_
- exec_ids: `5e9d843765fc`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed data shows exactly two users (Administrator and Guest) with null LM and NT hashes, and an empty blank_password_users list, which directly supports the claim's specific factual assertions about the local SAM contents.
- claim: > [CONFIRMED — exec_id=019e18b0-481e-7d43-bf23-5e9d843765fc] DC hashdump: Local SAM contains only Administrator and Guest with null LM/NT hashes. Expected for a domain controller (local SAM is not the c…

### ✅ verified _(line 126)_
- exec_ids: `f3c646bf8dae`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed data shows zero cached credentials (count: 0, empty by_domain and rows), which structurally matches the claim's assertion that there are 0 cached domain credentials on the DC.
- claim: > [CONFIRMED — exec_id=019e18b0-537e-71c2-894e-f3c646bf8dae] DC cachedump: 0 cached domain credentials. Domain controllers are the authentication authority and do not cache domain credentials locally. N…

### ✅ verified _(line 128)_
- tools: `vol3_skeleton_key_check`
- exec_ids: `444447ba500b`
- ✅ verified absences (negated): `lsass.exe`
- claim: > [CONFIRMED — exec_id=019e18b9-e266-7830-a5cc-444447ba500b] Skeleton key check on DC memory returned 0 results (found_count=0). No Mimikatz skeleton key patch is present in lsass.exe on the DC. This cl…

### ✅ verified _(line 132)_
- exec_ids: `bdc99def5c77`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed cachedump data structurally confirms the presence of 6 cached credential entries including the username 'nfury' with an associated MSCASH hash, matching the claim's specific factual assertions about count and content.
- claim: > [CONFIRMED — exec_id=019e18b0-5978-7630-983e-bdc99def5c77] nfury cachedump contains 6 cached domain credential entries (MSCASH/DCC2 hashes):

### ✅ verified _(line 147)_
- exec_ids: `609927065d51`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed hashdump data structurally confirms three specific users (Administrator, Guest, SRL-Helpdesk) all with null NT hashes, exactly matching the claim's assertion about the local account state.
- claim: > [CONFIRMED — exec_id=019e18b0-4eb0-78d2-bd28-609927065d51] nfury hashdump returns Administrator, Guest, SRL-Helpdesk — all with null NT hashes (domain-joined workstation; actual credentials in Active …

### ✅ verified _(line 151)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T00:14:13Z`, `2012-04-04T01:00:45Z`, `hydrakatz.exe`, `a.exe`
- claim: > [CONFIRMED — exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1] hydrakatz.exe executed on nromanoff at 2012-04-04T01:00:45Z (ShimCache position 14, executed: Yes). The HTTPPUMP C2 sessions on nromanoff (a.…

### ✅ verified _(line 153)_
- tools: `ezt_shimcache_parse`
- exec_ids: `96ec8c79a7bd`
- ✅ verified absences (negated): `hydrakatz.exe`
- claim: > [CONFIRMED — exec_id=019e18b3-c8ca-7280-90f2-96ec8c79a7bd] No hydrakatz.exe entry in DC ShimCache (962-entry search, 0 matches). The tool was used on workstations, not directly on the DC.

### ✅ verified _(line 161)_
- tools: `vol3_psscan`, `ezt_shimcache_parse`, `tsk_fls_list`, `ezt_shimcache_parse`, `tsk_fls_list`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `64adf4b8db89`, `2bf2356f4b15`, `1427e5156b6e`, `8d7f7cfd0dd1` (+5 more)
- matched: `7793`, `540`, `2012-04-03T22:53:39Z`, `spinlock.exe`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`
- claim: > [CONFIRMED] spinlock.exe (SHA256: 6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead) ran on all four hosts in scope: tdungan (memory PIDs 12244+3648 + ShimCache + disk inode 7793 — vol3…

### ✅ verified _(line 171)_
- tools: `vol3_netscan`, `vol3_psscan`, `vol3_svcscan`
- exec_ids: `65de7cf026f5`, `fc074bf1df17`, `f6f6d5caa3d4`
- matched: `27304`, `96.255.98.154`, `10.3.58.4`, `2012-03-20T17:58:12Z`, `usboesrv.exe`
- claim: > [CONFIRMED] The malicious usboesrv.exe (PID 27304) maintains two simultaneous ESTABLISHED TCP connections from 10.3.58.4 to 96.255.98.154:29932 (local ports 58497 and 58495), confirming the active C2 …

### ✅ verified _(line 175)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T00:44:11Z`, `2012-04-04T00:14:13Z`, `a.exe`, `\Windows\TEMP\a.exe`, `C:\Windows\TEMP\a.exe`
- claim: > [CONFIRMED] nromanoff ShimCache records 110 executions of C:\Windows\TEMP\a.exe with 1-minute-increment last_modified timestamps beginning 2012-04-04T00:14:13Z and extending to at least 2012-04-04T00:…

### ✅ verified _(line 179)_
- tools: `vol3_cachedump`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `bdc99def5c77`, `1427e5156b6e`, `88680ed9ce0d`
- matched: `8465`, `spinlock.exe`
- claim: > [CONFIRMED] The vibranium domain account's DCC2 hash cached on nfury proves interactive logon to that workstation (vol3_cachedump exec_id=019e18b0-5978-7630-983e-bdc99def5c77). The vibranium user's te…

### ✅ verified _(line 183)_
- tools: `ezt_shimcache_parse`, `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`, `96ec8c79a7bd`
- matched: `2012-04-03T21:13:07Z`, `2012-04-04T01:46:37Z`, `PSEXESVC.EXE`, `\Windows\PSEXESVC.EXE`, `C:\Windows\PSEXESVC.EXE`
- claim: > [CONFIRMED] C:\Windows\PSEXESVC.EXE appears at ShimCache position 9 on nromanoff (last_modified 2012-04-04T01:46:37Z, executed: Yes), and at positions 158, 160, 161, 162 (earliest: 2012-04-03T21:13:07…
