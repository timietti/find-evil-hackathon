# Validator Report — iter_3

## Summary

- Total tagged claims:        **60**
  - CONFIRMED:                 40
  - INFERRED:                  8
  - HYPOTHESIS:                0
  - GAP:                       12
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           32 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                0 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           2 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           4 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 80.0%** (32 verified / 40 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **7** (cost: $0.0073)
  - ✅ VERIFIED:    5 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 0 (downgraded to failed)
  - ❓ UNRELATED:   0 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   2 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### 🔍 not_confirmed _(line 3)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > - **[1]** The pe.exe claim has `[CONFIRMED]

### ✅ verified _(line 20)_
- tools: `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `88680ed9ce0d`, `f79aabdffa14`
- matched: `48869`, `adberdr813.exe`, `8e0fd39907d9086201affa2da9f29a95f347981254ee9a348071f20fd8c31e33`
- claim: > [CONFIRMED] adberdr813.exe (trojanized Adobe Reader 8.1.3 installer) is present at path Users/nromanoff/Downloads/adberdr813.exe (inode 48869, SHA256: 8e0fd39907d9086201affa2da9f29a95f347981254ee9a348…

### ✅ verified _(line 22)_
- tools: `tsk_fls_list`
- exec_ids: `88680ed9ce0d`
- matched: `48244`
- claim: > [CONFIRMED] A WER crash report at path ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e/Report.wer (inode 48244) is archived on t…

### ❓ unverifiable _(line 24)_
- exec_ids: `20499b3bcb73`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim contains only a confirmation marker and execution ID with no specific factual assertion about the YARA scan results to validate against the empty parsed data.
- claim: > [CONFIRMED — exec_id=019e18b3-e5e7-7653-9ec4-20499b3bcb73]

### ✅ verified _(line 28)_
- tools: `tsk_fls_list`
- exec_ids: `1427e5156b6e`
- matched: `23296`, `23294`, `-2CFF2AE5.pf`, `AdbeRdr910_en_US.exe`, `ADBERDR910_EN_US.EXE`
- claim: > [CONFIRMED] AdbeRdr910_en_US.exe was delivered via Dropbox. Path Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-02/AdbeRdr910_en_US (deleted 4f799e4f-1980380-08f01636).exe …

### ✅ verified _(line 38)_
- tools: `tsk_fls_list`, `tsk_icat_extract`, `tsk_icat_extract`, `hash_file`, `hash_file`
- exec_ids: `1427e5156b6e`, `c7a5a5ba77c5`, `0912c9194691`, `8b3-e50a-76e` (+1 more)
- matched: `540`, `7793`, `spinlock.exe`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`
- claim: > [CONFIRMED] spinlock.exe (SHA256: 6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead, 2,271,885 bytes) is present at path WINDOWS/system32/spinlock.exe (inode 7793) on tdungan and at ino…

### ✅ verified _(line 40)_
- tools: `ezt_shimcache_parse`
- exec_ids: `2bf2356f4b15`
- matched: `2012-04-04T17:06:37Z`, `spinlock.exe`, `C:\WINDOWS\system32\spinlock.exe`
- claim: > [CONFIRMED] tdungan ShimCache records path C:\WINDOWS\system32\spinlock.exe at position 0 (last_modified 2012-04-04T17:06:37Z), confirming spinlock.exe was placed on tdungan and registered in the appl…

### ✅ verified _(line 42)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-03T22:53:39Z`, `spinlock.exe`, `\Windows\system32\spinlock.exe`, `C:\Windows\system32\spinlock.exe`
- claim: > [CONFIRMED] nromanoff ShimCache records path C:\Windows\system32\spinlock.exe at position 7 (last_modified 2012-04-03T22:53:39Z, executed: Yes), confirming spinlock.exe ran on nromanoff (ezt_shimcache…

### ✅ verified _(line 44)_
- tools: `vol3_psscan`
- exec_ids: `64adf4b8db89`
- matched: `spinlock.exe`
- claim: > [CONFIRMED] tdungan memory shows spinlock.exe running at PIDs 12244 and 3648 at acquisition time (vol3_psscan exec_id=019e18b0-2df3-7880-b651-64adf4b8db89).

### ✅ verified _(line 46)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `1427e5156b6e`, `4ee1c05ec445`
- matched: `74152`, `8465`, `7958`, `spinlock.exe`
- claim: > [CONFIRMED] PyInstaller runtime extraction directories for spinlock.exe are present on tdungan at paths Documents and Settings/vibranium/Local Settings/Temp/_MEI122362/spinlock.exe.manifest (inode 846…

### ✅ verified _(line 48)_
- tools: `tsk_fls_list`
- exec_ids: `88680ed9ce0d`
- matched: `spinlock.exe`
- claim: > [CONFIRMED] Multiple PyInstaller _MEI extraction directories for spinlock.exe under path Users/vibranium/AppData/Local/Temp/ are present on nromanoff disk (including _MEI111242, _MEI138842, _MEI25602,…

### ✅ verified _(line 50)_
- tools: `vol3_vadyarascan`, `vol3_vadyarascan`
- exec_ids: `8bca82447c94`, `91d40757a443`
- ✅ verified absences (negated): `spinlock.exe`
- claim: > [CONFIRMED — exec_id=019e18b2-3a3e-7350-94d6-8bca82447c94, exec_id=019e18b2-482b-7131-9921-91d40757a443] No YARA matches in spinlock.exe memory (PIDs 12244, 3648 on tdungan). File-level scan also retu…

### ✅ verified _(line 54)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T00:44:11Z`, `2012-04-04T00:14:13Z`, `a.exe`, `\Windows\TEMP\a.exe`, `C:\Windows\TEMP\a.exe`
- claim: > [CONFIRMED] nromanoff ShimCache contains 110 entries for path C:\Windows\TEMP\a.exe (all executed: Yes), with last_modified timestamps incrementing by exactly 1 minute beginning 2012-04-04T00:14:13Z a…

### ✅ verified _(line 56)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `a.exe`, `\Windows\TEMP`, `C:\Windows\TEMP`
- claim: > [CONFIRMED] C:\Windows\TEMP accounts for 102 ShimCache entries on nromanoff (all a.exe executions), making a.exe responsible for approximately 15% of all ShimCache entries on that host (ezt_shimcache_…

### ✅ verified _(line 62)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T01:00:45Z`, `hydrakatz.exe`, `C:\windows\system32\hydrakatz.exe`
- claim: > [CONFIRMED] nromanoff ShimCache records path C:\windows\system32\hydrakatz.exe at position 14 (last_modified 2012-04-04T01:00:45Z, executed: Yes), confirming credential dumping activity on nromanoff (…

### ✅ verified _(line 64)_
- tools: `ezt_shimcache_parse`
- exec_ids: `96ec8c79a7bd`
- ✅ verified absences (negated): `hydrakatz.exe`
- claim: > [CONFIRMED — exec_id=019e18b3-c8ca-7280-90f2-96ec8c79a7bd] hydrakatz.exe does NOT appear in the DC ShimCache (962-entry search returned 0 matches), suggesting the tool was not executed directly on the…

### 🔍 not_confirmed _(line 70)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > <!-- FIX [1]: moved exec_id into [CONFIRMED]

### ✅ verified _(line 72)_
- tools: `vol3_psscan`
- exec_ids: `64adf4b8db89`
- matched: `10384`, `9512`, `2012-04-06T13:43:20Z`, `2012-04-05T17:23:01Z`, `2012-04-06T13:59:57Z`, `cmd.exe`, `pe.exe`
- claim: > [CONFIRMED — exec_id=019e18b0-2df3-7880-b651-64adf4b8db89] tdungan psscan shows two exited pe.exe processes: PID 10384 (ppid 7416, created 2012-04-06T13:43:20Z, exited 2012-04-06T13:59:57Z) and PID 95…

### ✅ verified _(line 82)_
- tools: `vol3_svcscan`, `tsk_fls_list`, `hash_file`
- exec_ids: `f6f6d5caa3d4`, `4ee1c05ec445`, `648c64e48b4f`
- matched: `71488`, `71670`, `usboesrv.exe`, `\Windows\system32\usboesrv.exe`, `C:\Windows\system32\usboesrv.exe`, `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`
- claim: > [CONFIRMED] Service usboesrv ("KernelPro USB over Ethernet Service") is configured SERVICE_AUTO_START and is SERVICE_RUNNING with binary path C:\Windows\system32\usboesrv.exe (vol3_svcscan exec_id=019…

### ✅ verified _(line 86)_
- tools: `strings_extract`, `yara_scan_extract`, `tsk_fls_list`
- exec_ids: `e1fe7c48962c`, `3bd4adc63c72`, `4ee1c05ec445`
- matched: `71670`, `usboesrv.exe`
- claim: > [CONFIRMED — exec_id=019e18b3-e45f-7f70-ae56-e1fe7c48962c, exec_id=019e18b3-e5d1-7793-9465-3bd4adc63c72, exec_id=019e18b0-794e-7960-a2c9-4ee1c05ec445] Strings extraction on the binary extracted from p…

### ✅ verified _(line 88)_
- tools: `vol3_psscan`
- exec_ids: `fc074bf1df17`
- matched: `27304`, `2012-03-20T17:58:12Z`
- claim: > [CONFIRMED] The usboesrv service was alive at acquisition time with PID 27304, created 2012-03-20T17:58:12Z — the C2 implant has been running since at least March 20, 2012 (vol3_psscan exec_id=019e18a…

### ✅ verified _(line 90)_
- exec_ids: `05616ddaacbe`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed data confirms that the HKLM Run keys contain exactly the four entries listed in the claim (DWPersistentQueuedReporting, VMware Tools, VMware User Process, McAfee HIP Tray) with no additional suspicious entries, supporting the assertion that these are legitimate autostart values.
- claim: > [CONFIRMED — exec_id=019e18b3-ce36-78e3-9420-05616ddaacbe] DC HKLM SOFTWARE Run keys contain no malicious entries (DWPersistentQueuedReporting, VMware Tools, VMware User Process, McAfee HIP Tray — all…

### ✅ verified _(line 94)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `49e5c81c22f9`
- matched: `svchost.exe`, `c:\windows\system32\dllhost\svchost.exe`
- claim: > [CONFIRMED] tdungan SOFTWARE hive HKLM Run key contains the entry "svchost" with value c:\windows\system32\dllhost\svchost.exe — a malicious binary placed in a fabricated subdirectory path dllhost\svc…

### ❌ failed _(line 102)_
- tools: `vol3_scheduled_tasks`
- exec_ids: `194d4d580db1`
- 🚨 negation violations (claimed absent but found): `2012-04-04T17:49:59Z`
- claim: > [CONFIRMED] DC scheduled tasks show 53 tasks total (45 enabled). One anomalous entry stands out: task "At2" was created 2012-04-04T17:49:59Z, configured as a one-time time-triggered task with no recor…

### ❓ unverifiable _(line 104)_
- exec_ids: `8b4f49ab6f02`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim contains only an execution ID confirmation marker with no specific factual assertion (process name, task name, timestamp, principal, or action) to validate against the parsed scheduled tasks summary data.
- claim: > [CONFIRMED — exec_id=019e18b0-663a-73a3-9062-8b4f49ab6f02]

### ✅ verified _(line 114)_
- exec_ids: `5e9d843765fc`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed data structurally confirms that the local SAM contains exactly two users (Administrator and Guest) with null LM and NT hashes, matching the claim's specific factual assertions.
- claim: > [CONFIRMED — exec_id=019e18b0-481e-7d43-bf23-5e9d843765fc] DC hashdump: Local SAM contains only Administrator and Guest with null LM/NT hashes. Expected for a domain controller (local SAM is not the c…

### ✅ verified _(line 116)_
- exec_ids: `f3c646bf8dae`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed data shows count=0 and empty rows, which structurally supports the claim's assertion that there are 0 cached domain credentials.
- claim: > [CONFIRMED — exec_id=019e18b0-537e-71c2-894e-f3c646bf8dae] DC cachedump: 0 cached domain credentials. Domain controllers are the authentication authority and do not cache domain credentials locally. N…

### ✅ verified _(line 118)_
- tools: `vol3_skeleton_key_check`
- exec_ids: `444447ba500b`
- ✅ verified absences (negated): `lsass.exe`
- claim: > [CONFIRMED — exec_id=019e18b9-e266-7830-a5cc-444447ba500b] Skeleton key check on DC memory returned 0 results (found_count=0). No Mimikatz skeleton key patch is present in lsass.exe on the DC. This cl…

### ✅ verified _(line 122)_
- exec_ids: `bdc99def5c77`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed cachedump data shows exactly 6 cached credential entries with usernames and MSCASH/DCC2 hashes, and 'nfury' is present as one of the cached usernames in the dataset.
- claim: > [CONFIRMED — exec_id=019e18b0-5978-7630-983e-bdc99def5c77] nfury cachedump contains 6 cached domain credential entries (MSCASH/DCC2 hashes):

### ✅ verified _(line 137)_
- exec_ids: `609927065d51`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed hashdump data structurally confirms the claim: three users (Administrator, Guest, SRL-Helpdesk) are present with null NT hashes, supporting the assertion of a domain-joined workstation where credentials are stored in Active Directory rather than locally.
- claim: > [CONFIRMED — exec_id=019e18b0-4eb0-78d2-bd28-609927065d51] nfury hashdump returns Administrator, Guest, SRL-Helpdesk — all with null NT hashes (domain-joined workstation; actual credentials in Active …

### ✅ verified _(line 141)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T01:00:45Z`, `2012-04-04T00:14:13Z`, `hydrakatz.exe`, `a.exe`
- claim: > [CONFIRMED — exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1] hydrakatz.exe executed on nromanoff at 2012-04-04T01:00:45Z (ShimCache position 14, executed: Yes). The HTTPPUMP C2 sessions on nromanoff (a.…

### ✅ verified _(line 143)_
- tools: `ezt_shimcache_parse`
- exec_ids: `96ec8c79a7bd`
- ✅ verified absences (negated): `hydrakatz.exe`
- claim: > [CONFIRMED — exec_id=019e18b3-c8ca-7280-90f2-96ec8c79a7bd] No hydrakatz.exe entry in DC ShimCache (962-entry search, 0 matches). The tool was used on workstations, not directly on the DC.

### ✅ verified _(line 151)_
- tools: `vol3_psscan`, `ezt_shimcache_parse`, `tsk_fls_list`, `ezt_shimcache_parse`, `tsk_fls_list`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `64adf4b8db89`, `2bf2356f4b15`, `1427e5156b6e`, `8d7f7cfd0dd1` (+5 more)
- matched: `540`, `7793`, `2012-04-03T22:53:39Z`, `spinlock.exe`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`
- claim: > [CONFIRMED] spinlock.exe (SHA256: 6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead) ran on all four hosts in scope: tdungan (memory PIDs 12244+3648 + ShimCache + disk inode 7793 — vol3…

### ✅ verified _(line 161)_
- tools: `vol3_netscan`, `vol3_psscan`, `vol3_svcscan`
- exec_ids: `65de7cf026f5`, `fc074bf1df17`, `f6f6d5caa3d4`
- matched: `27304`, `96.255.98.154`, `10.3.58.4`, `2012-03-20T17:58:12Z`, `usboesrv.exe`
- claim: > [CONFIRMED] The malicious usboesrv.exe (PID 27304) maintains two simultaneous ESTABLISHED TCP connections from 10.3.58.4 to 96.255.98.154:29932 (local ports 58497 and 58495), confirming the active C2 …

### ✅ verified _(line 165)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T00:44:11Z`, `2012-04-04T00:14:13Z`, `a.exe`, `\Windows\TEMP\a.exe`, `C:\Windows\TEMP\a.exe`
- claim: > [CONFIRMED] nromanoff ShimCache records 110 executions of C:\Windows\TEMP\a.exe with 1-minute-increment last_modified timestamps beginning 2012-04-04T00:14:13Z and extending to at least 2012-04-04T00:…

### ✅ verified _(line 169)_
- tools: `vol3_cachedump`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `bdc99def5c77`, `1427e5156b6e`, `88680ed9ce0d`
- matched: `8465`, `spinlock.exe`
- claim: > [CONFIRMED] The vibranium domain account's DCC2 hash cached on nfury proves interactive logon to that workstation (vol3_cachedump exec_id=019e18b0-5978-7630-983e-bdc99def5c77). The vibranium user's te…

### ✅ verified _(line 173)_
- tools: `ezt_shimcache_parse`, `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`, `96ec8c79a7bd`
- matched: `2012-04-04T01:46:37Z`, `2012-04-03T21:13:07Z`, `PSEXESVC.EXE`, `\Windows\PSEXESVC.EXE`, `C:\Windows\PSEXESVC.EXE`
- claim: > [CONFIRMED] C:\Windows\PSEXESVC.EXE appears at ShimCache position 9 on nromanoff (last_modified 2012-04-04T01:46:37Z, executed: Yes), and at positions 158, 160, 161, 162 (earliest: 2012-04-03T21:13:07…

### 🔍 not_confirmed _(line 185)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | # | Original Status | Resolution | Action Taken | |---|---|---|---| | 1 | not_confirmed (bare [CONFIRMED]

### ❌ failed _(line 185)_
- tools: `vol3_psscan`
- exec_ids: `64adf4b8db89`
- 🚨 negation violations (claimed absent but found): `pe.exe`
- claim: > no exec_id) | Re-confirmed | pe.exe claim split: [CONFIRMED — exec_id=019e18b0-2df3-7880-b651-64adf4b8db89]

### 🔍 not_confirmed _(line 185)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > for identity reasoning; exec_id moved into [CONFIRMED]
