# Validator Report — iter_1

## Summary

- Total tagged claims:        **53**
  - CONFIRMED:                 34
  - INFERRED:                  5
  - HYPOTHESIS:                0
  - GAP:                       14
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           14 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                13 (some tokens found, some missing)
- ❌ failed:                 1 (no tokens found)
- ❓ unverifiable:           3 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           3 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 41.2%** (14 verified / 34 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **8** (cost: $0.0082)
  - ✅ VERIFIED:    5 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 0 (downgraded to failed)
  - ❓ UNRELATED:   0 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   3 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### ⚠ partial _(line 54)_
- tools: `vol3_psscan`, `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `0a812380bd1e`, `f79aabdffa14`, `88680ed9ce0d`
- matched: `48869`, `adberdr813.exe`, `8e0fd39907d9086201affa2da9f29a95f347981254ee9a348071f20fd8c31e33`, `Zone.Identifier`, `Users/nromanoff/Downloads/adberdr813.exe`
- **missing**: `10.3.58.5`
- claim: > ### nromanoff (10.3.58.5) — Patient Zero [CONFIRMED] `adberdr813.exe` (trojanized Adobe Reader 8.1.3 installer) is present at `Users/nromanoff/Downloads/adberdr813.exe` (inode 48869, SHA256: `8e0fd399…

### ✅ verified _(line 56)_
- tools: `tsk_fls_list`
- exec_ids: `88680ed9ce0d`
- matched: `AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e`
- claim: > [CONFIRMED] A WER crash report `AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e` is archived on the nromanoff disk, confirming the installer was executed and crashed — characte…

### ❓ unverifiable _(line 58)_
- exec_ids: `20499b3bcb73`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim contains only a confirmation marker and execution ID with no specific factual assertion to validate against the empty YARA scan results.
- claim: > [CONFIRMED — exec_id=019e18b3-e5e7-7653-9ec4-20499b3bcb73]

### ⚠ partial _(line 61)_
- tools: `tsk_fls_list`
- exec_ids: `1427e5156b6e`
- matched: `23296`, `23294`, `AdbeRdr910_en_US.exe`, `-2CFF2AE5.pf`, `ADBERDR910_EN_US.EXE`
- **missing**: `10.3.58.7`, ` (inode 23296). A Prefetch file `
- claim: > ### tdungan (10.3.58.7) — Parallel Initial Vector [CONFIRMED] `AdbeRdr910_en_US.exe` was delivered via Dropbox to `Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-02/AdbeRdr…

### ⚠ partial _(line 70)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`
- exec_ids: `c7a5a5ba77c5`, `0912c9194691`
- matched: `540`, `7793`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`
- **missing**: `spinlock.exe`, `WINDOWS/system32/spinlock.exe`, `Windows/System32/spinlock.exe`
- claim: > ### spinlock.exe (Email Harvester) — Lateral Deployment Confirmed [CONFIRMED] `spinlock.exe` (SHA256: `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`, 2,271,885 bytes) is present at…

### ⚠ partial _(line 72)_
- tools: `ezt_shimcache_parse`
- exec_ids: `2bf2356f4b15`
- matched: `2012-04-04T17:06:37Z`, `spinlock.exe`, `C:\WINDOWS\system32\spinlock.exe`
- **missing**: `C:\WINDOWS\system32\spinlock.exe``
- claim: > [CONFIRMED] tdungan ShimCache records `C:\WINDOWS\system32\spinlock.exe` at position 0 (last_modified 2012-04-04T17:06:37Z), confirming execution (ezt_shimcache_parse exec_id=019e18b4-8214-7fd3-91a4-2…

### ⚠ partial _(line 74)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-03T22:53:39Z`, `spinlock.exe`, `C:\Windows\system32\spinlock.exe`
- **missing**: `\Windows\system32\spinlock.exe``, `C:\Windows\system32\spinlock.exe``, `Executed: Yes`
- claim: > [CONFIRMED] nromanoff ShimCache records `C:\Windows\system32\spinlock.exe` executed (position 7, last_modified 2012-04-03T22:53:39Z, `Executed: Yes`), confirming spinlock.exe ran on nromanoff as well …

### ✅ verified _(line 76)_
- tools: `vol3_psscan`
- exec_ids: `64adf4b8db89`
- matched: `11640`, `12244`, `2012-04-06T18:58:17Z`, `spinlock.exe`, `cmd.exe`
- claim: > [CONFIRMED] tdungan memory shows spinlock.exe running at PIDs 12244 and 3648 (child of PID 12244) under `cmd.exe` parents at time of acquisition (vol3_psscan exec_id=019e18b0-2df3-7880-b651-64adf4b8db…

### ⚠ partial _(line 78)_
- tools: `tsk_fls_list`
- exec_ids: `4ee1c05ec445`
- matched: `spinlock.exe`, `NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004`
- **missing**: ` confirm spinlock.exe is a PyInstaller-packed executable — the `, `) and `
- claim: > [CONFIRMED] vibranium's temp directory on tdungan (`Documents and Settings/vibranium/Local Settings/Temp/_MEI122362/spinlock.exe.manifest`) and `WINDOWS/Temp/_MEI122442/spinlock.exe.manifest` confirm …

### ✅ verified _(line 80)_
- tools: `vol3_vadyarascan`, `vol3_vadyarascan`, `vol3_vadyarascan`
- exec_ids: `8bca82447c94`, `83a3c19f8a12`, `91d40757a443`
- ✅ verified absences (negated): `spinlock.exe`
- claim: > [CONFIRMED — exec_id=019e18b2-3a3e-7350-94d6-8bca82447c94, exec_id=019e18b2-3fa3-7872-9cfb-83a3c19f8a12, exec_id=019e18b2-482b-7131-9921-91d40757a443] No YARA matches in spinlock.exe memory or disk (P…

### ⚠ partial _(line 83)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T00:14:13Z`, `2012-04-04T00:44:11Z`, `a.exe`, `C:\Windows\TEMP\a.exe`
- **missing**: `\Windows\TEMP\a.exe``, `C:\Windows\TEMP\a.exe``
- claim: > ### a.exe (HTTPPUMP C2 Beacon) [CONFIRMED] nromanoff ShimCache records `C:\Windows\TEMP\a.exe` executed at positions 19–49+ with last_modified timestamps incrementing by exactly 1 minute from ~2012-04…

### 🔍 not_confirmed _(line 85)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > [CONFIRMED] `C:\Windows\TEMP` accounts for 94 ShimCache entries on nromanoff, all attributable to a.exe executions.

### ⚠ partial _(line 90)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T01:00:45Z`, `hydrakatz.exe`, `C:\windows\system32\hydrakatz.exe`
- **missing**: `C:\windows\system32\hydrakatz.exe``, `Executed: Yes`
- claim: > ### hydrakatz.exe (Credential Extraction) [CONFIRMED] nromanoff ShimCache records `C:\windows\system32\hydrakatz.exe` executed (position 14, last_modified 2012-04-04T01:00:45Z, `Executed: Yes`), confi…

### ✅ verified _(line 92)_
- tools: `ezt_shimcache_parse`
- exec_ids: `96ec8c79a7bd`
- ✅ verified absences (negated): `hydrakatz.exe`
- claim: > [CONFIRMED — exec_id=019e18b3-c8ca-7280-90f2-96ec8c79a7bd] hydrakatz.exe does NOT appear in the DC ShimCache. DC ShimCache contains 962 entries; shimcache filter for "hydrakatz" returns 0 matches, sug…

### 🔍 not_confirmed _(line 97)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > ### pe.exe [CONFIRMED]

### ⚠ partial _(line 104)_
- tools: `vol3_svcscan`, `hash_file`
- exec_ids: `f6f6d5caa3d4`, `648c64e48b4f`
- matched: `usboesrv.exe`, `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`, `C:\Windows\system32\usboesrv.exe`, `usboesrv`
- **missing**: `71488`, `71670`, `\Windows\system32\usboesrv.exe``, `C:\Windows\system32\usboesrv.exe``, `Windows/System32/usboesrv.exe`, `Program Files/USB over Ethernet/usboesrv.exe`
- claim: > ### DC — usboesrv.exe Service Hijack (T1543.003 + Binary Masquerading T1036.005) [CONFIRMED] Service `usboesrv` ("KernelPro USB over Ethernet Service") is configured AUTO_START and is RUNNING with bin…

### ❌ failed _(line 106)_
- tools: `strings_extract`
- exec_ids: `e1fe7c48962c`
- **missing**: `spinlock.exe`, `usboesrv.exe`
- claim: > [CONFIRMED] The malicious `usboesrv.exe` in System32 produces only 1 string ("input from stdin or file") even at min_length=4 — identical to the spinlock.exe packing signature — confirming it is packe…

### ✅ verified _(line 108)_
- tools: `yara_scan_extract`
- exec_ids: `3bd4adc63c72`
- ✅ verified absences (negated): `usboesrv.exe`
- claim: > [CONFIRMED — exec_id=019e18b3-e5d1-7793-9465-3bd4adc63c72] No YARA hits on extracted usboesrv.exe. The packed binary evades bundled signature-based detection.

### ✅ verified _(line 110)_
- tools: `vol3_psscan`
- exec_ids: `fc074bf1df17`
- matched: `27304`, `2012-03-20T17:58:12Z`, `usboesrv`
- claim: > [CONFIRMED] The `usboesrv` service was alive at acquisition time with PID 27304, created 2012-03-20T17:58:12Z — the C2 implant has been running since at least March 20, 2012 (vol3_psscan exec_id=019e1…

### ✅ verified _(line 112)_
- exec_ids: `05616ddaacbe`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed data confirms that HKLM Run keys contain exactly the four entries named in the claim (DWPersistentQueuedReporting, VMware Tools, VMware User Process, McAfee Host Intrusion Prevention Tray), all with legitimate executable paths and none marked as deleted or suspicious.
- claim: > [CONFIRMED — exec_id=019e18b3-ce36-78e3-9420-05616ddaacbe] DC HKLM SOFTWARE Run keys contain no malicious entries (DWPersistentQueuedReporting, VMware Tools, VMware User Process, McAfee HIP Tray — all…

### ⚠ partial _(line 115)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `49e5c81c22f9`
- matched: `"svchost"`
- ✅ verified absences (negated): `C:\Windows\System32\svchost.exe`
- **missing**: `\Windows\system32\dllhost\svchost.exe``, `\Windows\System32\svchost.exe``, `c:\windows\system32\dllhost\svchost.exe``, `C:\Windows\system32\dllhost\svchost.exe``, `C:\Windows\System32\svchost.exe``
- 🚨 negation violations (claimed absent but found): `svchost.exe`, `c:\windows\system32\dllhost\svchost.exe`, `C:\Windows\system32\dllhost\svchost.exe`
- claim: > ### tdungan — HKLM Run Key Masquerading svchost (T1547.001 + T1036.005) [CONFIRMED] tdungan SOFTWARE hive HKLM Run key contains:   `"svchost"` = `c:\windows\system32\dllhost\svchost.exe`   This is a m…

### ❓ unverifiable _(line 122)_
- exec_ids: `194d4d580db1`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The parsed data contains only aggregate counts (53 total, 45 enabled) with empty breakdowns by principal and action type, providing no specific factual details to verify or refute the claim about DC and nfury scheduled tasks.
- claim: > ### Scheduled Tasks — DC and nfury [CONFIRMED — exec_id=019e18b0-5de1-7bb0-b1ca-194d4d580db1]

### ❓ unverifiable _(line 124)_
- exec_ids: `8b4f49ab6f02`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim contains only a confirmation marker with an execution ID and no specific factual assertion about scheduled tasks to validate against the parsed data.
- claim: > [CONFIRMED — exec_id=019e18b0-663a-73a3-9062-8b4f49ab6f02]

### ✅ verified _(line 133)_
- exec_ids: `5e9d843765fc`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed data confirms exactly two users (Administrator and Guest) with null LM and NT hashes, which structurally supports the claim's specific assertion that only these accounts exist with null hash values in the local SAM.
- claim: > ### DC — SAM/LSA Credential Dump Attempts [CONFIRMED — exec_id=019e18b0-481e-7d43-bf23-5e9d843765fc] DC hashdump: Local SAM contains only Administrator and Guest with null LM/NT hashes. This is expect…

### ✅ verified _(line 135)_
- exec_ids: `f3c646bf8dae`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed data shows count=0 and empty rows, directly supporting the claim that 0 cached domain credentials were found, which aligns with the expected behavior that domain controllers do not cache credentials locally.
- claim: > [CONFIRMED — exec_id=019e18b0-537e-71c2-894e-f3c646bf8dae] DC cachedump: 0 cached domain credentials. Domain controllers do not cache domain credentials locally — they ARE the authentication authority…

### ✅ verified _(line 138)_
- exec_ids: `bdc99def5c77`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed cachedump data structurally contains exactly 6 cached credential entries including the username 'nfury' with its associated hash, confirming the claim's specific assertion about 6 cached domain credential entries.
- claim: > ### nfury — Domain Credential Cache Exposed [CONFIRMED — exec_id=019e18b0-5978-7630-983e-bdc99def5c77] nfury cachedump contains 6 cached domain credential entries (MSCASH/DCC2 hashes):

### ✅ verified _(line 152)_
- exec_ids: `609927065d51`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed hashdump data structurally confirms the claim's specific factual assertions: three users (Administrator, Guest, SRL-Helpdesk) are present with all nt_hash values set to null, supporting the assertion that no crackable local hashes exist.
- claim: > ### nromanoff — hashdump [CONFIRMED — exec_id=019e18b0-4eb0-78d2-bd28-609927065d51] nfury hashdump returns Administrator, Guest, SRL-Helpdesk — all with null NT hashes (domain-joined workstation; actu…

### ✅ verified _(line 155)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T00:14:13Z`, `2012-04-04T01:00:45Z`, `a.exe`, `hydrakatz.exe`
- claim: > ### hydrakatz.exe Execution [CONFIRMED — ShimCache exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1] hydrakatz.exe executed on nromanoff at 2012-04-04T01:00:45Z. This is a credential dumping tool (name de…

### ✅ verified _(line 157)_
- tools: `ezt_shimcache_parse`
- exec_ids: `96ec8c79a7bd`
- ✅ verified absences (negated): `hydrakatz.exe`
- claim: > [CONFIRMED — exec_id=019e18b3-c8ca-7280-90f2-96ec8c79a7bd] No hydrakatz.exe in DC ShimCache. The tool was used on workstations, not the DC directly.

### 🔍 not_confirmed _(line 167)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > ### Email Harvesting [CONFIRMED] spinlock.exe (email harvester, SHA256: `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`) ran on tdungan (memory + ShimCache + disk), nromanoff (ShimC…

### ⚠ partial _(line 176)_
- tools: `vol3_psscan`, `vol3_svcscan`
- exec_ids: `fc074bf1df17`, `f6f6d5caa3d4`
- matched: `27304`, `2012-03-20T17:58:12Z`, `usboesrv.exe`
- **missing**: `96.255.98.154`, `96.255.98.154:29932`
- claim: > ### DC — usboesrv.exe C2 Beacon [CONFIRMED] The malicious `usboesrv.exe` (PID 27304) has been running continuously on the DC since 2012-03-20T17:58:12Z — over 17 days prior to acquisition. Prior analy…

### ⚠ partial _(line 179)_
- tools: `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`
- matched: `2012-04-04T00:14:13Z`, `a.exe`, `C:\Windows\TEMP\a.exe`
- **missing**: `\Windows\TEMP\a.exe``, `C:\Windows\TEMP\a.exe``
- claim: > ### nromanoff — a.exe HTTPPUMP C2 [CONFIRMED] nromanoff ShimCache records 30+ executions of `C:\Windows\TEMP\a.exe` with 1-minute-increment last_modified timestamps beginning 2012-04-04T00:14:13Z. Thi…

### ✅ verified _(line 182)_
- tools: `vol3_cachedump`, `tsk_fls_list`
- exec_ids: `bdc99def5c77`, `1427e5156b6e`
- matched: `spinlock.exe`, `vibranium`, `Documents and Settings/vibranium/Local Settings/Temp/_MEI122362/`
- claim: > ### vibranium Account — Attacker Interactive Presence [CONFIRMED] The `vibranium` domain account's DCC2 hash cached on nfury proves interactive logon to that workstation (vol3_cachedump exec_id=019e18…

### ⚠ partial _(line 185)_
- tools: `ezt_shimcache_parse`, `ezt_shimcache_parse`
- exec_ids: `8d7f7cfd0dd1`, `96ec8c79a7bd`
- matched: `2012-04-04T01:46:37Z`, `PSEXESVC.EXE`, `C:\Windows\PSEXESVC.EXE`
- **missing**: `\Windows\PSEXESVC.EXE``, `C:\Windows\PSEXESVC.EXE``
- claim: > ### PsExec Usage [CONFIRMED] `C:\Windows\PSEXESVC.EXE` appears at position 9 in nromanoff ShimCache (last_modified 2012-04-04T01:46:37Z, Executed: Yes), confirming PsExec was used to execute commands …
