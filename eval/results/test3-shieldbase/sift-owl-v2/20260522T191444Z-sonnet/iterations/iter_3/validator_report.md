# Validator Report — iter_3

## Summary

- Total tagged claims:        **47**
  - CONFIRMED:                 30
  - INFERRED:                  12
  - HYPOTHESIS:                2
  - GAP:                       3
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           18 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                5 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           3 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           2 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 60.0%** (18 verified / 30 confirmed)

## Per-claim verdicts

### ✅ verified _(line 32)_
- tools: `vol3_netscan`, `vol3_psscan`
- exec_ids: `ba879342060d`, `b8f1af42b7bd`
- matched: `172.16.6.11`, `local_addr`
- claim: > **[CONFIRMED — exec_id=019e511e-1ab2-7d33-afde-ba879342060d, exec_id=019e511c-f829-7930-965e-b8f1af42b7bd] Primary compromise host: rd01.** The vol3_netscan on rd01 returns 37 connections with field `…

### ❓ unverifiable _(line 44)_
- exec_ids: `b8f1af42b7bd`, `c02d18d27f1f`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id=019e511c-f829-7930-965e-b8f1af42b7bd, exec_id=019e511e-97da-7d12-9839-c02d18d27f1f]

### ✅ verified _(line 46)_
- tools: `vol3_malfind`
- exec_ids: `5d9ae3330772`
- matched: `8128`, `OUTLOOK.EXE`
- claim: > **[CONFIRMED — exec_id=019e5121-9861-7422-9ed4-5d9ae3330772] OUTLOOK.EXE (PID 8128, session 1) has two RWX private-memory VAD regions** — shellcode injection indicators targeting Outlook's process spa…

### ⚠ partial _(line 58)_
- tools: `tsk_fls_list`, `vol3_cmdline`, `tsk_icat_extract`
- exec_ids: `8e9fc8c51d46`, `c02d18d27f1f`, `f15f52bd5143`
- matched: `8260`, `5994`, `p.exe`, `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`, `Perfmon`
- **missing**: `c:\windows\temp\perfmon\p.exe`;`, `path: Windows/Temp/Perfmon/p.exe`, `args: c:\windows\temp\perfmon\p.exe`
- claim: > **[CONFIRMED — exec_id=019e5123-8c1b-7d22-9feb-8e9fc8c51d46, exec_id=019e511e-97da-7d12-9839-c02d18d27f1f, exec_id=019e5125-24bf-7130-9981-f15f52bd5143]** Disk listing (fls_list) finds inode 5994 with…

### ✅ verified _(line 60)_
- tools: `vol3_malfind`
- exec_ids: `5d9ae3330772`
- matched: `8260`, `p.exe`
- claim: > **[CONFIRMED — exec_id=019e5121-9861-7422-9ed4-5d9ae3330772]** vol3_malfind returns a VAD region for pid=8260 (process=p.exe) with tag=VadS, protection=PAGE_EXECUTE_READWRITE, private_memory=1, commit…

### ✅ verified _(line 62)_
- tools: `vol3_psscan`
- exec_ids: `b8f1af42b7bd`
- matched: `8260`, `rundll32.exe`, `cmd.exe`, `p.exe`
- claim: > **[CONFIRMED — exec_id=019e511c-f829-7930-965e-b8f1af42b7bd]** p.exe (pid=8260) spawned **9 exited rundll32.exe child processes** (ppid=5848 traced back through cmd.exe/p.exe chain) timestamped from 2…

### ✅ verified _(line 64)_
- tools: `vol3_malfind`
- exec_ids: `5d9ae3330772`
- matched: `8712`, `powershell.exe`
- claim: > **[CONFIRMED — exec_id=019e5121-9861-7422-9ed4-5d9ae3330772]** powershell.exe (pid=8712, the WMI-spawned parent of the attack chain) also has **3 VAD regions with protection=PAGE_EXECUTE_READWRITE** —…

### ✅ verified _(line 70)_
- tools: `vol3_psscan`
- exec_ids: `ecb3b51b8872`
- matched: `4072`, `3164`, `2018-08-28T22:08:26Z`, `2018-08-28T22:08:25Z`, `rundll32.exe`, `powershell.exe`
- claim: > **[CONFIRMED — exec_id=019e512b-b297-70c2-9041-ecb3b51b8872]** powershell.exe with pid=4072, ppid=1196, session_id=0, running since create_time=2018-08-28T22:08:25Z — a persistent PowerShell process i…

### ✅ verified _(line 74)_
- tools: `vol3_psscan`, `vol3_netscan`
- exec_ids: `26026b1960bb`, `f21f01f38c4e`
- matched: `5144`, `15116`, `172.16.4.10`, `172.16.4.6`, `2018-08-31T19:47:10Z`, `2018-09-05T12:07:48Z`, `2018-09-05T15:51:18Z`, `2018-09-05T12:05:44Z` (+2 more)
- claim: > **[CONFIRMED — exec_id=019e512f-0d8d-72e1-848a-26026b1960bb, exec_id=019e5131-2346-7951-aa11-f21f01f38c4e]** powershell.exe pid=5144, ppid=6644, session_id=2, create_time=2018-09-05T12:05:44Z on the E…

### ✅ verified _(line 78)_
- tools: `ezt_prefetch_parse`
- exec_ids: `196aac97a260`
- matched: `2018-05-14T05:26:17Z`, `SDELETE.EXE`
- ✅ verified absences (negated): `p.exe`
- claim: > **[CONFIRMED — exec_id=019e5128-366d-7560-a399-196aac97a260]** SDELETE.EXE prefetch exists on rd01 (1 run, last run 2018-05-14T05:26:17Z). No p.exe prefetch is present on the rd01 disk — consistent wi…

### ❓ unverifiable _(line 84)_
- exec_ids: `ba879342060d`, `ecb3b51b8872`, `26026b1960bb`, `334801d7c27a`
- note: claim has no extractable tokens (prose only)
- claim: > **[CONFIRMED — exec_id=019e511e-1ab2-7d33-afde-ba879342060d, exec_id=019e512b-b297-70c2-9041-ecb3b51b8872, exec_id=019e512f-0d8d-72e1-848a-26026b1960bb, exec_id=019e511e-a0a8-7a01-a762-334801d7c27a]**…

### ✅ verified _(line 96)_
- tools: `vol3_netscan`, `vol3_netscan`, `vol3_netscan`
- exec_ids: `ba879342060d`, `8306f3832d19`, `f21f01f38c4e`
- matched: `5144`, `172.16.4.10`
- claim: > **[CONFIRMED — exec_id=019e511e-1ab2-7d33-afde-ba879342060d, exec_id=019e512e-3ea4-7ac0-ad91-8306f3832d19, exec_id=019e5131-2346-7951-aa11-f21f01f38c4e]** All beaconing hosts route C2 traffic through …

### ✅ verified _(line 98)_
- tools: `vol3_netscan`
- exec_ids: `ba879342060d`
- matched: `52.16.55.11`, `13.89.220.65`
- claim: > **[CONFIRMED — exec_id=019e511e-1ab2-7d33-afde-ba879342060d]** External C2 endpoints contacted from rd01: foreign_addr=13.89.220.65, foreign_port=443 (CLOSED) and foreign_addr=52.16.55.11, foreign_por…

### ⚠ partial _(line 108)_
- tools: `tsk_fls_list`
- exec_ids: `8e9fc8c51d46`
- matched: `6.4.0.12512`, `6.3.0.12323`, `6.1.0.11480`, `Users/tdungan/AppData/Local/Packages/windows_ie_ac_001/AC/Dashlane/`, `6.2.0.12026`
- **missing**: `path: Users/tdungan/AppData/Roaming/Dashlane/procdump.exe`
- 🚨 negation violations (claimed absent but found): `184381`, `procdump.exe`
- claim: > **[CONFIRMED — exec_id=019e5123-8c1b-7d22-9feb-8e9fc8c51d46]** procdump.exe present in **9 locations** within tdungan's Dashlane directories on rd01 disk. Eight copies reside inside versioned applicat…

### ✅ verified _(line 114)_
- tools: `vol3_psscan`
- exec_ids: `334801d7c27a`
- matched: `2018-09-06T22:53:58Z`, `findstr.exe`, `cmd.exe`, `tasklist.exe`
- claim: > **[CONFIRMED — exec_id=019e511e-a0a8-7a01-a762-334801d7c27a]** The DC psscan shows **25 cmd.exe instances** and 2 tasklist.exe / 2 findstr.exe processes in the exited pool, spanning create_time range …

### ✅ verified _(line 133)_
- tools: `vol3_psscan`
- exec_ids: `ecb3b51b8872`
- matched: `2524`, `2018-09-05T14:43:11Z`, `2018-09-05T14:52:56Z`, `Rar.exe`
- claim: > **[CONFIRMED — exec_id=019e512b-b297-70c2-9041-ecb3b51b8872]** Rar.exe with pid=2524, ppid=6352 executed on file01 from create_time=2018-09-05T14:43:11Z to exit_time=2018-09-05T14:52:56Z (9 minutes, 4…

### ✅ verified _(line 141)_
- tools: `vol3_netscan`, `vol3_psscan`
- exec_ids: `f21f01f38c4e`, `26026b1960bb`
- matched: `5144`, `172.16.4.10`, `2018-09-05T12:07:48Z`, `2018-09-05T15:51:18Z`, `powershell.exe`
- claim: > **[CONFIRMED — exec_id=019e5131-2346-7951-aa11-f21f01f38c4e, exec_id=019e512f-0d8d-72e1-848a-26026b1960bb]** Exchange server is compromised with pid=5144 (owner=powershell.exe) holding two simultaneou…

### ✅ verified _(line 147)_
- tools: `vol3_netscan`
- exec_ids: `ba879342060d`
- matched: `172.16.4.10`, `52.16.55.11`, `13.89.220.65`
- claim: > **[CONFIRMED — exec_id=019e511e-1ab2-7d33-afde-ba879342060d]** External HTTPS connections from rd01 to foreign_addr=13.89.220.65, foreign_port=443 (state=CLOSED) and foreign_addr=52.16.55.11, foreign_…

### ✅ verified _(line 205)_
- tools: `vol3_psscan`, `vol3_psscan`
- exec_ids: `b8f1af42b7bd`, `ecb3b51b8872`
- matched: `rundll32.exe`
- claim: > 1. **Persistent dwell (9+ days)** with low-and-slow beacon cadence via rundll32.exe shells [CONFIRMED — exec_id=019e511c-f829-7930-965e-b8f1af42b7bd, exec_id=019e512b-b297-70c2-9041-ecb3b51b8872]

### ✅ verified _(line 206)_
- tools: `vol3_netscan`, `vol3_netscan`
- exec_ids: `ba879342060d`, `f21f01f38c4e`
- matched: `52.16.55.11`, `13.89.220.65`
- claim: > and proxy relay — avoiding burst traffic detection. 2. **Three-tier C2 hierarchy**: implant → proxy01 (foreign_port=8080/3128) → external endpoints (13.89.220.65, 52.16.55.11) — blending with corporat…

### ❌ failed _(line 208)_
- tools: `vol3_netscan`
- exec_ids: `f21f01f38c4e`
- **missing**: `172.16.6.11`
- claim: > Targeted R&D network** (rd01 at 172.16.6.11) as primary beachhead — objective is intellectual property. 4. **Exchange server compromise** for persistent email intelligence collection — hallmark of sta…

### ✅ verified _(line 209)_
- tools: `vol3_psscan`
- exec_ids: `334801d7c27a`
- matched: `cmd.exe`
- claim: > . 5. **Domain Controller penetration** with extensive enumeration (tasklist, findstr, 25 cmd.exe sessions) — full domain dominance achieved [CONFIRMED — exec_id=019e511e-a0a8-7a01-a762-334801d7c27a]

### ❓ unverifiable _(line 210)_
- exec_ids: `8e9fc8c51d46`, `196aac97a260`
- note: claim has no extractable tokens (prose only)
- claim: > . 6. **LSASS dump + SDelete** — systematic credential harvest with anti-forensic cleanup [CONFIRMED — exec_id=019e5123-8c1b-7d22-9feb-8e9fc8c51d46, exec_id=019e5128-366d-7560-a399-196aac97a260]

### ✅ verified _(line 211)_
- tools: `vol3_cmdline`, `vol3_psscan`
- exec_ids: `c02d18d27f1f`, `ecb3b51b8872`
- matched: `-s`
- claim: > . 7. **Dual PowerShell execution modes** (WMI-launched + PSRemoting `-s` flag) — consistent with PowerSploit/Empire-class toolkits [CONFIRMED — exec_id=019e511e-97da-7d12-9839-c02d18d27f1f, exec_id=01…

### ⚠ partial _(line 221)_
- tools: `vol3_netscan`
- exec_ids: `ba879342060d`
- matched: `local_addr`
- **missing**: `query_rows(filter_field=local_addr, filter_value=172.16.6.11)`, `local_addr: 172.16.6.11`
- 🚨 negation violations (claimed absent but found): `172.16.6.11`
- claim: > | # | Validator demotion | Resolution | Action | |---|---|---|---| | 1 | `local_addr: 172.16.6.11` token not matched | Confirmed via `query_rows(filter_field=local_addr, filter_value=172.16.6.11)` ret…

### 🔍 not_confirmed _(line 222)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > ; removed the `` backtick-colon formatting token | | 2 | `path: Windows/Temp/Perfmon/p.exe` and `args: c:\windows\temp\perfmon\p.exe` not matched | Confirmed via `query_rows(filter_field=inode, filter…

### ❌ failed _(line 223)_
- tools: `vol3_malfind`
- exec_ids: `5d9ae3330772`
- **missing**: `tag: VadS`, `private_memory: 1`, `commit_charge: 481`, `protection: PAGE_EXECUTE_READWRITE`
- 🚨 negation violations (claimed absent but found): `8260`
- claim: > ; cited exact field values | | 3 | `tag: VadS`, `private_memory: 1`, `commit_charge: 481`, `protection: PAGE_EXECUTE_READWRITE` not matched | All present in malfind row for pid=8260: tag=VadS, protect…

### ⚠ partial _(line 224)_
- tools: `vol3_netscan`
- exec_ids: `f21f01f38c4e`
- matched: `172.16.4.10`
- **missing**: `foreign_addr: ::1, foreign_port: 890`, `foreign_addr: 172.16.4.10, foreign_port: 3128`, `query_rows(filter_field=pid, filter_value=5144)`
- claim: > ; reformatted as field=value | | 4 | `foreign_addr: ::1, foreign_port: 890` and `foreign_addr: 172.16.4.10, foreign_port: 3128` not matched | Confirmed via `query_rows(filter_field=pid, filter_value=5…

### ⚠ partial _(line 225)_
- tools: `tsk_fls_list`
- exec_ids: `8e9fc8c51d46`
- matched: `184381`, `procdump.exe`
- **missing**: `query_rows(filter_field=inode, filter_value=184381)`, `path: Users/tdungan/AppData/Roaming/Dashlane/procdump.exe`
- claim: > ; reformatted with exact field=value | | 5 | inode 184381 / Roaming/Dashlane/procdump.exe listed as "negation violations" | Confirmed via `query_rows(filter_field=inode, filter_value=184381)` → `path:…

### 🔍 not_confirmed _(line 226)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > ; path is directly observed | | 6 | Same as #4 (repeated in G5) | Same resolution as #4 | Kept [CONFIRMED]
