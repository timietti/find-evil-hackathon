# Validator Report — iter_2

## Summary

- Total tagged claims:        **38**
  - CONFIRMED:                 23
  - INFERRED:                  10
  - HYPOTHESIS:                2
  - GAP:                       3
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           11 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                8 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           4 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 47.8%** (11 verified / 23 confirmed)

## Per-claim verdicts

### ⚠ partial _(line 24)_
- tools: `vol3_netscan`, `vol3_psscan`
- exec_ids: `ba879342060d`, `b8f1af42b7bd`
- matched: `172.16.6.11`
- **missing**: `local_addr: 172.16.6.11`
- claim: > **[CONFIRMED — exec_id=019e511e-1ab2-7d33-afde-ba879342060d, exec_id=019e511c-f829-7930-965e-b8f1af42b7bd] Primary compromise host: rd01 at local_addr 172.16.6.11.** The netscan shows 37 connections w…

### ❓ unverifiable _(line 36)_
- exec_ids: `b8f1af42b7bd`, `c02d18d27f1f`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id=019e511c-f829-7930-965e-b8f1af42b7bd, exec_id=019e511e-97da-7d12-9839-c02d18d27f1f]

### ✅ verified _(line 38)_
- tools: `vol3_malfind`
- exec_ids: `5d9ae3330772`
- matched: `8128`, `OUTLOOK.EXE`
- claim: > **[CONFIRMED — exec_id=019e5121-9861-7422-9ed4-5d9ae3330772] OUTLOOK.EXE (PID 8128, session 1) has two RWX private-memory VAD regions** — shellcode injection indicators targeting Outlook's process spa…

### ⚠ partial _(line 50)_
- tools: `tsk_fls_list`, `vol3_cmdline`, `tsk_icat_extract`
- exec_ids: `8e9fc8c51d46`, `c02d18d27f1f`, `f15f52bd5143`
- matched: `5994`, `p.exe`, `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`, `Perfmon`
- **missing**: `c:\windows\temp\perfmon\p.exe`;`, `path: Windows/Temp/Perfmon/p.exe`, `args: c:\windows\temp\perfmon\p.exe`
- claim: > **[CONFIRMED — exec_id=019e5123-8c1b-7d22-9feb-8e9fc8c51d46, exec_id=019e511e-97da-7d12-9839-c02d18d27f1f, exec_id=019e5125-24bf-7130-9981-f15f52bd5143]** Disk listing finds `path: Windows/Temp/Perfmo…

### ⚠ partial _(line 52)_
- tools: `vol3_malfind`
- exec_ids: `5d9ae3330772`
- matched: `8260`, `p.exe`
- **missing**: `tag: VadS`, `private_memory: 1`, `commit_charge: 481`, `protection: PAGE_EXECUTE_READWRITE`
- claim: > **[CONFIRMED — exec_id=019e5121-9861-7422-9ed4-5d9ae3330772]** vol3_malfind finds a VAD region for pid=8260 (p.exe) with `tag: VadS`, `protection: PAGE_EXECUTE_READWRITE`, `private_memory: 1`, `commit…

### ✅ verified _(line 54)_
- tools: `vol3_psscan`
- exec_ids: `b8f1af42b7bd`
- matched: `8260`, `rundll32.exe`, `p.exe`
- claim: > **[CONFIRMED — exec_id=019e511c-f829-7930-965e-b8f1af42b7bd]** p.exe (pid=8260) spawned **9 exited rundll32.exe child processes** timestamped from 2018-08-30 through 2018-09-06, used as short-lived C2…

### ✅ verified _(line 56)_
- tools: `vol3_malfind`
- exec_ids: `5d9ae3330772`
- matched: `8712`, `powershell.exe`
- claim: > **[CONFIRMED — exec_id=019e5121-9861-7422-9ed4-5d9ae3330772]** powershell.exe (pid=8712, the WMI-spawned parent of the attack chain) also has **3 VAD regions with protection PAGE_EXECUTE_READWRITE** —…

### ✅ verified _(line 62)_
- tools: `vol3_psscan`
- exec_ids: `ecb3b51b8872`
- matched: `4072`, `3164`, `2018-08-28T22:08:26Z`, `2018-08-28T22:08:25Z`, `rundll32.exe`, `powershell.exe`
- claim: > **[CONFIRMED — exec_id=019e512b-b297-70c2-9041-ecb3b51b8872]** powershell.exe with pid=4072, ppid=1196, session_id=0, running since create_time=2018-08-28T22:08:25Z — a persistent PowerShell process i…

### ⚠ partial _(line 66)_
- tools: `vol3_psscan`, `vol3_netscan`
- exec_ids: `26026b1960bb`, `f21f01f38c4e`
- matched: `5144`, `15116`, `172.16.4.10`, `2018-08-31T19:47:10Z`, `2018-09-05T12:05:44Z`, `rundll32.exe`, `powershell.exe`
- **missing**: `foreign_addr: ::1, foreign_port: 890, state: ESTABLISHED`, `foreign_addr: 172.16.4.10, foreign_port: 3128, state: ESTABLISHED`
- claim: > **[CONFIRMED — exec_id=019e512f-0d8d-72e1-848a-26026b1960bb, exec_id=019e5131-2346-7951-aa11-f21f01f38c4e]** powershell.exe with pid=5144, ppid=6644, session_id=2, create_time=2018-09-05T12:05:44Z on …

### ✅ verified _(line 70)_
- tools: `ezt_prefetch_parse`
- exec_ids: `196aac97a260`
- matched: `2018-05-14T05:26:17Z`, `SDELETE.EXE`
- ✅ verified absences (negated): `p.exe`
- claim: > **[CONFIRMED — exec_id=019e5128-366d-7560-a399-196aac97a260]** SDELETE.EXE prefetch exists on rd01 (1 run, last run **2018-05-14T05:26:17Z**). No p.exe prefetch is present on the rd01 disk — consisten…

### ❓ unverifiable _(line 76)_
- exec_ids: `ba879342060d`, `ecb3b51b8872`, `26026b1960bb`, `334801d7c27a`
- note: claim has no extractable tokens (prose only)
- claim: > **[CONFIRMED — exec_id=019e511e-1ab2-7d33-afde-ba879342060d, exec_id=019e512b-b297-70c2-9041-ecb3b51b8872, exec_id=019e512f-0d8d-72e1-848a-26026b1960bb, exec_id=019e511e-a0a8-7a01-a762-334801d7c27a]**…

### ✅ verified _(line 88)_
- tools: `vol3_netscan`, `vol3_netscan`, `vol3_netscan`
- exec_ids: `ba879342060d`, `8306f3832d19`, `f21f01f38c4e`
- matched: `172.16.4.10`
- claim: > **[CONFIRMED — exec_id=019e511e-1ab2-7d33-afde-ba879342060d, exec_id=019e512e-3ea4-7ac0-ad91-8306f3832d19, exec_id=019e5131-2346-7951-aa11-f21f01f38c4e]** All beaconing hosts route C2 traffic through …

### ✅ verified _(line 90)_
- tools: `vol3_netscan`
- exec_ids: `ba879342060d`
- matched: `52.16.55.11`, `13.89.220.65`
- claim: > **[CONFIRMED — exec_id=019e511e-1ab2-7d33-afde-ba879342060d]** External C2 endpoints contacted from rd01: foreign_addr=13.89.220.65, foreign_port=443 (CLOSED) and foreign_addr=52.16.55.11, foreign_por…

### ⚠ partial _(line 100)_
- tools: `tsk_fls_list`
- exec_ids: `8e9fc8c51d46`
- matched: `6.4.0.12512`, `6.3.0.12323`, `6.1.0.11480`, `Users/tdungan/AppData/Local/Packages/windows_ie_ac_001/AC/Dashlane/`, `6.2.0.12026`
- 🚨 negation violations (claimed absent but found): `184381`, `procdump.exe`, `Users/tdungan/AppData/Roaming/Dashlane/procdump.exe`, `Users/tdungan/AppData/Roaming/Dashlane/`
- claim: > **[CONFIRMED — exec_id=019e5123-8c1b-7d22-9feb-8e9fc8c51d46]** procdump.exe present in **9 locations** within tdungan's Dashlane directories on rd01 disk. Eight copies reside inside versioned applicat…

### ✅ verified _(line 106)_
- tools: `vol3_psscan`
- exec_ids: `334801d7c27a`
- matched: `2018-09-06T22:53:58Z`, `findstr.exe`, `cmd.exe`, `tasklist.exe`
- claim: > **[CONFIRMED — exec_id=019e511e-a0a8-7a01-a762-334801d7c27a]** The DC psscan shows **25 cmd.exe instances** and 2 tasklist.exe / 2 findstr.exe processes in the exited pool, spanning create_time range …

### ✅ verified _(line 125)_
- tools: `vol3_psscan`
- exec_ids: `ecb3b51b8872`
- matched: `2524`, `2018-09-05T14:43:11Z`, `2018-09-05T14:52:56Z`, `Rar.exe`
- claim: > **[CONFIRMED — exec_id=019e512b-b297-70c2-9041-ecb3b51b8872]** Rar.exe with pid=2524, ppid=6352 executed on file01 from create_time=2018-09-05T14:43:11Z to exit_time=2018-09-05T14:52:56Z (9 minutes, 4…

### ⚠ partial _(line 133)_
- tools: `vol3_netscan`, `vol3_psscan`
- exec_ids: `f21f01f38c4e`, `26026b1960bb`
- matched: `5144`, `172.16.4.10`, `powershell.exe`
- **missing**: `foreign_addr: ::1, foreign_port: 890, state: ESTABLISHED`, `foreign_addr: 172.16.4.10, foreign_port: 3128, state: ESTABLISHED`
- claim: > **[CONFIRMED — exec_id=019e5131-2346-7951-aa11-f21f01f38c4e, exec_id=019e512f-0d8d-72e1-848a-26026b1960bb]** Exchange server is compromised with pid=5144 (image=powershell.exe) connected to `foreign_a…

### ✅ verified _(line 139)_
- tools: `vol3_netscan`
- exec_ids: `ba879342060d`
- matched: `172.16.4.10`, `52.16.55.11`, `13.89.220.65`
- claim: > **[CONFIRMED — exec_id=019e511e-1ab2-7d33-afde-ba879342060d]** External HTTPS connections from rd01 to foreign_addr=13.89.220.65, foreign_port=443 (CLOSED) and foreign_addr=52.16.55.11, foreign_port=4…

### ⚠ partial _(line 198)_
- tools: `vol3_netscan`, `vol3_netscan`
- exec_ids: `ba879342060d`, `f21f01f38c4e`
- matched: `52.16.55.11`, `13.89.220.65`
- **missing**: `rundll32.exe`
- claim: > 1. **Persistent dwell (9+ days)** with low-and-slow beacon cadence via rundll32.exe shells and proxy relay — avoiding burst traffic detection 2. **Three-tier C2 hierarchy**: implant → proxy01 (foreign…

### ⚠ partial _(line 199)_
- tools: `vol3_netscan`
- exec_ids: `ba879342060d`
- matched: `172.16.6.11`
- **missing**: `172.16.6.0`
- claim: > 3. **Targeted R&D network** (rd01 at 172.16.6.11 in subnet 172.16.6.0/24) as primary beachhead — objective is intellectual property [CONFIRMED — exec_id=019e511e-1ab2-7d33-afde-ba879342060d]

### ❓ unverifiable _(line 200)_
- exec_ids: `f21f01f38c4e`
- note: claim has no extractable tokens (prose only)
- claim: > 4. **Exchange server compromise** for persistent email intelligence collection — hallmark of state espionage [CONFIRMED — exec_id=019e5131-2346-7951-aa11-f21f01f38c4e]

### ✅ verified _(line 201)_
- tools: `vol3_psscan`
- exec_ids: `334801d7c27a`
- matched: `cmd.exe`
- claim: > 5. **Domain Controller penetration** with extensive enumeration (tasklist, findstr, 25 cmd.exe sessions) — full domain dominance achieved [CONFIRMED — exec_id=019e511e-a0a8-7a01-a762-334801d7c27a]

### ❓ unverifiable _(line 202)_
- exec_ids: `8e9fc8c51d46`, `196aac97a260`
- note: claim has no extractable tokens (prose only)
- claim: > 6. **LSASS dump + SDelete** — systematic credential harvest with anti-forensic cleanup [CONFIRMED — exec_id=019e5123-8c1b-7d22-9feb-8e9fc8c51d46, exec_id=019e5128-366d-7560-a399-196aac97a260]
