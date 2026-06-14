# Validator Report — iter_1

## Summary

- Total tagged claims:        **34**
  - CONFIRMED:                 19
  - INFERRED:                  10
  - HYPOTHESIS:                2
  - GAP:                       3
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           7 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                7 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           3 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 36.8%** (7 verified / 19 confirmed)

## Per-claim verdicts

### 🔍 not_confirmed _(line 62)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED] Primary compromise host: rd01 (172.16.6.11)**

### ✅ verified _(line 76)_
- tools: `vol3_malfind`
- exec_ids: `5d9ae3330772`
- matched: `8128`, `OUTLOOK.EXE`
- claim: > **[CONFIRMED] OUTLOOK.EXE (PID 8128, session 1, user tdungan) has two RWX private-memory VAD regions** (vol3_malfind exec_id: 019e5121-9861-7422-9ed4-5d9ae3330772). This is the injection vector: shell…

### ⚠ partial _(line 88)_
- tools: `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `f15f52bd5143`, `8e9fc8c51d46`
- matched: `p.exe`, `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`
- **missing**: `\Windows\Temp\perfmon\p.exe`,`, `C:\Windows\Temp\perfmon\p.exe`,`, `C:\Windows\Temp\perfmon\p.exe`
- claim: > **[CONFIRMED]** `p.exe` at path `C:\Windows\Temp\perfmon\p.exe`, SHA-256: `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`, size 164,352 bytes [exec_id: tsk_icat_extract 019e5125-24b…

### ⚠ partial _(line 92)_
- tools: `vol3_malfind`, `vol3_malfind`
- exec_ids: `7422-9ed4-5d`, `5d9ae3330772`
- matched: `8260`, `p.exe`
- **missing**: `VadS / PAGE_EXECUTE_READWRITE / private_memory=True`, `p.exe (PID 8260)`
- claim: > **[CONFIRMED]** vol3_malfind reports a `VadS / PAGE_EXECUTE_READWRITE / private_memory=True` region of 481 committed pages within `p.exe (PID 8260)` — classic self-injecting shellcode payload [exec_id…

### ✅ verified _(line 94)_
- tools: `vol3_psscan`
- exec_ids: `b8f1af42b7bd`
- matched: `8260`, `rundll32.exe`, `p.exe`
- claim: > **[CONFIRMED]** p.exe (PID 8260) spawned **9 exited `rundll32.exe` child processes** timestamped from 2018-08-30 through 2018-09-06, used as short-lived C2 callback shells (T1218.011) [vol3_psscan exe…

### ✅ verified _(line 96)_
- tools: `vol3_malfind`
- exec_ids: `5d9ae3330772`
- matched: `8712`, `powershell.exe`
- claim: > **[CONFIRMED]** powershell.exe (PID 8712, parent of attack chain) also has **3 RWX VAD regions** — in-memory shellcode stage within the initial PowerShell dropper [exec_id: 019e5121-9861-7422-9ed4-5d9…

### ⚠ partial _(line 102)_
- tools: `vol3_psscan`
- exec_ids: `ecb3b51b8872`
- matched: `4072`, `3164`, `2018-08-28T22:08:25Z`, `rundll32.exe`, `powershell.exe`
- **missing**: `powershell.exe (PID 3164)`, `powershell.exe (PID 4072, ppid 1196, session 0)`
- claim: > **[CONFIRMED]** `powershell.exe (PID 4072, ppid 1196, session 0)` running since **2018-08-28T22:08:25Z** — a persistent PowerShell process spawning `powershell.exe (PID 3164)` which in turn spawned **…

### ⚠ partial _(line 106)_
- tools: `vol3_netscan`, `vol3_psscan`
- exec_ids: `f21f01f38c4e`, `26026b1960bb`
- matched: `5144`, `15116`, `172.16.4.10`, `2018-08-31T19:47:10Z`, `2018-09-05T12:05:44Z`, `rundll32.exe`, `powershell.exe`
- **missing**: `rundll32.exe (PID 15116)`, `powershell.exe (PID 5144)`
- claim: > **[CONFIRMED]** `powershell.exe (PID 5144)` active on the Exchange server since **2018-09-05T12:05:44Z**, connected to **172.16.4.10:3128 (proxy01/Squid) ESTABLISHED** [vol3_netscan exec_id: 019e5131-…

### ✅ verified _(line 110)_
- tools: `ezt_prefetch_parse`
- exec_ids: `196aac97a260`
- matched: `2018-05-14T05:26:17Z`, `SDELETE.EXE`
- ✅ verified absences (negated): `p.exe`
- claim: > **[CONFIRMED]** `SDELETE.EXE` prefetch exists on rd01 (1 run, last run **2018-05-14T05:26:17Z**) [exec_id: 019e5128-366d-7560-a399-196aac97a260]. No p.exe prefetch is present on the rd01 disk — consis…

### 🔍 not_confirmed _(line 116)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED]** Network evidence establishes the following lateral movement sequence:

### ✅ verified _(line 128)_
- tools: `vol3_netscan`, `vol3_netscan`, `vol3_netscan`
- exec_ids: `ba879342060d`, `8306f3832d19`, `f21f01f38c4e`
- matched: `172.16.4.10`
- claim: > **[CONFIRMED] Internal proxy relay confirmed:** All beaconing hosts route C2 traffic through **proxy01 (172.16.4.10)** — rd01 and file01 use port 8080; exchange01 uses port 3128 (Squid). proxy01 is no…

### ✅ verified _(line 130)_
- tools: `vol3_netscan`
- exec_ids: `ba879342060d`
- matched: `52.16.55.11`, `13.89.220.65`
- claim: > **[CONFIRMED] External C2 endpoints contacted from rd01:** 13.89.220.65:443 (CLOSED) and 52.16.55.11:443 (CLOSED) — both Internet-routable Microsoft Azure / AWS addresses [exec_id: 019e511e-1ab2-7d33-…

### ❌ failed _(line 140)_
- tools: `tsk_fls_list`
- exec_ids: `8e9fc8c51d46`
- 🚨 negation violations (claimed absent but found): `procdump.exe`, `Users/tdungan/AppData/Roaming/Dashlane/procdump.exe`, `tdungan`
- claim: > **[CONFIRMED]** `procdump.exe` present in **9 locations** within `tdungan`'s AppData on rd01, including a root-level copy at `Users/tdungan/AppData/Roaming/Dashlane/procdump.exe` — not inside any vers…

### ⚠ partial _(line 148)_
- tools: `vol3_psscan`
- exec_ids: `334801d7c27a`
- matched: `findstr.exe`, `cmd.exe`, `tasklist.exe`
- **missing**: `2018-09-06T22:57:49Z`
- claim: > **[CONFIRMED]** The DC memory (captured 2018-09-06T22:57:49Z) shows **25 cmd.exe instances** and 2 tasklist.exe / 2 findstr.exe processes in the exited pool, all consistent with interactive post-explo…

### ⚠ partial _(line 170)_
- tools: `vol3_psscan`
- exec_ids: `ecb3b51b8872`
- matched: `2524`, `2018-09-05T14:43:11Z`, `Rar.exe`
- **missing**: `Rar.exe (PID 2524)`
- 🚨 negation violations (claimed absent but found): `6352`
- claim: > **[CONFIRMED]** `Rar.exe (PID 2524)` executed on file01 from **2018-09-05T14:43:11Z to 14:52:56Z UTC** (9 minutes, 41 seconds) [vol3_psscan exec_id: 019e512b-b297-70c2-9041-ecb3b51b8872]. The parent p…

### ❌ failed _(line 172)_
- tools: `tsk_fls_list`
- exec_ids: `bd6c66ccb21e`
- 🚨 negation violations (claimed absent but found): `.rar`
- claim: > **[CONFIRMED]** No `.rar` archive files survive on the file01 disk [tsk_fls_list exec_id: 019e5130-3f0f-7032-b746-bd6c66ccb21e]. The output archive was exfiltrated or deleted immediately after creatio…

### ⚠ partial _(line 178)_
- tools: `vol3_netscan`
- exec_ids: `f21f01f38c4e`
- matched: `5144`, `powershell.exe`
- **missing**: `::1:890`, `powershell.exe (PID 5144)`
- claim: > **[CONFIRMED]** Exchange server (exchange01) is compromised with an active `powershell.exe` connected to the Exchange management endpoint (`::1:890` localhost MSRPC) via `powershell.exe (PID 5144)` [v…

### ✅ verified _(line 184)_
- tools: `vol3_netscan`
- exec_ids: `ba879342060d`
- matched: `172.16.4.10`, `52.16.55.11`, `13.89.220.65`
- claim: > **[CONFIRMED]** External HTTPS connections from rd01 to **13.89.220.65:443** and **52.16.55.11:443** are the confirmed egress endpoints (both CLOSED state at capture time) [exec_id: 019e511e-1ab2-7d33…

### 🔍 not_confirmed _(line 225)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > The following MITRE ATT&CK techniques are **[CONFIRMED]** from tool output:
