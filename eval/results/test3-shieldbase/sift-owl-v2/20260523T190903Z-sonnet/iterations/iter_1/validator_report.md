# Validator Report — iter_1

## Summary

- Total tagged claims:        **40**
  - CONFIRMED:                 26
  - INFERRED:                  9
  - HYPOTHESIS:                0
  - GAP:                       5
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           2 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                7 (some tokens found, some missing)
- ❌ failed:                 3 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           14 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 7.7%** (2 verified / 26 confirmed)

## Per-claim verdicts

### ⚠ partial _(line 64)_
- tools: `vol3_psscan`
- exec_ids: `629158db8679`
- matched: `p.exe`
- **missing**: `172.16.6.11`
- claim: > **Primary host: rd01 (172.16.6.11)** — [CONFIRMED] `p.exe` implant active in memory (exec_id `019e563e-23a4-7053-a243-629158db8679`), WMI-spawned PowerShell chain, and direct C2 connections all observ…

### ⚠ partial _(line 66)_
- tools: `vol3_psscan`
- exec_ids: `4fd90ebd2ea4`
- matched: `4072`, `2018-08-28T22:08:25Z`, `powershell.exe`, `WmiPrvSE.exe`
- **missing**: `172.16.4.5`, `2018-08-30T16:43:36Z`
- claim: > **Earlier-compromised host: file01 (172.16.4.5)** — [CONFIRMED] `powershell.exe` (PID 4072, PPID 1196 = `WmiPrvSE.exe`) has been running since **2018-08-28T22:08:25Z**, two days before rd01's first ma…

### 🔍 not_confirmed _(line 68)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **Initial access vector: WMI-based remote execution** — [CONFIRMED]

### ⚠ partial _(line 80)_
- tools: `tsk_fls_list`, `tsk_icat_extract`, `vol3_cmdline`
- exec_ids: `06a75ce6a645`, `c6b4de000c6c`, `f3f054e102d6`
- matched: `8260`, `5994`, `p.exe`, `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`, `VadS`, `c:\windows\temp\perfmon\p.exe`, `C:\Windows\Temp\Perfmon\p.exe`
- **missing**: `\Windows\Temp\Perfmon\p.exe``, `c:\windows\temp\perfmon\p.exe``, `C:\Windows\Temp\Perfmon\p.exe``, `wow64=false`
- claim: > ### Implant 1: `p.exe` on rd01 - **Path:** `C:\Windows\Temp\Perfmon\p.exe` (inode 5994, exec_id `019e5643-8479-76a0-adbe-06a75ce6a645`)   - **SHA256:** `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df…

### ❌ failed _(line 81)_
- tools: `vol3_malfind`
- exec_ids: `a741f5f7e254`
- **missing**: `172.16.4.10`, `172.16.4.10:8080`
- claim: > (exec_id `019e5646-47a5-7952-ad94-a741f5f7e254`)   - **C2 behavior:** 14 connections to `172.16.4.10:8080` (ESTABLISHED + CLOSE_WAIT) — internal C2 relay beacon pattern [CONFIRMED]

### ❌ failed _(line 82)_
- tools: `vol3_netscan`
- exec_ids: `0ead9bcd4b14`
- **missing**: `p.exe`, `rundll32.exe`
- claim: > (exec_id `019e563f-736c-7cb0-818c-0ead9bcd4b14`)   - `p.exe` spawned multiple `rundll32.exe` children: PIDs 1424, 7552, 5768 [CONFIRMED]

### ⚠ partial _(line 89)_
- tools: `tsk_fls_list`, `tsk_icat_extract`, `vol3_netscan`
- exec_ids: `168563e0736f`, `84b261f04f09`, `d3b9bff2b7ed`
- matched: `3164`, `113730`, `172.16.4.10`, `powershell.exe`, `p.exe`, `PerfSvc.exe`, `e722dd429510c83485bb276c559015df9bd4931e7e4339eb90683cc3efd9beaa`
- **missing**: `\Windows\Temp\Perfmon\PerfSvc.exe``, `C:\Windows\Temp\Perfmon\PerfSvc.exe``, `172.16.4.10:8080`, `C:\Windows\Temp\Perfmon\PerfSvc.exe`, `\Temp\Perfmon\`
- claim: > ### Implant 2: `PerfSvc.exe` on file01 - **Path:** `C:\Windows\Temp\Perfmon\PerfSvc.exe` (inode 113730, exec_id `019e564e-4737-72d2-8acb-168563e0736f`)   - **SHA256:** `e722dd429510c83485bb276c559015d…

### ⚠ partial _(line 92)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `629158db8679`, `f3f054e102d6`
- matched: `8712`, `5848`, `2876`, `8260`, `7552`, `1424`, `5768`, `5948` (+11 more)
- **missing**: `c:\windows\temp\perfmon\p.exe,`, `019e5642-27fd-7543-9134-f3f054e102d6`
- claim: > ### Execution Chain — rd01 [CONFIRMED] (exec_ids `019e563e-23a4-7053-a243-629158db8679`, `019e5642-27fd-7543-9134-f3f054e102d6`): ``` WmiPrvSE.exe (PID 2876, PPID 868)   └─ powershell.exe (PID 8712, n…

### ✅ verified _(line 105)_
- tools: `vol3_psscan`
- exec_ids: `4fd90ebd2ea4`
- matched: `3164`, `4072`, `1196`, `2018-08-28T22:08:25Z`, `2018-08-28T22:08:26Z`, `2018-08-08T18:08:06Z`, `powershell.exe`, `rundll32.exe` (+1 more)
- claim: > ### Execution Chain — file01 [CONFIRMED] (exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4`): ``` WmiPrvSE.exe (PID 1196, PPID 600, since 2018-08-08T18:08:06Z)   └─ powershell.exe (PID 4072, PPID 1196, 2…

### 🔍 not_confirmed _(line 115)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > on disk-based scheduled task persistence. - **Three RWX VAD regions** in `powershell.exe` (PID 8712) in addition to the p.exe region indicate in-memory shellcode [CONFIRMED]

### ⚠ partial _(line 118)_
- tools: `vol3_svcscan`, `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `d3e262cb2754`, `c41f340dbb25`, `a8199fa1cc17`
- matched: `Mnemosyne.sys`, `subject_srv.exe`, `C:\windows\subject_srv.exe`, `"F-Response Subject"`
- **missing**: `172.16.5.50`, `) and rd01 (exec_id `, ` (172.16.5.50). `, ` is the legitimate F-Response memory driver found on DC (exec_id `, `). Deployed by IR team to mount rd01 and file01 disks/memory to `, ` (exec_id `
- claim: > ### Legitimate IR Tooling (NOT Malware) - `subject_srv.exe` = **F-Response Subject agent** [CONFIRMED] — Service registered as `"F-Response Subject"`, binary path `C:\windows\subject_srv.exe -s "base-…

### ❌ failed _(line 124)_
- tools: `vol3_netscan`
- exec_ids: `0ead9bcd4b14`
- **missing**: `019e564c-ead0-7a70-b0c4-d3b9bff2b7ed`
- claim: > [CONFIRMED unless noted] All network evidence from exec_ids `019e563f-736c-7cb0-818c-0ead9bcd4b14` (rd01 netscan) and `019e564c-ead0-7a70-b0c4-d3b9bff2b7ed` (file01 netscan):

### 🔍 not_confirmed _(line 141)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **DC compromise confirmed:** [CONFIRMED]

### ✅ verified _(line 149)_
- tools: `tsk_fls_list`
- exec_ids: `06a75ce6a645`
- matched: `procdump.exe`, `windows_ie_ac_001`, `tdungan`
- claim: > **`procdump.exe` on rd01** [CONFIRMED]: Two versions found in user `tdungan`'s AppData under the Dashlane browser extension sandbox (`windows_ie_ac_001`): - `Users/tdungan/AppData/Local/Packages/windo…

### 🔍 not_confirmed _(line 158)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **Local accounts on rd01** [CONFIRMED]

### 🔍 not_confirmed _(line 166)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **`Rar.exe` on file01** [CONFIRMED]

### ⚠ partial _(line 172)_
- tools: `vol3_netscan`
- exec_ids: `0ead9bcd4b14`
- matched: `172.16.4.10`, `13.89.220.65`, `52.16.55.11`
- **missing**: `172.16.4.10:8080`, `13.89.220.65:443`
- claim: > **C2 exfiltration channels** [CONFIRMED]: - rd01 → `13.89.220.65:443` (Microsoft Azure — external C2/exfil) (exec_id `019e563f-736c-7cb0-818c-0ead9bcd4b14`) - rd01 → `52.16.55.11` (external IP, port u…

### 🔍 not_confirmed _(line 222)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | TTP | Evidence | |-----|----------| | **T1047 — WMI** | WmiPrvSE → PowerShell on both file01 and rd01 [CONFIRMED]

### 🔍 not_confirmed _(line 224)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | **T1059.001 — PowerShell** | Multi-stage PS chain; `-s -NoLogo -NoProfile` (stdin mode, no logging) [CONFIRMED]

### 🔍 not_confirmed _(line 225)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | **T1218.011 — Rundll32 LOLBin** | ≥28 `rundll32.exe` spawns from implant processes across two hosts [CONFIRMED]

### 🔍 not_confirmed _(line 226)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | **T1003.001 — LSASS dump via ProcDump** | `procdump.exe` staged in user sandbox on rd01 [CONFIRMED]

### 🔍 not_confirmed _(line 227)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | **T1560.001 — Archive via RAR** | `Rar.exe` ran 9 min 45 sec on file01 [CONFIRMED]

### 🔍 not_confirmed _(line 228)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | **T1071.001 — Web Protocols C2** | Beacon to 172.16.4.10:8080 from both hosts; external to 13.89.220.65:443 [CONFIRMED]

### 🔍 not_confirmed _(line 230)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | **T1036.005 — Masquerading** | Implants named `p.exe`/`PerfSvc.exe` in `\Temp\Perfmon\` [CONFIRMED]

### 🔍 not_confirmed _(line 231)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | **T1070 — Anti-forensics** | `Uninstall.exe` → workstation RPC; `SDELETE.EXE` prefetch (ran 2018-05-14) [CONFIRMED/INFERRED]

### 🔍 not_confirmed _(line 232)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | **T1021.001/.002 — RDP/SMB lateral** | rd01 → file01:3389; file01 → wkstn/RD-servers via SMB [CONFIRMED]
