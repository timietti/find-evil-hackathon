# Validator Report — iter_1

## Summary

- Total tagged claims:        **56**
  - CONFIRMED:                 42
  - INFERRED:                  9
  - HYPOTHESIS:                2
  - GAP:                       3
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           22 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                14 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           2 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           2 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 52.4%** (22 verified / 42 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **4** (cost: $0.0080)
  - ✅ VERIFIED:    1 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 1 (downgraded to failed)
  - ❓ UNRELATED:   1 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   1 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### ⚠ partial _(line 95)_
- tools: `vol3_netscan`
- exec_ids: `849d9fd58cba`
- matched: `52.16.55.11`, `13.89.220.65`, `172.16.4.10`
- **missing**: `2018-09-06T18:57:17Z`, `13.89.220.65:443`, `52.16.55.11:443`
- claim: > [CONFIRMED] rd01 shows the earliest confirmed external C2 connectivity in the RD subnet. At time of memory capture (2018-09-06T18:57:17Z), rd01 held 3 ESTABLISHED and 11 CLOSE_WAIT/CLOSED connections …

### ✅ verified _(line 97)_
- tools: `vol3_malfind`
- exec_ids: `05e521831779`
- matched: `8128`, `OUTLOOK.EXE`
- claim: > [CONFIRMED] OUTLOOK.EXE (PID 8128, session 1) was running on rd01 and has **two private RWX VAD regions** (commit_charge 16 each), consistent with injected shellcode or a malicious macro payload (vol3…

### ✅ verified _(line 101)_
- tools: `vol3_psscan`
- exec_ids: `6164161615fd`
- matched: `8712`, `2876`, `2018-08-30T16:43:36Z`, `WmiPrvSE.exe`, `powershell.exe`
- claim: > [CONFIRMED] The WMI execution chain on rd01: **WmiPrvSE.exe (PID 2876, ppid 2876's parent is svchost) → powershell.exe (PID 8712, 64-bit, created 2018-08-30T16:43:36Z)** (vol3_psscan exec_id=019e1372-…

### ⚠ partial _(line 111)_
- tools: `vol3_cmdline`, `tsk_icat_extract`
- exec_ids: `4346fa6683af`, `1e08077ba0a3`
- matched: `8260`, `5994`, `p.exe`, `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`, `c:\windows\temp\perfmon\p.exe`
- **missing**: `c:\windows\temp\perfmon\p.exe``
- claim: > [CONFIRMED] **p.exe** at `c:\windows\temp\perfmon\p.exe` (on-disk inode 5994, size 160,352 bytes, SHA256 `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`) running as PID 8260, sessio…

### ⚠ partial _(line 113)_
- tools: `vol3_cmdline`, `vol3_psscan`
- exec_ids: `4346fa6683af`, `6164161615fd`
- matched: `WmiPrvSE.exe`, `cmd.exe`, `p.exe`, `powershell.exe`, `/C c:\windows\temp\perfmon\p.exe`, `-Version 5.1 -s -NoLogo -NoProfile`
- **missing**: `c:\windows\temp\perfmon\p.exe`)`
- claim: > [CONFIRMED] Execution chain: **WmiPrvSE.exe (2876) → powershell.exe (8712, 64-bit) → powershell.exe (5848, WOW64, args=`-Version 5.1 -s -NoLogo -NoProfile`) → cmd.exe (5948, args=`/C c:\windows\temp\p…

### ✅ verified _(line 115)_
- tools: `vol3_malfind`
- exec_ids: `05e521831779`
- matched: `p.exe`
- claim: > [CONFIRMED] p.exe has a **2MB RWX private VAD region** (commit_charge=481 pages) — shellcode or reflective DLL hosting (vol3_malfind exec_id=019e1375-53b0-7843-97a5-05e521831779).

### ⚠ partial _(line 117)_
- tools: `vol3_dlllist`
- exec_ids: `2c0e04fc2922`
- matched: `WS2_32.dll`, `p.exe`, `DNSAPI.dll`, `bcrypt.dll`, `Secur32.dll`, `WININET.dll`
- **missing**: `SSPI/Secur32.dll`
- claim: > [CONFIRMED] p.exe loaded DLLs include `WININET.dll`, `WS2_32.dll`, `DNSAPI.dll`, `SSPI/Secur32.dll`, `bcrypt.dll` — HTTP-capable, DNS-aware, credential-capable network implant (vol3_dlllist exec_id=01…

### ⚠ partial _(line 119)_
- tools: `vol3_handles`
- exec_ids: `40a3dd5a244a`
- matched: `p.exe`, `\Device\NamedPipe\fhsvc-b378`
- **missing**: `\Device\NamedPipe\fhsvc-b378``
- claim: > [CONFIRMED] p.exe holds `\Device\NamedPipe\fhsvc-b378` — a named pipe consistent with **Cobalt Strike post-exploitation pipe naming** (vol3_handles exec_id=019e1378-f993-7922-8ea7-40a3dd5a244a).

### ✅ verified _(line 121)_
- tools: `vol3_psscan`
- exec_ids: `6164161615fd`
- matched: `5848`, `powershell.exe`, `rundll32.exe`
- claim: > [CONFIRMED] 9 rundll32.exe processes (all exited), all spawned by powershell.exe (PID 5848), acting as short-lived beacon tasks across multiple days (2018-08-30 through 2018-09-06) (vol3_psscan exec_i…

### ❌ failed _(line 125)_
- exec_ids: `f09f9fbc2cd5`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNSUPPORTED** — The parsed svcscan data contains only aggregate counts and state distributions with no granular service details (binary paths, service names, or locations) needed to verify the specific claim that no services have binaries in Temp or AppData.
- claim: > [CONFIRMED] No service-based persistence found: svcscan returned no services with binaries in Temp or AppData (vol3_svcscan exec_id=019e1376-e3cb-7461-94a5-f09f9fbc2cd5).

### ⚠ partial _(line 129)_
- tools: `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `31b6aa7fa0f9`, `ed9ca35c7518`
- matched: `113730`, `PerfSvc.exe`, `e722dd429510c83485bb276c559015df9bd4931e7e4339eb90683cc3efd9beaa`
- **missing**: `\Windows\Temp\perfmon\``, `c:\windows\temp\perfmon\PerfSvc.exe``, `c:\windows\temp\perfmon\PerfSvc.exe`, `\Windows\Temp\perfmon\`
- claim: > [CONFIRMED] **PerfSvc.exe** at `c:\windows\temp\perfmon\PerfSvc.exe` (inode 113730, size 18,944 bytes, SHA256 `e722dd429510c83485bb276c559015df9bd4931e7e4339eb90683cc3efd9beaa`) — same `\Windows\Temp\…

### ✅ verified _(line 131)_
- tools: `vol3_psscan`
- exec_ids: `c543e93a5ba7`
- matched: `3164`, `1196`, `4072`, `2018-08-28T22:08:26Z`, `2018-08-28T22:08:25Z`, `2018-08-30T01:46Z`, `rundll32.exe`, `WmiPrvSE.exe` (+1 more)
- claim: > [CONFIRMED] Identical WMI→PS chain: **WmiPrvSE.exe (PID 1196, ppid 600/svchost) → powershell.exe (PID 4072, 64-bit, 2018-08-28T22:08:25Z) → powershell.exe (PID 3164, WOW64, 2018-08-28T22:08:26Z)** → 2…

### ✅ verified _(line 133)_
- tools: `vol3_netscan`
- exec_ids: `c2657c847d24`
- matched: `3164`, `172.16.4.10`, `powershell.exe`
- claim: > [CONFIRMED] powershell.exe (PID 3164) had CLOSE_WAIT to 172.16.4.10:8080 — same C2 relay as rd01 (vol3_netscan exec_id=019e137e-1df0-74b3-8e18-c2657c847d24).

### ❌ failed _(line 137)_
- tools: `vol3_handles`, `vol3_psscan`
- exec_ids: `4391ff217ea7`, `4f65466c1d5d`
- **missing**: `\Device\NamedPipe\fhsvc-b378``
- 🚨 negation violations (claimed absent but found): `15116`, `15896`, `p.exe`, `rundll32.exe`, `\Device\NamedPipe\fhsvc-b378`
- claim: > [CONFIRMED] **rundll32.exe (PID 15116)** with no arguments, orphaned parent (PID 15896 not in process list), holds `\Device\NamedPipe\fhsvc-b378` — **the same named pipe as p.exe on rd01**, confirming…

### 🔍 not_confirmed _(line 145)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > [CONFIRMED] The following lateral movement paths are established from memory-resident network state:

### ✅ verified _(line 163)_
- tools: `vol3_psscan`
- exec_ids: `aad1927eab3f`
- matched: `cmd.exe`, `tasklist.exe`
- claim: > [CONFIRMED] Confirmed compromised hosts: **rd01, file01, exchange01, DC** (DC shows attacker cmd.exe/tasklist.exe execution at session 0, vol3_psscan exec_id=019e1372-f51a-7ba3-9b97-aad1927eab3f).

### ✅ verified _(line 167)_
- tools: `vol3_netscan`, `vol3_netscan`
- exec_ids: `849d9fd58cba`, `c2657c847d24`
- matched: `172.16.4.10`
- claim: > [CONFIRMED] C2 relay via proxy01 (172.16.4.10:8080): both rd01 and file01 connect through this internal host to reach external C2 infrastructure (vol3_netscan exec_ids 019e1372-d58b-7042-bfd9-849d9fd5…

### ✅ verified _(line 173)_
- tools: `vol3_dlllist`
- exec_ids: `2c0e04fc2922`
- matched: `Secur32.dll`, `p.exe`, `SSPICLI.DLL`
- claim: > [CONFIRMED] p.exe (rd01) loads `Secur32.dll`, `SSPICLI.DLL` — SSPI credential APIs directly accessible from the implant (vol3_dlllist exec_id=019e1377-1dc0-7e50-9a55-2c0e04fc2922).

### ✅ verified _(line 175)_
- tools: `vol3_malfind`
- exec_ids: `05e521831779`
- matched: `8128`, `OUTLOOK.EXE`
- claim: > [CONFIRMED] OUTLOOK.EXE (PID 8128, rd01) has 2 RWX private VAD injection regions — implanted code running inside the Outlook process, with access to user credentials stored in the Outlook profile (vol…

### ⚠ partial _(line 177)_
- tools: `vol3_psscan`
- exec_ids: `aad1927eab3f`
- matched: `7612`, `8492`, `2018-09-01T18:18:19Z`, `2018-09-06T17:57:41Z`, `tasklist.exe`, `findstr.exe`
- **missing**: `172.16.4.4`
- claim: > [CONFIRMED] DC (172.16.4.4) psscan shows **tasklist.exe** (PID 7612, exited 2018-09-06T17:57:41Z) and **findstr.exe** (PID 8492, exited 2018-09-01T18:18:19Z) — attacker enumeration tools run on the do…

### ⚠ partial _(line 179)_
- tools: `vol3_psscan`
- exec_ids: `aad1927eab3f`
- matched: `6628`, `908`, `2018-09-06T22:53:58Z`, `cmd.exe`
- **missing**: `sub-cmd.exe`
- claim: > [CONFIRMED] DC psscan shows **cmd.exe** (PID 6628) spawned by ManagementAgentHost (PID 908) at 2018-09-06T22:53:58Z with multiple sub-cmd.exe children (PIDs 9012, 7260, 8220) — unexpected parent-child…

### ✅ verified _(line 181)_
- tools: `vol3_netscan`
- exec_ids: `c2657c847d24`
- matched: `544`, `lsass.exe`
- claim: > [CONFIRMED] File server lsass.exe (PID 544) has connections to DC on ports 49670, 389, 135 — attacker-controlled processes authenticated to the DC using domain credentials (vol3_netscan exec_id=019e13…

### ⚠ partial _(line 191)_
- tools: `vol3_psscan`
- exec_ids: `c543e93a5ba7`
- matched: `2524`, `2018-09-05T14:52:56Z`, `2018-09-05T14:43:11Z`, `Rar.exe`
- 🚨 negation violations (claimed absent but found): `6352`
- claim: > [CONFIRMED] **Rar.exe (PID 2524)** ran on file01 from **2018-09-05T14:43:11Z to 2018-09-05T14:52:56Z** (~9 minutes) — active data archiving operation. Parent PID 6352 not found in scan (exited prior) …

### ⚠ partial _(line 193)_
- tools: `tsk_fls_list`
- exec_ids: `ed9ca35c7518`
- ✅ verified absences (negated): `Rar.exe`
- 🚨 negation violations (claimed absent but found): `.rar`
- claim: > [CONFIRMED] No `.rar` files present on the file server C: drive after Rar.exe completed — archives were either exfiltrated immediately to a network location or written to a share not captured in the e…

### ⚠ partial _(line 195)_
- tools: `tsk_fls_list`
- exec_ids: `ed9ca35c7518`
- matched: `Shares/`
- **missing**: `Rar.exe`
- claim: > [CONFIRMED] file01 hosts a `Shares/` directory containing corporate software installers, Office 2016 packages, and potentially sensitive configuration data (tsk_fls_list exec_id=019e1380-543d-7182-b5e…

### ✅ verified _(line 197)_
- tools: `vol3_netscan`
- exec_ids: `849d9fd58cba`
- matched: `172.16.4.10`
- claim: > [CONFIRMED] rd01 maintained **3 simultaneous ESTABLISHED connections** to C2 relay 172.16.4.10:8080 at memory capture — indicative of active data transfer in progress (vol3_netscan exec_id=019e1372-d5…

### ⚠ partial _(line 199)_
- tools: `vol3_netscan`
- exec_ids: `849d9fd58cba`
- matched: `52.16.55.11`, `13.89.220.65`
- **missing**: `13.89.220.65:443`, `52.16.55.11:443`
- claim: > [CONFIRMED] Historical HTTPS connections from rd01 to `13.89.220.65:443` (Azure US) and `52.16.55.11:443` (AWS Ireland) — prior exfiltration or C2 sessions to cloud-hosted infrastructure (vol3_netscan…

### ✅ verified _(line 201)_
- tools: `vol3_dlllist`
- exec_ids: `2c0e04fc2922`
- matched: `p.exe`, `WININET.dll`
- claim: > [CONFIRMED] p.exe uses `WININET.dll` for HTTP/HTTPS — capable of direct data exfiltration over encrypted channels (vol3_dlllist exec_id=019e1377-1dc0-7e50-9a55-2c0e04fc2922).

### 🔍 not_confirmed _(line 241)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > Evidence for Cobalt Strike attribution: - [CONFIRMED]

### ⚠ partial _(line 242)_
- tools: `vol3_handles`, `vol3_handles`
- exec_ids: `40a3dd5a244a`, `4391ff217ea7`
- matched: `p.exe`, `rundll32.exe`, `fhsvc-b378`
- **missing**: `<svcname>-<hexrandom>`
- claim: > Named pipe `fhsvc-b378` present on both rd01 (p.exe) and exchange01 (rundll32.exe) — the naming pattern `<svcname>-<hexrandom>` matches Cobalt Strike's default post-exploitation pipe naming convention…

### ✅ verified _(line 243)_
- tools: `vol3_cmdline`
- exec_ids: `4346fa6683af`
- matched: `-s -NoLogo -NoProfile`
- claim: > 32-bit WOW64 PowerShell staging (`-s -NoLogo -NoProfile`) is the canonical Cobalt Strike PowerShell spawn technique (vol3_cmdline exec_id=019e1374-3eba-7711-b85b-4346fa6683af). - [CONFIRMED]

### ⚠ partial _(line 244)_
- tools: `vol3_psscan`
- exec_ids: `6164161615fd`
- matched: `rundll32.exe`
- **missing**: `jump`, `execute-assembly`
- claim: > Multiple short-lived rundll32.exe processes spawned by the 32-bit PowerShell — consistent with Cobalt Strike `execute-assembly` or `jump` lateral movement tasks (vol3_psscan exec_id=019e1372-401b-7322…

### ✅ verified _(line 245)_
- tools: `vol3_dlllist`
- exec_ids: `2c0e04fc2922`
- matched: `p.exe`, `WININET.dll`
- claim: > p.exe uses WININET.dll for HTTP C2 — consistent with Cobalt Strike Beacon's HTTP profile (vol3_dlllist exec_id=019e1377-1dc0-7e50-9a55-2c0e04fc2922). - [CONFIRMED]

### ✅ verified _(line 246)_
- tools: `vol3_netscan`
- exec_ids: `849d9fd58cba`
- matched: `172.16.4.10`
- claim: > C2 through internal proxy (172.16.4.10:8080) masking external traffic — consistent with Cobalt Strike malleable C2 profile routing through a redirector (vol3_netscan exec_id=019e1372-d58b-7042-bfd9-84…

### ✅ verified _(line 253)_
- tools: `vol3_malfind`
- exec_ids: `19e1375-53b0`
- matched: `OUTLOOK.EXE`
- claim: > | OUTLOOK.EXE RWX injection, vol3_malfind 019e1375-53b0 | | WMI execution | T1047 | [CONFIRMED]

### ❓ unverifiable _(line 254)_
- exec_ids: `19e1372-401b`, `19e137c-d313`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim asserts that PowerShell (T1059.001) is related to WmiPrvSE, but the vol3_psscan data shows WmiPrvSE.exe and WmiApSrv.exe processes with no PowerShell process present in the exited process list, making the tool output fundamentally irrelevant to establishing a causal relationship between Wm
- claim: > | WmiPrvSE→PS on rd01+file01, vol3_psscan 019e1372-401b, 019e137c-d313 | | PowerShell | T1059.001 | [CONFIRMED]

### ❓ unverifiable _(line 255)_
- exec_ids: `19e1374-3eba`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The parsed data only provides a count (129) with no command-line details, process names, paths, or masquerading indicators needed to verify the specific claim about 64→32-bit PS chain, perfmon masquerading, or the cited process ID.
- claim: > | 64→32-bit PS chain, vol3_cmdline 019e1374-3eba | | Masquerading (Temp\perfmon) | T1036.004 | [CONFIRMED]

### ✅ verified _(line 256)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `19e1377-76d0`, `19e1380-543d`
- matched: `p.exe`, `PerfSvc.exe`
- claim: > | p.exe/PerfSvc.exe staging path, tsk_fls_list 019e1377-76d0, 019e1380-543d | | Process injection | T1055 | [CONFIRMED]

### ✅ verified _(line 257)_
- tools: `vol3_malfind`
- exec_ids: `19e1375-53b0`
- matched: `p.exe`
- claim: > | 2MB RWX private VAD in p.exe+OUTLOOK, vol3_malfind 019e1375-53b0 | | SMB lateral movement | T1021.002 | [CONFIRMED]

### ✅ verified _(line 259)_
- tools: `vol3_netscan`
- exec_ids: `19e1372-d58b`
- matched: `172.16.4.10`
- claim: > | 172.16.4.10:8080 as C2 relay, vol3_netscan 019e1372-d58b | | HTTPS C2 | T1071.001 | [CONFIRMED]

### ✅ verified _(line 260)_
- tools: `vol3_netscan`
- exec_ids: `19e1372-d58b`
- matched: `52.16.55.11`, `13.89.220.65`
- claim: > | 13.89.220.65:443, 52.16.55.11:443, vol3_netscan 019e1372-d58b | | Named pipe C2 (Cobalt Strike) | T1572 | [CONFIRMED]

### ✅ verified _(line 261)_
- exec_ids: `19e1378-f993`, `19e137c-eee6`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed data from vol3_handles contains two explicit references to the named pipe '\Device\NamedPipe\fhsvc-b378' in the file_handles_top list, which directly supports the claim's assertion about this handle identifier being present in the tool's output.
- claim: > | fhsvc-b378, vol3_handles 019e1378-f993, 019e137c-eee6 | | Archive for exfil | T1560.001 | [CONFIRMED]
