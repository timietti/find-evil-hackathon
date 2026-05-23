# Validator Report — iter_2

## Summary

- Total tagged claims:        **43**
  - CONFIRMED:                 29
  - INFERRED:                  8
  - HYPOTHESIS:                0
  - GAP:                       6
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           6 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                7 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           5 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           11 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 20.7%** (6 verified / 29 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **5** (cost: $0.0135)
  - ✅ VERIFIED:    0 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 0 (downgraded to failed)
  - ❓ UNRELATED:   4 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   1 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### ⚠ partial _(line 36)_
- tools: `vol3_psscan`, `vol3_netscan`
- exec_ids: `123862491ae3`, `c2d4d19271d4`
- matched: `8260`, `172.16.6.11`, `172.16.4.10`, `p.exe`
- **missing**: `172.16.4.10:8080`
- claim: > **Primary host: rd01 (172.16.6.11)** — [CONFIRMED — exec_id `019e5654-5ff8-7493-bb86-123862491ae3`, exec_id `019e5655-4b6b-70b1-b5e1-c2d4d19271d4`] `p.exe` implant active as PID 8260 in rd01 psscan; r…

### ⚠ partial _(line 40)_
- tools: `vol3_psscan`, `vol3_netscan`
- exec_ids: `77da158ec13f`, `e02624a34df7`
- matched: `4072`, `172.16.4.5`, `2018-08-28T22:08:25Z`, `powershell.exe`, `WmiPrvSE.exe`
- **missing**: `2018-08-30T16:43:36Z`
- claim: > **Earlier-compromised host: file01 (172.16.4.5)** — [CONFIRMED — exec_id `019e5655-fb5f-7091-ab27-77da158ec13f`, exec_id `019e5656-28b7-7210-ab68-e02624a34df7`] `powershell.exe` (PID 4072, PPID 1196 =…

### ✅ verified _(line 44)_
- tools: `vol3_psscan`, `vol3_psscan`
- exec_ids: `123862491ae3`, `77da158ec13f`
- matched: `8712`, `2876`, `1196`, `4072`, `2018-08-30T16:43:36Z`, `2018-08-28T22:08:25Z`, `WmiPrvSE.exe`
- claim: > **Initial access vector: WMI-based remote execution** — [CONFIRMED — exec_id `019e5654-5ff8-7493-bb86-123862491ae3`, exec_id `019e5655-fb5f-7091-ab27-77da158ec13f`] On both hosts the execution chain o…

### ❓ unverifiable _(line 56)_
- exec_ids: `6ea44075a886`, `9ee5def89f53`, `f23388f4815e`, `123862491ae3`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim lists only execution IDs with no factual assertion about file system artifacts, while tsk_fls_list provides file enumeration statistics (counts by extension and directory) with no execution ID or process tracking fields.
- claim: > [CONFIRMED — exec_id `019e5659-8e9a-7051-99bf-6ea44075a886`, exec_id `019e565e-42b0-7fb0-aec0-9ee5def89f53`, exec_id `019e5656-cd0e-7041-97a2-f23388f4815e`, exec_id `019e5654-5ff8-7493-bb86-123862491a…

### ⚠ partial _(line 65)_
- tools: `vol3_netscan`
- exec_ids: `c2d4d19271d4`
- matched: `172.16.6.11`, `172.16.4.10`
- **missing**: `8260`, `5994`, `p.exe`, `cmd.exe`, `c:\windows\temp\perfmon\p.exe``, `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`, `c:\windows\temp\perfmon\p.exe`, `Windows/Temp/Perfmon/p.exe` (+1 more)
- claim: > - **Path:** `Windows/Temp/Perfmon/p.exe` (inode 5994, exec_id `019e5659-8e9a-7051-99bf-6ea44075a886`) - **SHA256:** `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`, size 164,352 byt…

### ✅ verified _(line 69)_
- tools: `vol3_psscan`
- exec_ids: `123862491ae3`
- matched: `8260`, `2018-09-06T17:26:32Z`, `2018-09-06T14:58:41Z`, `2018-09-05T12:01:32Z`, `p.exe`, `rundll32.exe`
- claim: > - **p.exe (PID 8260) spawned three `rundll32.exe` children:** PIDs 1424 (2018-09-06T14:58:41Z), 7552 (2018-09-06T17:26:32Z), 5768 (2018-09-05T12:01:32Z) — [CONFIRMED — exec_id `019e5654-5ff8-7493-bb86…

### ❓ unverifiable _(line 75)_
- exec_ids: `d8a508bb35e6`, `2582b941b492`, `77da158ec13f`, `e02624a34df7`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim asserts the presence of specific execution IDs (UUIDs), which are not file-system metadata tracked by tsk_fls_list; the tool only provides file counts, extensions, and directory distributions.
- claim: > [CONFIRMED — exec_id `019e565c-50ce-7cf2-98a8-d8a508bb35e6`, exec_id `019e565e-441a-7cf1-bd0c-2582b941b492`, exec_id `019e5655-fb5f-7091-ab27-77da158ec13f`, exec_id `019e5656-28b7-7210-ab68-e02624a34d…

### ⚠ partial _(line 81)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `6ea44075a886`, `d8a508bb35e6`
- matched: `113730`, `PerfSvc.exe`, `Windows/Temp/perfmon/PerfSvc.exe`
- **missing**: `e722dd429510c83485bb276c559015df9bd4931e7e4339eb90683cc3efd9beaa`, `\Temp\Perfmon\`
- claim: > - **Path:** `Windows/Temp/perfmon/PerfSvc.exe` (inode 113730, exec_id `019e565c-50ce-7cf2-98a8-d8a508bb35e6`) - **SHA256:** `e722dd429510c83485bb276c559015df9bd4931e7e4339eb90683cc3efd9beaa`, size 18,…

### ⚠ partial _(line 82)_
- tools: `vol3_netscan`
- exec_ids: `e02624a34df7`
- matched: `4072`, `3164`, `172.16.4.10`, `powershell.exe`
- **missing**: `172.16.4.10:8080`
- claim: > - **C2 behavior:** `powershell.exe` (PID 3164, parent of file01 implant chain) → `172.16.4.10:8080` CLOSE_WAIT; `powershell.exe` (PID 4072) → `172.16.4.10:8080` CLOSED — [CONFIRMED — exec_id `019e5656…

### ❓ unverifiable _(line 86)_
- exec_ids: `123862491ae3`, `f23388f4815e`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim references exec_id values that are UUIDs/identifiers not present in vol3_psscan output, which contains only process metadata (PID, image name, timestamps, parent PID) with no exec_id fields.
- claim: > [CONFIRMED — exec_id `019e5654-5ff8-7493-bb86-123862491ae3`, exec_id `019e5656-cd0e-7041-97a2-f23388f4815e`]

### ❓ unverifiable _(line 103)_
- exec_ids: `77da158ec13f`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim references an exec_id UUID, which is not a field present in vol3_psscan process scan data that contains only PIDs, process names, timestamps, and parent-child relationships.
- claim: > [CONFIRMED — exec_id `019e5655-fb5f-7091-ab27-77da158ec13f`]

### ✅ verified _(line 118)_
- tools: `vol3_malfind`
- exec_ids: `4fa6029110a4`
- matched: `8712`, `powershell.exe`
- claim: > - **Three RWX VAD regions in `powershell.exe` (PID 8712)** indicate in-memory shellcode staging — [CONFIRMED — exec_id `019e5656-d60f-70d0-be5f-4fa6029110a4`] VadS regions at start_vpn 1876063551488, …

### ⚠ partial _(line 124)_
- tools: `vol3_svcscan`, `vol3_netscan`, `vol3_netscan`
- exec_ids: `b1d9822aa1a6`, `c2d4d19271d4`, `e02624a34df7`
- matched: `6160`, `172.16.5.50`, `2018-09-06T18:28:32Z`, `subject_srv.exe`, `C:\windows\subject_srv.exe`, `"F-Response Subject"`
- **missing**: `172.16.5.50:44262`, ` (svcscan exec_id `
- claim: > `subject_srv.exe` = **F-Response Subject agent** — [CONFIRMED — exec_id `019e5658-e682-76b2-ab9d-b1d9822aa1a6`, exec_id `019e5655-4b6b-70b1-b5e1-c2d4d19271d4`, exec_id `019e5656-28b7-7210-ab68-e02624a…

### 🔍 not_confirmed _(line 126)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > > **Fixes claim [11]**: svcscan + rd01 netscan + file01 netscan cited; 172.16.5.50 token present in file01 netscan (subject_srv.ex connection to 172.16.5.50:44262). Mnemosyne.sys on DC is downgraded f…

### ❓ unverifiable _(line 132)_
- exec_ids: `c2d4d19271d4`, `e02624a34df7`, `123862491ae3`, `77da158ec13f`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim references multiple exec_ids and tool executions but makes no specific factual assertion about network connections, IPs, processes, or other testable elements; it only provides metadata labels for evidence sources.
- claim: > [CONFIRMED unless noted] Network evidence from exec_id `019e5655-4b6b-70b1-b5e1-c2d4d19271d4` (rd01 netscan) and exec_id `019e5656-28b7-7210-ab68-e02624a34df7` (file01 netscan); process evidence from …

### ✅ verified _(line 152)_
- tools: `vol3_psscan`
- exec_ids: `b0943da897a6`
- matched: `6628`, `1036`, `3380`, `908`, `2018-09-06T17:47:38Z`, `2018-09-06T22:53:58Z`, `2018-09-06T18:17:46Z`, `cmd.exe` (+5 more)
- claim: > **DC compromise confirmed** — [CONFIRMED — exec_id `019e565a-9d1c-79f3-b06d-b0943da897a6`] DC psscan shows `subject_srv.ex` in `by_image` (IR team acquisition confirmed) and `ManagementAgen` (PID 908 …

### ✅ verified _(line 162)_
- tools: `tsk_fls_list`
- exec_ids: `6ea44075a886`
- matched: `procdump.exe`, `tdungan`
- claim: > **`procdump.exe` on rd01** — [CONFIRMED — exec_id `019e5659-8e9a-7051-99bf-6ea44075a886`] Multiple versions found in user `tdungan`'s AppData under Dashlane browser extension sandboxes and Roaming pro…

### ✅ verified _(line 187)_
- tools: `vol3_psscan`
- exec_ids: `77da158ec13f`
- matched: `2524`, `2018-09-05T14:43:11Z`, `2018-09-05T14:52:56Z`, `Rar.exe`
- claim: > **`Rar.exe` on file01** — [CONFIRMED — exec_id `019e5655-fb5f-7091-ab27-77da158ec13f`] PID 2524, PPID 6352 (parent exited before capture), start **2018-09-05T14:43:11Z**, exit **2018-09-05T14:52:56Z**…

### ⚠ partial _(line 193)_
- tools: `vol3_netscan`, `vol3_netscan`
- exec_ids: `c2d4d19271d4`, `e02624a34df7`
- matched: `172.16.4.10`, `52.16.55.11`, `13.89.220.65`
- **missing**: `172.16.4.10:8080`, `13.89.220.65:443`
- claim: > **C2 exfiltration channels** — [CONFIRMED — exec_id `019e5655-4b6b-70b1-b5e1-c2d4d19271d4`, exec_id `019e5656-28b7-7210-ab68-e02624a34df7`]: - rd01 → `13.89.220.65:443` (Microsoft Azure — external C2/…

### 🔍 not_confirmed _(line 246)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | TTP | Tag | Evidence | exec_id(s) | |-----|-----|----------|------------| | **T1047 — WMI** | [CONFIRMED]

### 🔍 not_confirmed _(line 248)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | Persistence via WMI subscription (Session 0 WMI spawns without interactive session) | `019e5654-5ff8-7493-bb86-123862491ae3`, `019e5655-fb5f-7091-ab27-77da158ec13f` | | **T1059.001 — PowerShell** | …

### 🔍 not_confirmed _(line 249)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | Multi-stage PS chain; PID 5848 args `-Version 5.1 -s -NoLogo -NoProfile` (stdin mode, no logging) | `019e5656-cd0e-7041-97a2-f23388f4815e`, `019e5654-5ff8-7493-bb86-123862491ae3` | | **T1218.011 — R…

### 🔍 not_confirmed _(line 250)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | ≥28 rundll32.exe spawns from implant PS chain on file01; 3 from p.exe on rd01 | `019e5655-fb5f-7091-ab27-77da158ec13f`, `019e5654-5ff8-7493-bb86-123862491ae3` | | **T1003.001 — LSASS dump via ProcDu…

### 🔍 not_confirmed _(line 251)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | procdump.exe in 9 locations under tdungan's AppData on rd01 | `019e5659-8e9a-7051-99bf-6ea44075a886` | | **T1560.001 — Archive via RAR** | [CONFIRMED]

### 🔍 not_confirmed _(line 252)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | Rar.exe (PID 2524) ran 9 min 45 sec on file01 2018-09-05T14:43:11Z–14:52:56Z | `019e5655-fb5f-7091-ab27-77da158ec13f` | | **T1071.001 — Web Protocols C2** | [CONFIRMED]

### 🔍 not_confirmed _(line 254)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | C2 through internal 172.16.4.10:8080 (not internet-facing services subnet) | `019e5655-4b6b-70b1-b5e1-c2d4d19271d4`, `019e5656-28b7-7210-ab68-e02624a34df7` | | **T1036.005 — Masquerading** | [CONFIR…

### 🔍 not_confirmed _(line 255)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | Both implants in `\Temp\Perfmon\` (p.exe, PerfSvc.exe) mimicking perf tools | `019e5659-8e9a-7051-99bf-6ea44075a886`, `019e565c-50ce-7cf2-98a8-d8a508bb35e6` | | **T1070 — Anti-forensics (Uninstall.e…

### 🔍 not_confirmed _(line 256)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | Uninstall.exe (PID 2340) → 172.16.7.12:135 RPC — host cleanup/uninstall operation | `019e5655-fb5f-7091-ab27-77da158ec13f`, `019e5656-28b7-7210-ab68-e02624a34df7` | | **T1021.001 — RDP lateral** | […

### 🔍 not_confirmed _(line 257)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | rd01 → file01:3389 CLOSED; file01 → rd01 3389 (inbound from 172.16.6.14) | `019e5655-4b6b-70b1-b5e1-c2d4d19271d4`, `019e5656-28b7-7210-ab68-e02624a34df7` | | **T1021.002 — SMB lateral** | [CONFIRMED…
