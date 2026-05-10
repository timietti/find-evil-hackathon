# Validator Report — iter_3

## Summary

- Total tagged claims:        **58**
  - CONFIRMED:                 42
  - INFERRED:                  11
  - HYPOTHESIS:                2
  - GAP:                       3
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           30 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                2 (some tokens found, some missing)
- ❌ failed:                 5 (no tokens found)
- ❓ unverifiable:           5 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 71.4%** (30 verified / 42 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **9** (cost: $0.0176)
  - ✅ VERIFIED:    0 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 4 (downgraded to failed)
  - ❓ UNRELATED:   2 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   3 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### ✅ verified _(line 30)_
- tools: `vol3_netscan`
- exec_ids: `849d9fd58cba`
- matched: `172.16.4.10`, `13.89.220.65`, `52.16.55.11`
- claim: > [CONFIRMED — exec_id=019e1372-d58b-7042-bfd9-849d9fd58cba] rd01 held 14 total connections to 172.16.4.10:8080 (internal C2 relay): 3 ESTABLISHED (ports 49786, 49787, 49788), 8 CLOSE_WAIT, and 3 CLOSED…

### ✅ verified _(line 32)_
- tools: `vol3_malfind`, `vol3_psscan`
- exec_ids: `05e521831779`, `6164161615fd`
- matched: `8128`, `2018-08-30T13:54:05Z`, `OUTLOOK.EXE`
- claim: > [CONFIRMED — exec_id=019e1375-53b0-7843-97a5-05e521831779, exec_id=019e1372-401b-7322-918d-6164161615fd] OUTLOOK.EXE (PID 8128, session 1, WOW64, created 2018-08-30T13:54:05Z) was running on rd01 and …

### ✅ verified _(line 36)_
- tools: `vol3_psscan`
- exec_ids: `6164161615fd`
- matched: `5848`, `8712`, `2876`, `2018-08-30T16:43:36Z`, `2018-08-30T16:43:42Z`, `2018-08-30T13:52:26Z`, `powershell.exe`, `WmiPrvSE.exe`
- claim: > [CONFIRMED — exec_id=019e1372-401b-7322-918d-6164161615fd] The WMI execution chain on rd01: WmiPrvSE.exe (PID 2876, ppid 868, created 2018-08-30T13:52:26Z) spawned powershell.exe (PID 8712, 64-bit, pp…

### ✅ verified _(line 46)_
- tools: `vol3_cmdline`, `vol3_psscan`
- exec_ids: `4346fa6683af`, `6164161615fd`
- matched: `8260`, `2018-08-30T22:15:18Z`, `p.exe`, `c:\windows\temp\perfmon\p.exe`
- claim: > [CONFIRMED — exec_id=019e1374-3eba-7711-b85b-4346fa6683af, exec_id=019e1372-401b-7322-918d-6164161615fd] p.exe at c:\windows\temp\perfmon\p.exe running as PID 8260 (session 0, 64-bit, ppid 5948, creat…

### ⚠ partial _(line 48)_
- tools: `vol3_cmdline`, `vol3_psscan`
- exec_ids: `4346fa6683af`, `6164161615fd`
- matched: `5948`, `8712`, `5848`, `2876`, `8260`, `cmd.exe`, `powershell.exe`, `WmiPrvSE.exe` (+1 more)
- **missing**: `c:\windows\temp\perfmon\p.exe)`
- claim: > [CONFIRMED — exec_id=019e1374-3eba-7711-b85b-4346fa6683af, exec_id=019e1372-401b-7322-918d-6164161615fd] Full execution chain: WmiPrvSE.exe (PID 2876) → powershell.exe (PID 8712, 64-bit) → powershell.…

### ✅ verified _(line 50)_
- tools: `vol3_malfind`
- exec_ids: `05e521831779`
- matched: `8260`, `p.exe`
- claim: > [CONFIRMED — exec_id=019e1375-53b0-7843-97a5-05e521831779] p.exe (PID 8260) has one RWX private VAD region spanning commit_charge 481 pages (~1.97 MB) — shellcode or reflective DLL hosting.

### ✅ verified _(line 52)_
- tools: `vol3_dlllist`
- exec_ids: `2c0e04fc2922`
- matched: `Secur32.dll`, `SSPICLI.DLL`, `p.exe`, `WININET.dll`, `WS2_32.dll`
- claim: > [CONFIRMED — exec_id=019e1377-1dc0-7e50-9a55-2c0e04fc2922] p.exe loaded DLLs include WININET.dll, WS2_32.dll, SSPICLI.DLL, and Secur32.dll — HTTP-capable, credential-capable network implant.

### ✅ verified _(line 54)_
- tools: `vol3_handles`
- exec_ids: `40a3dd5a244a`
- matched: `8260`, `p.exe`, `\Device\NamedPipe\fhsvc-b378`
- claim: > [CONFIRMED — exec_id=019e1378-f993-7922-8ea7-40a3dd5a244a] p.exe (PID 8260) holds two handles to \Device\NamedPipe\fhsvc-b378 (handle_values 464 and 2104, type=File) — a named pipe consistent with Cob…

### ✅ verified _(line 56)_
- tools: `vol3_psscan`
- exec_ids: `6164161615fd`
- matched: `p.exe`, `rundll32.exe`
- claim: > [CONFIRMED — exec_id=019e1372-401b-7322-918d-6164161615fd] Nine rundll32.exe processes (all exited) were spawned under the malware process tree on rd01: 6 with ppid=5848 (powershell WOW64) active 2018…

### ❌ failed _(line 60)_
- exec_ids: `f09f9fbc2cd5`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNSUPPORTED** — The parsed data provides aggregate statistics (1323 total services, 479 running, 753 drivers) but does not include binary paths or any per-service details needed to verify the specific assertion that 0 services have temp or suspicious staging paths.
- claim: > [CONFIRMED — exec_id=019e1376-e3cb-7461-94a5-f09f9fbc2cd5] No service-based persistence found: svcscan returned 0 services with binary paths containing temp or suspicious staging paths.

### ✅ verified _(line 64)_
- tools: `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `31b6aa7fa0f9`, `ed9ca35c7518`
- matched: `113730`, `PerfSvc.exe`
- claim: > [CONFIRMED — exec_id=019e1381-bdca-7522-9e5b-31b6aa7fa0f9, exec_id=019e1380-543d-7182-b5e3-ed9ca35c7518] PerfSvc.exe at Windows/Temp/perfmon/PerfSvc.exe (inode 113730) on the file server — same Window…

### ✅ verified _(line 66)_
- tools: `vol3_psscan`
- exec_ids: `c543e93a5ba7`
- matched: `1196`, `4072`, `3164`, `2018-08-28T22:08:25Z`, `2018-08-08T18:08:06Z`, `2018-08-30T01:46Z`, `2018-08-28T22:08:26Z`, `powershell.exe` (+2 more)
- claim: > [CONFIRMED — exec_id=019e137c-d313-7863-85b1-c543e93a5ba7] Identical WMI→PS chain on file01: WmiPrvSE.exe (PID 1196, ppid 600, started at system boot 2018-08-08T18:08:06Z) → powershell.exe (PID 4072, …

### ✅ verified _(line 68)_
- tools: `vol3_netscan`
- exec_ids: `c2657c847d24`
- matched: `4072`, `3164`, `172.16.4.10`, `powershell.exe`
- claim: > [CONFIRMED — exec_id=019e137e-1df0-74b3-8e18-c2657c847d24] powershell.exe (PID 3164) had CLOSE_WAIT to 172.16.4.10:8080; powershell.exe (PID 4072) had a CLOSED connection to 172.16.4.10:8080 — same C2…

### ✅ verified _(line 72)_
- tools: `vol3_handles`, `vol3_psscan`
- exec_ids: `4391ff217ea7`, `4f65466c1d5d`
- matched: `15116`, `2018-08-31T19:47:10Z`, `p.exe`, `rundll32.exe`, `\Device\NamedPipe\fhsvc-b378`
- claim: > [CONFIRMED — exec_id=019e137c-eee6-7f02-8131-4391ff217ea7, exec_id=019e137a-239a-7f12-8d8c-4f65466c1d5d] rundll32.exe (PID 15116, WOW64, ppid 15896, created 2018-08-31T19:47:10Z) holds handle_value=68…

### ❓ unverifiable _(line 80)_
- exec_ids: `c543e93a5ba7`, `c2657c847d24`, `6164161615fd`, `849d9fd58cba` (+2 more)
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim asserts lateral movement paths from network state, but vol3_psscan provides only process execution history (PIDs, process names, parent-child relationships, timestamps) with no network connectivity, IP addresses, or connection data.
- claim: > [CONFIRMED — exec_id=019e137c-d313-7863-85b1-c543e93a5ba7, exec_id=019e137e-1df0-74b3-8e18-c2657c847d24, exec_id=019e1372-401b-7322-918d-6164161615fd, exec_id=019e1372-d58b-7042-bfd9-849d9fd58cba, exe…

### ✅ verified _(line 95)_
- tools: `vol3_psscan`
- exec_ids: `aad1927eab3f`
- matched: `6628`, `8492`, `7612`, `2018-09-06T22:53:58Z`, `2018-09-01T18:18:19Z`, `2018-09-06T17:57:41Z`, `cmd.exe`, `tasklist.exe` (+1 more)
- claim: > [CONFIRMED — exec_id=019e1372-f51a-7ba3-9b97-aad1927eab3f] Confirmed compromised hosts include the DC: psscan shows tasklist.exe (PID 7612, created 2018-09-06T17:57:41Z), findstr.exe (PID 8492, create…

### ✅ verified _(line 97)_
- tools: `vol3_netscan`, `vol3_netscan`
- exec_ids: `849d9fd58cba`, `c2657c847d24`
- matched: `4072`, `3164`, `172.16.4.10`
- claim: > [CONFIRMED — exec_id=019e1372-d58b-7042-bfd9-849d9fd58cba, exec_id=019e137e-1df0-74b3-8e18-c2657c847d24] C2 relay via 172.16.4.10:8080: both rd01 (3 ESTABLISHED + multiple CLOSE_WAIT) and file01 (CLOS…

### ✅ verified _(line 105)_
- tools: `vol3_dlllist`
- exec_ids: `2c0e04fc2922`
- matched: `8260`, `Secur32.dll`, `SSPICLI.DLL`, `p.exe`
- claim: > [CONFIRMED — exec_id=019e1377-1dc0-7e50-9a55-2c0e04fc2922] p.exe (PID 8260, rd01) loaded SSPICLI.DLL and Secur32.dll — SSPI credential APIs directly accessible from the implant.

### ✅ verified _(line 107)_
- tools: `vol3_malfind`, `vol3_psscan`
- exec_ids: `05e521831779`, `6164161615fd`
- matched: `8128`, `OUTLOOK.EXE`
- claim: > [CONFIRMED — exec_id=019e1375-53b0-7843-97a5-05e521831779, exec_id=019e1372-401b-7322-918d-6164161615fd] OUTLOOK.EXE (PID 8128, session 1, rd01) has 2 RWX private VAD injection regions — implanted cod…

### ✅ verified _(line 109)_
- tools: `vol3_psscan`
- exec_ids: `aad1927eab3f`
- matched: `8492`, `7612`, `2018-09-01T18:18:20Z`, `2018-09-01T18:18:19Z`, `2018-09-06T17:57:41Z`, `tasklist.exe`, `findstr.exe`
- claim: > [CONFIRMED — exec_id=019e1372-f51a-7ba3-9b97-aad1927eab3f] DC psscan shows tasklist.exe (PID 7612, created and exited 2018-09-06T17:57:41Z) and findstr.exe (PID 8492, created 2018-09-01T18:18:19Z, exi…

### ✅ verified _(line 111)_
- tools: `vol3_psscan`
- exec_ids: `aad1927eab3f`
- matched: `5728`, `6628`, `2018-09-06T22:53:58Z`, `cmd.exe`, `conhost.exe`
- claim: > [CONFIRMED — exec_id=019e1372-f51a-7ba3-9b97-aad1927eab3f] DC psscan shows cmd.exe (PID 6628, ppid 908) at 2018-09-06T22:53:58Z with three child cmd.exe processes (PIDs 9012, 7260, 8220) and conhost.e…

### ✅ verified _(line 113)_
- tools: `vol3_netscan`
- exec_ids: `c2657c847d24`
- matched: `544`, `172.16.4.4`, `lsass.exe`
- claim: > [CONFIRMED — exec_id=019e137e-1df0-74b3-8e18-c2657c847d24] File server lsass.exe (PID 544) shows historical CLOSED connections to DC (172.16.4.4) on ports 49670, 389, 135 — attacker-controlled process…

### ✅ verified _(line 123)_
- tools: `vol3_psscan`
- exec_ids: `c543e93a5ba7`
- matched: `2524`, `2018-09-05T14:43:11Z`, `2018-09-05T14:52:56Z`, `Rar.exe`
- claim: > [CONFIRMED — exec_id=019e137c-d313-7863-85b1-c543e93a5ba7] Rar.exe (PID 2524, ppid 6352, 64-bit) ran on file01 from 2018-09-05T14:43:11Z to 2018-09-05T14:52:56Z (~9 minutes) — active data archiving op…

### ❌ failed _(line 127)_
- exec_ids: `ed9ca35c7518`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNSUPPORTED** — The parsed data shows a 'Shares' directory with 1212 files but provides no subdirectory structure, file names, or extensions to confirm the existence of a 'Shares/Installers/' directory or the specific software packages (7z, Adobe AcroReader, Office 2016) claimed in the assertion.
- claim: > [CONFIRMED — exec_id=019e1380-543d-7182-b5e3-ed9ca35c7518] file01 hosts a Shares/Installers/ directory containing software packages (7z, Adobe AcroReader, Office 2016 components) — a plausible staging…

### ✅ verified _(line 129)_
- tools: `vol3_netscan`
- exec_ids: `849d9fd58cba`
- matched: `172.16.4.10`
- claim: > [CONFIRMED — exec_id=019e1372-d58b-7042-bfd9-849d9fd58cba] rd01 maintained 3 simultaneous ESTABLISHED connections to C2 relay 172.16.4.10:8080 at memory capture — consistent with active beacon or data…

### ✅ verified _(line 131)_
- tools: `vol3_netscan`
- exec_ids: `849d9fd58cba`
- matched: `13.89.220.65`, `52.16.55.11`
- claim: > [CONFIRMED — exec_id=019e1372-d58b-7042-bfd9-849d9fd58cba] Historical CLOSED HTTPS connections from rd01 to 13.89.220.65:443 (Azure US) and 52.16.55.11:443 (AWS Ireland) — prior exfiltration or C2 ses…

### ✅ verified _(line 133)_
- tools: `vol3_dlllist`
- exec_ids: `2c0e04fc2922`
- matched: `WININET.dll`, `p.exe`
- claim: > [CONFIRMED — exec_id=019e1377-1dc0-7e50-9a55-2c0e04fc2922] p.exe uses WININET.dll — HTTP/HTTPS-capable, able to exfiltrate data directly over encrypted channels.

### ❓ unverifiable _(line 170)_
- exec_ids: `40a3dd5a244a`, `4391ff217ea7`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim contains only execution IDs with no specific factual assertion about handle data, file handles, registry keys, or process behavior that can be verified against the parsed handles data.
- claim: > - [CONFIRMED — exec_id=019e1378-f993-7922-8ea7-40a3dd5a244a, exec_id=019e137c-eee6-7f02-8131-4391ff217ea7]

### ❌ failed _(line 172)_
- exec_ids: `4346fa6683af`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNSUPPORTED** — The parsed data contains only a count (129) with no command-line arguments, process names, version flags, or staging details necessary to verify the specific PowerShell command-line assertion.
- claim: > - [CONFIRMED — exec_id=019e1374-3eba-7711-b85b-4346fa6683af] 32-bit WOW64 PowerShell staging with args -Version 5.1 -s -NoLogo -NoProfile is the canonical Cobalt Strike PowerShell spawn technique.

### ❓ unverifiable _(line 174)_
- exec_ids: `6164161615fd`, `c543e93a5ba7`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim contains only exec_id identifiers with no specific factual assertion about process names, timestamps, file paths, or other forensic indicators that could be verified against the vol3_psscan parsed data.
- claim: > - [CONFIRMED — exec_id=019e1372-401b-7322-918d-6164161615fd, exec_id=019e137c-d313-7863-85b1-c543e93a5ba7]

### ✅ verified _(line 176)_
- tools: `vol3_dlllist`
- exec_ids: `2c0e04fc2922`
- matched: `WININET.dll`, `p.exe`
- claim: > - [CONFIRMED — exec_id=019e1377-1dc0-7e50-9a55-2c0e04fc2922] p.exe loads WININET.dll for HTTP C2 — consistent with Cobalt Strike Beacon's HTTP profile.

### ✅ verified _(line 178)_
- tools: `vol3_netscan`, `vol3_netscan`
- exec_ids: `849d9fd58cba`, `c2657c847d24`
- matched: `172.16.4.10`
- claim: > - [CONFIRMED — exec_id=019e1372-d58b-7042-bfd9-849d9fd58cba, exec_id=019e137e-1df0-74b3-8e18-c2657c847d24] C2 through internal relay 172.16.4.10:8080 masking external traffic — consistent with Cobalt …

### ✅ verified _(line 180)_
- tools: `vol3_netscan`
- exec_ids: `849d9fd58cba`
- matched: `13.89.220.65`, `52.16.55.11`
- claim: > - [CONFIRMED — exec_id=019e1372-d58b-7042-bfd9-849d9fd58cba] Dual cloud C2 IPs (Azure 13.89.220.65, AWS 52.16.55.11) — state-level infrastructure diversification.

### ✅ verified _(line 187)_
- tools: `vol3_psscan`, `vol3_psscan`
- exec_ids: `6164161615fd`, `c543e93a5ba7`
- matched: `OUTLOOK.EXE`
- claim: > | OUTLOOK.EXE RWX injection | | WMI execution | T1047 | [CONFIRMED — exec_id=019e1372-401b-7322-918d-6164161615fd, exec_id=019e137c-d313-7863-85b1-c543e93a5ba7]

### ❌ failed _(line 188)_
- exec_ids: `4346fa6683af`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNSUPPORTED** — The parsed data only provides a count of 129 cmdline entries with no process name, parent-child relationships, spawning events, or hostnames to verify the specific claim that WmiPrvSE spawned PowerShell on rd01 and file01.
- claim: > | WmiPrvSE spawned PS on rd01 and file01 | | PowerShell | T1059.001 | [CONFIRMED — exec_id=019e1374-3eba-7711-b85b-4346fa6683af]

### ❓ unverifiable _(line 189)_
- exec_ids: `4346fa6683af`, `ed9ca35c7518`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The parsed data contains only a process count (129) with no command-line details, process names, arguments, or execution IDs needed to verify the specific claims about 64→32-bit PS chain, -s -NoLogo -NoProfile flags, Temp/perfmon masquerading, or the cited exec_ids.
- claim: > | 64→32-bit PS chain with -s -NoLogo -NoProfile | | Masquerading (Temp/perfmon) | T1036.004 | [CONFIRMED — exec_id=019e1374-3eba-7711-b85b-4346fa6683af, exec_id=019e1380-543d-7182-b5e3-ed9ca35c7518]

### ⚠ partial _(line 190)_
- tools: `vol3_malfind`
- exec_ids: `05e521831779`
- matched: `p.exe`
- **missing**: `PerfSvc.exe`
- claim: > | p.exe in staging path on rd01; PerfSvc.exe at Windows/Temp/perfmon/PerfSvc.exe on file01 | | Process injection | T1055 | [CONFIRMED — exec_id=019e1375-53b0-7843-97a5-05e521831779]

### ✅ verified _(line 191)_
- tools: `vol3_netscan`, `vol3_netscan`
- exec_ids: `849d9fd58cba`, `c2657c847d24`
- matched: `p.exe`, `OUTLOOK.EXE`
- claim: > | RWX private VADs in p.exe (481 pages) and OUTLOOK.EXE (16 pages x2) | | SMB lateral movement | T1021.002 | [CONFIRMED — exec_id=019e1372-d58b-7042-bfd9-849d9fd58cba, exec_id=019e137e-1df0-74b3-8e18-…

### ❓ unverifiable _(line 192)_
- exec_ids: `849d9fd58cba`, `c2657c847d24`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The parsed netscan data shows foreign IP connections but lacks protocol identification, process names, hostnames, or connection states needed to verify the specific claim about SMB connections between named hosts (rd01, file01, wkstn, DC) and proxy relay activity.
- claim: > | ESTABLISHED SMB rd01 to file01 and wkstn hosts; file01 to DC, wkstn, and RD servers | | Internal proxy relay | T1090.001 | [CONFIRMED — exec_id=019e1372-d58b-7042-bfd9-849d9fd58cba, exec_id=019e137e…

### ✅ verified _(line 193)_
- tools: `vol3_netscan`
- exec_ids: `849d9fd58cba`
- matched: `172.16.4.10`
- claim: > | 172.16.4.10:8080 as shared C2 relay for rd01 and file01 | | HTTPS C2 | T1071.001 | [CONFIRMED — exec_id=019e1372-d58b-7042-bfd9-849d9fd58cba]

### ❌ failed _(line 194)_
- tools: `vol3_handles`, `vol3_handles`
- exec_ids: `40a3dd5a244a`, `4391ff217ea7`
- **missing**: `13.89.220.65`, `52.16.55.11`
- claim: > | 13.89.220.65:443, 52.16.55.11:443 CLOSED sessions from rd01 | | Named pipe C2 | T1572 | [CONFIRMED — exec_id=019e1378-f993-7922-8ea7-40a3dd5a244a, exec_id=019e137c-eee6-7f02-8131-4391ff217ea7]

### ✅ verified _(line 195)_
- tools: `vol3_psscan`
- exec_ids: `c543e93a5ba7`
- matched: `rundll32.exe`, `p.exe`
- claim: > | fhsvc-b378 pipe on rd01 p.exe and exchange01 rundll32.exe | | Archive for exfil | T1560.001 | [CONFIRMED — exec_id=019e137c-d313-7863-85b1-c543e93a5ba7]
