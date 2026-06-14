# Validator Report — iter_1

## Summary

- Total tagged claims:        **29**
  - CONFIRMED:                 24
  - INFERRED:                  2
  - HYPOTHESIS:                0
  - GAP:                       3
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           0 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                19 (some tokens found, some missing)
- ❌ failed:                 4 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           1 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 0.0%** (0 verified / 24 confirmed)

## Per-claim verdicts

### ❌ failed _(line 88)_
- tools: `vol3_image_info`
- exec_ids: `eb4f583ff1a6`
- **missing**: `172.16.6.11`, `019e41aa-0f54-7450-b704-eb4f583ff1a6`, `vol3_image_info`
- claim: > **[CONFIRMED]** The primary compromise host is **rd01** (172.16.6.11), a Windows 10 build 16299 workstation in the R&D subnet. (`vol3_image_info` exec_id=`019e41aa-0f54-7450-b704-eb4f583ff1a6`)

### ⚠ partial _(line 90)_
- tools: `vol3_malfind`
- exec_ids: `559e1dda0921`
- matched: `8128`, `OUTLOOK.EXE`, `PAGE_EXECUTE_READWRITE`
- **missing**: `019e41c1-409b-7de2-a889-559e1dda0921`, `vol3_malfind`
- claim: > **[CONFIRMED]** Initial access was delivered via a **malicious email exploit targeting Outlook**. `vol3_malfind` detected two private `PAGE_EXECUTE_READWRITE` (RWX) memory regions in `OUTLOOK.EXE` (PI…

### ⚠ partial _(line 92)_
- tools: `vol3_psscan`
- exec_ids: `06cd24f2f663`
- matched: `8712`, `2876`, `2018-08-30T16:43:36Z`, `powershell.exe`, `WmiPrvSE.exe`
- **missing**: `query_rows`, `vol3_psscan`, `019e41aa-4fcd-7bf3-89c3-06cd24f2f663`
- 🚨 negation violations (claimed absent but found): `OUTLOOK.EXE`
- claim: > **[CONFIRMED]** The shellcode in OUTLOOK.EXE leveraged **WMI to execute PowerShell without a shell**: `WmiPrvSE.exe` (PID 2876, parent svchost -k DcomLaunch) spawned `powershell.exe` (PID 8712) at **2…

### ⚠ partial _(line 94)_
- tools: `vol3_malfind`
- exec_ids: `559e1dda0921`
- matched: `8712`, `powershell.exe`
- **missing**: `019e41c1-409b-7de2-a889-559e1dda0921`, `vol3_malfind`
- claim: > **[CONFIRMED]** `powershell.exe` (PID 8712) has three additional RWX private memory regions (`vol3_malfind` exec_id=`019e41c1-409b-7de2-a889-559e1dda0921`), indicating in-memory shellcode/Cobalt Strik…

### 🔍 not_confirmed _(line 102)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED]** `p.exe` is an HTTP-based RAT at `c:\windows\temp\perfmon\p.exe` — a Temp subdirectory named to impersonate the legitimate Windows Performance Monitor tool.

### ❌ failed _(line 112)_
- tools: `vol3_cmdline`
- exec_ids: `363cadff189b`
- **missing**: `vol3_cmdline`, `019e41ae-9c92-7ba1-8cc6-363cadff189b`, `args: null`
- 🚨 negation violations (claimed absent but found): `5848`, `8260`, `powershell.exe`, `rundll32.exe`, `p.exe`
- claim: > **[CONFIRMED]** `powershell.exe` (PID 5848) and `p.exe` (PID 8260) repeatedly spawned `rundll32.exe` processes with **no command-line arguments** (all 9 instances have `args: null`), a definitive indi…

### ⚠ partial _(line 129)_
- tools: `vol3_cmdline`
- exec_ids: `35b6b8378172`
- matched: `15116`, `rundll32.exe`, `C:\Windows\System32\rundll32.exe`
- **missing**: `172.16.4.6`, `2018-08-31T19:47:10Z`, `\Windows\System32\rundll32.exe``, `C:\Windows\System32\rundll32.exe``, `vol3_cmdline`, `019e41b1-b880-7151-aa22-35b6b8378172`
- claim: > **[CONFIRMED]** On the mail server (172.16.4.6 / Exchange), `rundll32.exe` (PID 15116) has been running since **2018-08-31T19:47:10Z** with bare commandline `C:\Windows\System32\rundll32.exe` (no DLL …

### ⚠ partial _(line 133)_
- tools: `vol3_netscan`, `vol3_psscan`
- exec_ids: `28631b698d07`, `fdd7a66342eb`
- matched: `3164`, `172.16.4.5`, `172.16.4.10`, `powershell.exe`, `rundll32.exe`
- **missing**: `vol3_psscan`, `019e41af-ad5a-78c3-ac02-fdd7a66342eb`, `019e41b1-c2d5-74d0-935e-28631b698d07`, `vol3_netscan`
- claim: > **[CONFIRMED]** `powershell.exe` (PID 3164) on the file server (172.16.4.5) holds an active TCP connection in CLOSE_WAIT to **172.16.4.10:8080** — the same C2 relay used by rd01. This PowerShell has s…

### ⚠ partial _(line 137)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `1156`, `10.10.254.1`, `rubyw.exe`
- **missing**: `vol3_netscan`, `019e41b1-c2d5-74d0-935e-28631b698d07`
- claim: > **[CONFIRMED]** `rubyw.exe` (PID 1156) on the file server has an ESTABLISHED TCP connection to **10.10.254.1:61613** (port 61613 = Apache ActiveMQ STOMP, used by Metasploit for message-bus pivoting). …

### ❌ failed _(line 148)_
- tools: `tsk_fls_list`
- exec_ids: `1ad22a29990b`
- **missing**: `019e41b4-b4c9-7521-aea3-1ad22a29990b`, `tsk_fls_list`
- 🚨 negation violations (claimed absent but found): `.bup`
- claim: > **[CONFIRMED]** McAfee VirusScan Enterprise quarantined **6 malware items** from rd01 (`.bup` files at inodes 18084, 18423, 61638, 80282, 80700, 20402 in the Quarantine directory), but their content (…

### ⚠ partial _(line 156)_
- tools: `vol3_netscan`
- exec_ids: `9b96e3f9c9be`
- matched: `172.16.6.11`, `172.16.4.10`
- **missing**: `vol3_netscan`, `019e41ab-901c-7111-be73-9b96e3f9c9be`, `proxy01`
- claim: > **[CONFIRMED]** rd01 (172.16.6.11) → **172.16.4.10:8080** (C2 relay host, likely `proxy01`): 14 TCP connections (3 ESTABLISHED, 8 CLOSE_WAIT, 3 CLOSED) confirming persistent C2 beaconing through an in…

### ⚠ partial _(line 158)_
- tools: `vol3_netscan`
- exec_ids: `9b96e3f9c9be`
- matched: `172.16.7.15`
- **missing**: `vol3_netscan`, `019e41ab-901c-7111-be73-9b96e3f9c9be`
- claim: > **[CONFIRMED]** rd01 → **172.16.7.15:445** (ESTABLISHED): SMB lateral movement to workstation subnet. (`vol3_netscan` exec_id=`019e41ab-901c-7111-be73-9b96e3f9c9be`)

### ❌ failed _(line 160)_
- tools: `vol3_psscan`
- exec_ids: `fdd7a66342eb`
- **missing**: `172.16.4.5`, `vol3_psscan`, `019e41af-ad5a-78c3-ac02-fdd7a66342eb`
- claim: > **[CONFIRMED]** rd01 → **172.16.4.5:445** (file server SMB, confirmed via file server netscan showing rd01 IP in foreign connections, `vol3_psscan` exec_id=`019e41af-ad5a-78c3-ac02-fdd7a66342eb`).

### ⚠ partial _(line 162)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `172.16.6.13`, `172.16.4.5`, `172.16.7.13`, `172.16.7.14`, `172.16.6.14`
- **missing**: `172.16.6.13:49889`, `172.16.6.14:54993`, `172.16.7.14:445`, `019e41b1-c2d5-74d0-935e-28631b698d07`, `vol3_netscan`
- claim: > **[CONFIRMED]** File server (172.16.4.5) active SMB connections to: `172.16.6.13:49889`, `172.16.6.14:54993` (R&D subnet RDS hosts), `172.16.7.13` and `172.16.7.14:445` (workstation subnet) — bidirect…

### ⚠ partial _(line 164)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `2340`, `172.16.7.12`, `Uninstall.exe`
- **missing**: `vol3_netscan`, `019e41b1-c2d5-74d0-935e-28631b698d07`
- claim: > **[CONFIRMED]** `Uninstall.exe` (PID 2340) on file server initiated a connection to **172.16.7.12:135** (RPC on workstation subnet). (`vol3_netscan` exec_id=`019e41b1-c2d5-74d0-935e-28631b698d07`)

### ⚠ partial _(line 166)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `172.16.5.21`
- **missing**: `vol3_netscan`, `019e41b1-c2d5-74d0-935e-28631b698d07`
- claim: > **[CONFIRMED]** File server executed WinRM connections to **172.16.5.21:5985** on multiple occasions (6 connection records in netscan — CLOSED), indicating lateral movement via PowerShell Remoting to …

### ⚠ partial _(line 168)_
- tools: `vol3_cmdline`
- exec_ids: `35b6b8378172`
- matched: `5144`, `powershell.exe`, `Connect-ExchangeServer -auto`
- **missing**: `172.16.4.6`, `2018-08-31T19:47:10Z`, `019e41b1-b880-7151-aa22-35b6b8378172`, `vol3_cmdline`
- claim: > **[CONFIRMED]** Mail server (172.16.4.6) compromised by 2018-08-31T19:47:10Z (rundll32 start time), with `powershell.exe` (PID 5144) opening an Exchange Management Shell session (`Connect-ExchangeServ…

### ⚠ partial _(line 181)_
- tools: `vol3_psscan`
- exec_ids: `06cd24f2f663`
- matched: `772`, `lsass.exe`, `p.exe`
- **missing**: `vol3_psscan`, `019e41aa-4fcd-7bf3-89c3-06cd24f2f663`
- claim: > **[CONFIRMED]** `lsass.exe` (PID 772) is running on rd01 and accessible to the attacker's processes executing in Session 0 (`vol3_psscan` exec_id=`019e41aa-4fcd-7bf3-89c3-06cd24f2f663`). `p.exe` runs …

### ⚠ partial _(line 185)_
- tools: `vol3_psscan`
- exec_ids: `09bb31dbf9fc`
- matched: `tasklist.exe`, `findstr.exe`, `cmd.exe`
- **missing**: `019e41ac-1aca-74d0-8057-09bb31dbf9fc`, `vol3_psscan`
- claim: > **[CONFIRMED]** The DC psscan shows **25 exited cmd.exe processes** spanning 2018-09-01 through 2018-09-06, including `findstr.exe` (2 instances) and `tasklist.exe` (2 instances) — confirming AD/domai…

### ⚠ partial _(line 187)_
- tools: `vol3_psscan`
- exec_ids: `09bb31dbf9fc`
- matched: `908`, `2018-09-06T22:53:58Z`, `cmd.exe`
- **missing**: `2018-09-06T22:57:49Z`, `ManagementAgentHost.exe`, `019e41ac-1aca-74d0-8057-09bb31dbf9fc`, `vol3_psscan`
- claim: > **[CONFIRMED]** Shortly before DC memory capture (2018-09-06T22:57:49Z), a burst of `cmd.exe` processes (PIDs 6628, 7260, 9012, 8220) spawned from `ManagementAgentHost.exe` (VMware CAF, PID 908) and i…

### ⚠ partial _(line 195)_
- tools: `vol3_psscan`
- exec_ids: `fdd7a66342eb`
- matched: `2524`, `2018-09-05T14:43:11Z`, `Rar.exe`
- **missing**: `vol3_psscan`, `019e41af-ad5a-78c3-ac02-fdd7a66342eb`
- claim: > **[CONFIRMED]** Data staging: `Rar.exe` (PID 2524, parent 6352) ran on the **file server** for approximately 10 minutes between **2018-09-05T14:43:11Z and 14:52:56Z**, then exited. This is a WinRAR ar…

### ⚠ partial _(line 197)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `1156`, `10.10.254.1`, `rubyw.exe`
- **missing**: `vol3_netscan`, `019e41b1-c2d5-74d0-935e-28631b698d07`
- 🚨 negation violations (claimed absent but found): `10.10.4.5`, `172.16.4.5`
- claim: > **[CONFIRMED]** Exfiltration channel via Metasploit: `rubyw.exe` (PID 1156) on the file server maintains an ESTABLISHED TCP connection to **10.10.254.1:61613** (STOMP/ActiveMQ protocol, used by Metasp…

### ⚠ partial _(line 199)_
- tools: `vol3_netscan`
- exec_ids: `9b96e3f9c9be`
- matched: `172.16.6.11`, `52.16.55.11`, `13.89.220.65`
- **missing**: `172.16.6.11:49360 → 52.16.55.11:443 CLOSED`, `vol3_netscan`, `172.16.6.11:49782 → 13.89.220.65:443 CLOSED`, `019e41ab-901c-7111-be73-9b96e3f9c9be`
- claim: > **[CONFIRMED]** External HTTPS connections from rd01: `172.16.6.11:49782 → 13.89.220.65:443 CLOSED` (Azure) and `172.16.6.11:49360 → 52.16.55.11:443 CLOSED` (AWS). Both connections to cloud IPs on HTT…

### ⚠ partial _(line 201)_
- tools: `vol3_cmdline`
- exec_ids: `35b6b8378172`
- matched: `5144`, `powershell.exe`, `Connect-ExchangeServer -auto`
- **missing**: `019e41b1-b880-7151-aa22-35b6b8378172`, `vol3_cmdline`
- claim: > **[CONFIRMED]** The mail server's Exchange Management Shell (`powershell.exe` PID 5144, `Connect-ExchangeServer -auto`) was active as of the memory capture, enabling the attacker to enumerate and pote…
