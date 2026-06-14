# Validator Report — iter_3

## Summary

- Total tagged claims:        **35**
  - CONFIRMED:                 25
  - INFERRED:                  7
  - HYPOTHESIS:                0
  - GAP:                       3
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           23 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                0 (some tokens found, some missing)
- ❌ failed:                 1 (no tokens found)
- ❓ unverifiable:           1 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 92.0%** (23 verified / 25 confirmed)

## Per-claim verdicts

### ✅ verified _(line 41)_
- tools: `vol3_netscan`
- exec_ids: `9b96e3f9c9be`
- matched: `172.16.6.11`
- claim: > **[CONFIRMED]** The primary compromise host is rd01 with local IP 172.16.6.11, confirmed as the source address across all rd01 network connections (vol3_netscan exec_id=019e41ab-901c-7111-be73-9b96e3f…

### ✅ verified _(line 45)_
- tools: `vol3_malfind`
- exec_ids: `559e1dda0921`
- matched: `8128`, `OUTLOOK.EXE`
- claim: > **[CONFIRMED]** Initial access was delivered via a malicious email exploit targeting Outlook. Two private PAGE_EXECUTE_READWRITE memory regions are present in OUTLOOK.EXE (PID 8128), both tagged VadS …

### ✅ verified _(line 47)_
- tools: `vol3_psscan`
- exec_ids: `06cd24f2f663`
- matched: `8712`, `2876`, `2018-08-30T16:43:36Z`, `powershell.exe`, `WmiPrvSE.exe`
- claim: > **[CONFIRMED]** WmiPrvSE.exe (PID 2876, ppid=868) on rd01 is the direct parent of powershell.exe (PID 8712, ppid=2876) which started at 2018-08-30T16:43:36Z, establishing the WMI-based code execution …

### ✅ verified _(line 49)_
- tools: `vol3_malfind`
- exec_ids: `559e1dda0921`
- matched: `8712`, `powershell.exe`
- claim: > **[CONFIRMED]** powershell.exe (PID 8712) carries three PAGE_EXECUTE_READWRITE private memory regions (all VadS, unbacked), indicating in-memory shellcode injection concurrent with the initial WMI foo…

### ✅ verified _(line 57)_
- tools: `vol3_cmdline`
- exec_ids: `363cadff189b`
- matched: `8260`, `p.exe`, `c:\windows\temp\perfmon\p.exe`
- claim: > **[CONFIRMED]** p.exe (PID 8260) executes with args c:\windows\temp\perfmon\p.exe — a Temp subdirectory impersonating the Windows Performance Monitor folder name (vol3_cmdline exec_id=019e41ae-9c92-7b…

### ✅ verified _(line 69)_
- tools: `vol3_cmdline`
- exec_ids: `363cadff189b`
- matched: `5848`, `8260`, `powershell.exe`, `rundll32.exe`, `p.exe`
- claim: > **[CONFIRMED]** powershell.exe (PID 5848) and p.exe (PID 8260) spawned 9 rundll32.exe processes all with args=null (no command-line arguments), the definitive indicator of process hollowing (vol3_cmdl…

### ✅ verified _(line 73)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `3a6834316f92`, `35b6b8378172`
- matched: `15116`, `2018-08-31T19:47:10Z`, `rundll32.exe`
- claim: > **[CONFIRMED]** On the mail server, rundll32.exe (PID 15116) has been running since 2018-08-31T19:47:10Z and was still alive at the 2018-09-05 memory capture (vol3_psscan exec_id=019e41af-df5d-7672-9d…

### ❌ failed _(line 75)_
- tools: `vol3_cmdline`
- exec_ids: `35b6b8378172`
- 🚨 negation violations (claimed absent but found): `15116`, `rundll32.exe`, `\Windows\System32\rundll32.exe`, `C:\Windows\System32\rundll32.exe`
- claim: > **[CONFIRMED]** rundll32.exe (PID 15116) on the mail server carries cmdline args C:\Windows\System32\rundll32.exe with no DLL or export argument — bare self-invocation consistent with process hollowin…

### ✅ verified _(line 79)_
- tools: `vol3_netscan`, `vol3_psscan`
- exec_ids: `28631b698d07`, `fdd7a66342eb`
- matched: `3164`, `172.16.4.5`, `172.16.4.10`, `2018-08-28T22:08:26Z`, `powershell.exe`, `rundll32.exe`
- claim: > **[CONFIRMED]** powershell.exe (PID 3164, ppid=4072, created 2018-08-28T22:08:26Z) on the file server (172.16.4.5) maintains a CLOSE_WAIT TCP connection to 172.16.4.10 port 8080 — the same internal C2…

### ✅ verified _(line 83)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `1156`, `10.10.4.5`, `10.10.254.1`, `rubyw.exe`
- claim: > **[CONFIRMED]** rubyw.exe (PID 1156) on the file server has an ESTABLISHED TCP connection with local_addr 10.10.4.5 port 59361 and foreign_addr 10.10.254.1 port 61613 — the Metasploit STOMP/ActiveMQ p…

### ❓ unverifiable _(line 91)_
- exec_ids: `1ad22a29990b`
- note: claim has no extractable tokens (prose only)
- claim: > **[CONFIRMED]** McAfee VirusScan Enterprise quarantined 6 malware items from rd01 — .bup files at inodes 61638, 80282, 20402, 80700, 18423, 18084, all under path Quarantine/ (tsk_fls_list exec_id=019e…

### ✅ verified _(line 97)_
- tools: `vol3_netscan`
- exec_ids: `9b96e3f9c9be`
- matched: `172.16.6.11`, `172.16.4.10`
- claim: > **[CONFIRMED]** rd01 (172.16.6.11) maintained 14 TCP connections to 172.16.4.10 port 8080 (states: ESTABLISHED, CLOSE_WAIT, CLOSED), confirming persistent C2 beaconing to the internal relay (vol3_nets…

### ✅ verified _(line 101)_
- tools: `vol3_netscan`
- exec_ids: `9b96e3f9c9be`
- matched: `172.16.6.11`, `172.16.7.15`
- claim: > **[CONFIRMED]** rd01 (172.16.6.11) → 172.16.7.15 port 445 ESTABLISHED: SMB lateral movement to workstation subnet (vol3_netscan exec_id=019e41ab-901c-7111-be73-9b96e3f9c9be).

### ✅ verified _(line 103)_
- tools: `vol3_netscan`
- exec_ids: `9b96e3f9c9be`
- matched: `172.16.6.11`, `172.16.4.5`
- claim: > **[CONFIRMED]** rd01 (172.16.6.11 port 49763) → 172.16.4.5 port 445 ESTABLISHED: SMB lateral movement to file server (vol3_netscan exec_id=019e41ab-901c-7111-be73-9b96e3f9c9be).

### ✅ verified _(line 105)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `172.16.6.13`, `172.16.4.5`, `172.16.7.13`, `172.16.7.14`, `172.16.6.14`
- claim: > **[CONFIRMED]** The file server (172.16.4.5) has active SMB connections to 172.16.6.13 port 49889 ESTABLISHED, 172.16.6.14 port 54993 ESTABLISHED (R&D subnet RDS hosts), 172.16.7.13 port 54369 ESTABLI…

### ✅ verified _(line 107)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `2340`, `172.16.7.12`, `Uninstall.exe`
- claim: > **[CONFIRMED]** Uninstall.exe (PID 2340) on the file server initiated a connection to 172.16.7.12 port 135 (RPC, workstation subnet) — CLOSED at capture time (vol3_netscan exec_id=019e41b1-c2d5-74d0-9…

### ✅ verified _(line 109)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `172.16.5.21`
- claim: > **[CONFIRMED]** The file server executed WinRM connections to 172.16.5.21 port 5985 — 6 total connection records (all CLOSED), indicating lateral movement via PowerShell Remoting to an unlisted manage…

### ✅ verified _(line 111)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `3a6834316f92`, `35b6b8378172`
- matched: `5144`, `15116`, `2018-09-05T12:05:44Z`, `2018-08-31T19:47:10Z`, `powershell.exe`, `rundll32.exe`
- claim: > **[CONFIRMED]** The mail server is compromised: rundll32.exe (PID 15116) has been running from 2018-08-31T19:47:10Z, and powershell.exe (PID 5144) started an Exchange Management Shell session at 2018-…

### ✅ verified _(line 124)_
- tools: `vol3_psscan`
- exec_ids: `06cd24f2f663`
- matched: `772`, `lsass.exe`
- claim: > **[CONFIRMED]** lsass.exe (PID 772, ppid=632, Session 0) is running on rd01 and is accessible to attacker processes operating in Session 0 via the WMI/PowerShell chain (vol3_psscan exec_id=019e41aa-4f…

### ✅ verified _(line 128)_
- tools: `vol3_psscan`
- exec_ids: `09bb31dbf9fc`
- matched: `cmd.exe`, `tasklist.exe`
- claim: > **[CONFIRMED]** The DC psscan shows tasklist.exe processes (2 instances, PIDs 7284 and 7612) and cmd.exe processes spanning 2018-09-01 through 2018-09-06, confirming domain enumeration was performed o…

### ✅ verified _(line 130)_
- tools: `vol3_psscan`
- exec_ids: `09bb31dbf9fc`
- matched: `908`, `6628`, `2018-09-06T17:47:38Z`, `2018-09-06T22:53:58Z`, `2018-09-06T18:17:46Z`, `2018-09-01T17:48:11Z`, `cmd.exe`
- claim: > **[CONFIRMED]** cmd.exe (PID 6628) spawned from ManagementAgen (PID 908) at 2018-09-06T22:53:58Z and exited in the same second on the DC; additional cmd.exe children of PID 908 at 2018-09-01T17:48:11Z…

### ✅ verified _(line 140)_
- tools: `vol3_psscan`
- exec_ids: `fdd7a66342eb`
- matched: `2524`, `2018-09-05T14:43:11Z`, `Rar.exe`
- claim: > **[CONFIRMED]** Rar.exe (PID 2524, ppid=6352) ran on the file server from 2018-09-05T14:43:11Z to 14:52:56Z — WinRAR archiving operation consistent with staging data for exfiltration (vol3_psscan exec…

### ✅ verified _(line 142)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `1156`, `10.10.4.5`, `10.10.254.1`, `rubyw.exe`
- claim: > **[CONFIRMED]** rubyw.exe (PID 1156) on the file server maintains an ESTABLISHED TCP connection with local_addr 10.10.4.5 port 59361 to foreign_addr 10.10.254.1 port 61613 — the Metasploit STOMP/Activ…

### ✅ verified _(line 144)_
- tools: `vol3_netscan`
- exec_ids: `9b96e3f9c9be`
- matched: `172.16.6.11`, `52.16.55.11`, `13.89.220.65`
- claim: > **[CONFIRMED]** External HTTPS connections from rd01 (172.16.6.11): port 49782 → 13.89.220.65 port 443 CLOSED (Azure) and port 49360 → 52.16.55.11 port 443 CLOSED (AWS) — secondary C2 or data exfiltra…

### ✅ verified _(line 146)_
- tools: `vol3_cmdline`, `vol3_psscan`
- exec_ids: `35b6b8378172`, `3a6834316f92`
- matched: `5144`, `2018-09-05T12:05:44Z`, `powershell.exe`
- claim: > **[CONFIRMED]** The mail server Exchange Management Shell was active: powershell.exe (PID 5144) ran with cmdline including Connect-ExchangeServer -auto -ClientApplication:ManagementShell starting 2018…
