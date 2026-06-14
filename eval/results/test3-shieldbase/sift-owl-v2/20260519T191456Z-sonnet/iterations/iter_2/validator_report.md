# Validator Report — iter_2

## Summary

- Total tagged claims:        **33**
  - CONFIRMED:                 24
  - INFERRED:                  6
  - HYPOTHESIS:                0
  - GAP:                       3
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           16 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                4 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           4 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 66.7%** (16 verified / 24 confirmed)

## Per-claim verdicts

### 🔍 not_confirmed _(line 28)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED]

### ⚠ partial _(line 30)_
- tools: `vol3_malfind`
- exec_ids: `559e1dda0921`
- matched: `8128`, `OUTLOOK.EXE`
- **missing**: `vol3_malfind`
- claim: > **[CONFIRMED]** Initial access was delivered via a **malicious email exploit targeting Outlook**. `vol3_malfind` detected two private PAGE_EXECUTE_READWRITE (RWX) memory regions in OUTLOOK.EXE (PID 81…

### 🔍 not_confirmed _(line 32)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED]

### ✅ verified _(line 34)_
- tools: `vol3_malfind`
- exec_ids: `559e1dda0921`
- matched: `8712`, `powershell.exe`
- claim: > **[CONFIRMED]** powershell.exe (PID 8712) carries **three** PAGE_EXECUTE_READWRITE private memory regions (all VadS, unbacked), indicating in-memory shellcode injection concurrent with the initial WMI…

### ⚠ partial _(line 42)_
- tools: `vol3_cmdline`
- exec_ids: `363cadff189b`
- matched: `8260`, `p.exe`, `c:\windows\temp\perfmon\p.exe`
- **missing**: `c:\windows\temp\perfmon\p.exe``
- claim: > **[CONFIRMED]** p.exe (PID 8260) runs from `c:\windows\temp\perfmon\p.exe` — a Temp subdirectory impersonating the Windows Performance Monitor folder name (vol3_cmdline exec_id=019e41ae-9c92-7ba1-8cc6…

### ✅ verified _(line 52)_
- tools: `vol3_cmdline`
- exec_ids: `363cadff189b`
- matched: `5848`, `8260`, `powershell.exe`, `rundll32.exe`, `p.exe`
- claim: > **[CONFIRMED]** powershell.exe (PID 5848) and p.exe (PID 8260) spawned **9 rundll32.exe** processes all with args=null (no command-line arguments), the definitive indicator of process hollowing (vol3_…

### ⚠ partial _(line 56)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `3a6834316f92`, `35b6b8378172`
- matched: `15116`, `2018-08-31T19:47:10Z`, `rundll32.exe`, `C:\Windows\System32\rundll32.exe`
- **missing**: `\Windows\System32\rundll32.exe``, `C:\Windows\System32\rundll32.exe``
- claim: > **[CONFIRMED]** On the mail server, rundll32.exe (PID 15116) has been running since **2018-08-31T19:47:10Z** and carries cmdline args `C:\Windows\System32\rundll32.exe` (no DLL or export specified — b…

### ✅ verified _(line 60)_
- tools: `vol3_netscan`, `vol3_psscan`
- exec_ids: `28631b698d07`, `fdd7a66342eb`
- matched: `3164`, `172.16.4.5`, `172.16.4.10`, `2018-08-28T22:08:26Z`, `powershell.exe`, `rundll32.exe`
- claim: > **[CONFIRMED]** powershell.exe (PID 3164, ppid=4072, created 2018-08-28T22:08:26Z) on the file server (172.16.4.5) maintains a CLOSE_WAIT TCP connection to **172.16.4.10:8080** — the same C2 relay as …

### ✅ verified _(line 64)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `1156`, `10.10.4.5`, `172.16.4.5`, `10.10.254.1`, `rubyw.exe`
- claim: > **[CONFIRMED]** rubyw.exe (PID 1156) on the file server has an ESTABLISHED TCP connection from **10.10.4.5:59361 → 10.10.254.1:61613** (port 61613 = Apache ActiveMQ STOMP, used by Metasploit). The loc…

### ✅ verified _(line 72)_
- tools: `tsk_fls_list`
- exec_ids: `1ad22a29990b`
- matched: `Quarantine/`
- claim: > **[CONFIRMED]** McAfee VirusScan Enterprise quarantined **6 malware items** from rd01 — .bup files at inodes 61638, 80282, 20402, 80700, 18423, 18084, all under path `Quarantine/` (tsk_fls_list exec_i…

### 🔍 not_confirmed _(line 78)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED]

### ✅ verified _(line 80)_
- tools: `vol3_netscan`
- exec_ids: `9b96e3f9c9be`
- matched: `172.16.7.15`
- claim: > **[CONFIRMED]** rd01 → **172.16.7.15:445 ESTABLISHED**: SMB lateral movement to workstation subnet (vol3_netscan exec_id=019e41ab-901c-7111-be73-9b96e3f9c9be).

### ✅ verified _(line 82)_
- tools: `vol3_netscan`
- exec_ids: `9b96e3f9c9be`
- matched: `172.16.6.11`, `172.16.4.5`
- claim: > **[CONFIRMED]** rd01 → **172.16.4.5:445 ESTABLISHED**: SMB lateral movement to file server (172.16.6.11:49763 → 172.16.4.5:445) (vol3_netscan exec_id=019e41ab-901c-7111-be73-9b96e3f9c9be).

### ✅ verified _(line 84)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `172.16.6.13`, `172.16.4.5`, `172.16.7.13`, `172.16.7.14`, `172.16.6.14`
- claim: > **[CONFIRMED]** File server (172.16.4.5) active SMB connections to: 172.16.6.13:49889 (ESTABLISHED), 172.16.6.14:54993 (ESTABLISHED) (R&D subnet RDS hosts), 172.16.7.13 (port 445, ESTABLISHED), 172.16…

### ✅ verified _(line 86)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `2340`, `172.16.7.12`, `Uninstall.exe`
- claim: > **[CONFIRMED]** Uninstall.exe (PID 2340) on the file server initiated a connection to **172.16.7.12:135** (RPC, workstation subnet) — CLOSED at capture time (vol3_netscan exec_id=019e41b1-c2d5-74d0-93…

### ✅ verified _(line 88)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `172.16.5.21`
- claim: > **[CONFIRMED]** File server executed WinRM connections to **172.16.5.21:5985** — 6 total connection records (all CLOSED), indicating lateral movement via PowerShell Remoting to an unlisted management …

### ✅ verified _(line 90)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `3a6834316f92`, `35b6b8378172`
- matched: `5144`, `15116`, `2018-09-05T12:05:44Z`, `2018-08-31T19:47:10Z`, `powershell.exe`, `rundll32.exe`, `Connect-ExchangeServer -auto`
- claim: > **[CONFIRMED]** Mail server compromised: rundll32.exe (PID 15116) running from 2018-08-31T19:47:10Z (vol3_psscan exec_id=019e41af-df5d-7672-9d1f-3a6834316f92). powershell.exe (PID 5144) opened an Exch…

### ✅ verified _(line 103)_
- tools: `vol3_psscan`
- exec_ids: `06cd24f2f663`
- matched: `772`, `lsass.exe`
- claim: > **[CONFIRMED]** lsass.exe (PID 772, ppid=632, Session 0) is running on rd01 and accessible to attacker processes operating in Session 0 via the WMI/PowerShell chain (vol3_psscan exec_id=019e41aa-4fcd-…

### ✅ verified _(line 107)_
- tools: `vol3_psscan`
- exec_ids: `09bb31dbf9fc`
- matched: `cmd.exe`, `tasklist.exe`
- claim: > **[CONFIRMED]** The DC psscan shows tasklist.exe processes (2 instances, PIDs 7284 and 7612) and cmd.exe processes spanning 2018-09-01 through 2018-09-06, confirming domain enumeration was performed o…

### 🔍 not_confirmed _(line 109)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED]

### ✅ verified _(line 117)_
- tools: `vol3_psscan`
- exec_ids: `fdd7a66342eb`
- matched: `2524`, `2018-09-05T14:43:11Z`, `Rar.exe`
- claim: > **[CONFIRMED]** Data staging: Rar.exe (PID 2524, ppid=6352) ran on the **file server** for approximately 10 minutes, **2018-09-05T14:43:11Z → 14:52:56Z**, then exited cleanly — WinRAR archiving operat…

### ⚠ partial _(line 119)_
- tools: `vol3_netscan`
- exec_ids: `28631b698d07`
- matched: `1156`, `10.10.254.1`, `rubyw.exe`
- 🚨 negation violations (claimed absent but found): `10.10.4.5`
- claim: > **[CONFIRMED]** Exfiltration channel via Metasploit: rubyw.exe (PID 1156) on the file server has an ESTABLISHED TCP connection from 10.10.4.5:59361 → **10.10.254.1:61613** (Metasploit STOMP/ActiveMQ).…

### ✅ verified _(line 121)_
- tools: `vol3_netscan`
- exec_ids: `9b96e3f9c9be`
- matched: `172.16.6.11`, `52.16.55.11`, `13.89.220.65`
- claim: > **[CONFIRMED]** External HTTPS connections from rd01 (172.16.6.11): 172.16.6.11:49782 → 13.89.220.65:443 CLOSED (Azure) and 172.16.6.11:49360 → 52.16.55.11:443 CLOSED (AWS). Both HTTPS to cloud IPs — …

### ✅ verified _(line 123)_
- tools: `vol3_cmdline`, `vol3_psscan`
- exec_ids: `35b6b8378172`, `3a6834316f92`
- matched: `5144`, `powershell.exe`, `RemoteExchange.ps1`, `C:\Program`
- claim: > **[CONFIRMED]** The mail server Exchange Management Shell (powershell.exe PID 5144, full cmdline `. 'C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1'; Connect-ExchangeServer -aut…
