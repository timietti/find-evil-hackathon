# Validator Report — iter_1

## Summary

- Total tagged claims:        **55**
  - CONFIRMED:                 35
  - INFERRED:                  7
  - HYPOTHESIS:                8
  - GAP:                       5
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           2 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                4 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           27 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 5.7%** (2 verified / 35 confirmed)

## Per-claim verdicts

### ⚠ partial _(line 97)_
- tools: `vol3_psscan`, `tsk_fls_list`
- exec_ids: `8891e848f830`, `0b57ffab283c`
- matched: `Rar.exe`, `rubyw.exe`, `Chocolatey`, `.rb`, `PowerShell`
- **missing**: `10.10.254.1`, `172.16.4.5`, `base-file-cdrive.E01`, `10.10.254.1:61613`
- claim: > ### Finding 1.1 — Earliest Compromised Host: File Server (file01) **[CONFIRMED]** The file server (172.16.4.5, `base-file-cdrive.E01`) shows evidence of compromise dating to **2018-08-28**, two days b…

### 🔍 not_confirmed _(line 104)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > ### Finding 1.2 — Primary Implant Host: rd01 **[CONFIRMED]** rd01 (172.16.6.11) is the most forensically rich compromise host, containing the primary active backdoor `p.exe` and the clearest attacker …

### ❌ failed _(line 113)_
- tools: `vol3_cmdline`, `vol3_psscan`
- exec_ids: `1c61f74282b0`, `d58e3bbb3cd2`
- **missing**: `vol3_psscan`, `vol3_cmdline`
- claim: > ### Finding 1.4 — Attacker Execution Chain on rd01 **[CONFIRMED]** The attack chain reconstructed from `vol3_cmdline` (exec_id: `019e597d-1cd6-7662-8c3a-1c61f74282b0`) and `vol3_psscan` (exec_id: `019…

### 🔍 not_confirmed _(line 130)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > ### Finding 2.1 — p.exe: Primary Backdoor on rd01 **[CONFIRMED]**

### ⚠ partial _(line 145)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `rubyw.exe`
- **missing**: `10.10.254.1`, `.rb`, `base-file-memory.img`, `10.10.254.1:61613`
- claim: > ### Finding 2.2 — Ruby STOMP Implant on File Server **[CONFIRMED]** Memory psscan of `base-file-memory.img` (exec_id: `019e5991-e973-74e2-bcbd-8891e848f830`) reveals `rubyw.exe` (Ruby Windows GUI proc…

### ⚠ partial _(line 148)_
- tools: `tsk_icat_extract`
- exec_ids: `756eee9a33fc`
- matched: `185325`, `57a04605ae0e308a0410b15f5478457417f03fcecf6eb30db7abb6409257429f`
- **missing**: `ri.exe`
- claim: > ### Finding 2.3 — ri.exe: Suspected Credential/Recon Tool **[CONFIRMED artifact; HYPOTHESIS purpose]** `ri.exe` (inode 185325, SHA-256: `57a04605ae0e308a0410b15f5478457417f03fcecf6eb30db7abb6409257429…

### 🔍 not_confirmed _(line 162)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > ### Finding 3.1 — Movement Timeline **[CONFIRMED/INFERRED]**

### 🔍 not_confirmed _(line 172)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > file01 (172.16.4.5) ← EARLIEST COMPROMISE     │ Ruby STOMP implant → 10.10.254.1:61613     │ Rar.exe data staging     │     ▼ [CONFIRMED: WMI lateral movement]

### 🔍 not_confirmed _(line 177)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > rd01 (172.16.6.11) ← PRIMARY IMPLANT HOST     │ WmiPrvSE.exe → powershell.exe → p.exe     │ p.exe → 172.16.4.10:8080 (C2 relay)     │     ├─▶ wkstn-01 (172.16.7.11) [CONFIRMED: 7 closed TCP/8080 conne…

### 🔍 not_confirmed _(line 179)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > │     └─▶ 172.16.4.10 ← C2 RELAY/PIVOT HOST [CONFIRMED as hub; identity [GAP]

### ✅ verified _(line 183)_
- tools: `vol3_netscan`, `vol3_netscan`, `vol3_netscan`
- exec_ids: `0358e8a16035`, `117e3451809a`, `cb18611fee86`
- matched: `172.16.4.10`, `p.exe`
- claim: > ### Finding 3.2 — C2 Relay Host (172.16.4.10) **[CONFIRMED]** Three hosts show connections to **172.16.4.10 port 8080**: - rd01: active p.exe C2 channel (vol3_netscan exec_id: `019e597b-fc85-75d3-bff1…

### 🔍 not_confirmed _(line 191)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > ### Finding 3.3 — Lateral Movement Methods **[CONFIRMED]

### ❌ failed _(line 200)_
- tools: `vol3_cachedump`
- exec_ids: `be8292d9d088`
- **missing**: `vol3_cachedump`
- claim: > ### Finding 4.1 — Domain Credentials Cached on rd01 **[CONFIRMED]** `vol3_cachedump` on rd01 (exec_id: `019e5999-1923-7dc1-ab8a-be8292d9d088`) recovered two MSCASH/DCC2 domain credential hashes:

### ⚠ partial _(line 210)_
- tools: `vol3_hashdump`
- exec_ids: `f7083bd0d3a4`
- matched: `range_admin`
- **missing**: `vol3_hashdump`
- claim: > ### Finding 4.2 — SAM Local Accounts on rd01 **[CONFIRMED]** `vol3_hashdump` (exec_id: `019e5999-092b-7230-ba7a-f7083bd0d3a4`) returned 6 local accounts: Administrator, Guest, DefaultAccount, WDAGUtil…

### ✅ verified _(line 223)_
- tools: `vol3_psscan`, `tsk_fls_list`
- exec_ids: `8891e848f830`, `0b57ffab283c`
- matched: `Rar.exe`, `Shares/`
- claim: > ### Finding 5.1 — Data Staging on File Server **[CONFIRMED]** The file server memory image (exec_id: `019e5991-e973-74e2-bcbd-8891e848f830`) shows `Rar.exe` execution, consistent with T1560.001 (Archi…

### 🔍 not_confirmed _(line 226)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > ### Finding 5.2 — C2 Exfiltration Channels **[CONFIRMED]** Two distinct exfiltration channels identified: 1. **HTTP/8080 → 172.16.4.10** (internal relay): Used by p.exe on rd01, rundll32/PowerShell on…

### 🔍 not_confirmed _(line 243)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | `019e5995-31eb-7720-9803-0332a5a39dc3` | | **2018-08-28** | **File server compromised** — Ruby STOMP implant established; Rar.exe staging begins | **[CONFIRMED]

### 🔍 not_confirmed _(line 245)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | `019e5999-29aa-75f2-a7c5-208d97db63c1` | | 2018-08-30T14:33:11Z | "Proxy" scheduled task created on rd01 (acproxy.dll) | [CONFIRMED]

### 🔍 not_confirmed _(line 246)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | `019e5999-29aa-75f2-a7c5-208d97db63c1` | | **2018-08-30T22:15:18Z** | **p.exe first executed on rd01** (prefetch last-run) | **[CONFIRMED]

### 🔍 not_confirmed _(line 247)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > ** | `019e5986-75ce-7382-9526-76f791917a71` | | 2018-09-05T15:48:20Z | Exchange server (172.16.4.6) memory captured — earliest capture | [CONFIRMED]

### 🔍 not_confirmed _(line 248)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | `019e598d-c83e-7a21-b6f7-3fdaef5c387f` | | 2018-09-06 (day) | Multiple hosts showing sc.exe, sd.exe, cmd.exe activity — attacker operational phase | [CONFIRMED]

### 🔍 not_confirmed _(line 249)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | multiple | | 2018-09-06T17:15:31Z | sc.exe executed on wkstn-01 (service manipulation) | [CONFIRMED]

### 🔍 not_confirmed _(line 250)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | `019e5995-31eb-7720-9803-0332a5a39dc3` | | 2018-09-06T18:57:17Z | rd01 memory captured (p.exe active, connections open) | [CONFIRMED]

### 🔍 not_confirmed _(line 251)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | `019e5979-fe75-76b2-affc-9ad475cf8a75` | | 2018-09-06T19:28:44Z | File server memory captured (rubyw.exe active) | [CONFIRMED]

### 🔍 not_confirmed _(line 252)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | `019e597a-0f87-7353-8f83-3bd2c11fcb45` | | 2018-09-06T22:57:49Z | DC memory captured | [CONFIRMED]

### 🔍 not_confirmed _(line 265)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Execution | Windows Management Instrumentation | T1047 | WmiPrvSE.exe → powershell.exe chain [CONFIRMED]

### 🔍 not_confirmed _(line 266)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Nested powershell.exe under WmiPrvSE [CONFIRMED]

### 🔍 not_confirmed _(line 267)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Execution | Command and Scripting Interpreter: Ruby | T1059.004 | 3,286 .rb files, rubyw.exe execution [CONFIRMED]

### 🔍 not_confirmed _(line 269)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Defense Evasion | Process Injection (shellcode via RWX) | T1055 | malfind RWX private memory on p.exe [CONFIRMED]

### 🔍 not_confirmed _(line 271)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Credential Access | OS Credential Dumping: Cached Domain Credentials | T1003.005 | DCC2 hashes for tdungan/spsql on rd01 [CONFIRMED]

### 🔍 not_confirmed _(line 273)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Discovery | System Service Discovery / Recon | T1007 | sc.exe, Autorunsc.exe on wkstn-01 [CONFIRMED]

### 🔍 not_confirmed _(line 274)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Lateral Movement | Remote Services: Windows Management Instrumentation | T1021.003 | WMI parent on rd01 [CONFIRMED]

### 🔍 not_confirmed _(line 275)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Collection | Archive Collected Data: Archive via Utility | T1560.001 | Rar.exe on file server [CONFIRMED]

### 🔍 not_confirmed _(line 276)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP C2 over port 8080 to internal relay [CONFIRMED]

### 🔍 not_confirmed _(line 277)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Command & Control | Application Layer Protocol: Mail Protocols (STOMP) | T1071.003 | STOMP/61613 rubyw.exe channel [CONFIRMED]
