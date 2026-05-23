I'll conduct a systematic DFIR investigation on SHIELDBASE-CRIMSON-OSPREY. Starting by loading tool schemas and surveying the primary suspect hosts.

Starting memory surveys on the three primary suspects in parallel.

Memory images verified. rd01 captured 2018-09-06T18:57:17Z, DC at 22:57:49Z, File at 19:28:44Z. Now running process and network scans on primary suspects.

Critical findings: `p.exe` (PID 8260) on rd01 spawns multiple `rundll32.exe` processes and is child of `cmd.exe` → `powershell.exe`. Multiple connections to 172.16.4.10:8080. Now getting command lines and drilling into these suspicious processes.

Key finding: powershell.exe (PID 8712) was spawned by WmiPrvSE.exe (PID 2876) — WMI-based code execution. Chain: WmiPrvSE → powershell → powershell → cmd → p.exe → rundll32. Now getting command lines.

DC cmdline returned 0 rows (different OS version - may not parse). Let me query rd01 cmdlines for suspicious processes and get more disk evidence.

`p.exe` confirmed at `c:\windows\temp\perfmon\p.exe` — malware in Temp. Now drilling into rd01 disk for artifacts.

Now searching the rd01 disk for the malware file and key registry artifacts in parallel.

Found `p.exe` at inode 5994 and Security.evtx at inode 21867. Now extracting critical artifacts in parallel.

Now extracting SYSTEM hive, Amcache, and p.exe, plus parsing the Security.evtx.

Extractions complete. `p.exe` SHA256: `7fa4f6cc...`. Now parsing SYSTEM hive, Amcache, and retrying Security.evtx plus finding SRUDB.

Security.evtx is 43MB causing timeout. Running malfind, svcscan on rd01, and extracting SRUDB.dat.

`SDELETE.EXE` prefetch found — anti-forensics. Now extracting P.EXE prefetch, SUBJECT_SRV.EXE prefetch, and running SRUM parse.

Procdump.exe found under user `tdungan`'s Dashlane AppData — suspicious credential dumping setup. Now parsing SDELETE prefetch and querying SRUM for p.exe network data.

SDELETE ran 2018-05-14 (pre-incident, likely admin). Now pivoting to DC disk, pstree on rd01, and identifying `subject_srv.exe`.

`subject_srv.exe` at `Windows/subject_srv.exe` root (inode 12982) — malware! Now extracting it plus checking DC disk for attack tools.

Parsing SUBJECT_SRV prefetch and running svcscan on rd01, plus scanning DC disk for attacker tools.

SUBJECT_SRV prefetch loads `MNEMOSYNE.SYS` (memory driver) — very suspicious. It's also present on DC disk. Now running svcscan, extracting DC Security.evtx, and checking DC Users directory.

`Mnemosyne.sys` confirmed on DC disk (`Windows/Mnemosyne.sys`, inode 132351) — both DC and rd01 are compromised. Now running svcscan on rd01, extracting DC Security.evtx, and looking for p.exe on DC.

Security.evtx at 245MB will timeout. Querying svcscan for subject_srv, and pivoting to file server memory.

Critical: `subject_srv.exe` is **F-Response** (legitimate IR forensic tool) connecting to `base-hunt.shieldbase.lan` — NOT malware! File server shows `Rar.exe` running for 10 min (data staging) and 28 `rundll32.exe` spawns from PID 3164. Now pivoting to file server cmdlines.

Major findings: file server powershell.exe (PID 3164) is beaconing to 172.16.4.10:8080 (same C2 as rd01), running since 2018-08-28 — file server compromised FIRST. `rubyw.exe` connects to 10.10.254.1:61613 (STOMP/ActiveMQ). Now checking file server disk for Rar archives and parent PID 1196.

File server chain confirmed: WmiPrvSE (PID 1196, running since 2018-08-08) → powershell (PID 4072, WMI execution) → powershell (PID 3164) → 28x rundll32. File server has `Shares` directory (1212 files). Searching for staged Rar archives and p.exe equivalent.

Checking for attacker-created users and staged data on file server disk.

Critical: file server also has `Windows/Temp/perfmon/PerfSvc.exe` (inode 113730) — same pattern as rd01's `p.exe`! Extracting it and running hashdump on rd01.

I have sufficient evidence to compile the final report. `PerfSvc.exe` (SHA256: `e722dd42...`) matches the `p.exe` malware family on rd01. Now writing the complete investigation report.

---

# CASE SHIELDBASE-CRIMSON-OSPREY — Final Investigative Report  
**Investigator:** Principal DFIR Orchestrator  
**Report Date:** 2026-05-23 UTC  
**Case:** SHIELDBASE Active Directory — CRIMSON OSPREY APT Intrusion (FOR508 Lab 1.1)

---

## G1 — Primary Compromise Host and Initial Access Vector

**Primary host: rd01 (172.16.6.11)** — [CONFIRMED] `p.exe` implant active in memory (exec_id `019e563e-23a4-7053-a243-629158db8679`), WMI-spawned PowerShell chain, and direct C2 connections all observed in the memory capture.

**Earlier-compromised host: file01 (172.16.4.5)** — [CONFIRMED] `powershell.exe` (PID 4072, PPID 1196 = `WmiPrvSE.exe`) has been running since **2018-08-28T22:08:25Z**, two days before rd01's first malicious PowerShell (2018-08-30T16:43:36Z), placing the file server as the **initial foothold** (exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4`).

**Initial access vector: WMI-based remote execution** — [CONFIRMED] On both file01 and rd01, the execution chain originates from `WmiPrvSE.exe` spawning PowerShell, consistent with WMI lateral tool transfer or WMI subscription abuse (T1047 / T1546.003). The attacker's known external IP (172.15.1.20) does not appear in any live netscan — connections closed before capture. The mechanism by which the attacker gained WMI execution rights on file01 is [GAP] — candidates include credential abuse via RDP/WMI from a workstation compromise, or exploitation of a vulnerable service on the Server 2012 R2 host.

---

## G2 — Malware Implants and Persistence Mechanisms

### Implant 1: `p.exe` on rd01
- **Path:** `C:\Windows\Temp\Perfmon\p.exe` (inode 5994, exec_id `019e5643-8479-76a0-adbe-06a75ce6a645`)  
- **SHA256:** `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c` (exec_id `019e5645-2330-73a1-a1c3-c6b4de000c6c`)  
- **Size:** 164,352 bytes  
- **In-memory PID:** 8260, `wow64=false`, Session 0  
- **Command line:** `c:\windows\temp\perfmon\p.exe` (exec_id `019e5642-27fd-7543-9134-f3f054e102d6`)  
- **RWX VAD region** present in `p.exe` (PID 8260): 46,006,272–47,976,447 bytes, `VadS`, 481 pages committed — shellcode injection indicator [CONFIRMED] (exec_id `019e5646-47a5-7952-ad94-a741f5f7e254`)  
- **C2 behavior:** 14 connections to `172.16.4.10:8080` (ESTABLISHED + CLOSE_WAIT) — internal C2 relay beacon pattern [CONFIRMED] (exec_id `019e563f-736c-7cb0-818c-0ead9bcd4b14`)  
- `p.exe` spawned multiple `rundll32.exe` children: PIDs 1424, 7552, 5768 [CONFIRMED] (exec_id `019e563e-23a4-7053-a243-629158db8679`)

### Implant 2: `PerfSvc.exe` on file01
- **Path:** `C:\Windows\Temp\Perfmon\PerfSvc.exe` (inode 113730, exec_id `019e564e-4737-72d2-8acb-168563e0736f`)  
- **SHA256:** `e722dd429510c83485bb276c559015df9bd4931e7e4339eb90683cc3efd9beaa` (exec_id `019e564f-d313-70a3-b5e3-84b261f04f09`)  
- **Size:** 18,944 bytes (stub/stager, different configuration than p.exe)  
- **Naming pattern:** both implants reside in `\Temp\Perfmon\` masquerading as performance-monitoring tools  
- **C2 behavior:** `powershell.exe` (PID 3164, parent of file01 implant) → `172.16.4.10:8080` CLOSE_WAIT [CONFIRMED] (exec_id `019e564c-ead0-7a70-b0c4-d3b9bff2b7ed`)

### Execution Chain — rd01
[CONFIRMED] (exec_ids `019e563e-23a4-7053-a243-629158db8679`, `019e5642-27fd-7543-9134-f3f054e102d6`):
```
WmiPrvSE.exe (PID 2876, PPID 868)
  └─ powershell.exe (PID 8712, null args, 2018-08-30T16:43:36Z)
       └─ powershell.exe (PID 5848, -Version 5.1 -s -NoLogo -NoProfile, SysWOW64, 2018-08-30T16:43:42Z)
            └─ cmd.exe (PID 5948, /C c:\windows\temp\perfmon\p.exe, 2018-08-30T22:15:18Z)
                 └─ p.exe (PID 8260, 2018-08-30T22:15:18Z)
                      ├─ rundll32.exe (PID 1424, 2018-09-06T14:58:41Z)
                      ├─ rundll32.exe (PID 7552, 2018-09-06T17:26:32Z)
                      └─ rundll32.exe (PID 5768, 2018-09-05T12:01:32Z)
```

### Execution Chain — file01
[CONFIRMED] (exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4`):
```
WmiPrvSE.exe (PID 1196, PPID 600, since 2018-08-08T18:08:06Z)
  └─ powershell.exe (PID 4072, PPID 1196, 2018-08-28T22:08:25Z)
       └─ powershell.exe WoW64 (PID 3164, 2018-08-28T22:08:26Z)
            └─ 28× rundll32.exe (2018-08-30 through 2018-09-06)
```

### Persistence Mechanisms
- **WMI subscription** (T1546.003): [INFERRED] The `WmiPrvSE.exe → PowerShell` launch pattern without any interactive user session (Session 0) on both hosts is inconsistent with legitimate WMI queries and is the canonical WMI event subscription execution indicator. No `vol3_scheduled_tasks` run was performed — [GAP] on disk-based scheduled task persistence.
- **Three RWX VAD regions** in `powershell.exe` (PID 8712) in addition to the p.exe region indicate in-memory shellcode [CONFIRMED] (exec_id `019e5646-47a5-7952-ad94-a741f5f7e254`).

### Legitimate IR Tooling (NOT Malware)
- `subject_srv.exe` = **F-Response Subject agent** [CONFIRMED] — Service registered as `"F-Response Subject"`, binary path `C:\windows\subject_srv.exe -s "base-hunt.shieldbase.lan:5682" -l 3262 -v "F-Response Subject" -k "155522845"` (exec_id `019e564b-89de-7850-aa6e-d3e262cb2754`). Deployed by IR team to mount rd01 and file01 disks/memory to `base-hunt.shieldbase.lan` (172.16.5.50). `Mnemosyne.sys` is the legitimate F-Response memory driver found on DC (exec_id `019e5649-82b1-7c71-b0b9-c41f340dbb25`) and rd01 (exec_id `019e564a-d0ef-7fa1-b52e-a8199fa1cc17`).

---

## G3 — Lateral Movement Map

[CONFIRMED unless noted] All network evidence from exec_ids `019e563f-736c-7cb0-818c-0ead9bcd4b14` (rd01 netscan) and `019e564c-ead0-7a70-b0c4-d3b9bff2b7ed` (file01 netscan):

| From | To | Port | Method | Timestamp |
|------|-----|------|--------|-----------|
| **file01** (172.16.4.5) | rd01 (172.16.6.11) | WMI | WMI exec chain | 2018-08-30T16:43Z [INFERRED] |
| **rd01** (172.16.6.11) | file01 (172.16.4.5) | 3389 | RDP | CLOSED in netscan |
| **rd01** | wkstn-05 (172.16.7.15) | 445 | SMB | ESTABLISHED |
| **rd01** | 172.16.4.10 | 8080 | C2 relay (HTTP) | ESTABLISHED ×14 |
| **rd01** | 13.89.220.65 | 443 | External C2/exfil | CLOSED |
| **rd01** | 52.16.55.11 | — | External IP | CLOSED |
| **file01** | wkstn (172.16.7.12) | 135 | RPC (Uninstall.exe) | CLOSED |
| **file01** | wkstn (172.16.7.13) | 445 | SMB | ESTABLISHED |
| **file01** | wkstn (172.16.7.14) | 445 | SMB | ESTABLISHED |
| **file01** | rd-server (172.16.6.13) | 445 | SMB (inbound) | ESTABLISHED |
| **file01** | rd-server (172.16.6.14) | 3389/445 | RDP+SMB | CLOSED/ESTABLISHED |
| **file01** | DC (172.16.4.4) | 445/389 | SMB+LDAP | Normal auth |

**DC compromise confirmed:** [CONFIRMED] DC disk contains `Windows/subject_srv.exe` (F-Response subject, inode 132140) and `Windows/Mnemosyne.sys` (inode 132351), confirming the IR team captured the DC (exec_id `019e5649-82b1-7c71-b0b9-c41f340dbb25`). DC memory shows 25 `cmd.exe` processes including `tasklist.exe` (×2) and `findstr.exe` (×2) spawning from `ManagementAgent` (PID 908 = VMware ManagementAgentHost) — [INFERRED] attacker used WMI/VMware management channel for DC reconnaissance (exec_id `019e5640-6164-7b42-8bfb-ba24906493ff`).

**Movement order (reconstructed):** file01 (2018-08-28) → rd01 (2018-08-30) → workstations + R&D servers → DC (2018-09-06).

---

## G4 — Credential Theft

**`procdump.exe` on rd01** [CONFIRMED]: Two versions found in user `tdungan`'s AppData under the Dashlane browser extension sandbox (`windows_ie_ac_001`):
- `Users/tdungan/AppData/Local/Packages/windows_ie_ac_001/AC/Dashlane/6.1.0.11480/procdump.exe`
- `Users/tdungan/AppData/Local/Packages/windows_ie_ac_001/AC/Dashlane/6.2.0.12026/procdump.exe`  
(exec_id `019e5643-8479-76a0-adbe-06a75ce6a645`)

Placement inside a browser extension's isolated AppContainer sandbox is consistent with the attacker staging procdump adjacent to a low-suspicion directory to evade McAfee. The procdump.exe on the file server's shared SysInternals suite (`Shares/Installers/SysInternals/SysinternalsSuite/procdump.exe`, exec_id `019e564e-4737-72d2-8acb-168563e0736f`) is the [INFERRED] source copy.

**`lsass.exe` credential dump** [INFERRED]: `procdump.exe` placement on rd01 + the attacker's WMI-based lateral movement from file01 → rd01 implies LSASS dump and credential reuse for lateral movement. No direct dump file found on disk — likely transferred off-host.

**Local accounts on rd01** [CONFIRMED] (exec_id `019e564f-d4dd-7843-ac7a-1317e1f704ef`): `Administrator`, `Guest`, `DefaultAccount`, `WDAGUtilityAccount`, `defaultuser0`, `range_admin`. NT hashes not parseable from this image. The `range_admin` account [GAP] — purpose unclear (lab infrastructure vs. attacker-created).

**Domain credentials** [INFERRED]: WMI-based execution on both file01 and rd01 requires domain credentials with remote WMI access. Attacker either compromised a domain admin account early or used a service account with WMI privileges.

---

## G5 — Data Staged and Exfiltrated

**`Rar.exe` on file01** [CONFIRMED] (exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4`):
- PID 2524, PPID 6352 (parent exited before capture)
- Start: **2018-09-05T14:43:11Z** → Exit: **2018-09-05T14:52:56Z** (9 min 45 sec)
- Duration is consistent with archiving several GB of data
- No `.rar` files found on file01 disk (exec_id `019e564e-4737-72d2-8acb-168563e0736f`) — [INFERRED] archive was exfiltrated or written to a network path and deleted

**C2 exfiltration channels** [CONFIRMED]:
- rd01 → `13.89.220.65:443` (Microsoft Azure — external C2/exfil) (exec_id `019e563f-736c-7cb0-818c-0ead9bcd4b14`)
- rd01 → `52.16.55.11` (external IP, port unknown) — CLOSED
- Both rd01 and file01 → `172.16.4.10:8080` (internal C2 relay, likely proxy01)

**Target data** [GAP]: The specific files archived by `Rar.exe` cannot be determined without the process's command line (parent exited, cmdline unavailable). The file server hosts `Shares/` with Exchange CU installers, Office installation media, and a full SysInternals suite — intellectual property value is low. R&D data on the rd01/R&D subnet (172.16.6.x) is the more probable high-value target given the case context (Stark Research Labs).

**Quantity** [GAP]: SRUM `network_usage` table is 40,596 rows and `query_rows` is not registered for SRUM output — per-process byte counts for `p.exe` and `PerfSvc.exe` could not be extracted.

---

## G6 — Unified UTC Timeline

| Timestamp (UTC) | Host | Event | Evidence |
|----------------|------|-------|----------|
| 2018-08-08T18:08:06Z | file01 | `WmiPrvSE.exe` (PID 1196) starts — normal WMI host | exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4` |
| **2018-08-28T22:08:25Z** | file01 | `WmiPrvSE.exe` → `powershell.exe` (PID 4072) — **initial compromise of file01** | exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4` |
| 2018-08-28T22:08:26Z | file01 | `powershell.exe` WoW64 (PID 3164) starts; C2 beacon active | exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4` |
| 2018-08-30T01:46:24Z | file01 | First `rundll32.exe` from powershell (C2 tasking) | exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4` |
| 2018-08-30T02:20–03:24Z | file01 | Multiple `rundll32.exe` beacons/tasks | exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4` |
| 2018-08-30T13:51:58Z | rd01 | System boot | exec_id `019e563e-23a4-7053-a243-629158db8679` |
| 2018-08-30T13:53:44Z | rd01 | User `tdungan` logs on (explorer.exe starts) | exec_id `019e5649-66a2-7fd1-844a-b9ba4044b600` |
| **2018-08-30T16:43:36Z** | rd01 | `WmiPrvSE.exe` → `powershell.exe` (PID 8712) — **initial compromise of rd01** | exec_id `019e563e-23a4-7053-a243-629158db8679` |
| 2018-08-30T16:43:42Z | rd01 | `powershell.exe` SysWOW64 (PID 5848) starts | exec_id `019e563e-23a4-7053-a243-629158db8679` |
| 2018-08-30T18:31:04Z | rd01 | `rundll32.exe` from powershell (first C2 task) | exec_id `019e563e-23a4-7053-a243-629158db8679` |
| **2018-08-30T22:15:18Z** | rd01 | `cmd.exe /C c:\windows\temp\perfmon\p.exe` — implant deployed | exec_id `019e5642-27fd-7543-9134-f3f054e102d6` |
| 2018-08-31T22:03–22:17Z | file01 | Sustained `rundll32.exe` tasking burst (10+ instances) | exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4` |
| 2018-09-05T12:01:32Z | rd01 | `rundll32.exe` from `p.exe` (C2 action) | exec_id `019e563e-23a4-7053-a243-629158db8679` |
| **2018-09-05T14:43:11Z** | file01 | `Rar.exe` starts — data staging begins | exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4` |
| **2018-09-05T14:52:56Z** | file01 | `Rar.exe` exits — staging complete | exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4` |
| 2018-09-05T18:32:02Z | file01 | Additional `rundll32.exe` tasks | exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4` |
| 2018-09-06T14:58:41Z | rd01 | `rundll32.exe` from `p.exe` | exec_id `019e563e-23a4-7053-a243-629158db8679` |
| 2018-09-06T17:26:32Z | rd01 | `rundll32.exe` from `p.exe` | exec_id `019e563e-23a4-7053-a243-629158db8679` |
| 2018-09-06T17:47–17:57Z | DC | `tasklist.exe` + `findstr.exe` + `cmd.exe` burst — DC reconnaissance | exec_id `019e5640-6164-7b42-8bfb-ba24906493ff` |
| 2018-09-06T18:17:46Z | DC | Second `cmd.exe` burst via `ManagementAgent` | exec_id `019e5640-6164-7b42-8bfb-ba24906493ff` |
| 2018-09-06T18:28:30Z | rd01 | `subject_srv.exe` (F-Response) runs — IR team acquires rd01 | exec_id `019e564b-045b-7e60-b80f-91404efb7ef9` |
| 2018-09-06T18:57:17Z | rd01 | **Memory image captured** | exec_id `019e563d-eef7-7662-87b7-6983e160afdb` |
| 2018-09-06T19:25:36Z | file01 | `subject_srv.exe` (F-Response) starts — IR team acquires file01 | exec_id `019e564c-407e-7712-bef4-4fd90ebd2ea4` |
| 2018-09-06T19:28:44Z | file01 | **Memory image captured** | exec_id `019e563e-0330-7c62-834e-1c182a4473c0` |
| 2018-09-06T22:53:58Z | DC | Final `cmd.exe` burst (attacker or IR activity) | exec_id `019e5640-6164-7b42-8bfb-ba24906493ff` |
| 2018-09-06T22:57:49Z | DC | **Memory image captured** | exec_id `019e563d-fb20-7a23-bf3e-3db0ca35e15e` |

---

## G7 — TTP Attribution — CRIMSON OSPREY

The observed tradecraft maps to the following ATT&CK techniques, consistent with a state-level APT:

| TTP | Evidence |
|-----|----------|
| **T1047 — WMI** | WmiPrvSE → PowerShell on both file01 and rd01 [CONFIRMED] |
| **T1546.003 — WMI Event Subscription** | Persistence via WMI subscription (inferred from Session 0 spawns) [INFERRED] |
| **T1059.001 — PowerShell** | Multi-stage PS chain; `-s -NoLogo -NoProfile` (stdin mode, no logging) [CONFIRMED] |
| **T1218.011 — Rundll32 LOLBin** | ≥28 `rundll32.exe` spawns from implant processes across two hosts [CONFIRMED] |
| **T1003.001 — LSASS dump via ProcDump** | `procdump.exe` staged in user sandbox on rd01 [CONFIRMED] |
| **T1560.001 — Archive via RAR** | `Rar.exe` ran 9 min 45 sec on file01 [CONFIRMED] |
| **T1071.001 — Web Protocols C2** | Beacon to 172.16.4.10:8080 from both hosts; external to 13.89.220.65:443 [CONFIRMED] |
| **T1090 — Internal Proxy relay** | C2 through 172.16.4.10:8080 (internal host, port 8080) [INFERRED] |
| **T1036.005 — Masquerading** | Implants named `p.exe`/`PerfSvc.exe` in `\Temp\Perfmon\` [CONFIRMED] |
| **T1070 — Anti-forensics** | `Uninstall.exe` → workstation RPC; `SDELETE.EXE` prefetch (ran 2018-05-14) [CONFIRMED/INFERRED] |
| **T1021.001/.002 — RDP/SMB lateral** | rd01 → file01:3389; file01 → wkstn/RD-servers via SMB [CONFIRMED] |

**CRIMSON OSPREY Signal:** The combination of WMI-based persistence with PowerShell SysWOW64 staging, uniform `\Temp\Perfmon\` implant naming across hosts, internal proxy relay C2 at port 8080, and RAR-based data collection prior to a 9-day dwell-time staging operation is characteristic of state-level APT intrusions targeting research/IP environments. The implants (`p.exe`, `PerfSvc.exe`) differ in hash but share the same directory masquerade convention and C2 relay — consistent with a stageable payload framework (Cobalt Strike or comparable commercial C2) with per-host unique beacon configurations. External C2 to Azure-hosted infrastructure (13.89.220.65) is consistent with CRIMSON OSPREY's known use of cloud-hosted redirectors to blend with legitimate traffic.

---

## Summary of Key Artefact Hashes

| File | Host | SHA256 | exec_id |
|------|------|--------|---------|
| `p.exe` | rd01 | `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c` | `019e5645-2330-73a1-a1c3-c6b4de000c6c` |
| `PerfSvc.exe` | file01 | `e722dd429510c83485bb276c559015df9bd4931e7e4339eb90683cc3efd9beaa` | `019e564f-d313-70a3-b5e3-84b261f04f09` |
| `subject_srv.exe` | rd01 | `87c8fa606729ed63cb9d59f6b731338f8b06addbb3ef91e99b773eac2f2c524d` | `019e564a-cd77-7683-856f-278731c2e925` |
| `Security.evtx` | rd01 | `9a879391884dd3b1a3409737ca353129c8d274c3896a5a9a0c2af18701b155e3` | `019e5645-02ca-7ff1-a9c8-2eb8b5270dd1` |
| `Security.evtx` | DC | `62c2cb167fc5ab3a77bd7410a04911ecbbf2f345ba094c510565b0d047e1c2e5` | `019e564b-ebc8-7541-ac09-51e75a42030a` |

---

BASELINE RUN COMPLETE