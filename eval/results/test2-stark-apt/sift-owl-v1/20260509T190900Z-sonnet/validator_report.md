# Validator Report — 20260509T190900Z-sonnet

## Summary

- Total tagged claims:        **60**
  - CONFIRMED:                 24
  - INFERRED:                  18
  - HYPOTHESIS:                1
  - GAP:                       17
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           7 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                15 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           2 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 29.2%** (7 verified / 24 confirmed)

## Per-claim verdicts

### ⚠ partial _(line 77)_
- tools: `vol3_psscan`
- exec_ids: `3e25052c1a74`
- matched: `556`, `27304`, `2012-03-20T17:58:12Z`, `services.exe`, `usboesrv.exe`
- **missing**: `\Windows\system32\usboesrv.exe``, `C:\Windows\system32\usboesrv.exe``, `C:\Windows\system32\usboesrv.exe`
- claim: > **`usboesrv.exe` (PID 27304)** — PRIMARY IMPLANT   [CONFIRMED — exec_id 019e0e26-3e83-7ca0-beb7-3e25052c1a74]   - Spawned by `services.exe` (PID 556), created **2012-03-20T17:58:12Z** - Binary: `C:\Wi…

### ✅ verified _(line 84)_
- tools: `vol3_netscan`, `vol3_netscan`
- exec_ids: `84774dc8a202`, `d21e2d675bc4`
- matched: `10.3.58.4`, `96.255.98.154`, `usboesrv.exe`
- claim: > **`usboesrv.exe` — C2 Connections**   [CONFIRMED — exec_id 019e0e26-d010-76a2-a909-84774dc8a202, query 019e0e27-13e6-7543-ba8f-d21e2d675bc4]   Three ESTABLISHED TCP connections from DC to **96.255.98.…

### ⚠ partial _(line 95)_
- tools: `vol3_svcscan`
- exec_ids: `bdf8ffcac48e`
- matched: `usboesrv.exe`, `SERVICE_DEMAND_START`, `SERVICE_AUTO_START`
- **missing**: `\Windows\system32\usboesrv.exe``, `C:\Windows\system32\usboesrv.exe``, `\Driver\usboeloaderdrv`, `\Driver\usboebusdrv`, `C:\Windows\system32\usboesrv.exe`
- claim: > [CONFIRMED — exec_id 019e0e27-d3ef-7011-9311-bdf8ffcac48e]   Service registration: - **usboesrv**: `SERVICE_AUTO_START`, binary `C:\Windows\system32\usboesrv.exe` - **usboebusdrv**: kernel driver, `SE…

### ⚠ partial _(line 106)_
- tools: `vol3_filescan`
- exec_ids: `3e5e98f88195`
- matched: `usboesrv.exe`
- **missing**: `\Windows\System32\usboesrv.exe``, `\Windows\System32\usboesrv.exe`
- claim: > [CONFIRMED — exec_id 019e0e2d-0586-78e2-aa07-3e5e98f88195]   `\Windows\System32\usboesrv.exe` — confirmed present in DC file object pool.

### ❓ unverifiable _(line 113)_
- exec_ids: `628d876de324`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e0e2a-8fd2-79d3-b454-628d876de324]

### ⚠ partial _(line 126)_
- tools: `vol3_userassist`
- exec_ids: `628d876de324`
- matched: `4.0.0.3`, `2012-03-20T18:54:16Z`, `2012-04-05T22:23:04Z`, `2012-03-20T17:56:42Z`, `2012-03-20T17:57:33Z`, `Tcpview.exe`, `hMailAdmin.exe`, `usboe.exe` (+6 more)
- **missing**: `usboesrv.exe`, `\Users\rsydow\AppData\Local\Temp\2\Temp1_usb-over-ethernet.zip\setup.exe``, `C:\Users\rsydow\AppData\Local\Temp\2\Temp1_usb-over-ethernet.zip\setup.exe``, `C:\Tools\SysInternals\Tcpview.exe``, `C:\Tools\SysInternals\sdelete.exe``, `P:\Security`, `C:\Users\rsydow\AppData\Local\Temp\2\Temp1_usb-over-ethernet.zip\setup.exe`, `P:\Security Tools\F-ResponseEnterprise-4.0.0.3-EN\...exe` (+5 more)
- claim: > **User `rsydow` (DC sysadmin, possibly compromised):** - `C:\Users\rsydow\AppData\Local\Temp\2\Temp1_usb-over-ethernet.zip\setup.exe` — ran at **2012-03-20T17:57:33Z** — this is the installation event…

### ✅ verified _(line 136)_
- tools: `vol3_pstree`
- exec_ids: `4b9683991279`
- matched: `138320`, `151132`, `137496`, `148904`, `8512`, `139776`, `2012-04-04T18:55:57Z`, `winlogon.exe` (+7 more)
- claim: > [CONFIRMED — exec_id 019e0e27-d07f-7d71-8d44-4b9683991279]   **Session 3 (vibranium — attacker):** `winlogon.exe` (PID 138320), `explorer.exe` (PID 139776), `cmd.exe` (PID 137496, created 2012-04-04T1…

### ⚠ partial _(line 140)_
- tools: `vol3_netscan`
- exec_ids: `84774dc8a202`
- matched: `10.3.16.5`, `10.3.58.4`
- **missing**: `10.3.58.4:3389 ← 10.3.16.5:46758`
- claim: > [CONFIRMED — exec_id 019e0e26-d010-76a2-a909-84774dc8a202]   External RDP connection: `10.3.58.4:3389 ← 10.3.16.5:46758` ESTABLISHED — examiner's workstation connected to DC at time of capture.

### ⚠ partial _(line 145)_
- tools: `vol3_netscan`
- exec_ids: `84774dc8a202`
- matched: `564`, `56.171.18.32`, `56.91.239.31`, `40.167.16.32`, `10.3.58.9`, `10.3.58.5`, `lsass.exe`
- **missing**: `System (pid=4): 10.3.58.4:443 → 173.173.88.154:18682 ESTABLISHED`, `lsass.exe → 10.3.58.5:49236 CLOSED`, `lsass.exe (pid=564)`, `10.3.58.9:445 → 10.3.58.5:49805 ESTABLISHED (System)`
- 🚨 negation violations (claimed absent but found): `4`, `173.173.88.154`, `10.3.58.4`
- claim: > [CONFIRMED — exec_id 019e0e26-d010-76a2-a909-84774dc8a202]   - `System (pid=4): 10.3.58.4:443 → 173.173.88.154:18682 ESTABLISHED` — SSL/HTTPS connection from the System process (not a user application…

### ⚠ partial _(line 153)_
- tools: `vol3_malfind`
- exec_ids: `7892e62ee8a6`
- matched: `152840`, `w3wp.exe`
- **missing**: `tlntsvr.exe`
- claim: > [CONFIRMED — exec_id 019e0e28-c41b-7f12-86b8-7892e62ee8a6]   `w3wp.exe` (IIS worker, PID 152840) has two RWX private VAD regions. `w3wp.exe` cmdline is null. [INFERRED] RWX regions in an IIS worker pr…

### ⚠ partial _(line 160)_
- tools: `vol3_psscan`
- exec_ids: `3e25052c1a74`
- matched: `1720`, `152840`, `3928`, `153192`, `3732`, `2012-04-06T23:29:40Z`, `2012-04-06T23:24:05Z`, `tlntsvr.exe` (+4 more)
- **missing**: `40.167.16.32`, `hMailServer.exe`
- claim: > - `tlntsvr.exe` (PID 3928): Telnet server running — plaintext credential interception risk [CONFIRMED — exec_id 019e0e26-3e83-7ca0-beb7-3e25052c1a74] - `Apache.exe` (PID 3732) + `tomcat5.exe`: McAfee …

### ✅ verified _(line 176)_
- tools: `vol3_netscan`
- exec_ids: `84774dc8a202`
- matched: `10.3.58.9`, `10.3.58.5`, `lsass.exe`
- claim: > **Indirect evidence from DC:** [CONFIRMED — exec_id 019e0e26-d010-76a2-a909-84774dc8a202]   - DC (10.3.58.9:445) → nromanoff (10.3.58.5:49805) ESTABLISHED at capture time — DC SMB to nromanoff live - …

### ✅ verified _(line 193)_
- tools: `vol3_psscan`
- exec_ids: `73e3e9b33f30`
- ✅ verified absences (negated): `pe.exe`, `UdaterUI.exe`, `spinlock.exe`
- claim: > [CONFIRMED — exec_id 019e0e26-7d45-7302-bef8-73e3e9b33f30]   38 processes total — all standard Windows processes plus McAfee AV suite, VMware Tools, and F-Response examiner tool. No spinlock.exe, pe.e…

### ⚠ partial _(line 204)_
- tools: `vol3_netscan`
- exec_ids: `d21e2d675bc4`
- matched: `552`, `10.3.58.6`, `56.251.168.26`, `10.3.16.5`, `10.3.58.4`, `lsass.exe`
- **missing**: `lsass.exe (pid=552)`, `10.3.58.6:49325 → 10.3.58.4:139 CLOSED`, `10.3.58.6:49265 → 10.3.16.5:389 CLOSED`
- claim: > [CONFIRMED — exec_id 019e0e27-13e6-7543-ba8f-d21e2d675bc4]   - `lsass.exe (pid=552)` → `56.251.168.26` CLOSED — lsass connecting to external IP. [INFERRED] Residual pool entry; lsass made an outbound …

### ❓ unverifiable _(line 221)_
- exec_ids: `d6cfa0d5ff3f`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e0e26-b5a6-7602-9d54-d6cfa0d5ff3f]

### ✅ verified _(line 245)_
- tools: `vol3_psscan`
- exec_ids: `d6cfa0d5ff3f`
- matched: `2920`, `3092`, `2012-04-06T19:07:04Z`, `McTray.exe`, `UdaterUI.exe`, `FrameworkServic`
- claim: > **`UdaterUI.exe`** (PID 2920, PPID 644=`FrameworkServic`) — SUSPICIOUS TOOL   [CONFIRMED — exec_id 019e0e26-b5a6-7602-9d54-d6cfa0d5ff3f]   Created 2012-04-06T19:07:04Z. Name is a deliberate misspellin…

### ⚠ partial _(line 279)_
- tools: `vol3_userassist`
- exec_ids: `628d876de324`
- matched: `spinlock.exe`
- **missing**: `2012-04-05T17:16Z`, `2012-04-04T18:31Z`
- claim: > [CONFIRMED — exec_id 019e0e2a-8fd2-79d3-b454-628d876de324] **DC → tdungan (or vice versa):** `spinlock.exe` deployed on DC (first run by vibranium 2012-04-04T18:31Z) then on tdungan (2012-04-05T17:16Z…

### ✅ verified _(line 281)_
- tools: `vol3_netscan`
- exec_ids: `84774dc8a202`
- matched: `10.3.58.9`, `10.3.58.5`
- claim: > [CONFIRMED — exec_id 019e0e26-d010-76a2-a909-84774dc8a202] **DC → nromanoff:** DC (10.3.58.9:445) has an ESTABLISHED SMB connection to nromanoff (10.3.58.5:49805) at capture time. DC's lsass also had …

### ✅ verified _(line 298)_
- tools: `vol3_svcscan`
- exec_ids: `bdf8ffcac48e`
- ✅ verified absences (negated): `spinlock.exe`, `spinlock`
- claim: > [CONFIRMED — exec_id 019e0e27-d3ef-7011-9311-bdf8ffcac48e] No `spinlock` service entry found on DC. `spinlock.exe` was run interactively but may rely on a scheduled task or run key (registry-based) fo…

### ⚠ partial _(line 304)_
- tools: `vol3_netscan`, `vol3_cmdline`
- exec_ids: `84774dc8a202`, `6bfb1af4e973`
- matched: `96.255.98.154`, `usboesrv.exe`
- **missing**: `96.255.98.154:29932`
- claim: > [CONFIRMED — exec_id 019e0e26-d010-76a2-a909-84774dc8a202, 019e0e27-c4bc-7833-8e96-6bfb1af4e973]   **Primary exfiltration channel:** `usboesrv.exe` (DC) → `96.255.98.154:29932` — 3 simultaneous TCP co…

### ⚠ partial _(line 307)_
- tools: `vol3_netscan`
- exec_ids: `84774dc8a202`
- matched: `173.173.88.154`
- **missing**: `173.173.88.154:18682`
- claim: > [CONFIRMED — exec_id 019e0e26-d010-76a2-a909-84774dc8a202]   **Secondary channel:** System process (DC) → `173.173.88.154:18682` via local port 443 (SSL) — ESTABLISHED. Kernel-mode or highly-privilege…

### ⚠ partial _(line 310)_
- tools: `vol3_userassist`
- exec_ids: `628d876de324`
- matched: `sdelete.exe`
- **missing**: `C:\Tools\SysInternals\sdelete.exe``, `C:\Tools\SysInternals\sdelete.exe`
- 🚨 negation violations (claimed absent but found): `spinlock.exe`
- claim: > [CONFIRMED — exec_id 019e0e2a-8fd2-79d3-b454-628d876de324]   **Anti-forensics:** rsydow ran `C:\Tools\SysInternals\sdelete.exe` (secure deletion) — consistent with the attacker (or compromised rsydow)…

### ⚠ partial _(line 362)_
- tools: `vol3_userassist`
- exec_ids: `628d876de324`
- matched: `spinlock.exe`, `rsydow`, `vibranium`
- **missing**: `usboesrv.exe`
- claim: > **Confirmed compromised / attacker-controlled accounts:** - `vibranium` — [CONFIRMED — exec_id 019e0e2a-8fd2-79d3-b454-628d876de324] Ran spinlock.exe on the DC 10 times, maintained RDP session (sessio…

### ⚠ partial _(line 366)_
- tools: `vol3_netscan`
- exec_ids: `84774dc8a202`
- matched: `10.3.58.5`, `tlntsvr.exe`
- **missing**: `56.251.168.26`
- 🚨 negation violations (claimed absent but found): `56.171.18.32`, `56.91.239.31`, `40.167.16.32`, `lsass.exe`
- claim: > **Credential theft mechanisms observed:** [CONFIRMED — exec_id 019e0e26-d010-76a2-a909-84774dc8a202]   - `lsass.exe` on DC had CLOSED connections to `56.171.18.32` (×5), `56.91.239.31`, `40.167.16.32`…
