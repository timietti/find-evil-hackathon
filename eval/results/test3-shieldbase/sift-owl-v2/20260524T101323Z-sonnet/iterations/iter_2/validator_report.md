# Validator Report — iter_2

## Summary

- Total tagged claims:        **95**
  - CONFIRMED:                 77
  - INFERRED:                  11
  - HYPOTHESIS:                3
  - GAP:                       4
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           42 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                23 (some tokens found, some missing)
- ❌ failed:                 1 (no tokens found)
- ❓ unverifiable:           7 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           4 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 54.5%** (42 verified / 77 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **9** (cost: $0.0307)
  - ✅ VERIFIED:    2 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 0 (downgraded to failed)
  - ❓ UNRELATED:   4 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   3 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### 🔍 not_confirmed _(line 1)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > I'll systematically address all 33 validator demotions. The main issues are: (a) tool names in claim text causing "failed" validation, (b) exec_ids in different table cells from [CONFIRMED] tags, (c) …

### ✅ verified _(line 55)_
- tools: `vol3_psscan`, `vol3_netscan`, `tsk_fls_list`
- exec_ids: `8891e848f830`, `117e3451809a`, `0b57ffab283c`
- matched: `172.16.4.5`, `2018-08-08T18:08:00Z`
- claim: > **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830, exec_id 019e5991-2e2e-71b1-a420-117e3451809a, exec_id 019e5992-d9fd-78a1-86c0-0b57ffab283c]** The file server (local address 172.16.4.5) sh…

### ✅ verified _(line 58)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `1156`, `2018-08-08T18:08:00Z`, `rubyw.exe`
- claim: > Evidence: - `rubyw.exe` (PID 1156) was running on the file server with process creation time `2018-08-08T18:08:00Z` **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ⚠ partial _(line 59)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `1156`, `10.10.4.5`, `10.10.254.1`, `rubyw.exe`
- **missing**: `10.10.4.5:59361`, `10.10.254.1:61613`
- claim: > ** - `rubyw.exe` (PID 1156) maintained an ESTABLISHED TCP connection from `10.10.4.5:59361` to `10.10.254.1:61613` (STOMP protocol / Apache ActiveMQ port 61613) — C2 channel via message-broker **[CONF…

### ✅ verified _(line 60)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `2524`, `2018-09-05T14:43:11Z`, `2018-09-05T14:52:56Z`, `Rar.exe`
- claim: > ** - `Rar.exe` (PID 2524) ran on the file server from `2018-09-05T14:43:11Z` to `2018-09-05T14:52:56Z` (~9.75 min) — data archival/staging **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ✅ verified _(line 61)_
- tools: `tsk_fls_list`
- exec_ids: `0b57ffab283c`
- matched: `choco.exe`, `ProgramData/chocolatey/bin/choco.exe`, `Chocolatey`
- claim: > ** - `Chocolatey` (package manager) is installed on the file server disk: `ProgramData/chocolatey/bin/choco.exe` **[CONFIRMED — exec_id 019e5992-d9fd-78a1-86c0-0b57ffab283c]

### ✅ verified _(line 62)_
- tools: `tsk_fls_list`
- exec_ids: `0b57ffab283c`
- matched: `.rb`, `ProgramData/PuppetLabs/puppet/`
- claim: > ** - 3,302 `.rb` (Ruby) files present under `ProgramData/PuppetLabs/puppet/` — these are PuppetLabs Puppet configuration management scripts, indicating Puppet is installed; the attacker likely leverag…

### ⚠ partial _(line 63)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `7092`, `172.16.4.5`, `172.16.4.10`, `ngentask.exe`
- **missing**: `172.16.4.10:8080`
- claim: > ** - `ngentask.exe` (PID 7092) on the file server had two CLOSED connections from `172.16.4.5` to `172.16.4.10:8080` — the same internal C2 relay used by rd01 and wkstn-01 **[CONFIRMED — exec_id 019e5…

### ⚠ partial _(line 67)_
- tools: `vol3_psscan`, `vol3_malfind`, `vol3_netscan`
- exec_ids: `d58e3bbb3cd2`, `6ddae88d43e5`, `0358e8a16035`
- matched: `8260`, `172.16.4.10`, `172.16.6.11`, `p.exe`
- **missing**: `172.16.4.10:8080`
- claim: > **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id 019e5980-870a-78f2-90d4-6ddae88d43e5, exec_id 019e597b-fc85-75d3-bff1-0358e8a16035]** rd01 (172.16.6.11) is the most forensically a…

### ❓ unverifiable _(line 78)_
- exec_ids: `d58e3bbb3cd2`, `1c61f74282b0`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim references specific exec_ids and asserts an 'attack chain' but provides no concrete factual assertions (process names, timestamps, PIDs, command lines, or parent-child relationships) that can be verified against the psscan data; the data itself contains process records but the claim's subs
- claim: > **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id 019e597d-1cd6-7662-8c3a-1c61f74282b0]** The attack chain confirmed from psscan and cmdline on rd01:

### ⚠ partial _(line 82)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `d58e3bbb3cd2`, `1c61f74282b0`
- matched: `WmiPrvSE.exe`, `wmiprvse.exe`, `C:\WINDOWS\system32\wbem\wmiprvse.exe`
- **missing**: `C:\WINDOWS\system32\wbem\wmiprvse.exe``
- claim: > | PID | PPID | Image | Evidence | |-----|------|-------|---------| | 2876 | 868 | WmiPrvSE.exe | `C:\WINDOWS\system32\wbem\wmiprvse.exe` — WMI provider host initiates chain **[CONFIRMED — exec_id 019e…

### ✅ verified _(line 83)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `2876`, `WmiPrvSE.exe`, `powershell.exe`
- claim: > ** | | 8712 | 2876 | powershell.exe | Child of WmiPrvSE.exe (PID 2876) — WMI-triggered execution (T1047) **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 84)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `8712`, `powershell.exe`
- claim: > ** | | 5848 | 8712 | powershell.exe | WOW64 child of powershell (PID 8712) — nested/obfuscated execution (T1059.001) **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 85)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `5848`, `2018-08-30T22:15:18Z`, `cmd.exe`
- claim: > ** | | 5948 | 5848 | cmd.exe | WOW64 child of powershell (PID 5848), created `2018-08-30T22:15:18Z` **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 86)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `5948`, `2018-08-30T22:15:18Z`, `p.exe`, `cmd.exe`
- claim: > ** | | 8260 | 5948 | p.exe | Primary backdoor; child of cmd.exe (PID 5948), created `2018-08-30T22:15:18Z` **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ❓ unverifiable _(line 94)_
- exec_ids: `d58e3bbb3cd2`, `6ddae88d43e5`, `e9c3dd728cf7`, `76f791917a71`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim cites execution IDs (exec_id GUIDs) which are not present in the vol3_psscan tool's parsed data, which contains only process identifiers (PIDs, PPIDs, image names, timestamps, and memory offsets) with no execution UUID/GUID fields.
- claim: > **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id 019e5980-870a-78f2-90d4-6ddae88d43e5, exec_id 019e5985-d676-7202-ad5c-e9c3dd728cf7, exec_id 019e5986-75ce-7382-9526-76f791917a71]**

### ❓ unverifiable _(line 109)_
- exec_ids: `8891e848f830`, `117e3451809a`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim references execution IDs (exec_id) but the vol3_psscan tool's parsed data contains only process metadata (pid, ppid, image, timestamps, offsets) with no execution ID fields or matching identifiers.
- claim: > **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830, exec_id 019e5991-2e2e-71b1-a420-117e3451809a]

### ⚠ partial _(line 109)_
- tools: `tsk_fls_list`
- exec_ids: `0b57ffab283c`
- matched: `1156`
- **missing**: `10.10.254.1`, `2018-08-08T18:08:00Z`, `10.10.254.1:61613`
- 🚨 negation violations (claimed absent but found): `rubyw.exe`, `ProgramData/PuppetLabs/`
- claim: > ** `rubyw.exe` (PID 1156) was running on the file server with creation time `2018-08-08T18:08:00Z` and maintained an ESTABLISHED TCP connection to `10.10.254.1:61613` (STOMP / Apache ActiveMQ protocol…

### ✅ verified _(line 117)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `5588`, `2018-09-06T17:14:51Z`, `2018-09-06T17:14:57Z`, `2018-09-06T17:15:31Z`, `sd.exe`, `sc.exe`
- claim: > **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]** `sd.exe` (PID 5588, ppid=12172) ran on wkstn-01 from `2018-09-06T17:14:51Z` to `2018-09-06T17:14:57Z` (6 seconds). This binary name does …

### ✅ verified _(line 131)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `1156`, `2018-08-08T18:08:00Z`, `rubyw.exe`
- claim: > **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]** The file server (rubyw.exe PID 1156 created 2018-08-08T18:08:00Z) is the earliest confirmed compromised host, pre-dating rd01 by 23 days.

### ✅ verified _(line 133)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `5948`, `8260`, `8712`, `2876`, `5848`, `p.exe`, `WmiPrvSE.exe`, `cmd.exe` (+1 more)
- claim: > **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]** The WmiPrvSE.exe (PID 2876) → powershell.exe (PID 8712) → powershell.exe (PID 5848) → cmd.exe (PID 5948) → p.exe (PID 8260) chain on rd01…

### ⚠ partial _(line 135)_
- tools: `vol3_netscan`
- exec_ids: `0358e8a16035`
- matched: `172.16.4.10`, `172.16.6.11`
- **missing**: `172.16.4.10:8080`
- claim: > **[CONFIRMED — exec_id 019e597b-fc85-75d3-bff1-0358e8a16035]** rd01 (172.16.6.11) had 14 connections to `172.16.4.10:8080` including 1 ESTABLISHED and multiple CLOSE_WAIT states at capture time, confi…

### ⚠ partial _(line 137)_
- tools: `vol3_netscan`
- exec_ids: `cb18611fee86`
- matched: `172.16.7.11`, `172.16.4.10`
- **missing**: `172.16.4.10:8080`
- claim: > **[CONFIRMED — exec_id 019e5993-a131-7ae2-9ba4-cb18611fee86]** wkstn-01 (172.16.7.11) had exactly 7 CLOSED connections to `172.16.4.10:8080`, indicating prior C2 contact from this workstation.

### ⚠ partial _(line 139)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `7092`, `172.16.4.5`, `172.16.4.10`, `ngentask.exe`
- **missing**: `172.16.4.10:8080`
- claim: > **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]** file01 (172.16.4.5) had connections from `ngentask.exe` (PID 7092) to `172.16.4.10:8080` — a second process on the file server using the …

### ❓ unverifiable _(line 145)_
- exec_ids: `8891e848f830`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim appears to reference an execution ID but contains no specific factual assertion about processes, timestamps, or other data that can be verified against the psscan process data provided.
- claim: > | **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ⚠ partial _(line 146)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `2018-08-30T22:15:18Z`, `p.exe`
- **missing**: `172.16.6.11`
- claim: > ** | | rd01 (172.16.6.11) | 2018-08-30T22:15:18Z (p.exe first run) | WMI lateral movement from file01 or DC | **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ❓ unverifiable _(line 147)_
- exec_ids: `cb18611fee86`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim contains only an execution ID marker with no specific factual assertion about network connections, IPs, or other data that could be verified against the netscan output.
- claim: > | **[CONFIRMED — exec_id 019e5993-a131-7ae2-9ba4-cb18611fee86]

### ⚠ partial _(line 151)_
- tools: `vol3_netscan`, `vol3_netscan`, `vol3_netscan`
- exec_ids: `0358e8a16035`, `117e3451809a`, `cb18611fee86`
- matched: `7092`, `172.16.7.11`, `172.16.4.5`, `172.16.4.10`, `172.16.6.11`, `ngentask.exe`
- **missing**: `172.16.4.10:8080`
- claim: > **[CONFIRMED — exec_id 019e597b-fc85-75d3-bff1-0358e8a16035, exec_id 019e5991-2e2e-71b1-a420-117e3451809a, exec_id 019e5993-a131-7ae2-9ba4-cb18611fee86]** Three distinct hosts show connections to `172…

### ✅ verified _(line 157)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `d58e3bbb3cd2`, `1c61f74282b0`
- matched: `2876`, `WmiPrvSE.exe`
- claim: > **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id 019e597d-1cd6-7662-8c3a-1c61f74282b0]** WMI execution (T1047) confirmed by WmiPrvSE.exe (PID 2876) as parent of the attacker PowerS…

### ✅ verified _(line 159)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `5588`, `3068`, `2018-09-06T17:14:51Z`, `2018-09-06T17:15:31Z`, `sc.exe`, `sd.exe`
- claim: > **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]** `sc.exe` (PID 3068) ran on wkstn-01 at `2018-09-06T17:15:31Z`, and `sd.exe` (PID 5588) ran 40 seconds earlier at `2018-09-06T17:14:51Z` —…

### ✅ verified _(line 167)_
- exec_ids: `be8292d9d088`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed vol3_cachedump data structurally contains two cached credential hash entries (MSCASH/DCC2 format) with usernames 'tdungan' and 'spsql', matching the claim's assertion of two domain credential hashes recovered.
- claim: > **[CONFIRMED — exec_id 019e5999-1923-7dc1-ab8a-be8292d9d088]** Two MSCASH/DCC2 domain credential hashes recovered from rd01 memory:

### ✅ verified _(line 178)_
- tools: `vol3_hashdump`
- exec_ids: `f7083bd0d3a4`
- matched: `DefaultAccount`, `range_admin`, `defaultuser0`, `WDAGUtilityAccount`, `Administrator`, `Guest`
- claim: > **[CONFIRMED — exec_id 019e5999-092b-7230-ba7a-f7083bd0d3a4]** Six local accounts identified: `Administrator`, `Guest`, `DefaultAccount`, `WDAGUtilityAccount`, `defaultuser0`, `range_admin`. All NT ha…

### ❓ unverifiable _(line 194)_
- exec_ids: `8891e848f830`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim provides only an execution ID without any specific factual assertion about processes, files, timestamps, or other forensic artifacts that the parsed psscan data could verify or contradict.
- claim: > **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ⚠ partial _(line 194)_
- tools: `tsk_fls_list`
- exec_ids: `0b57ffab283c`
- matched: `2524`, `Shares/`
- **missing**: `2018-09-05T14:43:11Z`, `2018-09-05T14:52:56Z`, `Rar.exe`
- claim: > ** `Rar.exe` (PID 2524) ran on the file server from `2018-09-05T14:43:11Z` to `2018-09-05T14:52:56Z` (~9.75 minutes), consistent with archiving a large dataset (T1560.001). The file server disk contai…

### ⚠ partial _(line 200)_
- tools: `vol3_netscan`
- exec_ids: `0358e8a16035`
- matched: `172.16.4.10`
- **missing**: `8260`, `p.exe`, `172.16.4.10:8080`
- claim: > 1. **HTTP/8080 → 172.16.4.10 (internal relay)**: `p.exe` (PID 8260) on rd01 used connections to `172.16.4.10:8080` as its C2 channel **[CONFIRMED — exec_id 019e597b-fc85-75d3-bff1-0358e8a16035]

### ⚠ partial _(line 200)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `7092`, `172.16.4.5`, `172.16.4.10`, `ngentask.exe`
- **missing**: `172.16.4.10:8080`
- claim: > **; `ngentask.exe` (PID 7092) on file01 also connected to `172.16.4.10:8080` from `172.16.4.5` **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]

### ⚠ partial _(line 200)_
- tools: `vol3_netscan`
- exec_ids: `cb18611fee86`
- matched: `172.16.7.11`, `172.16.4.10`
- **missing**: `172.16.4.10:8080`
- claim: > **; wkstn-01 (172.16.7.11) had 7 CLOSED connections to `172.16.4.10:8080` **[CONFIRMED — exec_id 019e5993-a131-7ae2-9ba4-cb18611fee86]

### ⚠ partial _(line 202)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `1156`, `10.10.4.5`, `10.10.254.1`, `rubyw.exe`
- **missing**: `10.10.4.5:59361`, `10.10.254.1:61613`
- claim: > 2. **STOMP/61613 → 10.10.254.1 (external, via Ruby)**: `rubyw.exe` (PID 1156) on file01 maintained an ESTABLISHED connection from `10.10.4.5:59361` to `10.10.254.1:61613` **[CONFIRMED — exec_id 019e59…

### ✅ verified _(line 214)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `2018-08-04T16:28:20Z`, `vmtoolsd.exe`
- claim: > | Timestamp (UTC) | Event | Confidence | |-----------------|-------|------------| | 2018-08-04T16:28:20Z | vmtoolsd.exe boots on wkstn-01 — baseline date | **[CONFIRMED — exec_id 019e5995-31eb-7720-98…

### ✅ verified _(line 215)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `1156`, `2018-08-08T18:08:00Z`, `rubyw.exe`
- claim: > ** | | **2018-08-08T18:08:00Z** | **rubyw.exe (PID 1156) created on file server — earliest confirmed compromise** | **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ✅ verified _(line 216)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `9048`, `2018-08-15T17:10:32Z`, `Autorunsc.exe`
- claim: > ** | | 2018-08-15T17:10:32Z | Autorunsc.exe (PID 9048) ran on wkstn-01 (recon or IR tool) | **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]

### ✅ verified _(line 217)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `4`, `2018-08-30T13:51:58Z`
- claim: > ** | | 2018-08-30T13:51:58Z | System (PID 4) boot on rd01 — system baseline | **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 218)_
- tools: `ezt_prefetch_parse`, `vol3_psscan`
- exec_ids: `76f791917a71`, `d58e3bbb3cd2`
- matched: `5948`, `8260`, `2018-08-30T22:15:18Z`, `p.exe`, `cmd.exe`
- claim: > ** | | **2018-08-30T22:15:18Z** | **p.exe (PID 8260) first executed on rd01 via cmd.exe (PID 5948) — prefetch RunCount=1** | **[CONFIRMED — exec_id 019e5986-75ce-7382-9526-76f791917a71, exec_id 019e59…

### ✅ verified _(line 219)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `2524`, `2018-09-05T14:43:11Z`, `Rar.exe`
- claim: > ** | | 2018-09-05T14:43:11Z | Rar.exe (PID 2524) begins data archiving on file server | **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ✅ verified _(line 220)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `2018-09-05T14:52:56Z`, `Rar.exe`
- claim: > ** | | 2018-09-05T14:52:56Z | Rar.exe exits after 9.75 minutes — staging complete | **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ⚠ partial _(line 221)_
- tools: `vol3_image_info`
- exec_ids: `3fdaef5c387f`
- matched: `2018-09-05T15:48:20Z`
- **missing**: `172.16.4.6`
- claim: > ** | | 2018-09-05T15:48:20Z | Exchange server (172.16.4.6) memory captured — earliest memory capture | **[CONFIRMED — exec_id 019e598d-c83e-7a21-b6f7-3fdaef5c387f]

### ✅ verified _(line 222)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `11948`, `2018-09-06T14:03:54Z`, `WmiPrvSE.exe`
- claim: > ** | | 2018-09-06T14:03:54Z | WmiPrvSE.exe (PID 11948) spawned on rd01 — new WMI execution | **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 223)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `3712`, `2018-09-06T16:36:04Z`, `explorer.exe`
- claim: > ** | | 2018-09-06T16:36:04Z | explorer.exe (PID 3712) active on file server with UDP socket | **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]

### ✅ verified _(line 224)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `5588`, `2018-09-06T17:14:51Z`, `sd.exe`
- claim: > ** | | 2018-09-06T17:14:51Z | sd.exe (PID 5588) ran on wkstn-01 for 6 seconds | **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]

### ✅ verified _(line 225)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `3068`, `2018-09-06T17:15:31Z`, `sc.exe`
- claim: > ** | | 2018-09-06T17:15:31Z | sc.exe (PID 3068) ran on wkstn-01 — service manipulation | **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]

### ⚠ partial _(line 226)_
- tools: `vol3_image_info`
- exec_ids: `9ad475cf8a75`
- matched: `2018-09-06T18:57:17Z`
- **missing**: `8260`, `p.exe`
- claim: > ** | | 2018-09-06T18:57:17Z | rd01 memory captured — p.exe (PID 8260) and WmiPrvSE chain active | **[CONFIRMED — exec_id 019e5979-fe75-76b2-affc-9ad475cf8a75]

### ⚠ partial _(line 227)_
- tools: `vol3_image_info`
- exec_ids: `3bd2c11fcb45`
- matched: `2018-09-06T19:28:44Z`
- **missing**: `rubyw.exe`
- claim: > ** | | 2018-09-06T19:28:44Z | file01 memory captured — rubyw.exe STOMP C2 active | **[CONFIRMED — exec_id 019e597a-0f87-7353-8f83-3bd2c11fcb45]

### ✅ verified _(line 228)_
- tools: `vol3_image_info`
- exec_ids: `179f8e2b97f1`
- matched: `2018-09-06T22:57:49Z`
- claim: > ** | | 2018-09-06T22:57:49Z | DC memory captured | **[CONFIRMED — exec_id 019e597a-08c7-7ce0-bc1b-179f8e2b97f1]

### ✅ verified _(line 241)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `d58e3bbb3cd2`, `1c61f74282b0`
- matched: `8712`, `2876`, `WmiPrvSE.exe`, `powershell.exe`
- claim: > ** | | Execution | Windows Management Instrumentation | T1047 | WmiPrvSE.exe (PID 2876) spawning powershell.exe (PID 8712) on rd01 **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id …

### ✅ verified _(line 242)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `5848`, `WmiPrvSE.exe`, `powershell.exe`
- claim: > ** | | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Nested powershell.exe (PID 5848) under WmiPrvSE.exe chain **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 243)_
- tools: `vol3_psscan`, `tsk_fls_list`
- exec_ids: `8891e848f830`, `0b57ffab283c`
- matched: `1156`, `rubyw.exe`
- claim: > ** | | Execution | Command and Scripting Interpreter: Ruby | T1059.004 | rubyw.exe (PID 1156) on file01, 3,302 .rb files in PuppetLabs directory leveraged **[CONFIRMED — exec_id 019e5991-e973-74e2-bcb…

### ✅ verified _(line 244)_
- tools: `vol3_malfind`
- exec_ids: `6ddae88d43e5`
- matched: `8260`, `p.exe`
- claim: > ** | | Defense Evasion | Process Injection / RWX shellcode | T1055 | p.exe (PID 8260) PAGE_EXECUTE_READWRITE private VadS memory **[CONFIRMED — exec_id 019e5980-870a-78f2-90d4-6ddae88d43e5]

### ⚠ partial _(line 245)_
- tools: `tsk_fls_list`
- exec_ids: `3d0cc116babb`
- matched: `p.exe`
- **missing**: `Windows\Temp\Perfmon\`
- claim: > ** | | Defense Evasion | Masquerading | T1036 | p.exe placed in `Windows\Temp\Perfmon\` (system-like path) **[CONFIRMED — exec_id 019e5984-20d1-7612-bc2e-3d0cc116babb]

### ✅ verified _(line 246)_
- exec_ids: `be8292d9d088`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed cachedump data contains DCC2 hashes for both usernames (tdungan and spsql) explicitly mentioned in the claim, confirming the presence of cached domain credentials.
- claim: > ** | | Credential Access | OS Credential Dumping: Cached Domain Credentials | T1003.005 | DCC2 hashes for tdungan and spsql on rd01 **[CONFIRMED — exec_id 019e5999-1923-7dc1-ab8a-be8292d9d088]

### ✅ verified _(line 248)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `9048`, `3068`, `sc.exe`, `Autorunsc.exe`
- claim: > ** | | Discovery | System Service Discovery / Recon | T1007 | sc.exe (PID 3068) and Autorunsc.exe (PID 9048) on wkstn-01 **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]

### ✅ verified _(line 249)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `d58e3bbb3cd2`, `1c61f74282b0`
- matched: `2876`, `WmiPrvSE.exe`
- claim: > ** | | Lateral Movement | WMI-based remote execution | T1021.003 | WmiPrvSE.exe (PID 2876) as parent of attacker chain on rd01 **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id 019e…

### ✅ verified _(line 251)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `2524`, `Rar.exe`
- claim: > ** | | Collection | Archive Collected Data: Archive via Utility | T1560.001 | Rar.exe (PID 2524) ran 9.75 min on file01 **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ✅ verified _(line 252)_
- tools: `vol3_netscan`, `vol3_netscan`, `vol3_netscan`
- exec_ids: `0358e8a16035`, `117e3451809a`, `cb18611fee86`
- matched: `172.16.4.10`, `ngentask.exe`, `p.exe`
- claim: > ** | | Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP C2 over port 8080 to 172.16.4.10 from rd01 (p.exe), file01 (ngentask.exe), wkstn-01 **[CONFIRMED — exec_id 019e5…

### ✅ verified _(line 253)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `10.10.254.1`, `rubyw.exe`
- claim: > ** | | Command & Control | Non-Standard Protocol (STOMP/ActiveMQ) | T1095 | rubyw.exe STOMP/61613 to 10.10.254.1 on file01 **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]

### 🔍 not_confirmed _(line 279)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > with explicit reasoning | | 7–11 | not_confirmed — ASCII diagram [CONFIRMED]

### ❓ unverifiable _(line 283)_
- exec_ids: `be8292d9d088`, `f7083bd0d3a4`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim text is a table structure describing validation outcomes across multiple rows rather than a specific factual assertion about parsed data, making it impossible to verify against the cachedump output showing two cached credentials (tdungan and spsql) with their respective hashes.
- claim: > without exec_ids | Converted to prose table with inline exec_ids per row | | 12 | failed — "vol3_cachedump" as claim token | Rewrote removing tool name; tdungan/spsql hashes confirmed in exec_id 019e5…

### 🔍 not_confirmed _(line 283)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > no exec_id in same cell | Restructured table; exec_id now in Confidence column with [CONFIRMED]

### 🔍 not_confirmed _(line 284)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | 16 | not_confirmed — Proxy task [CONFIRMED]

### ❌ failed _(line 288)_
- tools: `vol3_scheduled_tasks`, `ezt_prefetch_parse`, `vol3_psscan`, `vol3_image_info`, `vol3_image_info`
- exec_ids: `208d97db63c1`, `76f791917a71`, `d58e3bbb3cd2`, `19e598d-c83e` (+1 more)
- 🚨 negation violations (claimed absent but found): `p.exe`
- claim: > with exec_id 019e5999-29aa-75f2-a7c5-208d97db63c1 | | 17 | not_confirmed — p.exe timeline no exec_id in cell | Added exec_ids 019e5986-75ce-7382-9526-76f791917a71, 019e597a-322c-7db1-b1de-d58e3bbb3cd2…

### ⚠ partial _(line 296)_
- tools: `tsk_icat_extract`
- exec_ids: `e9c3dd728cf7`
- matched: `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`
- **missing**: `p.exe`, `Windows\Temp\Perfmon\`
- claim: > | Type | Value | Host | Confidence | |------|-------|------|------------| | File SHA-256 | `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c` (p.exe) | rd01 `Windows\Temp\Perfmon\` | *…

### ⚠ partial _(line 297)_
- tools: `tsk_icat_extract`
- exec_ids: `756eee9a33fc`
- matched: `57a04605ae0e308a0410b15f5478457417f03fcecf6eb30db7abb6409257429f`
- **missing**: `ri.exe`
- claim: > ** | | File SHA-256 | `57a04605ae0e308a0410b15f5478457417f03fcecf6eb30db7abb6409257429f` (ri.exe) | rd01 spsql Downloads | **[CONFIRMED — exec_id 019e598e-0d91-7c21-844b-756eee9a33fc]

### ⚠ partial _(line 298)_
- tools: `vol3_netscan`, `vol3_netscan`, `vol3_netscan`
- exec_ids: `0358e8a16035`, `117e3451809a`, `cb18611fee86`
- matched: `172.16.4.10`
- **missing**: `172.16.4.10:8080`
- claim: > ** | | C2 IP:Port | `172.16.4.10:8080` (internal relay) | rd01, file01, wkstn-01 | **[CONFIRMED — exec_id 019e597b-fc85-75d3-bff1-0358e8a16035, exec_id 019e5991-2e2e-71b1-a420-117e3451809a, exec_id 01…

### ⚠ partial _(line 299)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `10.10.254.1`
- **missing**: `10.10.254.1:61613`
- claim: > ** | | C2 IP:Port | `10.10.254.1:61613` (STOMP external) | file01 | **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]

### ✅ verified _(line 300)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `p.exe`, `WmiPrvSE.exe`, `cmd.exe`, `powershell.exe`
- claim: > ** | | Process chain | WmiPrvSE.exe (2876) → powershell.exe (8712) → powershell.exe (5848) → cmd.exe (5948) → p.exe (8260) | rd01 | **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 301)_
- tools: `vol3_cachedump`
- exec_ids: `be8292d9d088`
- matched: `b1 f8 72 62 37 0d 99 9b 3a b0 a9 43 19 d2 32 65`
- claim: > ** | | Credential hash | tdungan DCC2: `b1 f8 72 62 37 0d 99 9b 3a b0 a9 43 19 d2 32 65` | rd01 cached | **[CONFIRMED — exec_id 019e5999-1923-7dc1-ab8a-be8292d9d088]

### ✅ verified _(line 302)_
- tools: `vol3_cachedump`
- exec_ids: `be8292d9d088`
- matched: `4e 7a 21 7b 9b 6a df 36 e2 1a 7e 76 ce 1c 71 d2`
- claim: > ** | | Credential hash | spsql DCC2: `4e 7a 21 7b 9b 6a df 36 e2 1a 7e 76 ce 1c 71 d2` | rd01 cached | **[CONFIRMED — exec_id 019e5999-1923-7dc1-ab8a-be8292d9d088]

### ✅ verified _(line 303)_
- tools: `vol3_hashdump`
- exec_ids: `f7083bd0d3a4`
- matched: `range_admin`
- claim: > ** | | Suspicious account | `range_admin` (non-standard local account) | rd01 | **[CONFIRMED — exec_id 019e5999-092b-7230-ba7a-f7083bd0d3a4]
