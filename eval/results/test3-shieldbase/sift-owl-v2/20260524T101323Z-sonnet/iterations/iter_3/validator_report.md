# Validator Report — iter_3

## Summary

- Total tagged claims:        **96**
  - CONFIRMED:                 79
  - INFERRED:                  10
  - HYPOTHESIS:                3
  - GAP:                       4
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           71 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                1 (some tokens found, some missing)
- ❌ failed:                 1 (no tokens found)
- ❓ unverifiable:           4 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           2 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 89.9%** (71 verified / 79 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **7** (cost: $0.0189)
  - ✅ VERIFIED:    3 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 0 (downgraded to failed)
  - ❓ UNRELATED:   3 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   1 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### 🔍 not_confirmed _(line 1)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > I need to resolve 28 validator demotions. The main patterns are: (1) `IP:port` combined tokens not found in netscan data, (2) `[CONFIRMED]` tags in the Demotion Resolution Summary table itself, (3) mi…

### 🔍 not_confirmed _(line 22)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > I now have all the information needed. Key findings from queries: - `172.16.4.10:8080` is stored as separate fields `foreign_addr`/`foreign_port` — the combined "IP:port" token never appears - Same fo…

### ✅ verified _(line 56)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `1156`, `2018-08-08T18:08:00Z`, `rubyw.exe`
- claim: > **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]** `rubyw.exe` (PID 1156) was running on the file server with process creation time `2018-08-08T18:08:00Z` — nearly four weeks before rd01 w…

### ✅ verified _(line 58)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `1156`, `10.10.4.5`, `10.10.254.1`, `rubyw.exe`, `59361`, `61613`
- claim: > **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]** `rubyw.exe` (PID 1156) maintained an ESTABLISHED TCP connection from `10.10.4.5` port `59361` to `10.10.254.1` port `61613` (STOMP/Active…

### ✅ verified _(line 60)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `2524`, `2018-09-05T14:43:11Z`, `2018-09-05T14:52:56Z`, `Rar.exe`
- claim: > **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]** `Rar.exe` (PID 2524) ran on the file server from `2018-09-05T14:43:11Z` to `2018-09-05T14:52:56Z` (~9.75 min) — data archival/staging.

### ✅ verified _(line 62)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `7092`, `172.16.4.5`, `172.16.4.10`, `ngentask.exe`, `8080`
- claim: > **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]** `ngentask.exe` (PID 7092) on the file server had CLOSED connections from `172.16.4.5` to `172.16.4.10` port `8080` — the same internal C2…

### ✅ verified _(line 64)_
- tools: `tsk_fls_list`
- exec_ids: `0b57ffab283c`
- matched: `.rb`, `Shares/`, `ProgramData/PuppetLabs/puppet/`
- claim: > **[CONFIRMED — exec_id 019e5992-d9fd-78a1-86c0-0b57ffab283c]** The file server disk contains 3,302 `.rb` (Ruby) files under `ProgramData/PuppetLabs/puppet/` — the attacker leveraged the existing Puppe…

### ✅ verified _(line 68)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `8260`, `2018-08-30T22:15:18Z`, `p.exe`
- claim: > **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]** `p.exe` (PID 8260, ppid 5948) is in memory on rd01 with creation time `2018-08-30T22:15:18Z`.

### ✅ verified _(line 70)_
- tools: `vol3_malfind`
- exec_ids: `6ddae88d43e5`
- matched: `8260`, `p.exe`
- claim: > **[CONFIRMED — exec_id 019e5980-870a-78f2-90d4-6ddae88d43e5]** `p.exe` (PID 8260) has PAGE_EXECUTE_READWRITE private VadS memory — RWX shellcode-class injection confirmed.

### ✅ verified _(line 72)_
- tools: `vol3_netscan`
- exec_ids: `0358e8a16035`
- matched: `172.16.4.10`, `172.16.6.11`, `8080`
- claim: > **[CONFIRMED — exec_id 019e597b-fc85-75d3-bff1-0358e8a16035]** rd01 (local `172.16.6.11`) shows 14 connections to `172.16.4.10` port `8080` including 1 ESTABLISHED and multiple CLOSE_WAIT states at ca…

### ❓ unverifiable _(line 82)_
- exec_ids: `d58e3bbb3cd2`, `1c61f74282b0`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim references a process chain with specific exec_ids and a host identifier (rd01), but the vol3_psscan data contains only process snapshots with PIDs, PPIDs, image names, and timestamps—no exec_ids, host names, or chain linkage information that would support the claim's assertion about a spec
- claim: > **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id 019e597d-1cd6-7662-8c3a-1c61f74282b0]** Full process chain on rd01:

### ⚠ partial _(line 86)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `d58e3bbb3cd2`, `1c61f74282b0`
- matched: `WmiPrvSE.exe`, `wmiprvse.exe`, `C:\WINDOWS\system32\wbem\`
- **missing**: `C:\WINDOWS\system32\wbem\``
- claim: > | PID | PPID | Image | Evidence | |-----|------|-------|---------| | 2876 | 868 | WmiPrvSE.exe | WMI provider host; path wmiprvse.exe in `C:\WINDOWS\system32\wbem\` — initiates chain **[CONFIRMED — ex…

### ✅ verified _(line 87)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `2876`, `WmiPrvSE.exe`, `powershell.exe`
- claim: > ** | | 8712 | 2876 | powershell.exe | Child of WmiPrvSE.exe (PID 2876) — WMI-triggered execution (T1047) **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 88)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `8712`, `powershell.exe`
- claim: > ** | | 5848 | 8712 | powershell.exe | WOW64 child of powershell (PID 8712) — nested execution (T1059.001) **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 89)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `5848`, `2018-08-30T22:15:18Z`, `cmd.exe`
- claim: > ** | | 5948 | 5848 | cmd.exe | WOW64 child of powershell (PID 5848), created `2018-08-30T22:15:18Z` **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 90)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `5948`, `2018-08-30T22:15:18Z`, `p.exe`, `cmd.exe`
- claim: > ** | | 8260 | 5948 | p.exe | Primary backdoor; child of cmd.exe (PID 5948), created `2018-08-30T22:15:18Z` **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ❓ unverifiable _(line 98)_
- exec_ids: `d58e3bbb3cd2`, `6ddae88d43e5`, `3d0cc116babb`, `e9c3dd728cf7` (+1 more)
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim contains only execution IDs (UUIDs) with no testable factual assertions about processes, timestamps, file paths, or other attributes that the vol3_psscan tool's parsed data could verify or refute.
- claim: > **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id 019e5980-870a-78f2-90d4-6ddae88d43e5, exec_id 019e5984-20d1-7612-bc2e-3d0cc116babb, exec_id 019e5985-d676-7202-ad5c-e9c3dd728cf7, e…

### ✅ verified _(line 102)_
- tools: `tsk_fls_list`
- exec_ids: `3d0cc116babb`
- matched: `5994`, `p.exe`, `Windows/Temp/Perfmon/p.exe`
- claim: > | Attribute | Value | exec_id | |-----------|-------|---------| | Path | `Windows/Temp/Perfmon/p.exe` (inode 5994) | **[CONFIRMED — exec_id 019e5984-20d1-7612-bc2e-3d0cc116babb]

### ✅ verified _(line 103)_
- tools: `tsk_icat_extract`
- exec_ids: `e9c3dd728cf7`
- matched: `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`
- claim: > ** | | SHA-256 | `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c` | **[CONFIRMED — exec_id 019e5985-d676-7202-ad5c-e9c3dd728cf7]

### ✅ verified _(line 104)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `2018-08-30T22:15:18Z`, `cmd.exe`
- claim: > ** | | PID | 8260, ppid=5948 (cmd.exe), created `2018-08-30T22:15:18Z` | **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 105)_
- tools: `ezt_prefetch_parse`
- exec_ids: `76f791917a71`
- matched: `2018-08-30T22:15:18Z`
- claim: > ** | | First/only execution | `2018-08-30T22:15:18Z`, RunCount=1 | **[CONFIRMED — exec_id 019e5986-75ce-7382-9526-76f791917a71]

### ✅ verified _(line 106)_
- tools: `ezt_prefetch_parse`
- exec_ids: `76f791917a71`
- matched: `CRYPTSP.dll`, `WININET.dll`, `RSAENH.dll`, `WS2_32.dll`, `DNSAPI.dll`
- claim: > ** | | DLLs loaded | WININET.dll, WS2_32.dll, DNSAPI.dll, CRYPTSP.dll, RSAENH.dll | **[CONFIRMED — exec_id 019e5986-75ce-7382-9526-76f791917a71]

### ✅ verified _(line 107)_
- tools: `vol3_malfind`
- exec_ids: `6ddae88d43e5`
- matched: `8260`
- claim: > ** | | RWX private memory | PID 8260, PAGE_EXECUTE_READWRITE, VadS tag, private_memory=1 | **[CONFIRMED — exec_id 019e5980-870a-78f2-90d4-6ddae88d43e5]

### ✅ verified _(line 113)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `1156`, `2018-08-08T18:08:00Z`, `rubyw.exe`
- claim: > **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]** `rubyw.exe` (PID 1156) was running on the file server with creation time `2018-08-08T18:08:00Z`.

### ✅ verified _(line 115)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `1156`, `10.10.4.5`, `10.10.254.1`, `rubyw.exe`, `59361`, `61613`
- claim: > **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]** `rubyw.exe` (PID 1156) maintained an ESTABLISHED TCP connection from `10.10.4.5` port `59361` to `10.10.254.1` port `61613` — STOMP/Apach…

### ❌ failed _(line 117)_
- tools: `tsk_fls_list`
- exec_ids: `0b57ffab283c`
- 🚨 negation violations (claimed absent but found): `rubyw.exe`, `ProgramData/PuppetLabs/`
- claim: > **[CONFIRMED — exec_id 019e5992-d9fd-78a1-86c0-0b57ffab283c]** Although the file server has a legitimate Puppet installation with 3,302 Ruby files in `ProgramData/PuppetLabs/`, Puppet communicates via…

### ✅ verified _(line 125)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `5588`, `2018-09-06T17:14:51Z`, `2018-09-06T17:14:57Z`, `2018-09-06T17:15:31Z`, `sd.exe`, `sc.exe`
- claim: > **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]** `sd.exe` (PID 5588, ppid=12172) ran on wkstn-01 from `2018-09-06T17:14:51Z` to `2018-09-06T17:14:57Z` (6 seconds). This binary name does …

### ✅ verified _(line 139)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `1156`, `2018-08-08T18:08:00Z`, `rubyw.exe`
- claim: > **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]** The file server has `rubyw.exe` (PID 1156) created `2018-08-08T18:08:00Z` — the earliest confirmed compromise, 23 days before rd01.

### ✅ verified _(line 141)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `5948`, `8260`, `8712`, `2876`, `5848`, `p.exe`, `WmiPrvSE.exe`, `cmd.exe` (+1 more)
- claim: > **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]** The WmiPrvSE.exe (PID 2876) → powershell.exe (PID 8712) → powershell.exe (PID 5848) → cmd.exe (PID 5948) → p.exe (PID 8260) chain on rd01…

### ✅ verified _(line 143)_
- tools: `vol3_netscan`
- exec_ids: `0358e8a16035`
- matched: `172.16.4.10`, `172.16.6.11`, `8080`
- claim: > **[CONFIRMED — exec_id 019e597b-fc85-75d3-bff1-0358e8a16035]** rd01 (`172.16.6.11`) had 14 connections to `172.16.4.10` port `8080` including 1 ESTABLISHED and multiple CLOSE_WAIT states — active C2 b…

### ✅ verified _(line 145)_
- tools: `vol3_netscan`
- exec_ids: `cb18611fee86`
- matched: `172.16.7.11`, `172.16.4.10`, `8080`
- claim: > **[CONFIRMED — exec_id 019e5993-a131-7ae2-9ba4-cb18611fee86]** wkstn-01 (`172.16.7.11`) had exactly 7 CLOSED connections to `172.16.4.10` port `8080`, indicating prior C2 contact from this workstation…

### ✅ verified _(line 147)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `7092`, `172.16.4.5`, `172.16.4.10`, `ngentask.exe`, `8080`
- claim: > **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]** file01 (`172.16.4.5`) had connections from `ngentask.exe` (PID 7092) to `172.16.4.10` port `8080` — a second process on the file server u…

### ❓ unverifiable _(line 153)_
- exec_ids: `8891e848f830`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim references an 'exec_id' identifier that is not a field present in process scan data; this appears to be a metadata or report tracking identifier unrelated to the actual process forensic content of the vol3_psscan tool output.
- claim: > | **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ✅ verified _(line 154)_
- tools: `vol3_psscan`, `vol3_netscan`
- exec_ids: `d58e3bbb3cd2`, `0358e8a16035`
- matched: `8260`, `172.16.6.11`, `2018-08-30T22:15:18Z`, `p.exe`
- claim: > ** | | rd01 (172.16.6.11) | `2018-08-30T22:15:18Z` (p.exe PID 8260 first run) | WMI lateral movement (T1047) | **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id 019e597b-fc85-75d3-b…

### ❓ unverifiable _(line 155)_
- exec_ids: `cb18611fee86`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim contains only an execution ID with a 'CONFIRMED' status label but makes no specific factual assertion about network connections, IPs, or other data that could be verified against the netscan output.
- claim: > | **[CONFIRMED — exec_id 019e5993-a131-7ae2-9ba4-cb18611fee86]

### ✅ verified _(line 159)_
- tools: `vol3_netscan`, `vol3_netscan`, `vol3_netscan`
- exec_ids: `0358e8a16035`, `117e3451809a`, `cb18611fee86`
- matched: `7092`, `172.16.7.11`, `172.16.4.5`, `172.16.4.10`, `172.16.6.11`, `ngentask.exe`, `8080`
- claim: > **[CONFIRMED — exec_id 019e597b-fc85-75d3-bff1-0358e8a16035, exec_id 019e5991-2e2e-71b1-a420-117e3451809a, exec_id 019e5993-a131-7ae2-9ba4-cb18611fee86]** Three distinct hosts show connections to `172…

### ✅ verified _(line 165)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `d58e3bbb3cd2`, `1c61f74282b0`
- matched: `2876`, `WmiPrvSE.exe`
- claim: > **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id 019e597d-1cd6-7662-8c3a-1c61f74282b0]** WMI execution (T1047) confirmed by WmiPrvSE.exe (PID 2876) as parent of the attacker PowerS…

### ✅ verified _(line 167)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `5588`, `3068`, `2018-09-06T17:14:51Z`, `2018-09-06T17:15:31Z`, `sc.exe`, `sd.exe`
- claim: > **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]** `sc.exe` (PID 3068) ran on wkstn-01 at `2018-09-06T17:15:31Z`, and `sd.exe` (PID 5588) ran 40 seconds earlier at `2018-09-06T17:14:51Z` —…

### ✅ verified _(line 175)_
- exec_ids: `be8292d9d088`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed cachedump data contains exactly two credential hash entries with usernames 'tdungan' and 'spsql', each with an associated hash value, structurally matching the claim of two MSCASH/DCC2 domain credential hashes recovered.
- claim: > **[CONFIRMED — exec_id 019e5999-1923-7dc1-ab8a-be8292d9d088]** Two MSCASH/DCC2 domain credential hashes recovered from rd01 memory:

### ✅ verified _(line 182)_
- exec_ids: `be8292d9d088`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed cachedump data structurally confirms the presence of two cached credential hashes for accounts 'tdungan' and 'spsql', which supports the claim that both accounts logged into the system and exposed DCC2 (Domain Cached Credentials) hashes that are offline-crackable.
- claim: > Both accounts logged into rd01, exposing DCC2 hashes that are offline-crackable (T1003.005). **[CONFIRMED — exec_id 019e5999-1923-7dc1-ab8a-be8292d9d088]**

### ✅ verified _(line 186)_
- tools: `vol3_hashdump`
- exec_ids: `f7083bd0d3a4`
- matched: `DefaultAccount`, `range_admin`, `defaultuser0`, `WDAGUtilityAccount`, `Administrator`, `Guest`
- claim: > **[CONFIRMED — exec_id 019e5999-092b-7230-ba7a-f7083bd0d3a4]** Six local accounts identified: `Administrator`, `Guest`, `DefaultAccount`, `WDAGUtilityAccount`, `defaultuser0`, `range_admin`. All NT ha…

### ✅ verified _(line 202)_
- tools: `vol3_psscan`, `tsk_fls_list`
- exec_ids: `8891e848f830`, `0b57ffab283c`
- matched: `2524`, `2018-09-05T14:43:11Z`, `2018-09-05T14:52:56Z`, `Rar.exe`, `Shares/`
- claim: > **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830, exec_id 019e5992-d9fd-78a1-86c0-0b57ffab283c]** `Rar.exe` (PID 2524) ran on the file server from `2018-09-05T14:43:11Z` to `2018-09-05T14:5…

### ✅ verified _(line 208)_
- tools: `vol3_netscan`
- exec_ids: `0358e8a16035`
- matched: `172.16.4.10`, `172.16.6.11`, `8080`
- claim: > 1. **HTTP port 8080 → 172.16.4.10 (internal relay)**: rd01 (`172.16.6.11`) had active connections to `172.16.4.10` port `8080` **[CONFIRMED — exec_id 019e597b-fc85-75d3-bff1-0358e8a16035]

### ✅ verified _(line 208)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `7092`, `172.16.4.5`, `172.16.4.10`, `ngentask.exe`, `8080`
- claim: > **; `ngentask.exe` (PID 7092) on file01 also connected to `172.16.4.10` port `8080` from `172.16.4.5` **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]

### ✅ verified _(line 208)_
- tools: `vol3_netscan`
- exec_ids: `cb18611fee86`
- matched: `172.16.7.11`, `172.16.4.10`, `8080`
- claim: > **; wkstn-01 (`172.16.7.11`) had 7 CLOSED connections to `172.16.4.10` port `8080` **[CONFIRMED — exec_id 019e5993-a131-7ae2-9ba4-cb18611fee86]

### ✅ verified _(line 210)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `1156`, `10.10.4.5`, `10.10.254.1`, `rubyw.exe`, `59361`, `61613`
- claim: > 2. **STOMP port 61613 → 10.10.254.1 (external, via Ruby)**: `rubyw.exe` (PID 1156) on file01 maintained an ESTABLISHED connection from `10.10.4.5` port `59361` to `10.10.254.1` port `61613` **[CONFIRM…

### ✅ verified _(line 222)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `2018-08-04T16:28:20Z`, `vmtoolsd.exe`
- claim: > | Timestamp (UTC) | Event | Confidence | |-----------------|-------|------------| | 2018-08-04T16:28:20Z | vmtoolsd.exe boots on wkstn-01 — baseline date | **[CONFIRMED — exec_id 019e5995-31eb-7720-98…

### ✅ verified _(line 223)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `1156`, `2018-08-08T18:08:00Z`, `rubyw.exe`
- claim: > ** | | **2018-08-08T18:08:00Z** | **rubyw.exe (PID 1156) created on file server — earliest confirmed compromise** | **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ✅ verified _(line 224)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `9048`, `2018-08-15T17:10:32Z`, `Autorunsc.exe`
- claim: > ** | | 2018-08-15T17:10:32Z | Autorunsc.exe (PID 9048) ran on wkstn-01 (recon or IR tool) | **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]

### ✅ verified _(line 225)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `4`, `2018-08-30T13:51:58Z`
- claim: > ** | | 2018-08-30T13:51:58Z | System (PID 4) boot on rd01 — system baseline | **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 226)_
- tools: `ezt_prefetch_parse`, `vol3_psscan`
- exec_ids: `76f791917a71`, `d58e3bbb3cd2`
- matched: `5948`, `8260`, `2018-08-30T22:15:18Z`, `p.exe`, `cmd.exe`
- claim: > ** | | **2018-08-30T22:15:18Z** | **p.exe (PID 8260) first executed on rd01 via cmd.exe (PID 5948) — RunCount=1** | **[CONFIRMED — exec_id 019e5986-75ce-7382-9526-76f791917a71, exec_id 019e597a-322c-7…

### ✅ verified _(line 227)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `2524`, `2018-09-05T14:43:11Z`, `Rar.exe`
- claim: > ** | | 2018-09-05T14:43:11Z | Rar.exe (PID 2524) begins data archiving on file server | **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ✅ verified _(line 228)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `2524`, `2018-09-05T14:52:56Z`, `Rar.exe`
- claim: > ** | | 2018-09-05T14:52:56Z | Rar.exe (PID 2524) exits after ~9.75 min — staging complete | **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ✅ verified _(line 229)_
- tools: `vol3_image_info`
- exec_ids: `3fdaef5c387f`
- matched: `2018-09-05T15:48:20Z`
- claim: > ** | | 2018-09-05T15:48:20Z | Exchange server memory captured — earliest memory capture | **[CONFIRMED — exec_id 019e598d-c83e-7a21-b6f7-3fdaef5c387f]

### ✅ verified _(line 230)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `11948`, `2018-09-06T14:03:54Z`, `WmiPrvSE.exe`
- claim: > ** | | 2018-09-06T14:03:54Z | WmiPrvSE.exe (PID 11948) spawned on rd01 — new WMI execution | **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 231)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `5588`, `2018-09-06T17:14:51Z`, `sd.exe`
- claim: > ** | | 2018-09-06T17:14:51Z | sd.exe (PID 5588) ran on wkstn-01 for 6 seconds | **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]

### ✅ verified _(line 232)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `3068`, `2018-09-06T17:15:31Z`, `sc.exe`
- claim: > ** | | 2018-09-06T17:15:31Z | sc.exe (PID 3068) ran on wkstn-01 — service manipulation | **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]

### ✅ verified _(line 233)_
- tools: `vol3_image_info`, `vol3_psscan`
- exec_ids: `9ad475cf8a75`, `d58e3bbb3cd2`
- matched: `8260`, `2018-09-06T18:57:17Z`, `p.exe`
- claim: > ** | | 2018-09-06T18:57:17Z | rd01 memory captured — p.exe (PID 8260) and WmiPrvSE chain active | **[CONFIRMED — exec_id 019e5979-fe75-76b2-affc-9ad475cf8a75, exec_id 019e597a-322c-7db1-b1de-d58e3bbb3…

### ✅ verified _(line 234)_
- tools: `vol3_image_info`, `vol3_psscan`
- exec_ids: `3bd2c11fcb45`, `8891e848f830`
- matched: `1156`, `2018-09-06T19:28:44Z`, `rubyw.exe`
- claim: > ** | | 2018-09-06T19:28:44Z | file01 memory captured — rubyw.exe (PID 1156) STOMP C2 active | **[CONFIRMED — exec_id 019e597a-0f87-7353-8f83-3bd2c11fcb45, exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ✅ verified _(line 235)_
- tools: `vol3_image_info`
- exec_ids: `179f8e2b97f1`
- matched: `2018-09-06T22:57:49Z`
- claim: > ** | | 2018-09-06T22:57:49Z | DC memory captured | **[CONFIRMED — exec_id 019e597a-08c7-7ce0-bc1b-179f8e2b97f1]

### ✅ verified _(line 248)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `d58e3bbb3cd2`, `1c61f74282b0`
- matched: `8712`, `2876`, `WmiPrvSE.exe`, `powershell.exe`
- claim: > ** | | Execution | Windows Management Instrumentation | T1047 | WmiPrvSE.exe (PID 2876) spawning powershell.exe (PID 8712) on rd01 **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id …

### ✅ verified _(line 249)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `5848`, `WmiPrvSE.exe`, `powershell.exe`
- claim: > ** | | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Nested powershell.exe (PID 5848) under WmiPrvSE.exe chain **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 250)_
- tools: `vol3_psscan`, `tsk_fls_list`
- exec_ids: `8891e848f830`, `0b57ffab283c`
- matched: `1156`, `rubyw.exe`
- claim: > ** | | Execution | Command and Scripting Interpreter: Ruby | T1059.004 | rubyw.exe (PID 1156) on file01 leveraging PuppetLabs Ruby runtime **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830, …

### ✅ verified _(line 251)_
- tools: `vol3_malfind`
- exec_ids: `6ddae88d43e5`
- matched: `8260`, `p.exe`
- claim: > ** | | Defense Evasion | Process Injection / RWX shellcode | T1055 | p.exe (PID 8260) PAGE_EXECUTE_READWRITE private VadS memory **[CONFIRMED — exec_id 019e5980-870a-78f2-90d4-6ddae88d43e5]

### ✅ verified _(line 252)_
- tools: `tsk_fls_list`
- exec_ids: `3d0cc116babb`
- matched: `p.exe`, `Windows/Temp/Perfmon/`
- claim: > ** | | Defense Evasion | Masquerading | T1036 | p.exe placed in `Windows/Temp/Perfmon/` (system-like path) **[CONFIRMED — exec_id 019e5984-20d1-7612-bc2e-3d0cc116babb]

### ✅ verified _(line 253)_
- exec_ids: `be8292d9d088`
- note: claim has no extractable tokens (prose only)
- LLM check: **VERIFIED** — The parsed cachedump data structurally contains two usernames (tdungan and spsql) with corresponding DCC2 hashes, directly matching the claim's specific assertion about cached credentials for these accounts.
- claim: > ** | | Credential Access | OS Credential Dumping: Cached Domain Credentials | T1003.005 | DCC2 hashes for tdungan and spsql on rd01 **[CONFIRMED — exec_id 019e5999-1923-7dc1-ab8a-be8292d9d088]

### ✅ verified _(line 255)_
- tools: `vol3_psscan`
- exec_ids: `0332a5a39dc3`
- matched: `9048`, `3068`, `sc.exe`, `Autorunsc.exe`
- claim: > ** | | Discovery | System Service Discovery / Recon | T1007 | sc.exe (PID 3068) and Autorunsc.exe (PID 9048) on wkstn-01 **[CONFIRMED — exec_id 019e5995-31eb-7720-9803-0332a5a39dc3]

### ✅ verified _(line 256)_
- tools: `vol3_psscan`, `vol3_cmdline`
- exec_ids: `d58e3bbb3cd2`, `1c61f74282b0`
- matched: `2876`, `WmiPrvSE.exe`
- claim: > ** | | Lateral Movement | WMI-based remote execution | T1021.003 | WmiPrvSE.exe (PID 2876) as parent of attacker chain on rd01 **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2, exec_id 019e…

### ✅ verified _(line 258)_
- tools: `vol3_psscan`
- exec_ids: `8891e848f830`
- matched: `2524`, `Rar.exe`
- claim: > ** | | Collection | Archive Collected Data: Archive via Utility | T1560.001 | Rar.exe (PID 2524) ran 9.75 min on file01 **[CONFIRMED — exec_id 019e5991-e973-74e2-bcbd-8891e848f830]

### ✅ verified _(line 259)_
- tools: `vol3_netscan`, `vol3_netscan`, `vol3_netscan`
- exec_ids: `0358e8a16035`, `117e3451809a`, `cb18611fee86`
- matched: `7092`, `172.16.7.11`, `172.16.4.5`, `172.16.4.10`, `172.16.6.11`, `ngentask.exe`
- claim: > ** | | Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP C2 over port 8080 to 172.16.4.10 from rd01 (`172.16.6.11`), file01 (`172.16.4.5`, ngentask.exe PID 7092), wkstn-…

### ✅ verified _(line 260)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `1156`, `10.10.254.1`, `rubyw.exe`
- claim: > ** | | Command & Control | Non-Standard Protocol (STOMP/ActiveMQ) | T1095 | rubyw.exe (PID 1156) STOMP port 61613 to 10.10.254.1 on file01 **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]

### ✅ verified _(line 280)_
- tools: `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `e9c3dd728cf7`, `3d0cc116babb`
- matched: `p.exe`, `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`, `Windows/Temp/Perfmon/p.exe`
- claim: > | Type | Value | Host | Confidence | |------|-------|------|------------| | File SHA-256 | `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c` — `Windows/Temp/Perfmon/p.exe` | rd01 | **…

### ✅ verified _(line 281)_
- tools: `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `756eee9a33fc`, `3d0cc116babb`
- matched: `ri.exe`, `57a04605ae0e308a0410b15f5478457417f03fcecf6eb30db7abb6409257429f`, `Users/spsql/Downloads/ri.exe`
- claim: > ** | | File SHA-256 | `57a04605ae0e308a0410b15f5478457417f03fcecf6eb30db7abb6409257429f` — `Users/spsql/Downloads/ri.exe` | rd01 | **[CONFIRMED — exec_id 019e598e-0d91-7c21-844b-756eee9a33fc, exec_id …

### ✅ verified _(line 282)_
- tools: `vol3_netscan`, `vol3_netscan`, `vol3_netscan`
- exec_ids: `0358e8a16035`, `117e3451809a`, `cb18611fee86`
- matched: `172.16.7.11`, `172.16.4.5`, `172.16.4.10`, `172.16.6.11`, `8080`
- claim: > ** | | C2 IP + Port | `172.16.4.10` port `8080` (internal relay) — rd01 (`172.16.6.11`), file01 (`172.16.4.5`), wkstn-01 (`172.16.7.11`) | rd01, file01, wkstn-01 | **[CONFIRMED — exec_id 019e597b-fc85…

### ✅ verified _(line 283)_
- tools: `vol3_netscan`
- exec_ids: `117e3451809a`
- matched: `10.10.254.1`, `61613`
- claim: > ** | | C2 IP + Port | `10.10.254.1` port `61613` (STOMP external) | file01 | **[CONFIRMED — exec_id 019e5991-2e2e-71b1-a420-117e3451809a]

### ✅ verified _(line 284)_
- tools: `vol3_psscan`
- exec_ids: `d58e3bbb3cd2`
- matched: `p.exe`, `WmiPrvSE.exe`, `cmd.exe`, `powershell.exe`
- claim: > ** | | Process chain | WmiPrvSE.exe (2876) → powershell.exe (8712) → powershell.exe (5848) → cmd.exe (5948) → p.exe (8260) | rd01 | **[CONFIRMED — exec_id 019e597a-322c-7db1-b1de-d58e3bbb3cd2]

### ✅ verified _(line 285)_
- tools: `vol3_cachedump`
- exec_ids: `be8292d9d088`
- matched: `b1 f8 72 62 37 0d 99 9b 3a b0 a9 43 19 d2 32 65`
- claim: > ** | | Credential hash | tdungan DCC2: `b1 f8 72 62 37 0d 99 9b 3a b0 a9 43 19 d2 32 65` | rd01 | **[CONFIRMED — exec_id 019e5999-1923-7dc1-ab8a-be8292d9d088]

### ✅ verified _(line 286)_
- tools: `vol3_cachedump`
- exec_ids: `be8292d9d088`
- matched: `4e 7a 21 7b 9b 6a df 36 e2 1a 7e 76 ce 1c 71 d2`
- claim: > ** | | Credential hash | spsql DCC2: `4e 7a 21 7b 9b 6a df 36 e2 1a 7e 76 ce 1c 71 d2` | rd01 | **[CONFIRMED — exec_id 019e5999-1923-7dc1-ab8a-be8292d9d088]

### ✅ verified _(line 287)_
- tools: `vol3_hashdump`
- exec_ids: `f7083bd0d3a4`
- matched: `range_admin`
- claim: > ** | | Suspicious account | `range_admin` (non-standard local account) | rd01 | **[CONFIRMED — exec_id 019e5999-092b-7230-ba7a-f7083bd0d3a4]
