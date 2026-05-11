# MITRE ATT&CK coverage — SIFT-OWL v0.4 (26 MCP tools)

> Per-technique evaluation of the current typed MCP inventory's ability to
> surface forensic evidence supporting detection. Cross-references the
> existing 26 tools (11 vol3 + 6 disk + 8 EZ Tools + query_rows) and points
> to the roadmap phases that close remaining gaps.

## Status legend

- ✅ **Full** — multiple corroborating sources (memory + disk + EVTX), dedicated parsers
- 🟡 **Partial** — adequate signal in current tools but a key parser is missing or rule-based aggregation is needed
- 🟠 **Indirect** — only via raw artefacts (e.g. extracted hive without a parser); manual interpretation required
- ❌ **Missing** — no current capability
- ❓ **Unknown** — technique ID not recognised in MITRE ATT&CK Enterprise

## Coverage matrix

| Technique | Name | Status | Current tools | Primary gap | Closes via |
|---|---|---|---|---|---|
| **T1566** | Phishing | ✅ Full | `vol3_filescan`, `vol3_psscan/pstree`, `vol3_malfind` (Outlook RWX), `ezt_evtx_parse` (4688), `ezt_prefetch_parse`, `ezt_jumplist_parse` | OST/PST inspection | (out of scope — libpff future) |
| **T1091** | Replication through Removable Media | 🟡 Partial | `ezt_jumplist_parse` (drive serials), `ezt_shimcache_parse` (`autorun.inf`), `tsk_fls_list` (`setupapi.dev.log`) | USB registry plugins + Shellbags parser | Phase 5 (`ezt_shellbags_parse` + RECmd USB) |
| **T1078** | Valid Accounts | ✅ Full | `ezt_evtx_parse` (4624 / 4625 + logon type), `vol3_userassist`, `ezt_srum_parse` | SAM-hive direct inspection | Phase 5 (RECmd SAM plugin) |
| **T1059** | Command and Scripting Interpreter | ✅ Full | `vol3_cmdline`, `vol3_psscan/pstree`, `ezt_evtx_parse` (4688, 4104), `ezt_prefetch_parse` | PS ScriptBlock decoded content, `consolehost_history.txt` | Phase 5 + `ezt_evtx_parse` already reads 4104 |
| **T1053** | Scheduled Task/Job | ✅ Full | `vol3_scheduled_tasks` (live in-memory), `ezt_task_xml_parse` (disk XMLs), `ezt_evtx_parse` (TaskScheduler 106/140/141/200) | None significant | — *(closed by Phase 1.5)* |
| **T1204** | User Execution | ✅ Full | `ezt_prefetch_parse`, `ezt_jumplist_parse`, `vol3_userassist`, `ezt_recyclebin_parse`, `ezt_amcache_parse` | None significant | — |
| **T1098** | Account Manipulation | ✅ Full | `ezt_evtx_parse` (4720 / 4732 / 4756 / 4724 / 4738 / 4781) | SAM-hive snapshot | Phase 5 (RECmd SAM) |
| **T1547** | Boot/Logon Autostart Execution | ✅ Full | `vol3_svcscan`, `vol3_userassist`, `ezt_persistence_keys_parse` (Run/RunOnce/RunOnceEx/Policies-Run/Winlogon Shell+Userinit+Notify) | None significant | — *(closed by Phase 1.5)* |
| **T1136** | Create Account | ✅ Full | `ezt_evtx_parse` (4720), `vol3_userassist` (per-user hive presence in memory) | SAM-hive parser | Phase 5 |
| **T1543** | Create/Modify System Process (.003 Windows Service) | ✅ Full | `vol3_svcscan`, `ezt_evtx_parse` (7045 install, 7036 state change), `ezt_amcache_parse`, `ezt_shimcache_parse` | None significant | — |
| **T1055** | Process Injection | ✅ Full | `vol3_malfind` (RWX VAD), `vol3_dlllist` (unbacked DLLs — Phase 1), `vol3_handles` (named pipes — Phase 1) | Targeted YARA in process memory | Phase 3 (`vol3_vadyarascan`) |
| **T1140** | Deobfuscate/Decode Files or Information | 🟡 Partial | `vol3_cmdline` (encoded args), `vol3_filescan` (dropped tmp files), `ezt_evtx_parse` (4104) | strings extraction over dropped binaries | Phase 3 (`strings_extract`) |
| **T1574** | Hijack Execution Flow (DLL sideload / IFEO / Path) | ✅ Full | `vol3_dlllist` (unbacked / sideloaded), `vol3_envars` (Path / PSModulePath interception), `ezt_persistence_keys_parse` (IFEO Debugger + SilentProcessExit + AppInit_DLLs + AppCertDlls) | None significant | — *(closed by Phase 1.5)* |
| **T1218** | System Binary Proxy Execution (LOLBins) | ✅ Full | `vol3_cmdline`, `vol3_psscan/pstree`, `ezt_prefetch_parse`, `ezt_shimcache_parse`, `ezt_amcache_parse`, `ezt_evtx_parse` (4688) | None significant | — |
| **T1685** | Disable or Modify Tools | ✅ Full | `ezt_evtx_parse` (7036 / 7045 / 1102 + Defender Operational channel), `vol3_svcscan` (service state), `vol3_cmdline` (`taskkill` / `Stop-Service` / `sc stop` / `net stop` args), `vol3_dlllist` (sideloaded DLL inside AV process) | Registry killswitches (`DisableAntiSpyware`, `DisableRealtimeMonitoring`) — secondary | Phase 5 (RECmd `triage_basic.reb`) |
| **T1686** | Disable or Modify System Firewall | ✅ Full | `ezt_evtx_parse` (Microsoft-Windows-Windows-Firewall-With-Advanced-Security/Firewall channel), `vol3_cmdline` (`netsh advfirewall` args), `vol3_psscan/pstree` (netsh parent), `vol3_svcscan` (`mpssvc` state) | Firewall registry policy (`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\...`) — secondary | Phase 5 (RECmd) |
| **T1110** | Brute Force | ✅ Full | `ezt_evtx_parse` (4625 / 4771 volume) | Threshold aggregation helper (account-level) | Phase 6 (correlator) |
| **T1003** | OS Credential Dumping (LSASS / NTDS / SAM) | ✅ Full | `vol3_hashdump` (SAM local hashes — T1003.002), `vol3_cachedump` (LSA cached domain creds / MSCASH — T1003.005), `vol3_handles(pid=lsass)`, `vol3_dlllist(pid=lsass)`, `vol3_filescan` (lsass.dmp), `ezt_evtx_parse` (4663 NTDS) | Mimikatz YARA signatures for in-memory residue | Phase 3 (extends, not closes) |
| **T1558** | Steal/Forge Kerberos Tickets (Kerberoasting, Golden/Silver) | ✅ Full | `vol3_skeleton_key_check` (Mimikatz skeleton key in lsass), `ezt_evtx_parse` (4768 / 4769 with TicketEncryptionType), `vol3_handles` | RC4_HMAC anomaly aggregation across many events | Phase 6 (correlator helper) |
| **T1021** | Remote Services (RDP/SMB/WMI/WinRM) | ✅ Full | `ezt_evtx_parse` (4624 type 3/10, 5140), `vol3_netscan` (3389/445/5985), `ezt_jumplist_parse` (mstsc), `ezt_shimcache_parse` | RDP bitmap-cache reconstruction (specialised, out of scope) | — |
| **T1071** | Application Layer Protocol (HTTP/DNS/SMTP) | 🟡 Partial | `vol3_netscan`, `vol3_filescan`, `ezt_evtx_parse` (DNS-Client/Operational) | DNS cache from memory, browser history, bulk-feature carving | **Phase 1.5** (`vol3_dnscache`) + Phase 3 (bulk_extractor URLs/IPs) + Phase 5 (SQLECmd browsers) |
| **T1219** | Remote Access Software (TeamViewer / AnyDesk / Atera / ScreenConnect) | ✅ Full | `vol3_psscan/cmdline`, `ezt_amcache_parse`, `ezt_shimcache_parse`, `ezt_prefetch_parse`, `ezt_srum_parse` (bytes per process) | Signature-based detection of specific RAS families | Phase 3 (YARA rules for known RAS) |

## Coverage tally

| Status | Count | % |
|---|---|---|
| ✅ Full | 18 | 82% |
| 🟡 Partial | 4 | 18% |
| 🟠 Indirect | 0 | 0% |
| ❌ Missing | 0 | 0% |

**No technique in this list has zero detection capability.** Phase 1.5 (shipped 2026-05-11) closed 5 Partial → Full: T1003, T1053, T1547, T1558, T1574.

Remaining Partial techniques and their closure phase:
- **T1091** (Replication via USB) — Phase 5 RECmd USB devices + ShellBags (`ezt_shellbags_parse`)
- **T1140** (Deobfuscate/Decode) — Phase 3 `strings_extract` over dropped temp files
- **T1071** (Application Layer Protocol — DNS/HTTP slices) — Phase 3 bulk_extractor URLs/IPs + Phase 5 SQLECmd browser history
- **T1110** (Brute Force aggregation) — Phase 6 correlator threshold helper

> Note on IDs: T1685 (Disable or Modify Tools) and T1686 (Disable or Modify System Firewall) appear in some published technique lists. As of the writer's training cutoff these were canonically tracked as the **T1562.001** and **T1562.004** sub-techniques of T1562 Impair Defenses; MITRE may have promoted them to top-level IDs since. Detection semantics are identical — IDs preserved as the user supplied them.

## Highest-leverage additions (cross-technique impact)

Sorted by how many techniques each closes:

| Addition | Phase | Techniques closed |
|---|---|---|
| `vol3_scheduled_tasks` | **1.5 (new)** | T1053 (full closure) |
| `vol3_skeleton_key_check` | **1.5 (new)** | T1558 (full closure) |
| `vol3_hashdump` | **1.5 (new)** | T1003 (large lift) |
| `vol3_envars` | **1.5 (new)** | T1574 (Path interception) |
| `vol3_dnscache` (via `windows.cachedump` for DNS) | **1.5 (new)** | T1071 (DNS slice) |
| RECmd with `triage_basic.reb` batch | Phase 5 | T1547, T1078, T1098, T1136, T1091, T1574 (6 techniques) |
| SQLECmd browser plugins | Phase 5 | T1071 (browser-protocol slice), T1566 (phishing-link history) |
| bulk_extractor | Phase 3 | T1071 (URLs/IPs/domains from raw), T1140 (decoded strings, BTC, emails) |
| YARA on memory + extracted files | Phase 3 | T1003 (Mimikatz patterns), T1055 (injected payload signatures), T1219 (RAS families) |

## Notes

The matrix excludes **non-detection** coverage (e.g. atomic-red-team-style adversary emulation). SIFT-OWL is a forensic-analysis platform; detection here means "agent can find evidence supporting a hypothesis that technique X was used", not "agent can trigger or prevent technique X".

For each technique, the corresponding *forensic artefacts* MITRE documents — registry keys, log events, file paths, in-memory primitives — are the search space. Tools that parse those artefacts give the agent direct access; missing parsers leave the artefacts as raw bytes the agent must reason about indirectly.

The roadmap (`plans/MCP_TOOL_ROADMAP.md`) is updated with a **Phase 1.5** that bundles the 5 high-leverage Vol3 wrappers above into a single small release. Together they take Partial coverage of T1003 / T1053 / T1558 / T1574 / T1071 to Full, with ~2 hours of implementation effort.
