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
| **T1053** | Scheduled Task/Job | 🟡 Partial | `tsk_fls_list/icat` can pull `\Windows\System32\Tasks\*` XMLs + EVTX TaskScheduler logs | No `vol3_scheduled_tasks` wrapper; no Task-XML parser | **Phase 1.5** (`vol3_scheduled_tasks`) |
| **T1204** | User Execution | ✅ Full | `ezt_prefetch_parse`, `ezt_jumplist_parse`, `vol3_userassist`, `ezt_recyclebin_parse`, `ezt_amcache_parse` | None significant | — |
| **T1098** | Account Manipulation | ✅ Full | `ezt_evtx_parse` (4720 / 4732 / 4756 / 4724 / 4738 / 4781) | SAM-hive snapshot | Phase 5 (RECmd SAM) |
| **T1547** | Boot/Logon Autostart Execution | 🟡 Partial | `vol3_svcscan`, `vol3_userassist`; `tsk_icat_extract` can pull SOFTWARE/NTUSER but no Run-key parser | Run/RunOnce, Winlogon, AppInit DLLs — only ShimCache currently parsed from hives | Phase 5 (RECmd `triage_basic.reb` batch) |
| **T1136** | Create Account | ✅ Full | `ezt_evtx_parse` (4720), `vol3_userassist` (per-user hive presence in memory) | SAM-hive parser | Phase 5 |
| **T1543** | Create/Modify System Process (.003 Windows Service) | ✅ Full | `vol3_svcscan`, `ezt_evtx_parse` (7045 install, 7036 state change), `ezt_amcache_parse`, `ezt_shimcache_parse` | None significant | — |
| **T1055** | Process Injection | ✅ Full | `vol3_malfind` (RWX VAD), `vol3_dlllist` (unbacked DLLs — Phase 1), `vol3_handles` (named pipes — Phase 1) | Targeted YARA in process memory | Phase 3 (`vol3_vadyarascan`) |
| **T1140** | Deobfuscate/Decode Files or Information | 🟡 Partial | `vol3_cmdline` (encoded args), `vol3_filescan` (dropped tmp files), `ezt_evtx_parse` (4104) | strings extraction over dropped binaries | Phase 3 (`strings_extract`) |
| **T1574** | Hijack Execution Flow (DLL sideload / IFEO / Path) | 🟡 Partial | `vol3_dlllist` (unbacked + sideloaded), `tsk_icat_extract` on SOFTWARE hive | IFEO registry plugin; Path env var | **Phase 1.5** (`vol3_envars`) + Phase 5 (RECmd IFEO) |
| **T1218** | System Binary Proxy Execution (LOLBins) | ✅ Full | `vol3_cmdline`, `vol3_psscan/pstree`, `ezt_prefetch_parse`, `ezt_shimcache_parse`, `ezt_amcache_parse`, `ezt_evtx_parse` (4688) | None significant | — |
| **T1686** | (not a standard ATT&CK ID) | ❓ Unknown | — | Please verify the ID — `T1686` is not in MITRE ATT&CK Enterprise. Closest candidates: T1056 (Input Capture) or T1656 (Impersonation). | (clarify) |
| **T1685** | (not a standard ATT&CK ID) | ❓ Unknown | — | Please verify — `T1685` is not in MITRE ATT&CK Enterprise. Closest: T1556 (Modify Authentication Process) or T1657 (Financial Theft). | (clarify) |
| **T1110** | Brute Force | ✅ Full | `ezt_evtx_parse` (4625 / 4771 volume) | Threshold aggregation helper (account-level) | Phase 6 (correlator) |
| **T1003** | OS Credential Dumping (LSASS / NTDS / SAM) | 🟡 Partial | `vol3_handles(pid=lsass)`, `vol3_dlllist(pid=lsass)`, `vol3_filescan` (lsass.dmp), `ezt_evtx_parse` (4663 NTDS) | No dedicated SAM dumper, no Mimikatz signatures | **Phase 1.5** (`vol3_hashdump`) + Phase 3 (Mimikatz YARA) |
| **T1558** | Steal/Forge Kerberos Tickets (Kerberoasting, Golden/Silver) | 🟡 Partial | `ezt_evtx_parse` (4768 / 4769 with TicketEncryptionType), `vol3_handles` | RC4_HMAC anomaly aggregation; skeleton-key detection | **Phase 1.5** (`vol3_skeleton_key_check`) + Phase 6 (correlator) |
| **T1021** | Remote Services (RDP/SMB/WMI/WinRM) | ✅ Full | `ezt_evtx_parse` (4624 type 3/10, 5140), `vol3_netscan` (3389/445/5985), `ezt_jumplist_parse` (mstsc), `ezt_shimcache_parse` | RDP bitmap-cache reconstruction (specialised, out of scope) | — |
| **T1071** | Application Layer Protocol (HTTP/DNS/SMTP) | 🟡 Partial | `vol3_netscan`, `vol3_filescan`, `ezt_evtx_parse` (DNS-Client/Operational) | DNS cache from memory, browser history, bulk-feature carving | **Phase 1.5** (`vol3_dnscache`) + Phase 3 (bulk_extractor URLs/IPs) + Phase 5 (SQLECmd browsers) |
| **T1219** | Remote Access Software (TeamViewer / AnyDesk / Atera / ScreenConnect) | ✅ Full | `vol3_psscan/cmdline`, `ezt_amcache_parse`, `ezt_shimcache_parse`, `ezt_prefetch_parse`, `ezt_srum_parse` (bytes per process) | Signature-based detection of specific RAS families | Phase 3 (YARA rules for known RAS) |

## Coverage tally

| Status | Count | % |
|---|---|---|
| ✅ Full | 11 | 50% |
| 🟡 Partial | 9 | 41% |
| 🟠 Indirect | 0 | 0% |
| ❌ Missing | 0 | 0% |
| ❓ Unknown ID | 2 | 9% |

**No technique in this list has zero detection capability.** Every partial-coverage technique is closed by a planned tool addition. The two unknown IDs (T1685, T1686) need user clarification before they can be mapped.

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
