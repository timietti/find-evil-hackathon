# MITRE ATT&CK coverage — SIFT-OWL v0.4 (38 MCP tools)

> Per-technique evaluation of the current typed MCP inventory's ability to
> surface forensic evidence supporting detection. Cross-references the
> existing 38 tools (17 vol3 + 6 disk + 10 EZ Tools + 4 hunt/carve/hash +
> query_rows) and points to the roadmap phases that close remaining gaps.
>
> The two `EZT`-prefixed tools that wrap a Linux-broken EZ Tool — Prefetch
> and SRUM — were rebuilt on libyal libraries (`libscca` / `libesedb`,
> W3-41 + W3-43). The MITRE coverage semantics they deliver are unchanged
> from the original SrumECmd / PECmd output.
>
> Validator v6 (W3-50/52) tightens the rule-based pass — backticked
> exec-id tokens no longer leak into the verifiable-token list, and
> multi-tag bullet-list paragraphs scope each trailing `(exec_id …)`
> cite to its own claim. Inline `--llm-check` (Haiku 4.5) auto-enables
> when `ANTHROPIC_API_KEY` is in env (W3-45). Vol3 runs fully offline
> after W3-53.

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
| **T1055** | Process Injection | ✅ Full | `vol3_malfind` (RWX VAD), `vol3_dlllist` (unbacked DLLs), `vol3_handles` (named pipes), `vol3_vadyarascan` (Cobalt Strike / Mimikatz / PyInstaller signatures in process memory), `yara_scan_extract` (extracted binary signatures) | None significant | — *(closed by Phase 3)* |
| **T1140** | Deobfuscate/Decode Files or Information | ✅ Full | `vol3_cmdline` (encoded args), `vol3_filescan` (dropped tmp files), `ezt_evtx_parse` (4104 ScriptBlock), `strings_extract` (decoded payload remnants from extracted binaries), `bulk_extract` (base64-decoded content in raw bytes) | None significant | — *(closed by Phase 3)* |
| **T1574** | Hijack Execution Flow (DLL sideload / IFEO / Path) | ✅ Full | `vol3_dlllist` (unbacked / sideloaded), `vol3_envars` (Path / PSModulePath interception), `ezt_persistence_keys_parse` (IFEO Debugger + SilentProcessExit + AppInit_DLLs + AppCertDlls) | None significant | — *(closed by Phase 1.5)* |
| **T1218** | System Binary Proxy Execution (LOLBins) | ✅ Full | `vol3_cmdline`, `vol3_psscan/pstree`, `ezt_prefetch_parse`, `ezt_shimcache_parse`, `ezt_amcache_parse`, `ezt_evtx_parse` (4688) | None significant | — |
| **T1685** | Disable or Modify Tools | ✅ Full | `ezt_evtx_parse` (7036 / 7045 / 1102 + Defender Operational channel), `vol3_svcscan` (service state), `vol3_cmdline` (`taskkill` / `Stop-Service` / `sc stop` / `net stop` args), `vol3_dlllist` (sideloaded DLL inside AV process) | Registry killswitches (`DisableAntiSpyware`, `DisableRealtimeMonitoring`) — secondary | Phase 5 (RECmd `triage_basic.reb`) |
| **T1686** | Disable or Modify System Firewall | ✅ Full | `ezt_evtx_parse` (Microsoft-Windows-Windows-Firewall-With-Advanced-Security/Firewall channel), `vol3_cmdline` (`netsh advfirewall` args), `vol3_psscan/pstree` (netsh parent), `vol3_svcscan` (`mpssvc` state) | Firewall registry policy (`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\...`) — secondary | Phase 5 (RECmd) |
| **T1110** | Brute Force | ✅ Full | `ezt_evtx_parse` (4625 / 4771 volume) | Threshold aggregation helper (account-level) | Phase 6 (correlator) |
| **T1003** | OS Credential Dumping (LSASS / NTDS / SAM) | ✅ Full | `vol3_hashdump` (SAM local hashes — T1003.002), `vol3_cachedump` (LSA cached domain creds / MSCASH — T1003.005), `vol3_handles(pid=lsass)`, `vol3_dlllist(pid=lsass)`, `vol3_vadyarascan` (Mimikatz patterns in lsass memory), `yara_scan_extract` (LSASS-dump magic on extracted files), `vol3_filescan` (lsass.dmp), `ezt_evtx_parse` (4663 NTDS) | None significant | — |
| **T1558** | Steal/Forge Kerberos Tickets (Kerberoasting, Golden/Silver) | ✅ Full | `vol3_skeleton_key_check` (Mimikatz skeleton key in lsass), `ezt_evtx_parse` (4768 / 4769 with TicketEncryptionType), `vol3_handles` | RC4_HMAC anomaly aggregation across many events | Phase 6 (correlator helper) |
| **T1021** | Remote Services (RDP/SMB/WMI/WinRM) | ✅ Full | `ezt_evtx_parse` (4624 type 3/10, 5140), `vol3_netscan` (3389/445/5985), `ezt_jumplist_parse` (mstsc), `ezt_shimcache_parse` | RDP bitmap-cache reconstruction (specialised, out of scope) | — |
| **T1071** | Application Layer Protocol (HTTP/DNS/SMTP) | ✅ Full | `vol3_netscan`, `vol3_filescan`, `bulk_extract` (URL / domain / email / IP scanners over raw bytes anywhere in image), `ezt_evtx_parse` (DNS-Client/Operational) | Browser history (Phase 5 SQLECmd) extends but doesn't close | — *(closed by Phase 3 bulk_extractor)* |
| **T1219** | Remote Access Software (TeamViewer / AnyDesk / Atera / ScreenConnect) | ✅ Full | `vol3_psscan/cmdline`, `ezt_amcache_parse`, `ezt_shimcache_parse`, `ezt_prefetch_parse`, `ezt_srum_parse` (bytes per process), `yara_scan_extract` (bundled SIFTOWL_RAS_Software_Common rule covers TeamViewer / AnyDesk / ScreenConnect / Atera) | None significant | — |

## Coverage tally

| Status | Count | % |
|---|---|---|
| ✅ Full | 20 | 91% |
| 🟡 Partial | 2 | 9% |
| 🟠 Indirect | 0 | 0% |
| ❌ Missing | 0 | 0% |

**No technique in this list has zero detection capability.**

Phase history:
- **Phase 1** (2026-05-10) — Prefetch / JumpList / RecycleBin / SRUM / dlllist / handles
- **Phase 1.5** (2026-05-11) — 5 Vol3 plugins + 2 disk-side parsers; closed T1003, T1053, T1547, T1558, T1574
- **Phase 3** (2026-05-11) — YARA + bulk_extractor + strings + hashing; closed T1055, T1071, T1140, T1219 (extended) and added cross-cutting `yara_scan_extract` + `vol3_vadyarascan`

Remaining Partial techniques and their closure phase:
- **T1091** (Replication via USB) — Phase 5 RECmd USB devices + ShellBags (`ezt_shellbags_parse`)
- **T1110** (Brute Force volume aggregation) — Phase 6 correlator threshold helper

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

## Tool-portability status (Linux SIFT)

| Tool family       | Backend                | Linux | Notes |
|---|---|---|---|
| `vol3_*` (17)     | Volatility 3 (Python) | ✅ | Runs fully offline (W3-53): community symbol pack cached at `/opt/sift-owl/vol3-symbols/`, MCP wrapper passes `-s` automatically. Cold-start `windows.info` ~5 s on x64 images. **Win7-x86 PAE** (e.g. STARK-APT `nromanoff`) is a known Vol3 `KernelPDBScanner` limitation — symbol pack does not unblock it; disk-side fallback is the working route. |
| `tsk_* / ewf_*` (6) | Sleuth Kit + libewf  | ✅ | Native Linux build. |
| `ezt_prefetch_parse` | libyal `libscca` (pyscca) | ✅ | PECmd 2026.5.0 is **Linux-broken** ("ESI-specific Windows libraries"). pyscca is portable; same fields. |
| `ezt_srum_parse`  | libyal `libesedb` (pyesedb) | ✅ | SrumECmd 2026.5.0 has the same guard. pyesedb parses SRUDB.dat directly; joins SruDbIdMapTable for app/user resolution. |
| Other `ezt_*` (8) | EZ Tools `.dll` via `dotnet` runtime | ✅ | MFTECmd / AppCompatCacheParser / EvtxECmd / AmcacheParser / RBCmd / JLECmd / RECmd / task XML + persistence-keys Python parsers. All older releases — no Windows guard. |
| `yara_scan_extract`, `vol3_vadyarascan`, `bulk_extract`, `strings_extract`, `hash_file` | YARA + bulk_extractor + Python | ✅ | All on PATH or pip-installable. |
| `query_rows`      | in-process audit-log replay | ✅ | Pure Python. |
