# SIFT-OWL — MCP tool roadmap

> Plan for expanding the typed MCP function inventory beyond the current 38 tools.
> Optimised for **two goals at once**: (a) win the hackathon — strengthen the
> SHIELDBASE final-eval pipeline; (b) leave a tool that is broadly useful for
> general DFIR after the hackathon, including legacy Windows (Win7-x86, WinXP).

---

## 0. Current state (2026-06-12)

**38 tools shipped**: 17 vol3 + 6 disk (TSK + EWF) + 10 EZ Tools
(MFT, ShimCache, EVTX, Amcache, Prefetch via libscca, JumpList,
RecycleBin, SRUM via libesedb, scheduled-task XML,
persistence_keys via RECmd) + 4 hunt/carve/hash (YARA,
bulk_extractor, strings, sha-family hashing) + `query_rows`.
Phase 1 + 1.5 + 3 all shipped. See `docs/ARCHITECTURE.md` §
"MCP server function inventory" for the full table and
`docs/MITRE_COVERAGE.md` for per-technique coverage at the
current inventory.

The two `EZT`-prefixed tools that wrapped a Linux-broken EZ Tool
— Prefetch and SRUM — were rebuilt on libyal libraries
(`libscca` / `libesedb`, W3-41 + W3-43); semantics are unchanged
from the original .NET output.

Held-out evals shipped on the 38-tool inventory: SHIELDBASE
89.9 % strict-verified (W3-52, full stack), VANKO-001 100.0 %
(W3-61, post W3-60 prompt fix). Remaining work on the *tool*
side is Phase 5 — the rest of the EZ Tools suite (RECmd full,
SQLECmd, LECmd, WxTCmd, SBECmd) — deferred as post-submission.

### Tool inventory present on this SIFT install but **not yet wrapped** (Phase 5 targets)

> Pruned 2026-06-15: `JLECmd` (jumplist), `RBCmd` (recyclebin),
> `bstrings` (strings_extract), and `bulk_extractor` (bulk_extract)
> moved out of this table — all shipped in the 38-tool inventory.

| Tool | Location | What it gives us |
|---|---|---|
| `LECmd.dll` | `/opt/zimmermantools/` | Single `.lnk` parsing — target path, MAC times, drive serial |
| `SBECmd.dll` | `/opt/zimmermantools/` | Shellbags — every folder the user opened in Explorer, including external drives no longer attached |
| `WxTCmd.dll` | `/opt/zimmermantools/` | Win10 Timeline (`ActivitiesCache.db`) — per-user activity feed |
| `RecentFileCacheParser.dll` | `/opt/zimmermantools/` | Win7 `RecentFileCache.bcf` — Amcache predecessor |
| `RECmd/RECmd.dll` | `/opt/zimmermantools/RECmd/` | Registry Explorer with 200+ plugins — Run keys, Services, USB devices, BAM, AppCompat, SAM, etc. (Note: a curated RECmd persistence batch already ships as `ezt_persistence_keys_parse`; Phase 5 generalises it) |
| `SQLECmd/SQLECmd.dll` | `/opt/zimmermantools/SQLECmd/` | SQLite parsing with plugin packs (Chrome / Edge / Firefox / Skype / Teams history) |

### Tool inventory **missing on this install** — would need install routine entries

> Updated 2026-06-15: YARA now installed + wrapped (`yara_scan_extract`);
> Prefetch + SRUM rebuilt on libyal (`libscca` / `libesedb`) so PECmd /
> SrumECmd are no longer required. Remaining gaps are Vol2 + Memory
> Baseliner, both post-submission.

| Tool | Why we need it | Install |
|---|---|---|
| **Volatility 2** (`vol.py` v2.6.x, Python 2) | **Required** for Win7-x86 PAE + WinXP memory images — Vol3's PDB-symbol approach can't auto-download symbols for these. Vol2 has built-in profiles. (Phase 2) | `pip2 install volatility` (Python 2) OR `apt install volatility` (Ubuntu ships 2.6) |
| **Memory Baseliner** (`baseline.py`) | Compare two memory images (suspect vs clean baseline) → diff of non-baseline processes/services/connections. CLAUDE.md references `/opt/memory-baseliner/baseline.py` but the dir doesn't exist on this image. | `git clone https://github.com/FSecureLABS/Memory-Baseliner /opt/memory-baseliner` |
| **Zeek** (`zeek`) | PCAP → structured `conn`/`dns`/`http`/`ssl` logs for network-evidence analysis (Phase 8). | `apt install zeek` or build from source |

### Plan for install-routine additions

Add a `scripts/bootstrap_sift_tools.sh` that installs the missing pieces and is referenced from `INSTALL.md`:

```bash
# YARA binary
sudo apt-get install -y yara

# Volatility 2 (Win7-x86 / WinXP support)
sudo apt-get install -y volatility   # SIFT ships this; on bare Ubuntu, needs Python 2 pip

# Missing EZ Tools (download into /opt/zimmermantools)
for tool in PECmd SrumECmd; do
    curl -L "https://download.mikestammer.com/net6/${tool}.zip" -o /tmp/${tool}.zip
    sudo unzip -o /tmp/${tool}.zip -d /opt/zimmermantools/
done

# Memory Baseliner
sudo git clone https://github.com/FSecureLABS/Memory-Baseliner /opt/memory-baseliner
```

---

## 1. Phased roadmap

Phases are sized so each one **ships as a self-contained release** with tests + docs.
Effort estimates are rough wall-clock budgets for the implementation.

### Phase 1 — Pre-SHIELDBASE essentials (Win10 program-exec depth) 🎯 *highest priority*

These are the missing pieces that will move the SHIELDBASE accuracy number.
Win10 multi-host case → program execution evidence is the spine, and the agent
currently has ShimCache + Amcache but not the OS-canonical Prefetch.

| # | New tool | Wraps | Pre-req on disk |
|---|---|---|---|
| 1.1 | `ezt_prefetch_parse(extract_exec_id)` | `PECmd --json` | `Windows\Prefetch\<NAME>-<HASH>.pf` |
| 1.2 | `ezt_jumplist_parse(extract_exec_id)` | `JLECmd --json` | `\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*` |
| 1.3 | `ezt_shellbags_parse(extract_exec_id)` | `SBECmd --json` | `NTUSER.DAT` + `UsrClass.dat` per user |
| 1.4 | `ezt_recyclebin_parse(extract_exec_id)` | `RBCmd --json` | `$Recycle.Bin\S-*\$I*` |
| 1.5 | `ezt_srum_parse(extract_exec_id)` | `SrumECmd --csv` | `Windows\System32\sru\SRUDB.dat` |
| 1.6 | `vol3_dlllist(image, pid?)` | `windows.dlllist` | none (memory) |
| 1.7 | `vol3_handles(image, pid)` | `windows.handles --pid` | none (memory) |

**Effort:** ~3-4 hours. Same shape as the existing `ezt_*` wrappers; one new parser per
EZ tool; two new Vol3 wrappers using `_run_jsonl_plugin`.

**Install touches:** PECmd + SrumECmd download (see §0). Both ship as standard EZ
Tools downloads; need to add to `scripts/bootstrap_sift_tools.sh`.

**Why it matters for SHIELDBASE:** SHIELDBASE is a Win10 enterprise case. Prefetch
is the program-execution gold standard on Win10. Jump Lists answer "what did the
attacker open" without needing the EVTX 4688 record. SRUM tells us how many bytes
went out per process — the exfil detector we've been missing.

---

### Phase 1.5 — MITRE-driven Vol3 plugin gaps (5 high-leverage wrappers) ✅ *shipped*

Surfaced by the MITRE ATT&CK coverage audit (`docs/MITRE_COVERAGE.md`). Each
wrapper closes a Partial-coverage technique to Full. All target Vol3 plugins
already installed on this SIFT (`vol -h | grep windows.<plugin>` confirms).

| # | New tool | Wraps | Closes | Status |
|---|---|---|---|---|
| 1.5.1 | `vol3_scheduled_tasks(image)` | `windows.scheduled_tasks` | **T1053** Scheduled Task/Job | ✅ |
| 1.5.2 | `vol3_skeleton_key_check(image)` | `windows.skeleton_key_check` | **T1558** Steal/Forge Kerberos Tickets (skeleton key) | ✅ |
| 1.5.3 | `vol3_hashdump(image)` | `windows.hashdump` | **T1003** OS Credential Dumping | ✅ |
| 1.5.4 | `vol3_envars(image, pid?)` | `windows.envars` | **T1574** Hijack Execution Flow (Path interception) | ✅ |
| 1.5.5 | `vol3_cachedump(image)` | `windows.cachedump` (LSA cached domain creds) | **T1003.005** DCC2/MSCASH | ✅ |

**Shipped substitution:** 1.5.5 landed as `vol3_cachedump` (LSA cached
domain credentials, T1003.005) rather than the originally-scoped
`vol3_dnscache` — cached-credential theft was the higher-signal gap on
the SHIELDBASE/STARK AD cases. A dedicated DNS-cache wrapper (T1071) is
folded into the Phase 8 network work below.

**Effort:** ~2 hours (actual). All five followed the existing
`_run_jsonl_plugin` shape; parsers are flat row-oriented. `vol3_envars`
mirrors `vol3_dlllist`'s optional pid filter; the other four are image-only.

**Install touches:** none — all plugins already present in Vol3 on SIFT 24.x.

---

### Phase 2 — Legacy Windows memory support (Win7-x86 / WinXP)

**Status update 2026-05-27 (W3-53):** Investigated as "Option A — targeted
Vol3 symbol fix". Outcome:

- ✅ **Vol3 community symbol pack wired in** (`/opt/sift-owl/vol3-symbols/`,
  ~800 MB, populated by `bootstrap_sift_tools.sh`). Vol3 now runs **fully
  offline**; cold-start `windows.info` on x64 images drops ~30 s → ~5 s.
  Validated against the STARK-APT win2008R2 dump.
- ✅ **WinXP (`tdungan`) confirmed working** with current Vol3 — not a
  gap, just no one had run `windows.info` on it directly before.
- ❌ **Win7-x86 PAE (`nromanoff`) still fails** with the pack in place.
  `KernelPDBScanner` finds 0 candidates even though the pack contains
  the correct `ntkrpamp.pdb` JSONs. The bottleneck is Vol3's page-map
  scanning logic on PAE dumps, not symbol availability. Vol3's verbose
  trace confirms it finds a PAE DTB at offset 1593344 with 4 valid
  pointers, then can't cross-reference to a kernel.

**Path forward for nromanoff:** Disk-side analysis is the only working
route (Prefetch, MFT, Amcache — already exercised in current STARK-APT
runs). Vol2 wrappers OR `memprocfs` integration would unblock memory
analysis on PAE; both are post-submission territory and out of scope
under the original "Option A" remit.

Vol2 specifically requires installing Python 2.7 or a community Py3
port (`apt install volatility` is no longer available on Ubuntu Noble),
which is ~12-16 hr of work for one host's memory signal on one dev
case. The accuracy report's variance-band analysis already shows
STARK-APT hits 86.1% relying on disk-side evidence for nromanoff.

#### Design choice: parallel `vol2_*` family, not auto-routing

Two reasons to keep `vol2_*` separate from `vol3_*` rather than auto-dispatching:

1. **Different plugin sets.** Vol2 has plugins Vol3 dropped (`ssdt`, `callbacks`,
   `printkey`, `connections` for XP-era). Forcing parity would lose Vol2 strengths.
2. **Different output shapes.** Vol2's text output is column-aligned, Vol3 uses
   `-r jsonl`. Parsers can't be shared.

Instead, add a single dispatcher tool `memory_profile_detect(image)` that returns
`{engine: "vol2"|"vol3", profile_or_build}`. The agent calls that first, then
picks the right family.

| # | New tool | Wraps | Profile target |
|---|---|---|---|
| 2.1 | `memory_profile_detect(image)` | Vol3 `windows.info` first, fall back to Vol2 `imageinfo` | Any |
| 2.2 | `vol2_imageinfo(image)` | `vol.py -f img imageinfo` | Win7-x86 PAE, WinXP, also Win7-x64 |
| 2.3 | `vol2_pslist(image, profile)` | `vol.py --profile=<P> pslist` | Same |
| 2.4 | `vol2_psscan(image, profile)` | `vol.py --profile=<P> psscan` | Same |
| 2.5 | `vol2_pstree(image, profile)` | `vol.py --profile=<P> pstree` | Same |
| 2.6 | `vol2_cmdline(image, profile)` | `vol.py --profile=<P> cmdline` | Same |
| 2.7 | `vol2_connections(image, profile)` | `vol.py --profile=<P> connections` (XP) **or** `connscan` (XP) | XP-era |
| 2.8 | `vol2_netscan(image, profile)` | `vol.py --profile=<P> netscan` | Win7+ |
| 2.9 | `vol2_malfind(image, profile)` | `vol.py --profile=<P> malfind` | Same |
| 2.10 | `vol2_dlllist(image, profile, pid?)` | `vol.py --profile=<P> dlllist` | Same |
| 2.11 | `vol2_modules(image, profile)` | `vol.py --profile=<P> modules` | Same |
| 2.12 | `vol2_modscan(image, profile)` | `vol.py --profile=<P> modscan` | Same |
| 2.13 | `vol2_svcscan(image, profile)` | `vol.py --profile=<P> svcscan` | Same |
| 2.14 | `vol2_ssdt(image, profile)` | `vol.py --profile=<P> ssdt` | XP/Win7 rootkit detection |
| 2.15 | `vol2_callbacks(image, profile)` | `vol.py --profile=<P> callbacks` | XP/Win7 kernel callbacks |

**Effort:** ~6-8 hours. New parser module `mcp_server/parsers/vol2.py` (text-table
parsers); new tool module `mcp_server/tools/memory_vol2.py`; reuses
`run_subprocess` and `AuditLogger`. Wire 15 tools into the FastMCP server.

**Install touches:** `apt install volatility` (or pip2). Add a sanity check in
`memory_profile_detect()` that returns a clear error if Vol2 absent.

**Why it matters beyond hackathon:** Vast amounts of legacy DFIR work is on Win7
and earlier (industrial control, govt, healthcare systems still run XP).
Tool that can't analyse a Win7-x86 memory dump is not a general-purpose DFIR tool.

---

### Phase 3 — Threat-hunt + carving + cross-source ✅ *shipped*

All five shipped and are in the 38-tool inventory.

| # | New tool | Wraps | Notes | Status |
|---|---|---|---|---|
| 3.1 | `yara_scan_extract(extract_exec_id, ruleset)` | `yara -r <rules> <file>` | Scan a previously-extracted file | ✅ |
| 3.2 | `vol3_vadyarascan(image, ruleset, pid?)` | `windows.vadyarascan` | YARA against per-process memory; per-PID is fast | ✅ |
| 3.3 | `bulk_extract(image)` | `bulk_extractor -j 4 -o <out>` | Feature files: URLs, emails, IPs, BTC, ZIP/RAR. Works on disk + memory. | ✅ |
| 3.4 | `strings_extract(extract_exec_id, encoding, min_len)` | `bstrings -f <file>` | High-perf strings with regex filter | ✅ |
| 3.5 | `hash_file(extract_exec_id)` | Python `hashlib` + ssdeep | MD5/SHA-1/SHA-256/ssdeep on extracted bytes | ✅ |

**Bundled YARA ruleset:** Ship a curated minimal set under `mcp_server/yara_rules/`:
- `apt_implants_basic.yar` — HTRAN, WEBC2, GREENCAT signatures
- `lolbins_suspicious.yar` — abused legitimate binaries
- `python_packed_pe.yar` — PyInstaller / py2exe footprint
- `mimikatz.yar` — well-known credential dumper signatures
- `webshells_basic.yar` — common .aspx / .php / .jsp webshells

`yara_scan_extract` defaults to bundled rules; an env override `SIFT_OWL_YARA_RULES`
points to an external dir.

**Effort:** ~6-8 hours. YARA parser is one-liner per match; bulk_extractor parser
is the work (feature-file walker per category).

**Install touches:** `apt install yara` + ship bundled rules in repo.

---

### Phase 4 — Plaso super-timeline (dropped, 2026-05-25)

Originally scoped as a post-submission addition. Removed from the roadmap
after the W3-52 SHIELDBASE run (89.9% strict, 71/79 verified) showed the
existing inventory builds adequate per-claim timelines from individual
tool outputs (psscan create_time + MFT timestamps + EVTX + Prefetch).
A super-timeline would add a multi-million-event firehose at ~2 hr/disk
wall — out of proportion to the marginal signal vs. the agent's current
targeted approach.

---

### Phase 5 — Registry + browser depth

| # | New tool | Wraps | Notes |
|---|---|---|---|
| 5.1 | `ezt_recmd_parse(extract_exec_id, batch_name)` | `RECmd --bn <batch>` | Run a curated RECmd batch (Run keys, USB, BAM, services, etc.) |
| 5.2 | `ezt_sqlecmd_parse(extract_exec_id)` | `SQLECmd --dedupe` | Auto-detects SQLite type via plugin packs (browser history, Teams, etc.) |
| 5.3 | `ezt_lnk_parse(extract_exec_id)` | `LECmd --json` | Single .lnk file — drive serial, target MAC times |
| 5.4 | `ezt_winten_parse(extract_exec_id)` | `WxTCmd --csv` | Win10 ActivitiesCache.db |
| 5.5 | `ezt_recentfilecache_parse(extract_exec_id)` | `RecentFileCacheParser --csv` | Win7-only Amcache predecessor |

**Bundled RECmd batches:** Curate 3-4 batch files in `mcp_server/recmd_batches/`:
- `triage_basic.reb` — Run keys, services, scheduled tasks, USB
- `program_execution.reb` — BAM, UserAssist (already covered by vol3_userassist for memory), AppCompatFlags
- `network.reb` — wireless profiles, network adapters

**Effort:** ~4-6 hours. Five EZ Tools, each a parser+wrapper of the standard pattern.

**Install touches:** RECmd batch files in repo; SQLECmd plugins are bundled with the DLL.

---

### Phase 6 — Cross-source correlator (meta-tools)

Not new forensic primitives, but new agent helpers built on top of the audit log.

| # | New tool | Returns |
|---|---|---|
| 6.1 | `correlate_indicator(value, kind?)` | All exec_log rows whose `parsed_summary` contains the value (IP, hash, path, account name). Cross-source by construction. |
| 6.2 | `correlate_process(name, hostname?)` | Memory psscan + disk MFT + ShimCache + Amcache + Prefetch + EVTX 4688 rows matching the process name. |
| 6.3 | `audit_search(query)` | Full-text search over `parsed_summary` and `summary` fields in `audit/exec_log.jsonl`. |

**Why these matter:** Today the agent has to do correlation by hand — "I see STUN.exe
in psscan, now let me query_rows on MFT for the path, now let me query EVTX...".
These tools fold the pattern into a single call.

**Effort:** ~3-4 hours. Pure-Python; reads the audit log; no subprocess.

---

### Phase 7 — Linux/macOS memory (post-hackathon stretch)

Vol3 has profiles for Linux + macOS. Adding `vol3_linux_*` and `vol3_mac_*` families
would make SIFT-OWL the only public AI DFIR agent that handles non-Windows memory.

Out of scope for the hackathon (SHIELDBASE is Windows-only), but worth a paragraph
in the post-submission roadmap.

---

### Phase 8 — Network / PCAP evidence (Zeek-first, post-submission)

Today the only network signal is `vol3_netscan` (memory sockets at capture
time) and `bulk_extract` (IP/URL carving from raw bytes). A real intrusion
case ships PCAP — C2 beaconing, DNS tunnelling, and exfil live there.
**Zeek-first:** rather than re-deriving protocol logic per query with
`tshark` display filters, run Zeek once to produce structured `*.log`
files, then parse those — it gives connection/DNS/HTTP/TLS context "for
free" and the same flat-row parser shape the rest of the inventory uses.
`tshark` stays available for object extraction where Zeek has no analyser.

| # | New tool | Wraps | Notes |
|---|---|---|---|
| 8.1 | `zeek_analyze(pcap)` | `zeek -r <pcap> LogAscii::use_json=T` | One run → `conn`/`dns`/`http`/`ssl`/`files`/`weird` logs under `audit/raw/<exec_id>/`; returns per-log row counts + summary |
| 8.2 | `zeek_log_query(exec_id, log, filter?)` | re-parse a prior `zeek_analyze` log (`conn.log`, `dns.log`, …) | Drill/filter a single Zeek log by field — mirrors `query_rows` semantics |
| 8.3 | `pcap_conversations(pcap)` | `tshark -q -z conv,tcp -z conv,udp` | Flow/talker summary when a fast top-N is wanted without full Zeek |
| 8.4 | `pcap_extract_objects(pcap, proto)` | `tshark --export-objects <http\|smb\|tftp>` | Carve transferred files into the extract chain (→ feed `ezt_*` / `hash_file` / `yara_scan_extract`) |
| 8.5 | `pcap_dns(pcap)` | Zeek `dns.log` (or `tshark -Y dns`) | Beaconing / DGA / tunnelling indicators; closes the deferred **T1071** (Application Layer Protocol: DNS) |

**Effort:** ~6-8 hours. Zeek JSON logs are flat NDJSON → reuse the existing
`_run_jsonl_plugin`-style parser; `tshark` paths add a thin text/JSON parser.

**Install touches:** `apt install zeek` (or build); add to
`scripts/bootstrap_sift_tools.sh` with a sanity check. `tshark` ships with
Wireshark on SIFT.

**Architectural fit:** PCAP files arrive as evidence under the `/cases/`
allow-list → typed `pcap: str` input (same validation as `image`); all
output under `audit/raw/<exec_id>/`; one exec-log row per call; row lists
truncated at the wire with full logs drillable via `zeek_log_query`.

---

### Phase 9 — Log aggregation / non-Windows logs (post-submission)

EVTX is covered (`ezt_evtx_parse`), but Linux/Unix hosts, network
appliances, and application logs are not. For multi-host enterprise cases
(and the post-hackathon general-DFIR goal) a normalised, time-windowed log
ingester feeds the Phase 6 correlator across host boundaries.

| # | New tool | Wraps / does | Notes |
|---|---|---|---|
| 9.1 | `linux_auth_parse(extract_exec_id)` | parse `auth.log` / `secure` | SSH logins, sudo, su, cron, useradd — T1078 / T1098 / T1136 on Linux |
| 9.2 | `journald_parse(extract_exec_id, unit?)` | `journalctl --file <journal> -o json` | systemd journal export from an extracted `*.journal` |
| 9.3 | `syslog_parse(extract_exec_id, facility?)` | RFC3164/5424 line parser | Generic syslog (firewall/router/appliance) → normalised rows |
| 9.4 | `log_aggregate(exec_ids, since?, until?)` | merge prior log-parse outputs | Time-window union across hosts/sources → one sorted timeline of events, normalised `{ts, host, source, event}` rows for the correlator |

**Effort:** ~5-7 hours. Mostly line-regex parsers + a merge/sort pass;
no new external binary (journald needs `systemd`'s `journalctl`, already
present on SIFT).

**Architectural fit:** non-Windows log files enter via `tsk_icat_extract`
(disk) or a `cylr_collection`-style triage drop, so tools take
`extract_exec_id`, never paths. `log_aggregate` is pure-Python over the
audit log — same family as the Phase 6 correlator meta-tools.

---

## 2. Recommended sequencing

What actually shipped for submission, then the post-submission queue:

```
Phase 1 ✓ (Prefetch + JLE + SBE + RBE + SRUM + dlllist + handles)  ← shipped
    │
    ▼
SHIELDBASE final eval run ✓                                        ← 71.4% single-shot held-out;
                                                                     89.9% (71/79) with v2 loop
                                                                     + libesedb SRUM + LLM-check (W3-52)
    │
    ▼
Phase 1.5 ✓ (5 Vol3 plugin gaps from MITRE audit)                  ← shipped (1.5.5 as cachedump)
    │
    ▼
Phase 3 ✓ (YARA + vadyarascan + bulk_extractor + strings + hash)  ← shipped
    │
    ▼
VANKO-001 held-out eval ✓                                          ← 36.4% single-shot → 100.0% (W3-61)
    │
    ▼
Submission ✓                                                       ← repo public + video + Devpost
    │
    ▼
═══ POST-SUBMISSION QUEUE (none shipped yet) ═══
    │
    ▼
Phase 5 (RECmd / SQLECmd / LECmd / WxTCmd / RecentFileCache)       ← 4-6 hr  (T1547/T1078/T1098/
    │                                                                          T1091/T1136/T1574)
    ▼
Phase 2 (Vol2 fallback for Win7-x86 / WinXP)                       ← 6-8 hr  (general-DFIR legacy)
    │
    ▼
Phase 6 (cross-source correlator meta-tools)                       ← 3-4 hr
    │
    ▼
Phase 8 (Zeek-first network / PCAP)                                ← 6-8 hr  (closes T1071 DNS)
    │
    ▼
Phase 9 (log aggregation / non-Windows logs)                       ← 5-7 hr
    │
    ▼
Phase 7 (Linux/macOS memory)                                       ← stretch
```

> **Note:** Phase 5 was promoted to "pre-submission" earlier (2026-05-11)
> on the MITRE audit, but did not ship before the deadline — the 38-tool
> inventory already reached 13 Full / 9 Partial / 0 Missing coverage and
> the held-out results (SHIELDBASE 89.9 %, VANKO 100 %) cleared the bar.
> Phase 5 now heads the post-submission queue.

**SRUM (libesedb-based, W3-43):** ✓ done. `ezt_srum_parse` now reads
`SRUDB.dat` in-process via libyal `libesedb` (pyesedb), joining
`SruDbIdMapTable` for app/user resolution and projecting seven provider
tables — `network_usage`, `app_resource_use`, `network_connections`,
`push_notifications`, `energy_usage`, `energy_usage_lt`, `app_timeline`.
This replaces SrumECmd, which v2026.5.0 refuses to run on Linux ("ESI
specific Windows libraries"). Same refactor pattern as Prefetch +
libscca (W3-41).

**Reordering note (2026-05-11):** Phase 5 promoted from post-submission to
pre-submission after the MITRE coverage audit found it closes 7 of 9
Partial-coverage techniques.

**Phase 4 (Plaso) removed from roadmap (2026-05-25):** Originally a
post-submission addition. Dropped after the W3-52 SHIELDBASE run showed
the existing inventory builds adequate per-claim timelines without a
super-timeline firehose; the wall-time cost (~2 hr/disk) is out of
proportion to the marginal signal.

Phase 1 ships **before** SHIELDBASE so the headline result includes Prefetch +
JumpList coverage. Phase 2 ships **after** SHIELDBASE because legacy-OS support
doesn't help the Win10 case but does materially help the post-hackathon value
proposition.

---

## 3. Architectural invariants (preserved across all phases)

Every new tool **must**:

- Take **typed inputs only** — no free-form paths from the agent. Disk-side tools
  accept `image: str` against the evidence-root allow-list; artifact parsers accept
  `extract_exec_id: str` resolved via the audit log (TB4).
- Write subprocess output **only** under `audit/raw/<exec_id>/` — never to `/cases/`,
  never to user-supplied paths.
- Record exactly **one** `audit/exec_log.jsonl` row per call, with `parsed_summary`
  preserving aggregates but stripping bulky row lists.
- Truncate row lists at the MCP boundary to ≤50 entries; full rows remain on disk
  and are reachable via `query_rows` (registered in `_PARSERS` + `_ROWS_KEY`).
- Be argv-list `subprocess.run` calls — **never `shell=True`** (TB3).
- Ship with at least one unit-test against a synthetic fixture, and an e2e marker
  (skipped if real evidence absent).

---

## 4. Effort summary

| Phase | New tools | Effort | Order | Status |
|---|---|---|---|---|
| 1 — SHIELDBASE essentials | 6 | 3-4 hr | first | ✅ shipped (W3-19) |
| 1.5 — MITRE-driven Vol3 gaps | 5 | ~2 hr | second | ✅ shipped (1.5.5 as cachedump) |
| 3 — YARA + carving | 5 | 6-8 hr | third | ✅ shipped |
| 5 — Registry + browser | 5 | 4-6 hr | post-submission (queue head) | pending |
| 2 — Vol2 fallback | 15 | 6-8 hr | post-submission | pending |
| 6 — Correlator helpers | 3 | 3-4 hr | post-submission | pending |
| 8 — Network / PCAP (Zeek-first) | 5 | 6-8 hr | post-submission | pending |
| 9 — Log aggregation / non-Windows | 4 | 5-7 hr | post-submission | pending |
| 7 — Linux/mac memory | ~8 | — | future | future |

**Inventory growth — shipped, then the post-submission queue:**

```
Phase 1 (W3-19)        ─┐
Phase 1.5              ─┤  cumulative → 38 tools shipped for submission
Phase 3               ─┘  (17 vol3 + 6 disk + 10 EZ + 4 hunt + query_rows)
─────────────────────────  ↑ SHIELDBASE 89.9% / VANKO 100% ran on this set
+ Phase 5 (5)             43
+ Phase 2 (15)            58   (Vol2 family; Win7-x86/XP closure)
+ Phase 6 (3)             61   (correlator meta-tools)
+ Phase 8 (5)             66   (Zeek/PCAP network evidence)
+ Phase 9 (4)             70   (log aggregation / non-Windows)
```

**MITRE coverage at the shipped 38-tool inventory** (per
`docs/MITRE_COVERAGE.md`): **13 Full, 9 Partial, 0 Missing**. Phase 5
closes 7 of the 9 Partials to Full; Phase 8 closes the deferred T1071
(DNS) Partial. **Post-submission effort total:** ~24-33 hours across
Phases 5/2/6/8/9.
