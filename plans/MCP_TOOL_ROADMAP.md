# SIFT-OWL — MCP tool roadmap

> Plan for expanding the typed MCP function inventory beyond the current 20 tools.
> Optimised for **two goals at once**: (a) win the hackathon — strengthen the
> SHIELDBASE final-eval pipeline; (b) leave a tool that is broadly useful for
> general DFIR after the hackathon, including legacy Windows (Win7-x86, WinXP).

---

## 0. Current state (2026-05-10)

20 tools shipped: 9 vol3 + 6 disk (TSK + EWF) + 4 EZ Tools (MFT, ShimCache, EVTX,
Amcache) + `query_rows`. See `docs/ARCHITECTURE.md` § "MCP server function inventory".

### Tool inventory present on this SIFT install but **not yet wrapped**

| Tool | Location | What it gives us |
|---|---|---|
| `LECmd.dll` | `/opt/zimmermantools/` | Single `.lnk` parsing — target path, MAC times, drive serial |
| `JLECmd.dll` | `/opt/zimmermantools/` | Jump Lists (`.automaticDestinations-ms` / `.customDestinations-ms`) — recent files per app, MUTI-IMPORTANT for hands-on-keyboard evidence |
| `RBCmd.dll` | `/opt/zimmermantools/` | Recycle Bin (`$Recycle.Bin/$I*` records) — deleted-by-user evidence |
| `SBECmd.dll` | `/opt/zimmermantools/` | Shellbags — every folder the user opened in Explorer, including external drives no longer attached |
| `WxTCmd.dll` | `/opt/zimmermantools/` | Win10 Timeline (`ActivitiesCache.db`) — per-user activity feed |
| `RecentFileCacheParser.dll` | `/opt/zimmermantools/` | Win7 `RecentFileCache.bcf` — Amcache predecessor |
| `RECmd/RECmd.dll` | `/opt/zimmermantools/RECmd/` | Registry Explorer with 200+ plugins — Run keys, Services, USB devices, BAM, AppCompat, SAM, etc. |
| `SQLECmd/SQLECmd.dll` | `/opt/zimmermantools/SQLECmd/` | SQLite parsing with plugin packs (Chrome / Edge / Firefox / Skype / Teams history) |
| `bstrings.dll` | `/opt/zimmermantools/` | High-perf strings extractor with regex filters |
| `bulk_extractor` | `/usr/bin/` | Feature extraction (URLs, emails, BTC, IPs, phone, ZIP/RAR signatures) over raw bytes — works on disk AND memory |
| Plaso (`log2timeline.py` / `psort.py` / `pinfo.py`) | `/usr/bin/` | Super-timeline — single biggest force-multiplier in DFIR |

### Tool inventory **missing on this install** — would need install routine entries

| Tool | Why we need it | Install |
|---|---|---|
| **YARA binary** (`yara`) | YARA scanning of files + disk regions; `yara-python` is installed but a CLI tool is cleaner for subprocess wrappers. CLAUDE.md says v4.1.0 at `/usr/local/bin/yara` but it's absent on this image. | `apt install yara` or build from source |
| **PECmd** (Prefetch parser, .NET) | **High-signal** Win10/Win11 program execution — `.pf` files include the executable name + last 8 run times + file accesses. Standard EZ Tools bundle ships this; this install is missing it. | Download from `https://github.com/EricZimmerman/PECmd/releases` to `/opt/zimmermantools/` |
| **SrumECmd** (SRUM, .NET) | Win8+ System Resource Usage Monitor: per-process network bytes + per-app wall time + push notifications. Killer for exfil detection. | Download to `/opt/zimmermantools/` |
| **Volatility 2** (`vol.py` v2.6.x, Python 2) | **Required** for Win7-x86 PAE + WinXP memory images — Vol3's PDB-symbol approach can't auto-download symbols for these. Vol2 has built-in profiles. | `pip2 install volatility` (Python 2) OR `apt install volatility` (Ubuntu ships 2.6) |
| **Memory Baseliner** (`baseline.py`) | Compare two memory images (suspect vs clean baseline) → diff of non-baseline processes/services/connections. CLAUDE.md references `/opt/memory-baseliner/baseline.py` but the dir doesn't exist on this image. | `git clone https://github.com/FSecureLABS/Memory-Baseliner /opt/memory-baseliner` |

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

### Phase 1.5 — MITRE-driven Vol3 plugin gaps (5 high-leverage wrappers) 🎯 *next up*

Surfaced by the MITRE ATT&CK coverage audit (`docs/MITRE_COVERAGE.md`). Each
wrapper closes a Partial-coverage technique to Full. All target Vol3 plugins
already installed on this SIFT (`vol -h | grep windows.<plugin>` confirms).

| # | New tool | Wraps | Closes |
|---|---|---|---|
| 1.5.1 | `vol3_scheduled_tasks(image)` | `windows.scheduled_tasks` | **T1053** Scheduled Task/Job |
| 1.5.2 | `vol3_skeleton_key_check(image)` | `windows.skeleton_key_check` | **T1558** Steal/Forge Kerberos Tickets (skeleton key) |
| 1.5.3 | `vol3_hashdump(image)` | `windows.hashdump` | **T1003** OS Credential Dumping |
| 1.5.4 | `vol3_envars(image, pid?)` | `windows.envars` | **T1574** Hijack Execution Flow (Path interception) |
| 1.5.5 | `vol3_dnscache(image)` | `windows.cachedump` (DNS slice) **or** dedicated DNS-cache plugin | **T1071** Application Layer Protocol (DNS) |

Total inventory after this phase: **26 → 31 tools**.

**Effort:** ~2 hours. All five follow the existing `_run_jsonl_plugin` shape;
parsers are flat row-oriented. `vol3_envars` mirrors `vol3_dlllist`'s optional
pid filter; the other four are image-only.

**Install touches:** none — all plugins already present in Vol3 on SIFT 24.x.

**Why before Phase 2:** Phase 2 is general-DFIR value (Win7-x86/XP). Phase 1.5
directly improves SHIELDBASE-class Win10/11 detection coverage with negligible
effort. Should ship even before Phase 3 (YARA) if a SHIELDBASE re-run is on
the table.

---

### Phase 2 — Legacy Windows memory support (Win7-x86 / WinXP) 🎯 *general-DFIR value*

**This is the gap the user explicitly called out.** Vol3 cannot get PDB symbols
for Win7-x86 PAE (`ntkrpamp.pdb`) or WinXP — these were the failure mode on
nromanoff during STARK-APT. Vol2 has built-in profiles for both, no symbol download
needed.

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

### Phase 3 — Threat-hunt + carving + cross-source

| # | New tool | Wraps | Notes |
|---|---|---|---|
| 3.1 | `yara_scan_extract(extract_exec_id, ruleset)` | `yara -r <rules> <file>` | Scan a previously-extracted file |
| 3.2 | `vol3_vadyarascan(image, ruleset, pid?)` | `windows.vadyarascan` | YARA against per-process memory; per-PID is fast |
| 3.3 | `bulk_extract(image)` | `bulk_extractor -j 4 -o <out>` | Feature files: URLs, emails, IPs, BTC, ZIP/RAR. Works on disk + memory. |
| 3.4 | `strings_extract(extract_exec_id, encoding, min_len)` | `bstrings -f <file>` | High-perf strings with regex filter |
| 3.5 | `hash_file(extract_exec_id)` | Python `hashlib` + ssdeep | MD5/SHA-1/SHA-256/ssdeep on extracted bytes |

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

### Phase 4 — Plaso super-timeline (biggest force-multiplier) ⏳ *can run async*

| # | New tool | Wraps | Notes |
|---|---|---|---|
| 4.1 | `plaso_build(image)` | `log2timeline.py` | **SLOW** — hours on 14 GB disk. Produces `.plaso` storage file. |
| 4.2 | `plaso_filter(plaso_exec_id, time_range, sources)` | `psort.py -o json_line --time-slice=...` | Query the .plaso file for a time window + source filter |
| 4.3 | `plaso_info(plaso_exec_id)` | `pinfo.py` | Event source counts, hostname extraction, time range |

**Design note:** Plaso is the single highest-signal cross-source tool in DFIR
because it natively parses **everything** — registry, EVTX, prefetch, MFT, EZ tools
output, browser history, etc. — into a unified normalised event stream. The
problem is wall time: a single `log2timeline.py` run on a 14 GB E01 takes ~2 hours.

**Design choice:** Run `plaso_build` once per disk image, cache the `.plaso` storage
file under `audit/raw/plaso/<exec_id>.plaso`, then `plaso_filter` reads from the
cache instantly. The agent doesn't pay the cost twice per case.

**Effort:** ~8-10 hours including a runtime / timeout strategy that doesn't block
the iteration loop indefinitely.

**Install touches:** Already installed on this SIFT (`plaso 20260119`).

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
| 6.3 | `timeline_aggregate(start_utc, end_utc)` | Every timestamped row across all prior exec_log entries in the window, sorted chronologically. |
| 6.4 | `audit_search(query)` | Full-text search over `parsed_summary` and `summary` fields in `audit/exec_log.jsonl`. |

**Why these matter:** Today the agent has to do correlation by hand — "I see STUN.exe
in psscan, now let me query_rows on MFT for the path, now let me query EVTX...".
These tools fold the pattern into a single call.

**Effort:** ~4-6 hours. Pure-Python; reads the audit log; no subprocess.

---

### Phase 7 — Linux/macOS memory (post-hackathon stretch)

Vol3 has profiles for Linux + macOS. Adding `vol3_linux_*` and `vol3_mac_*` families
would make SIFT-OWL the only public AI DFIR agent that handles non-Windows memory.

Out of scope for the hackathon (SHIELDBASE is Windows-only), but worth a paragraph
in the post-submission roadmap.

---

## 2. Recommended sequencing

Working backwards from SHIELDBASE final eval:

```
Phase 1 ✓ (Prefetch + JLE + SBE + RBE + SRUM + dlllist + handles)  ← done
    │
    ▼
SHIELDBASE final eval run ✓                                        ← done (71.4%)
    │
    ▼
Phase 1.5 (5 Vol3 plugin gaps from MITRE audit)                    ← 2 hr — NEXT
    │
    ▼
Phase 3 (YARA + bulk_extractor + strings)                          ← 6-8 hr
    │
    ▼
Phase 2 (Vol2 fallback for Win7-x86 / WinXP)                       ← 6-8 hr
    │
    ▼
Phase 5 (RECmd / SQLECmd / LECmd / WxTCmd) ⚠ promoted              ← 4-6 hr
    │                                                                 (covers
    │                                                                  T1547,
    │                                                                  T1078, T1098,
    │                                                                  T1091, T1136,
    │                                                                  T1574, T1071 —
    │                                                                  highest cross-
    │                                                                  technique impact
    │                                                                  in the audit)
    ▼
Submission deliverables                                            ← #30/#31/#32
    │
    ▼
[Post-submission] Phase 4 (Plaso) → Phase 6 (correlator) → Phase 7 (Linux/mac)
```

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
Partial-coverage techniques. Phase 4 (Plaso) deferred to post-submission
since it's a heavy lift and the existing inventory already covers most
correlator-friendly artefacts via `query_rows` over the audit log.

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
| 1 — SHIELDBASE essentials | 6 | 3-4 hr | first | ✓ shipped (W3-19) |
| **1.5 — MITRE-driven Vol3 gaps** | **5** | **~2 hr** | **next** | pending |
| 2 — Vol2 fallback | 15 | 6-8 hr | post-Phase 3 | pending |
| 3 — YARA + carving | 5 | 6-8 hr | post-Phase 1.5 | pending |
| 4 — Plaso | 3 | 8-10 hr | post-submission | pending |
| 5 — Registry + browser | 5 | 4-6 hr | **pre-submission** ⚠ promoted | pending |
| 6 — Correlator helpers | 4 | 4-6 hr | post-submission | pending |
| 7 — Linux/mac | ~8 | — | future | future |

**Inventory growth across the pre-submission phases:**

```
v0.4 (today)     26 tools  (W3-19 shipped)
+ Phase 1.5      31 tools
+ Phase 3        36 tools
+ Phase 5        41 tools   ← MITRE-driven promotion to pre-submission
+ Phase 2        56 tools   (Vol2 family; general-DFIR Win7-x86/XP closure)
```

**Total pre-submission effort:** ~18-24 hours. Resulting MITRE coverage:
22 of 22 target techniques at Full or Partial-with-acknowledged-gap.
Current breakdown (per `docs/MITRE_COVERAGE.md`): 13 Full, 9 Partial,
0 Missing. Phase 5 closes 7 of the 9 Partials to Full.
