# Validator Report — iter_2

## Summary

- Total tagged claims:        **42**
  - CONFIRMED:                 38
  - INFERRED:                  4
  - HYPOTHESIS:                0
  - GAP:                       0
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           9 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                4 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           8 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           17 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 23.7%** (9 verified / 38 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **8** (cost: $0.0091)
  - ✅ VERIFIED:    0 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 0 (downgraded to failed)
  - ❓ UNRELATED:   8 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   0 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### ❓ unverifiable _(line 58)_
- exec_ids: `7cc627c154e8`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The MFT parser output provides only aggregate file statistics (counts by extension, total files, deleted count) with no user attribution, OneDrive paths, SRL project identifiers, or account ownership data necessary to verify the claim about Fred's access to specific research projects.
- claim: > **[CONFIRMED — exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8`]** Fred had access to at least three SRL research projects on this Surface, evidenced by files present in his OneDrive and local filesyste…

### ⚠ partial _(line 69)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `.\Users\srl-h\`, `srl-h`
- **missing**: `\Users\srl-h\``
- claim: > **[CONFIRMED — exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8`]** A second local user account `srl-h` existed on this machine (files under `.\Users\srl-h\` present in MFT); this account's OneDrive dire…

### ⚠ partial _(line 71)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `124037`, `Setup.pdf`, `SRL VPN Setup.pdf`
- **missing**: `\Users\fredr\OneDrive\Documents\SRL\``, `.\Users\fredr\OneDrive\Documents\SRL\`
- claim: > **[CONFIRMED — exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8`]** `SRL VPN Setup.pdf` (157,471 bytes, MFT entry 124037) was present in `.\Users\fredr\OneDrive\Documents\SRL\` — VPN credentials for SRL …

### ❓ unverifiable _(line 77)_
- exec_ids: `d68f99218c85`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The parsed data contains only a file count (42798) with no file paths, names, or document identifiers that would support or contradict a claim about specific intellectual-property documents being open in a particular process's memory.
- claim: > **[CONFIRMED — exec_id `019eb545-f281-7ec0-bddf-d68f99218c85`]** The following SRL intellectual-property documents were open in process pool memory at the moment of capture, placing them in the intrud…

### ✅ verified _(line 82)_
- tools: `vol3_filescan`
- exec_ids: `d68f99218c85`
- matched: `SRL.docx`, `\Users\fredr\OneDrive`, `201816094876896`, `\Users\fredr\OneDrive - Stark Research Labs\Research\Vibrainium - SRL.docx`, `Vibrainium - SRL.docx`
- claim: > 1. **`Vibrainium - SRL.docx`** — SRL Vibranium research      Path: `\Users\fredr\OneDrive - Stark Research Labs\Research\Vibrainium - SRL.docx`      Pool memory offset: `201816094876896`      [CONFIRM…

### ✅ verified _(line 87)_
- tools: `vol3_filescan`
- exec_ids: `d68f99218c85`
- matched: `Dimensions.pdf`, `\Users\fredr\Stark`, `201816460363840`, `Quantum Particles Affected by Other Dimensions.pdf`
- claim: > 2. **`Quantum Particles Affected by Other Dimensions.pdf`** — SRL FTL communications research      Path: `\Users\fredr\Stark Research Labs\SRL-Projects - Gunstar\FTL Comms\Quantum Particles Affected b…

### ✅ verified _(line 92)_
- tools: `vol3_filescan`
- exec_ids: `d68f99218c85`
- matched: `SRL.lnk`, `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\Data`, `\Users\fredr\OneDrive\Data`, `\Users\fredr\OneDrive\Data Set Results SRL`, `201816472455136`, `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\Data Set Results SRL.lnk`, `Data Set Results SRL`, `201816233460192`
- claim: > 3. **`Data Set Results SRL`** — SRL dataset      Path: `\Users\fredr\OneDrive\Data Set Results SRL`      Pool memory offset: `201816233460192`; Recent LNK at `\Users\fredr\AppData\Roaming\Microsoft\Wi…

### ✅ verified _(line 94)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `2020-11-14T05:11:18Z`
- claim: > **[CONFIRMED — exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8`]** The following SRL project files have MFT timestamps placing their creation or last modification inside the intruder window (created 202…

### ✅ verified _(line 98)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `130588`, `2020-11-14T05:11:18Z`, `Overview_MH.pptx`, `Tesseract Overview_MH.pptx`
- claim: > 4. **`Tesseract Overview_MH.pptx`** (3,994,107 bytes) — Project P.E.G.A.S.U.S. classified overview      MFT entry 130588, created 2020-11-14T05:11:18Z, accessed 2020-11-14T05:11:18Z      [CONFIRMED — …

### ✅ verified _(line 102)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `130659`, `2020-11-02T17:20:50Z`, `2020-11-10T14:01:19Z`, `ADAMANTIUM-Background.docx`
- claim: > 5. **`ADAMANTIUM-Background.docx`** (62,334 bytes) — Adamantium alloy background research      MFT entry 130659, created 2020-11-02T17:20:50Z, accessed 2020-11-10T14:01:19Z      [CONFIRMED — exec_id `…

### ⚠ partial _(line 106)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `104304`, `2020-11-02T15:02:12Z`, `SUCCESS-TEST-PLAN-VIBRANIUM-ALLOY-RESULTS.docx`, `.\Users\fredr\OneDrive\Documents\`
- **missing**: `\Users\fredr\OneDrive\Documents\``
- claim: > 6. **`SUCCESS-TEST-PLAN-VIBRANIUM-ALLOY-RESULTS.docx`** (455,437 bytes) — Vibranium alloy test results      MFT entry 104304, `.\Users\fredr\OneDrive\Documents\` accessed 2020-11-02T15:02:12Z      [CO…

### ✅ verified _(line 108)_
- tools: `vol3_filescan`
- exec_ids: `d68f99218c85`
- matched: `IJD15WX.pdf`, `S-1-5-21-528816539-567677750-276746561-1002`, `\$Recycle.Bin\S-1-5-21-528816539-567677750-276746561-1002\$IJD15WX.pdf`, `201816387163968`
- claim: > **[CONFIRMED — exec_id `019eb545-f281-7ec0-bddf-d68f99218c85`]** A PDF was present in the Recycle Bin under SID `S-1-5-21-528816539-567677750-276746561-1002`:   `\$Recycle.Bin\S-1-5-21-528816539-56767…

### ✅ verified _(line 112)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `124037`, `Setup.pdf`, `SRL VPN Setup.pdf`
- claim: > **[CONFIRMED — exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8`]** `SRL VPN Setup.pdf` (157,471 bytes, MFT entry 124037) was accessible — VPN credentials for SRL infrastructure were exposed.

### ❓ unverifiable _(line 118)_
- exec_ids: `ce929bbcdd47`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The netscan tool data shows IP address connection counts but contains no information about RDP, clipboard operations, file transfers, or any execution identifiers that could verify the claim's specific assertions about the attack vector.
- claim: > **[CONFIRMED — exec_id `019eb530-2955-7a33-b1fc-ce929bbcdd47`] Primary vector: Remote Desktop Protocol clipboard / file transfer**

### ❓ unverifiable _(line 129)_
- exec_ids: `ce929bbcdd47`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The parsed netscan data contains only foreign IP address connection counts with no process execution identifiers, exec_ids, or process-level metadata to verify the claimed exec_id.
- claim: > [CONFIRMED — exec_id `019eb530-2955-7a33-b1fc-ce929bbcdd47`]

### ❓ unverifiable _(line 133)_
- exec_ids: `7cc627c154e8`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim asserts a secondary attack vector (USB removable media) and references an execution ID, but the ezt_mft_parse tool output contains only MFT statistics (file counts, extensions, and metadata flags) with no fields related to USB devices, removable media, or execution identifiers.
- claim: > **[CONFIRMED — exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8`] Secondary vector: USB removable media**

### ❓ unverifiable _(line 137)_
- exec_ids: `7cc627c154e8`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The MFT parser output contains only file system metadata statistics (file counts, extensions, timestomping indicators) and lacks any data fields related to RDP configuration, client settings, or the specific execution ID referenced in the claim.
- claim: > **[CONFIRMED — exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8`] RDP client configuration saved**

### ❓ unverifiable _(line 149)_
- exec_ids: `ce929bbcdd47`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The vol3_netscan data shows only foreign IP connection counts with no process identifiers, port numbers, protocols, or direction indicators (inbound/outbound), making it structurally incapable of supporting a claim about RDP protocol or a specific process execution ID.
- claim: > **[CONFIRMED — exec_id `019eb530-2955-7a33-b1fc-ce929bbcdd47`] T1021.001 — Remote Desktop Protocol (inbound)**

### ❓ unverifiable _(line 159)_
- exec_ids: `7cc627c154e8`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim asserts data staging on removable media (T1092/T1074) with a specific execution ID, but the parsed MFT data contains only aggregate file statistics (counts by extension, deletion status, timestomp indicators) with no fields relating to removable media, staging locations, execution context,
- claim: > **[CONFIRMED — exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8`] T1092 / T1074 — Removable Media Staging**

### ✅ verified _(line 163)_
- tools: `vol3_malfind`, `ezt_persistence_keys_parse`, `ezt_persistence_keys_parse`, `vol3_hashdump`
- exec_ids: `7c48a3790c07`, `0dc5573f9d78`, `51547213c421`, `705ddf9d5a8c`
- ✅ verified absences (negated): `019eb543-a154-70c0-8906-705ddf9d5a8c`, `019eb545-3ac3-74e1-8543-0dc5573f9d78`, `019eb545-4454-7eb3-805b-51547213c421`
- claim: > **[CONFIRMED — exec_id `019eb536-a9ed-72e3-ab46-7c48a3790c07`, `019eb545-3ac3-74e1-8543-0dc5573f9d78`, `019eb545-4454-7eb3-805b-51547213c421`, `019eb543-a154-70c0-8906-705ddf9d5a8c`] No malware / no p…

### 🔍 not_confirmed _(line 182)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | 2020-11-14T03:42:56Z | `TSTHEME.EXE-01D23267.pf` created in `.\Windows\Prefetch\` — first RDP session of intrusion | `019eb541-08ea-7ea0-9495-7cc627c154e8` (entry 96265) | [CONFIRMED]

### 🔍 not_confirmed _(line 183)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | 2020-11-14T05:05:33Z | UserAssist `Microsoft.Windows.RemoteDesktop` last_updated — attacker used RDP client on Surface | `019eb533-5a98-7bd0-af52-7de9219dc49b` | [CONFIRMED]

### 🔍 not_confirmed _(line 184)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | 2020-11-14T05:10:44Z | `Default.rdp` created/modified in `.\Users\fredr\OneDrive\Documents\` — RDP connection config saved and synced to cloud | `019eb541-08ea-7ea0-9495-7cc627c154e8` (entry 10430…

### 🔍 not_confirmed _(line 185)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | 2020-11-14T05:11:18Z | SRL OneDrive files created/synced: `Tesseract Overview_MH.pptx`, Case Files / Project P.E.G.A.S.U.S | `019eb541-08ea-7ea0-9495-7cc627c154e8` (entries 130535, 130588) | [CONF…

### 🔍 not_confirmed _(line 186)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | 2020-11-14T08:19:19Z | PowerShell engine start/stop (events 40961 pid=13392, 53504 pid=13392, 40962 pid=13392) — inside intruder window | `019eb545-3355-7fb1-a261-aab0c85d7634` (records 42–44) | […

### 🔍 not_confirmed _(line 187)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | 2020-11-14T14:17:21Z | `TSTHEME.EXE-01D23267.pf` last modified — second or continued RDP session | `019eb541-08ea-7ea0-9495-7cc627c154e8` (entry 96265) | [CONFIRMED]

### 🔍 not_confirmed _(line 188)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | 2020-11-15T09:05:17Z | PowerShell engine start/stop (events 40961 pid=4920, 53504 pid=4920, 40962 pid=4920) — inside intruder window | `019eb545-3355-7fb1-a261-aab0c85d7634` (records 45–47) | [CON…

### 🔍 not_confirmed _(line 189)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | 2020-11-16T02:29:42Z | `DRVINST.EXE-39D9EAC7.pf` created in `.\Windows\Prefetch\` — USB driver installation, removable device inserted | `019eb541-08ea-7ea0-9495-7cc627c154e8` (entry 61982) | [CON…

### 🔍 not_confirmed _(line 190)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | 2020-11-16T02:31:26Z | First visible fresh RDP connection from 81.30.144.115:53145 (CLOSED), pid=1248, svchost.exe | `019eb530-2955-7a33-b1fc-ce929bbcdd47` | [CONFIRMED]

### 🔍 not_confirmed _(line 191)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | 2020-11-16T02:32:38Z | **Memory captured** — four ESTABLISHED RDP sessions active from 81.30.144.115 and 213.202.233.104; SRL research files open in pool memory | `019eb52b-b26c-7e81-95e9-30145fbc…

### ⚠ partial _(line 212)_
- tools: `vol3_netscan`
- exec_ids: `ce929bbcdd47`
- matched: `81.30.144.115`
- **missing**: `019eb530-2955-7a33-b1fc-ce929bbcdd47`
- claim: > | Indicator | Value | exec_id | Confidence | |---|---|---|---| | Attacker IP #1 | `81.30.144.115` | `019eb530-2955-7a33-b1fc-ce929bbcdd47` | [CONFIRMED]

### 🔍 not_confirmed _(line 213)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > — 59 inbound RDP connection objects | | Attacker IP #2 | `213.202.233.104` | `019eb530-2955-7a33-b1fc-ce929bbcdd47` | [CONFIRMED]

### 🔍 not_confirmed _(line 214)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > — 54 inbound RDP connection objects | | Entry vector | RDP port 3389, T1021.001, PID 1248 svchost.exe | `019eb530-2955-7a33-b1fc-ce929bbcdd47` | [CONFIRMED]

### 🔍 not_confirmed _(line 215)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Exfil vector #1 | RDP clipboard/file transfer (4 simultaneous ESTABLISHED sessions) | `019eb530-2955-7a33-b1fc-ce929bbcdd47` | [CONFIRMED]

### 🔍 not_confirmed _(line 216)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Exfil vector #2 | USB removable storage (DRVINST.EXE at 2020-11-16T02:29:42Z) | `019eb541-08ea-7ea0-9495-7cc627c154e8` | [CONFIRMED]

### 🔍 not_confirmed _(line 217)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Target data | VIBRANIUM, ADAMANTIUM, Project P.E.G.A.S.U.S., FTL comms research, SRL VPN credentials | `019eb541-08ea-7ea0-9495-7cc627c154e8`, `019eb545-f281-7ec0-bddf-d68f99218c85` | [CONFIRMED]

### 🔍 not_confirmed _(line 218)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Persistence installed | None detected | `019eb545-3ac3-74e1-8543-0dc5573f9d78`, `019eb545-4454-7eb3-805b-51547213c421`, `019eb536-a9ed-72e3-ab46-7c48a3790c07` | [CONFIRMED]

### 🔍 not_confirmed _(line 219)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Malware used | None detected | `019eb536-a9ed-72e3-ab46-7c48a3790c07` | [CONFIRMED]
