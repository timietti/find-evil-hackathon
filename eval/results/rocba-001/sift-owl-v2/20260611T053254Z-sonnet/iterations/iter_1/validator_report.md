# Validator Report — iter_1

## Summary

- Total tagged claims:        **42**
  - CONFIRMED:                 38
  - INFERRED:                  3
  - HYPOTHESIS:                0
  - GAP:                       1
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           12 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                6 (some tokens found, some missing)
- ❌ failed:                 1 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           19 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 31.6%** (12 verified / 38 confirmed)

## Per-claim verdicts

### 🔍 not_confirmed _(line 78)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED]** Fred had access to at least three SRL research projects on this Surface, evidenced by files present in his OneDrive and local filesystem at the time of capture:

### 🔍 not_confirmed _(line 89)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED]** A second local account `srl-h` also existed on this machine (MFT inode 39: `.\Users\srl-h\...` OneDrive setup log); this user's OneDrive share `\Users\srl-h\OneDrive\Documents\` was pr…

### ⚠ partial _(line 91)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `124037`, `Setup.pdf`, `\Users\fredr\OneDrive\Documents\SRL`, `SRL VPN Setup.pdf`
- **missing**: `.\Users\fredr\OneDrive\Documents\SRL\`
- claim: > **[CONFIRMED]** `SRL VPN Setup.pdf` (157,471 bytes, inode 124037, `.\Users\fredr\OneDrive\Documents\SRL\`) was on the device. **[exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8`]**

### 🔍 not_confirmed _(line 97)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED]** The following SRL intellectual-property documents were accessed during the intruder window and were open in process pool memory at the moment of capture, placing them directly in the i…

### ⚠ partial _(line 102)_
- tools: `vol3_filescan`
- exec_ids: `d68f99218c85`
- matched: `SRL.docx`, `\Users\fredr\OneDrive`, `\Users\fredr\OneDrive - Stark Research Labs\Research\Vibrainium - SRL.docx`, `Vibrainium - SRL.docx`
- **missing**: `2020-11-16T02:32:38Z`, `0x201816094876896`
- claim: > 1. **`Vibrainium - SRL.docx`** — SRL Vibranium research      Path: `\Users\fredr\OneDrive - Stark Research Labs\Research\Vibrainium - SRL.docx`      Status: open file object in pool memory at 2020-11-…

### ⚠ partial _(line 107)_
- tools: `vol3_filescan`
- exec_ids: `d68f99218c85`
- matched: `Dimensions.pdf`, `\Users\fredr\Stark`, `Quantum Particles Affected by Other Dimensions.pdf`
- **missing**: `2020-11-16T02:32:38Z`, `0x201816460363840`
- claim: > 2. **`Quantum Particles Affected by Other Dimensions.pdf`** — SRL FTL communications research      Path: `\Users\fredr\Stark Research Labs\SRL-Projects - Gunstar\FTL Comms\Quantum Particles Affected b…

### ⚠ partial _(line 112)_
- tools: `vol3_filescan`
- exec_ids: `d68f99218c85`
- matched: `\Users\fredr\OneDrive\Data`, `Data Set Results SRL`, `\Users\fredr\OneDrive\Data Set Results SRL`
- **missing**: `0x201816233460192`
- claim: > 3. **`Data Set Results SRL`** — data set file (likely SRL dataset)      Path: `\Users\fredr\OneDrive\Data Set Results SRL`      Status: open file object in pool memory      [CONFIRMED, exec_id `019eb5…

### 🔍 not_confirmed _(line 114)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED]** The following SRL project files were synced to the SRL OneDrive during the intruder window (MFT created/record_changed = 2020-11-14T05:11:18Z, entirely within the intrusion):

### ✅ verified _(line 119)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `130588`, `2020-11-14T05:11:18Z`, `Overview_MH.pptx`, `\Users\fredr\OneDrive`, `Tesseract Overview_MH.pptx`
- claim: > 4. **`Tesseract Overview_MH.pptx`** (3.99 MB) — Project P.E.G.A.S.U.S. classified overview      `.\Users\fredr\OneDrive - Stark Research Labs\Documents\Case Files\Project P.E.G.A.S.U.S\`      MFT entr…

### ✅ verified _(line 123)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `130659`, `2020-11-10T14:01:19Z`, `2020-11-02T17:20:50Z`, `ADAMANTIUM-Background.docx`
- claim: > 5. **`ADAMANTIUM-Background.docx`** (62 KB) — Adamantium alloy background research      MFT entry 130659, created 2020-11-02T17:20:50Z, accessed 2020-11-10T14:01:19Z (pre-window, but last access insid…

### ✅ verified _(line 127)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `104304`, `2020-11-02T15:02:12Z`, `SUCCESS-TEST-PLAN-VIBRANIUM-ALLOY-RESULTS.docx`, `\Users\fredr\OneDrive\Documents`, `.\Users\fredr\OneDrive\Documents\`
- claim: > 6. **`SUCCESS-TEST-PLAN-VIBRANIUM-ALLOY-RESULTS.docx`** (455 KB) — Vibranium test results      MFT entry 104304, `.\Users\fredr\OneDrive\Documents\`, accessed 2020-11-02T15:02:12Z      [CONFIRMED, exe…

### ⚠ partial _(line 129)_
- tools: `vol3_filescan`
- exec_ids: `d68f99218c85`
- matched: `IJD15WX.pdf`, `S-1-5-21-528816539-567677750-276746561-1002`, `\$Recycle.Bin\S-1-5-21-528816539-567677750-276746561-1002\$IJD15WX.pdf`
- **missing**: `0x201816387163968`
- claim: > **[CONFIRMED]** A PDF was staged in the Recycle Bin under SID `S-1-5-21-528816539-567677750-276746561-1002`:   `\$Recycle.Bin\S-1-5-21-528816539-567677750-276746561-1002\$IJD15WX.pdf`   [exec_id `019e…

### ✅ verified _(line 133)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `124037`, `Setup.pdf`, `SRL VPN Setup.pdf`
- claim: > **[CONFIRMED]** `SRL VPN Setup.pdf` (157 KB, inode 124037) was present and accessible — credentials for SRL VPN access were exposed.  [exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8`]

### 🔍 not_confirmed _(line 139)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED] Primary vector: Remote Desktop Protocol clipboard / file transfer**

### 🔍 not_confirmed _(line 152)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED] Secondary vector: USB removable media**

### 🔍 not_confirmed _(line 159)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED] RDP client configuration saved**

### 🔍 not_confirmed _(line 173)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED] T1021.001 — Remote Desktop Protocol (inbound)**

### 🔍 not_confirmed _(line 183)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED] T1092 / T1074 — Removable Media Staging**

### 🔍 not_confirmed _(line 187)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > **[CONFIRMED] No malware / no persistence implanted**

### 🔍 not_confirmed _(line 207)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | **2020-11-13T22:00:00Z** | **Intruder window opens** — Fred family departs for Disney World | Case briefing | [CONFIRMED]

### ✅ verified _(line 208)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `2020-11-14T03:42:56Z`, `TSTHEME.EXE`, `-01D23267.pf`, `\Windows\Prefetch`, `TSTHEME.EXE-01D23267.pf`, `.\Windows\Prefetch\`
- claim: > | | 2020-11-14T03:42:56Z | `TSTHEME.EXE-01D23267.pf` created in `.\Windows\Prefetch\` — first RDP session of the intrusion | exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8` (entry 96265) | [CONFIRMED]

### ✅ verified _(line 209)_
- tools: `vol3_userassist`
- exec_ids: `7de9219dc49b`
- matched: `2020-11-14T05:05:33Z`, `Microsoft.Windows.RemoteDesktop`
- claim: > | | 2020-11-14T05:05:33Z | UserAssist `Microsoft.Windows.RemoteDesktop` last_updated — attacker used RDP client on the Surface | exec_id `019eb533-5a98-7bd0-af52-7de9219dc49b` | [CONFIRMED]

### ✅ verified _(line 210)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `2020-11-14T05:10:44Z`, `\Users\fredr\OneDrive\Documents`, `Default.rdp`, `.\Users\fredr\OneDrive\Documents\`
- claim: > | | 2020-11-14T05:10:44Z | `Default.rdp` created/modified in `.\Users\fredr\OneDrive\Documents\` — RDP connection config saved and synced to cloud | exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8` (ent…

### ✅ verified _(line 211)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `2020-11-14T05:11:18Z`, `Overview_MH.pptx`, `Tesseract Overview_MH.pptx`
- claim: > | | 2020-11-14T05:11:18Z | SRL OneDrive files created/synced: `Tesseract Overview_MH.pptx`, Case Files / Project P.E.G.A.S.U.S., Marketing materials | exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8` (e…

### ✅ verified _(line 212)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `2020-11-14T14:17:21Z`, `TSTHEME.EXE`, `-01D23267.pf`, `TSTHEME.EXE-01D23267.pf`
- claim: > | | 2020-11-14T14:17:21Z | `TSTHEME.EXE-01D23267.pf` last modified — second or continued RDP session | exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8` (entry 96265) | [CONFIRMED]

### ❌ failed _(line 213)_
- tools: `ezt_evtx_parse`
- exec_ids: `aab0c85d7634`
- 🚨 negation violations (claimed absent but found): `2020-11-15T09:05:17Z`
- claim: > | | 2020-11-15T09:05:17Z | PowerShell engine start/stop (events 40961/40962) — activity inside intruder window, no script content logged | exec_id `019eb545-3355-7fb1-a261-aab0c85d7634` (records 45–47…

### ✅ verified _(line 214)_
- tools: `ezt_mft_parse`
- exec_ids: `7cc627c154e8`
- matched: `2020-11-16T02:29:42Z`, `-39D9EAC7.pf`, `DRVINST.EXE`, `DRVINST.EXE-39D9EAC7.pf`
- claim: > | | 2020-11-16T02:29:42Z | `DRVINST.EXE-39D9EAC7.pf` created — USB driver installation, removable device inserted | exec_id `019eb541-08ea-7ea0-9495-7cc627c154e8` (entry 61982) | [CONFIRMED]

### ✅ verified _(line 215)_
- tools: `vol3_netscan`
- exec_ids: `ce929bbcdd47`
- matched: `213.202.233.104`, `2020-11-16T02:31:18Z`
- claim: > | | 2020-11-16T02:31:18Z | First visible fresh RDP connection from 213.202.233.104:58072 (CLOSED) | exec_id `019eb530-2955-7a33-b1fc-ce929bbcdd47` | [CONFIRMED]

### ✅ verified _(line 216)_
- tools: `vol3_netscan`
- exec_ids: `ce929bbcdd47`
- matched: `81.30.144.115`, `2020-11-16T02:31:27Z`
- claim: > | | 2020-11-16T02:31:27Z | First visible fresh RDP connection from 81.30.144.115:59055 (CLOSED) | exec_id `019eb530-2955-7a33-b1fc-ce929bbcdd47` | [CONFIRMED]

### ⚠ partial _(line 217)_
- tools: `vol3_image_info`
- exec_ids: `30145fbc7b79`
- matched: `2020-11-16T02:32:38Z`
- **missing**: `213.202.233.104`, `81.30.144.115`, `Dimensions.pdf`, `SRL.docx`, `Data Set Results SRL`, `Quantum Particles Affected by Other Dimensions.pdf`, `Vibrainium - SRL.docx`
- claim: > | | 2020-11-16T02:32:38Z | **Memory captured** — two ESTABLISHED RDP sessions active from 81.30.144.115 and 213.202.233.104. SRL research documents (`Vibrainium - SRL.docx`, `Quantum Particles Affecte…

### 🔍 not_confirmed _(line 238)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | Indicator | Value | Confidence | |---|---|---| | Attacker IP #1 | `81.30.144.115` | [CONFIRMED]

### 🔍 not_confirmed _(line 239)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > — 59 inbound RDP connection objects | | Attacker IP #2 | `213.202.233.104` | [CONFIRMED]

### 🔍 not_confirmed _(line 240)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > — 54 inbound RDP connection objects | | Entry vector | RDP (port 3389, T1021.001) using Fred's pre-existing Windows credentials | [CONFIRMED]

### 🔍 not_confirmed _(line 241)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Exfil vector #1 | RDP clipboard/file transfer (two simultaneous sessions) | [CONFIRMED]

### 🔍 not_confirmed _(line 242)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Exfil vector #2 | USB removable storage (DRVINST.EXE 02:29:42Z) | [CONFIRMED]

### 🔍 not_confirmed _(line 243)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Target data | VIBRANIUM, ADAMANTIUM, Project P.E.G.A.S.U.S. (Tesseract), FTL comms research, SRL VPN credentials | [CONFIRMED]

### 🔍 not_confirmed _(line 244)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Persistence installed | **None detected** | [CONFIRMED]

### 🔍 not_confirmed _(line 245)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | Malware used | **None detected** | [CONFIRMED]
