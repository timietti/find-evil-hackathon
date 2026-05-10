# Validator Report — 20260509T174516Z-sonnet

## Summary

- Total tagged claims:        **54**
  - CONFIRMED:                 42
  - INFERRED:                  3
  - HYPOTHESIS:                0
  - GAP:                       9
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           24 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                12 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           4 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 57.1%** (24 verified / 42 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **5** (cost: $0.0047)
  - ✅ VERIFIED:    0 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 1 (downgraded to failed)
  - ❓ UNRELATED:   3 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   1 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### ⚠ partial _(line 39)_
- tools: `vol3_image_info`
- exec_ids: `116723a96053`
- matched: `2020-11-16T02:32:38Z`
- **missing**: `2020-11-13T22:00Z`, `/cases/find-evil-test/Rocba-Memory.raw`
- claim: > # ROCBA-001 Memory Forensics Report **Examiner:** SIFT-OWL v1 (DFIR Orchestrator)   **Evidence:** `/cases/find-evil-test/Rocba-Memory.raw` (18 GB RAM, Windows 10 build 19041 x64)   **Capture time:** `…

### ❓ unverifiable _(line 63)_
- exec_ids: `6ba398beced8`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim is a metadata label with an execution ID but contains no specific factual assertion about file paths, counts, or other forensic artifacts that could be verified against the vol3_filescan file count data.
- claim: > [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8]

### ✅ verified _(line 65)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `NETFLIX.xlsx`, `Findoreria_Solved.xlsx`, `Firedam.xls`, `Research.docx`, `Spreadsheet.xls`, `WACC Calc Spreadsheet.xls`, `TIVO Research.docx`
- claim: > Fred also had personal VC (Venture Capital) financial files on OneDrive: `WACC Calc Spreadsheet.xls`, `Findoreria_Solved.xlsx`, `NETFLIX.xlsx`, `TIVO Research.docx`, `Firedam.xls` [CONFIRMED — exec_id…

### ⚠ partial _(line 75)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `StarFury.zip`, `StarFury.lnk`, `\Users\fredr\OneDrive\StarFury.zip`, `starfury (2).lnk`
- **missing**: `\Users\fredr\OneDrive\StarFury.zip``
- claim: > **1. StarFury project archive**   `\Users\fredr\OneDrive\StarFury.zip` — a ZIP package of the StarFury project placed inside the OneDrive sync folder. Any active OneDrive sync would auto-upload this t…

### ✅ verified _(line 81)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `Exported-PST.lnk`, `IDNBREY.pst`, `backup.pst`, `\Users\fredr\OneDrive\Documents\Outlook`, `\Users\fredr\OneDrive\Documents\Outlook Files\backup.pst`, `srl-h`, `\$Recycle.Bin\S-1-5-21-528816539-567677750-276746561-1002\$IDNBREY.pst`
- claim: > **2. Complete Outlook email archive (PST)**   `\Users\fredr\OneDrive\Documents\Outlook Files\backup.pst` — the entire SRL Outlook email store placed inside the OneDrive sync folder.   `\$Recycle.Bin\S…

### ✅ verified _(line 85)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `ADAMANTIUM-Background.lnk`, `France DGSE Intel Analysis Adamantium .pptx`
- claim: > **3. France DGSE / Adamantium intelligence document**   `France DGSE Intel Analysis Adamantium .pptx` (OneDrive - Stark Research Labs\Research) is in memory. Recent LNK `ADAMANTIUM-Background.lnk` con…

### ⚠ partial _(line 89)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `Death_Blossom_attack.png`, `Specs.xlsx`, `Death_Blossom_test_visualization.png`, `Data.docx`, `GunStar Upgrade Specs.xlsx`, `GunStar Death Blossom Data.docx`
- **missing**: `Particles...pdf`, `FTL Comms/Quantum Particles...pdf`
- claim: > **4. Gunstar weapons data**   `GunStar Death Blossom Data.docx`, `GunStar Upgrade Specs.xlsx`, `Death_Blossom_attack.png`, `Death_Blossom_test_visualization.png`, `FTL Comms/Quantum Particles...pdf` a…

### ✅ verified _(line 93)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `Background.docx`, `KITT.lnk`, `Background.lnk`, `Hydrogen_Hybrid_Tech.docx`, `KITT.pptx`, `German-KITT-Specs.docx`, `KITT-older-version.lnk`, `Future of KITT - Technical Background.lnk` (+4 more)
- claim: > **5. KITT project materials**   `The Future of KITT.pptx`, `Future of KITT - Technical Background.docx`, `German-KITT-Specs.docx`, `Hydrogen_Hybrid_Tech.docx` all in memory; Recent LNKs `The Future of…

### ✅ verified _(line 97)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `Airwolf-ARL.lnk`, `Airwolf_schematics.png`, `Wolves_Lair_Tech_Specs.pptx`, `airwolf_blueprint.jpg`, `airwolf_blueprints.gif`
- claim: > **6. Airwolf blueprints and specifications**   `Wolves_Lair_Tech_Specs.pptx`, `Airwolf_schematics.png`, `airwolf_blueprint.jpg`, `airwolf_blueprints.gif` in memory. Recent LNK `Airwolf-ARL.lnk` confir…

### ✅ verified _(line 101)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `RareEarthDeposits_Confidential.jpg`, `SRL.docx`, `Vibrainium - SRL.docx`
- claim: > **7. Vibranium and rare earth materials research**   `Vibrainium - SRL.docx` (OneDrive Research folder). `RareEarthDeposits_Confidential.jpg`.   [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398bece…

### ✅ verified _(line 105)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `Key.lnk`, `fred.rocba@outlook.com`, `fred.rocba@outlook.com Firefox Recovery Key.lnk`
- claim: > **8. Fred's Firefox recovery key / credentials**   Recent LNK: `fred.rocba@outlook.com Firefox Recovery Key.lnk` — personal Firefox account credential material accessed.   [CONFIRMED — exec_id 019e0dd…

### ⚠ partial _(line 109)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `Encryption.lnk`, `BitLocker Drive Encryption.lnk`
- **missing**: `1694D560-...lnk`, `26F77152-...lnk`, `C42458BB-...lnk`, `BitLocker Recovery Key 1694D560-...lnk`, `BitLocker Recovery Key 26F77152-...lnk`, `BitLocker Recovery Key C42458BB-...lnk`
- claim: > **9. Three BitLocker recovery keys**   Recent LNKs: `BitLocker Recovery Key 1694D560-...lnk`, `BitLocker Recovery Key 26F77152-...lnk`, `BitLocker Recovery Key C42458BB-...lnk` plus `BitLocker Drive E…

### ✅ verified _(line 113)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `system.lnk`, `Files from SRL system.lnk`
- claim: > **10. "Files from SRL system"**   Recent LNK: `Files from SRL system.lnk` — confirms a collection of files from the corporate SRL system was accessed as a folder or file bundle.   [CONFIRMED — exec_id…

### ✅ verified _(line 117)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `starkresearchlabs-my.sharepoint.com.url`, `starkresearchlabs.sharepoint.com.url`, `WorkingFiles on starkresearchlabs-my.sharepoint.com.url`, `KITT-CompetitiveAnalysisDocs on starkresearchlabs-my.sharepoint.com.url`, `Megaforce on starkresearchlabs.sharepoint.com.url`
- claim: > **11. Megaforce and Blue Thunder project data**   Office Recent URLs `Megaforce on starkresearchlabs.sharepoint.com.url`, `KITT-CompetitiveAnalysisDocs on starkresearchlabs-my.sharepoint.com.url`, `Wo…

### ⚠ partial _(line 126)_
- tools: `vol3_cmdline`, `vol3_filescan`
- exec_ids: `6721d68c42cf`, `6ba398beced8`
- matched: `6188`, `9648`, `StarFury.zip`, `backup.pst`, `\Users\fredr\OneDrive\Documents\Outlook`, `\Users\fredr\OneDrive\`, `\Users\fredr\OneDrive\Documents\Outlook Files\`
- **missing**: `\Users\fredr\OneDrive\``
- claim: > `StarFury.zip` and `backup.pst` were placed in `\Users\fredr\OneDrive\` and `\Users\fredr\OneDrive\Documents\Outlook Files\` — both within the OneDrive for personal sync folder. With OneDrive running …

### ⚠ partial _(line 131)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `srl-h`, `\Users\srl-h\AppData\Local\Microsoft\OneDrive\`
- **missing**: `\Users\srl-h\AppData\Local\Microsoft\OneDrive\``
- claim: > The `srl-h` user account has its own OneDrive installation: `\Users\srl-h\AppData\Local\Microsoft\OneDrive\` — all OneDrive binaries confirmed in memory. This provides a second, attacker-controlled On…

### ✅ verified _(line 136)_
- tools: `vol3_netscan`
- exec_ids: `28eef0687026`
- matched: `81.30.144.115`
- claim: > Four external IPs connected via RDP to port 3389 simultaneously: - `81.30.144.115` — 59 connections, 2 ESTABLISHED at capture [CONFIRMED — exec_id 019e0dda-6764-76f3-9816-28eef0687026]

### ✅ verified _(line 137)_
- tools: `vol3_netscan`
- exec_ids: `28eef0687026`
- matched: `213.202.233.104`
- claim: > - `213.202.233.104` — 54 connections, 2 ESTABLISHED at capture [CONFIRMED — exec_id 019e0dda-6764-76f3-9816-28eef0687026]

### ✅ verified _(line 138)_
- tools: `vol3_netscan`
- exec_ids: `28eef0687026`
- matched: `201.193.188.114`
- claim: > - `201.193.188.114` — 3 connections, first at 02:30:05Z (earliest of all attacker IPs) [CONFIRMED — exec_id 019e0dda-6764-76f3-9816-28eef0687026]

### ✅ verified _(line 139)_
- tools: `vol3_netscan`
- exec_ids: `28eef0687026`
- matched: `81.19.209.101`
- claim: > - `81.19.209.101` — 2 connections including one in SYN_RCVD state at capture (actively connecting) [CONFIRMED — exec_id 019e0dda-6764-76f3-9816-28eef0687026]

### ⚠ partial _(line 146)_
- tools: `vol3_filescan`, `vol3_cmdline`
- exec_ids: `6ba398beced8`, `6721d68c42cf`
- matched: `MRC.exe`, `\Tools\`, `D:\Tools\MRC.exe`
- **missing**: `D:\Tools\MRC.exe``
- claim: > MRC.exe resides at `D:\Tools\MRC.exe` — Drive D: is not the system drive, indicating an external USB flash drive or removable media was connected. The `\Tools\` directory in the filesystem pool confir…

### ✅ verified _(line 156)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `2020-11-14T04:39:15Z`
- claim: > - **Regedit** (Registry Editor) opened at `2020-11-14T04:39:15Z` — likely to enable RDP, create the backdoor account, or disable security settings. [CONFIRMED — exec_id 019e0ddb-7249-70a0-8527-ab77603…

### ⚠ partial _(line 157)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `2020-11-14T05:05:33Z`
- **missing**: `mstsc.exe`
- claim: > - **Remote Desktop Connection client (mstsc.exe)** launched twice (UserAssist count:2) last used at `2020-11-14T05:05:33Z` — intruder may have connected FROM the laptop to an external command system t…

### ✅ verified _(line 158)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `SystemPropertiesProtection.exe`, `SystemPropertiesAdvanced.exe`
- claim: > - **SystemPropertiesProtection.exe** (focus:7, time:4:33) and **SystemPropertiesAdvanced.exe** (focus:4) accessed — likely to disable System Restore / shadow copy protection, destroying forensic artif…

### ✅ verified _(line 159)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `BitLockerWizard.exe`
- claim: > - **BitLockerWizard.exe** (focus:3, time:1:13) accessed — intruder studied and likely exfiltrated the three BitLocker recovery keys. [CONFIRMED — exec_id 019e0ddb-7249-70a0-8527-ab776038fd0a]

### ❓ unverifiable _(line 160)_
- exec_ids: `ab776038fd0a`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The userassist data provides only aggregate execution counts (120 total, 112 real, 8 sessions) from a single hive without timestamps, application names, or execution sequence details needed to verify the rapid succession claim or the specific time window (04:23–04:49Z).
- claim: > - **Office applications** — PowerPoint, Word, Excel, Outlook, Adobe Reader opened in rapid succession (04:23–04:49Z) to identify and stage high-value documents. [CONFIRMED — exec_id 019e0ddb-7249-70a0…

### ✅ verified _(line 161)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `2020-11-14T13:50:02Z`, `DropboxUninstaller.exe`
- claim: > - **Dropbox uninstalled** at `2020-11-14T13:50:02Z` (`DropboxUninstaller.exe` UserAssist count:1) — removed Dropbox to prevent SRL from detecting changed file sync activity, or to eliminate competing …

### ❌ failed _(line 162)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- **missing**: `\Users\srl-h\Downloads\`.`, `\Users\srl-h\`,`
- 🚨 negation violations (claimed absent but found): `sdelete64.exe`, `\Users\srl-h\`, `srl-h`, `\Users\srl-h\Downloads\`
- claim: > - **Backdoor account `srl-h` created** — not directly visible in memory analysis, but confirmed by profile artifacts under `\Users\srl-h\`, CLR usage logs showing PowerShell (both 32-bit and 64-bit) a…

### ✅ verified _(line 163)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `RemoteFXvGPUDisablement.exe`
- claim: > - **RemoteFXvGPUDisablement.exe** ran under srl-h — disables RemoteFX GPU virtualization to optimize RDP sessions, suggesting the srl-h account was used for RDP-based remote access. [CONFIRMED — exec_…

### ✅ verified _(line 168)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `Exported-PST.lnk`, `backup.pst`
- claim: > - **Outlook PST exported** — `Exported-PST.lnk` in Recent plus `backup.pst` in OneDrive confirm PST was exported and staged. [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8]

### ⚠ partial _(line 169)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `SDelete.zip`, `sdelete.exe`, `sdelete64.exe`, `SDelete.lnk`, `\Users\fredr\Downloads\SDelete\`
- **missing**: `\Users\fredr\Downloads\SDelete\`.`
- claim: > - **SDelete downloaded and staged** — `SDelete.zip` downloaded; extracted `sdelete.exe` placed in `\Users\fredr\Downloads\SDelete\`. A `SDelete.lnk` in Recent confirms it was launched. `sdelete64.exe`…

### ✅ verified _(line 170)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `2020-11-14T12:43:01Z`
- claim: > - **Command Prompt** launched at `2020-11-14T12:43:01Z` — likely used to run SDelete, copy files, or execute scripts. [CONFIRMED — exec_id 019e0ddb-7249-70a0-8527-ab776038fd0a]

### ⚠ partial _(line 174)_
- tools: `vol3_pstree`, `vol3_cmdline`, `vol3_filescan`
- exec_ids: `ca3ed66e47c7`, `6721d68c42cf`, `6ba398beced8`
- matched: `29440`, `2020-11-16T02:31:15Z`, `MRC.exe`, `MRC179.tmp`, `D:\Tools\MRC.exe`
- **missing**: `D:\Tools\MRC.exe``, `D:\Tools\)`
- claim: > - **MRC.exe** (pid 29440, 32-bit, wow64:true) launched at `2020-11-16T02:31:15Z` from `D:\Tools\MRC.exe` via Explorer (ppid 7464), session_id:1, 20 threads — still RUNNING at RAM capture. A companion …

### ⚠ partial _(line 175)_
- tools: `vol3_netscan`
- exec_ids: `28eef0687026`
- matched: `1248`, `81.30.144.115`, `213.202.233.104`, `svchost.exe`
- **missing**: `MRC.exe`
- claim: > - **RDP flood from 4 attacker IPs** — within seconds of MRC.exe launch, 113+ TCP connections hit port 3389 from two primary IPs and two secondary IPs, overwhelming the TermService (svchost.exe pid 124…

### ✅ verified _(line 177)_
- tools: `vol3_malfind`
- exec_ids: `9748ae5d944c`
- matched: `SearchApp.exe`, `MsMpEng.exe`, `Teams.exe`
- claim: > **No malware injection detected:** Malfind analysis returned only 16 findings, all attributable to legitimate JIT/CLR activity in MsMpEng.exe (Defender), SearchApp.exe, and Teams.exe. No shellcode or …

### ⚠ partial _(line 221)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `sdelete64.exe`, `\Users\srl-h\`
- **missing**: `\Users\srl-h\``
- claim: > - Profile directory `\Users\srl-h\` populated with CLR usage logs, OneDrive binaries, and sdelete64.exe [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8]

### ✅ verified _(line 222)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `powershell.exe`, `powershell.exe.log`
- claim: > - `powershell.exe.log` in both CLR_v4.0 and CLR_v4.0_32 (64-bit and 32-bit PowerShell executed) [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8]

### ✅ verified _(line 223)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `mmc.exe`, `mmc.exe.log`
- claim: > - `mmc.exe.log` (Microsoft Management Console used — likely for account/computer management) [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8]

### ✅ verified _(line 224)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `RemoteFXvGPUDisablement.exe`, `RemoteFXvGPUDisablement.exe.log`
- claim: > - `RemoteFXvGPUDisablement.exe.log` (RDP performance optimization) [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8]

### ❓ unverifiable _(line 225)_
- exec_ids: `6ba398beced8`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The vol3_filescan data provides only a file count (42,798) with no structural details about OneDrive installation, file paths, cloud sync configuration, or any attacker-controlled account evidence that would support the claim's specific factual assertions.
- claim: > - OneDrive fully installed — independent cloud sync path to attacker-controlled account [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8]

### ❌ failed _(line 226)_
- exec_ids: `6ba398beced8`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNSUPPORTED** — The parsed vol3_filescan data contains only a file count (42798) with no structure showing deleted files, Recycle Bin entries, file paths, SIDs, RIDs, or PST file references needed to verify this claim.
- claim: > - PST file deleted to Recycle Bin under SID for RID 1002 [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8]

### ❓ unverifiable _(line 241)_
- exec_ids: `28eef0687026`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim contains only an execution ID reference with no specific factual assertion about network data; the netscan tool data shows foreign IP connection counts but contains no exec_id field or related metadata to validate the claim's identifier.
- claim: > [CONFIRMED — exec_id 019e0dda-6764-76f3-9816-28eef0687026]
