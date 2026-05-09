# Validator Report — 20260509T174516Z-sonnet

## Summary

- Total tagged claims:        **54**
  - CONFIRMED:                 42
  - INFERRED:                  3
  - HYPOTHESIS:                0
  - GAP:                       9
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           13 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                27 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           2 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 31.0%** (13 verified / 42 confirmed)

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
- claim: > [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8]

### ✅ verified _(line 65)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `NETFLIX.xlsx`, `Spreadsheet.xls`, `Firedam.xls`, `Findoreria_Solved.xlsx`, `Research.docx`, `WACC Calc Spreadsheet.xls`, `TIVO Research.docx`
- claim: > Fred also had personal VC (Venture Capital) financial files on OneDrive: `WACC Calc Spreadsheet.xls`, `Findoreria_Solved.xlsx`, `NETFLIX.xlsx`, `TIVO Research.docx`, `Firedam.xls` [CONFIRMED — exec_id…

### ⚠ partial _(line 75)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `StarFury.lnk`, `StarFury.zip`, `starfury (2).lnk`
- **missing**: `\Users\fredr\OneDrive\StarFury.zip``, `\Users\fredr\OneDrive\StarFury.zip`
- claim: > **1. StarFury project archive**   `\Users\fredr\OneDrive\StarFury.zip` — a ZIP package of the StarFury project placed inside the OneDrive sync folder. Any active OneDrive sync would auto-upload this t…

### ⚠ partial _(line 81)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `IDNBREY.pst`, `Exported-PST.lnk`, `backup.pst`, `srl-h`
- **missing**: `\Users\fredr\OneDrive\Documents\Outlook`, `\$Recycle.Bin\S-1-5-21-528816539-567677750-276746561-1002\$IDNBREY.pst`, `\Users\fredr\OneDrive\Documents\Outlook Files\backup.pst`
- claim: > **2. Complete Outlook email archive (PST)**   `\Users\fredr\OneDrive\Documents\Outlook Files\backup.pst` — the entire SRL Outlook email store placed inside the OneDrive sync folder.   `\$Recycle.Bin\S…

### ✅ verified _(line 85)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `ADAMANTIUM-Background.lnk`, `France DGSE Intel Analysis Adamantium .pptx`
- claim: > **3. France DGSE / Adamantium intelligence document**   `France DGSE Intel Analysis Adamantium .pptx` (OneDrive - Stark Research Labs\Research) is in memory. Recent LNK `ADAMANTIUM-Background.lnk` con…

### ⚠ partial _(line 89)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `Data.docx`, `Specs.xlsx`, `Death_Blossom_test_visualization.png`, `Death_Blossom_attack.png`, `GunStar Upgrade Specs.xlsx`, `GunStar Death Blossom Data.docx`
- **missing**: `Particles...pdf`, `FTL Comms/Quantum Particles...pdf`
- claim: > **4. Gunstar weapons data**   `GunStar Death Blossom Data.docx`, `GunStar Upgrade Specs.xlsx`, `Death_Blossom_attack.png`, `Death_Blossom_test_visualization.png`, `FTL Comms/Quantum Particles...pdf` a…

### ✅ verified _(line 93)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `Background.lnk`, `KITT-older-version.lnk`, `KITT.pptx`, `Hydrogen_Hybrid_Tech.docx`, `KITT.lnk`, `German-KITT-Specs.docx`, `Background.docx`, `Future of KITT - Technical Background.lnk` (+4 more)
- claim: > **5. KITT project materials**   `The Future of KITT.pptx`, `Future of KITT - Technical Background.docx`, `German-KITT-Specs.docx`, `Hydrogen_Hybrid_Tech.docx` all in memory; Recent LNKs `The Future of…

### ✅ verified _(line 97)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `airwolf_blueprints.gif`, `Wolves_Lair_Tech_Specs.pptx`, `Airwolf-ARL.lnk`, `airwolf_blueprint.jpg`, `Airwolf_schematics.png`
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
- **missing**: `C42458BB-...lnk`, `26F77152-...lnk`, `1694D560-...lnk`, `BitLocker Recovery Key 1694D560-...lnk`, `BitLocker Recovery Key 26F77152-...lnk`, `BitLocker Recovery Key C42458BB-...lnk`
- claim: > **9. Three BitLocker recovery keys**   Recent LNKs: `BitLocker Recovery Key 1694D560-...lnk`, `BitLocker Recovery Key 26F77152-...lnk`, `BitLocker Recovery Key C42458BB-...lnk` plus `BitLocker Drive E…

### ✅ verified _(line 113)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `system.lnk`, `Files from SRL system.lnk`
- claim: > **10. "Files from SRL system"**   Recent LNK: `Files from SRL system.lnk` — confirms a collection of files from the corporate SRL system was accessed as a folder or file bundle.   [CONFIRMED — exec_id…

### ✅ verified _(line 117)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `starkresearchlabs-my.sharepoint.com.url`, `starkresearchlabs.sharepoint.com.url`, `KITT-CompetitiveAnalysisDocs on starkresearchlabs-my.sharepoint.com.url`, `WorkingFiles on starkresearchlabs-my.sharepoint.com.url`, `Megaforce on starkresearchlabs.sharepoint.com.url`
- claim: > **11. Megaforce and Blue Thunder project data**   Office Recent URLs `Megaforce on starkresearchlabs.sharepoint.com.url`, `KITT-CompetitiveAnalysisDocs on starkresearchlabs-my.sharepoint.com.url`, `Wo…

### ⚠ partial _(line 126)_
- tools: `vol3_cmdline`, `vol3_filescan`
- exec_ids: `6721d68c42cf`, `6ba398beced8`
- matched: `9648`, `6188`, `StarFury.zip`, `backup.pst`
- **missing**: `\Users\fredr\OneDrive\Documents\Outlook`, `\Users\fredr\OneDrive\``, `\Users\fredr\OneDrive\`, `\Users\fredr\OneDrive\Documents\Outlook Files\`
- claim: > `StarFury.zip` and `backup.pst` were placed in `\Users\fredr\OneDrive\` and `\Users\fredr\OneDrive\Documents\Outlook Files\` — both within the OneDrive for personal sync folder. With OneDrive running …

### ⚠ partial _(line 131)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `srl-h`
- **missing**: `\Users\srl-h\AppData\Local\Microsoft\OneDrive\``, `\Users\srl-h\AppData\Local\Microsoft\OneDrive\`
- claim: > The `srl-h` user account has its own OneDrive installation: `\Users\srl-h\AppData\Local\Microsoft\OneDrive\` — all OneDrive binaries confirmed in memory. This provides a second, attacker-controlled On…

### ✅ verified _(line 136)_
- tools: `vol3_netscan`
- exec_ids: `28eef0687026`
- matched: `201.193.188.114`, `81.30.144.115`, `81.19.209.101`, `213.202.233.104`
- claim: > Four external IPs connected via RDP to port 3389 simultaneously: - `81.30.144.115` — 59 connections, 2 ESTABLISHED at capture [CONFIRMED — exec_id 019e0dda-6764-76f3-9816-28eef0687026] - `213.202.233.…

### ✅ verified _(line 137)_
- tools: `vol3_netscan`
- exec_ids: `28eef0687026`
- matched: `201.193.188.114`, `81.30.144.115`, `81.19.209.101`, `213.202.233.104`
- claim: > Four external IPs connected via RDP to port 3389 simultaneously: - `81.30.144.115` — 59 connections, 2 ESTABLISHED at capture [CONFIRMED — exec_id 019e0dda-6764-76f3-9816-28eef0687026] - `213.202.233.…

### ✅ verified _(line 138)_
- tools: `vol3_netscan`
- exec_ids: `28eef0687026`
- matched: `201.193.188.114`, `81.30.144.115`, `81.19.209.101`, `213.202.233.104`
- claim: > Four external IPs connected via RDP to port 3389 simultaneously: - `81.30.144.115` — 59 connections, 2 ESTABLISHED at capture [CONFIRMED — exec_id 019e0dda-6764-76f3-9816-28eef0687026] - `213.202.233.…

### ✅ verified _(line 139)_
- tools: `vol3_netscan`
- exec_ids: `28eef0687026`
- matched: `201.193.188.114`, `81.30.144.115`, `81.19.209.101`, `213.202.233.104`
- claim: > Four external IPs connected via RDP to port 3389 simultaneously: - `81.30.144.115` — 59 connections, 2 ESTABLISHED at capture [CONFIRMED — exec_id 019e0dda-6764-76f3-9816-28eef0687026] - `213.202.233.…

### ⚠ partial _(line 146)_
- tools: `vol3_filescan`, `vol3_cmdline`
- exec_ids: `6ba398beced8`, `6721d68c42cf`
- matched: `MRC.exe`, `\Tools\`
- **missing**: `D:\Tools\MRC.exe``, `D:\Tools\MRC.exe`
- claim: > MRC.exe resides at `D:\Tools\MRC.exe` — Drive D: is not the system drive, indicating an external USB flash drive or removable media was connected. The `\Tools\` directory in the filesystem pool confir…

### ⚠ partial _(line 156)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `2020-11-14T04:39:15Z`, `2020-11-14T05:05:33Z`, `2020-11-14T13:50:02Z`, `BitLockerWizard.exe`, `SystemPropertiesAdvanced.exe`, `SystemPropertiesProtection.exe`, `DropboxUninstaller.exe`
- ✅ verified absences (negated): `sdelete64.exe`, `\Users\srl-h\Downloads\`, `srl-h`, `\Users\srl-h\`
- **missing**: `RemoteFXvGPUDisablement.exe`, `mstsc.exe`, `\Users\srl-h\Downloads\`.`, `\Users\srl-h\`,`
- claim: > - **Regedit** (Registry Editor) opened at `2020-11-14T04:39:15Z` — likely to enable RDP, create the backdoor account, or disable security settings. [CONFIRMED — exec_id 019e0ddb-7249-70a0-8527-ab77603…

### ⚠ partial _(line 157)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `2020-11-14T04:39:15Z`, `2020-11-14T05:05:33Z`, `2020-11-14T13:50:02Z`, `BitLockerWizard.exe`, `SystemPropertiesAdvanced.exe`, `SystemPropertiesProtection.exe`, `DropboxUninstaller.exe`
- ✅ verified absences (negated): `sdelete64.exe`, `\Users\srl-h\Downloads\`, `srl-h`, `\Users\srl-h\`
- **missing**: `RemoteFXvGPUDisablement.exe`, `mstsc.exe`, `\Users\srl-h\Downloads\`.`, `\Users\srl-h\`,`
- claim: > - **Regedit** (Registry Editor) opened at `2020-11-14T04:39:15Z` — likely to enable RDP, create the backdoor account, or disable security settings. [CONFIRMED — exec_id 019e0ddb-7249-70a0-8527-ab77603…

### ⚠ partial _(line 158)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `2020-11-14T04:39:15Z`, `2020-11-14T05:05:33Z`, `2020-11-14T13:50:02Z`, `BitLockerWizard.exe`, `SystemPropertiesAdvanced.exe`, `SystemPropertiesProtection.exe`, `DropboxUninstaller.exe`
- ✅ verified absences (negated): `sdelete64.exe`, `\Users\srl-h\Downloads\`, `srl-h`, `\Users\srl-h\`
- **missing**: `RemoteFXvGPUDisablement.exe`, `mstsc.exe`, `\Users\srl-h\Downloads\`.`, `\Users\srl-h\`,`
- claim: > - **Regedit** (Registry Editor) opened at `2020-11-14T04:39:15Z` — likely to enable RDP, create the backdoor account, or disable security settings. [CONFIRMED — exec_id 019e0ddb-7249-70a0-8527-ab77603…

### ⚠ partial _(line 159)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `2020-11-14T04:39:15Z`, `2020-11-14T05:05:33Z`, `2020-11-14T13:50:02Z`, `BitLockerWizard.exe`, `SystemPropertiesAdvanced.exe`, `SystemPropertiesProtection.exe`, `DropboxUninstaller.exe`
- ✅ verified absences (negated): `sdelete64.exe`, `\Users\srl-h\Downloads\`, `srl-h`, `\Users\srl-h\`
- **missing**: `RemoteFXvGPUDisablement.exe`, `mstsc.exe`, `\Users\srl-h\Downloads\`.`, `\Users\srl-h\`,`
- claim: > - **Regedit** (Registry Editor) opened at `2020-11-14T04:39:15Z` — likely to enable RDP, create the backdoor account, or disable security settings. [CONFIRMED — exec_id 019e0ddb-7249-70a0-8527-ab77603…

### ⚠ partial _(line 160)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `2020-11-14T04:39:15Z`, `2020-11-14T05:05:33Z`, `2020-11-14T13:50:02Z`, `BitLockerWizard.exe`, `SystemPropertiesAdvanced.exe`, `SystemPropertiesProtection.exe`, `DropboxUninstaller.exe`
- ✅ verified absences (negated): `sdelete64.exe`, `\Users\srl-h\Downloads\`, `srl-h`, `\Users\srl-h\`
- **missing**: `RemoteFXvGPUDisablement.exe`, `mstsc.exe`, `\Users\srl-h\Downloads\`.`, `\Users\srl-h\`,`
- claim: > - **Regedit** (Registry Editor) opened at `2020-11-14T04:39:15Z` — likely to enable RDP, create the backdoor account, or disable security settings. [CONFIRMED — exec_id 019e0ddb-7249-70a0-8527-ab77603…

### ⚠ partial _(line 161)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `2020-11-14T04:39:15Z`, `2020-11-14T05:05:33Z`, `2020-11-14T13:50:02Z`, `BitLockerWizard.exe`, `SystemPropertiesAdvanced.exe`, `SystemPropertiesProtection.exe`, `DropboxUninstaller.exe`
- ✅ verified absences (negated): `sdelete64.exe`, `\Users\srl-h\Downloads\`, `srl-h`, `\Users\srl-h\`
- **missing**: `RemoteFXvGPUDisablement.exe`, `mstsc.exe`, `\Users\srl-h\Downloads\`.`, `\Users\srl-h\`,`
- claim: > - **Regedit** (Registry Editor) opened at `2020-11-14T04:39:15Z` — likely to enable RDP, create the backdoor account, or disable security settings. [CONFIRMED — exec_id 019e0ddb-7249-70a0-8527-ab77603…

### ⚠ partial _(line 162)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `RemoteFXvGPUDisablement.exe`, `mstsc.exe`, `BitLockerWizard.exe`, `SystemPropertiesAdvanced.exe`, `SystemPropertiesProtection.exe`
- ✅ verified absences (negated): `\Users\srl-h\Downloads\`, `\Users\srl-h\`
- **missing**: `2020-11-14T04:39:15Z`, `2020-11-14T05:05:33Z`, `2020-11-14T13:50:02Z`, `DropboxUninstaller.exe`, `\Users\srl-h\Downloads\`.`, `\Users\srl-h\`,`
- 🚨 negation violations (claimed absent but found): `sdelete64.exe`, `srl-h`
- claim: > - **Regedit** (Registry Editor) opened at `2020-11-14T04:39:15Z` — likely to enable RDP, create the backdoor account, or disable security settings. [CONFIRMED — exec_id 019e0ddb-7249-70a0-8527-ab77603…

### ⚠ partial _(line 163)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `RemoteFXvGPUDisablement.exe`, `mstsc.exe`, `BitLockerWizard.exe`, `SystemPropertiesAdvanced.exe`, `SystemPropertiesProtection.exe`
- ✅ verified absences (negated): `\Users\srl-h\Downloads\`, `\Users\srl-h\`
- **missing**: `2020-11-14T04:39:15Z`, `2020-11-14T05:05:33Z`, `2020-11-14T13:50:02Z`, `DropboxUninstaller.exe`, `\Users\srl-h\Downloads\`.`, `\Users\srl-h\`,`
- 🚨 negation violations (claimed absent but found): `sdelete64.exe`, `srl-h`
- claim: > - **Regedit** (Registry Editor) opened at `2020-11-14T04:39:15Z` — likely to enable RDP, create the backdoor account, or disable security settings. [CONFIRMED — exec_id 019e0ddb-7249-70a0-8527-ab77603…

### ⚠ partial _(line 168)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `sdelete.exe`, `SDelete.zip`, `SDelete.lnk`, `sdelete64.exe`, `Exported-PST.lnk`, `backup.pst`, `StarFury.zip`
- **missing**: `2020-11-14T12:43:01Z`, `\Users\fredr\Downloads\SDelete\`.`, `\Users\fredr\Downloads\SDelete\`
- claim: > - **StarFury.zip created** — project files were compressed and moved to the OneDrive sync folder. [INFERRED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8; reasoning: ZIP present in OneDrive root with…

### ⚠ partial _(line 169)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `sdelete.exe`, `SDelete.zip`, `SDelete.lnk`, `sdelete64.exe`, `Exported-PST.lnk`, `backup.pst`, `StarFury.zip`
- **missing**: `2020-11-14T12:43:01Z`, `\Users\fredr\Downloads\SDelete\`.`, `\Users\fredr\Downloads\SDelete\`
- claim: > - **StarFury.zip created** — project files were compressed and moved to the OneDrive sync folder. [INFERRED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8; reasoning: ZIP present in OneDrive root with…

### ⚠ partial _(line 170)_
- tools: `vol3_userassist`
- exec_ids: `ab776038fd0a`
- matched: `2020-11-14T12:43:01Z`, `sdelete.exe`
- **missing**: `SDelete.zip`, `SDelete.lnk`, `sdelete64.exe`, `Exported-PST.lnk`, `backup.pst`, `StarFury.zip`, `\Users\fredr\Downloads\SDelete\`.`, `\Users\fredr\Downloads\SDelete\`
- claim: > - **StarFury.zip created** — project files were compressed and moved to the OneDrive sync folder. [INFERRED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8; reasoning: ZIP present in OneDrive root with…

### ⚠ partial _(line 174)_
- tools: `vol3_pstree`, `vol3_cmdline`, `vol3_filescan`
- exec_ids: `ca3ed66e47c7`, `6721d68c42cf`, `6ba398beced8`
- matched: `29440`, `1248`, `2020-11-16T02:31:15Z`, `svchost.exe`, `MRC.exe`, `MRC179.tmp`
- **missing**: `81.30.144.115`, `213.202.233.104`, `D:\Tools\MRC.exe``, `D:\Tools\)`, `D:\Tools\MRC.exe`
- claim: > - **MRC.exe** (pid 29440, 32-bit, wow64:true) launched at `2020-11-16T02:31:15Z` from `D:\Tools\MRC.exe` via Explorer (ppid 7464), session_id:1, 20 threads — still RUNNING at RAM capture. A companion …

### ⚠ partial _(line 175)_
- tools: `vol3_netscan`
- exec_ids: `28eef0687026`
- matched: `1248`, `81.30.144.115`, `213.202.233.104`, `svchost.exe`
- **missing**: `29440`, `2020-11-16T02:31:15Z`, `MRC.exe`, `MRC179.tmp`, `D:\Tools\MRC.exe``, `D:\Tools\)`, `D:\Tools\MRC.exe`
- claim: > - **MRC.exe** (pid 29440, 32-bit, wow64:true) launched at `2020-11-16T02:31:15Z` from `D:\Tools\MRC.exe` via Explorer (ppid 7464), session_id:1, 20 threads — still RUNNING at RAM capture. A companion …

### ✅ verified _(line 177)_
- tools: `vol3_malfind`
- exec_ids: `9748ae5d944c`
- matched: `MsMpEng.exe`, `Teams.exe`, `SearchApp.exe`
- claim: > **No malware injection detected:** Malfind analysis returned only 16 findings, all attributable to legitimate JIT/CLR activity in MsMpEng.exe (Defender), SearchApp.exe, and Teams.exe. No shellcode or …

### ⚠ partial _(line 221)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `sdelete64.exe`, `powershell.exe`, `RemoteFXvGPUDisablement.exe`, `mmc.exe`, `powershell.exe.log`, `RemoteFXvGPUDisablement.exe.log`, `mmc.exe.log`
- **missing**: `\Users\srl-h\``, `\Users\srl-h\`
- claim: > - Profile directory `\Users\srl-h\` populated with CLR usage logs, OneDrive binaries, and sdelete64.exe [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8] - `powershell.exe.log` in both CLR_v4…

### ⚠ partial _(line 222)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `sdelete64.exe`, `powershell.exe`, `RemoteFXvGPUDisablement.exe`, `mmc.exe`, `powershell.exe.log`, `RemoteFXvGPUDisablement.exe.log`, `mmc.exe.log`
- **missing**: `\Users\srl-h\``, `\Users\srl-h\`
- claim: > - Profile directory `\Users\srl-h\` populated with CLR usage logs, OneDrive binaries, and sdelete64.exe [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8] - `powershell.exe.log` in both CLR_v4…

### ⚠ partial _(line 223)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `sdelete64.exe`, `powershell.exe`, `RemoteFXvGPUDisablement.exe`, `mmc.exe`, `powershell.exe.log`, `RemoteFXvGPUDisablement.exe.log`, `mmc.exe.log`
- **missing**: `\Users\srl-h\``, `\Users\srl-h\`
- claim: > - Profile directory `\Users\srl-h\` populated with CLR usage logs, OneDrive binaries, and sdelete64.exe [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8] - `powershell.exe.log` in both CLR_v4…

### ⚠ partial _(line 224)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `sdelete64.exe`, `powershell.exe`, `RemoteFXvGPUDisablement.exe`, `mmc.exe`, `powershell.exe.log`, `RemoteFXvGPUDisablement.exe.log`, `mmc.exe.log`
- **missing**: `\Users\srl-h\``, `\Users\srl-h\`
- claim: > - Profile directory `\Users\srl-h\` populated with CLR usage logs, OneDrive binaries, and sdelete64.exe [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8] - `powershell.exe.log` in both CLR_v4…

### ⚠ partial _(line 225)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `sdelete64.exe`, `powershell.exe`, `RemoteFXvGPUDisablement.exe`, `mmc.exe`, `powershell.exe.log`, `RemoteFXvGPUDisablement.exe.log`, `mmc.exe.log`
- **missing**: `\Users\srl-h\``, `\Users\srl-h\`
- claim: > - Profile directory `\Users\srl-h\` populated with CLR usage logs, OneDrive binaries, and sdelete64.exe [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8] - `powershell.exe.log` in both CLR_v4…

### ⚠ partial _(line 226)_
- tools: `vol3_filescan`
- exec_ids: `6ba398beced8`
- matched: `sdelete64.exe`, `powershell.exe`, `RemoteFXvGPUDisablement.exe`, `mmc.exe`, `powershell.exe.log`, `RemoteFXvGPUDisablement.exe.log`, `mmc.exe.log`
- **missing**: `\Users\srl-h\``, `\Users\srl-h\`
- claim: > - Profile directory `\Users\srl-h\` populated with CLR usage logs, OneDrive binaries, and sdelete64.exe [CONFIRMED — exec_id 019e0ddc-336a-77c3-ae5d-6ba398beced8] - `powershell.exe.log` in both CLR_v4…

### ❓ unverifiable _(line 241)_
- exec_ids: `28eef0687026`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e0dda-6764-76f3-9816-28eef0687026]
