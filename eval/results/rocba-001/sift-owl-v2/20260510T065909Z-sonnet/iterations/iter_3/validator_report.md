# Validator Report — iter_3

## Summary

- Total tagged claims:        **73**
  - CONFIRMED:                 60
  - INFERRED:                  7
  - HYPOTHESIS:                1
  - GAP:                       5
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           49 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                10 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           1 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 81.7%** (49 verified / 60 confirmed)

## Per-claim verdicts

### ✅ verified _(line 20)_
- tools: `vol3_image_info`
- exec_ids: `5688d0d7063f`
- matched: `2020-11-16T02:32:38Z`
- claim: > **Capture time:** system_time_utc 2020-11-16T02:32:38Z [CONFIRMED — exec_id 019e10cb-61a0-72b1-943d-5688d0d7063f]

### ❓ unverifiable _(line 22)_
- exec_ids: `5688d0d7063f`
- note: claim has no extractable tokens (prose only)
- claim: > **OS:** Windows 10 build 19041 x64, NtProductWinNt [CONFIRMED — exec_id 019e10cb-61a0-72b1-943d-5688d0d7063f]

### ⚠ partial _(line 24)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `ntuser.dat`
- **missing**: `\C:\Users\fredr\ntuser.dat,`, `C:\Users\fredr\ntuser.dat,`
- claim: > **User hive:** \??\C:\Users\fredr\ntuser.dat, 120 UserAssist entries, hive_name confirmed [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6]

### ✅ verified _(line 32)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `Specs.xlsx`, `Death_Blossom_attack.png`, `Data.xlsx`, `Data.docx`, `\Users\fredr\Stark`
- claim: > The Gunstar project \Users\fredr\Stark Research Labs\SRL-Projects - Gunstar contained GunStar Death Blossom Data.docx, GunStar Upgrade Specs.xlsx, Gunstar Test Harness Data.xlsx, and Death_Blossom_att…

### ✅ verified _(line 34)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `Hydrogen_Hybrid_Tech.docx`, `KITT.pptx`, `German-KITT-Specs.docx`, `Background.docx`, `\Users\fredr\Stark`
- claim: > The KITT project \Users\fredr\Stark Research Labs\Maria Hill - KITT contained The Future of KITT.pptx, Future of KITT - Technical Background.docx, and Hydrogen_Hybrid_Tech.docx; \Users\fredr\Stark Res…

### ✅ verified _(line 36)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `Airwolf_schematics.png`, `airwolf_blueprints.gif`, `Wolves_Lair_Tech_Specs.pptx`, `\Users\fredr\Stark`
- claim: > The Airwolf project \Users\fredr\Stark Research Labs\SRL-Projects - Airwolf contained Wolves_Lair_Tech_Specs.pptx, Airwolf_schematics.png, and airwolf_blueprints.gif [CONFIRMED — exec_id 019e10d1-a143…

### ✅ verified _(line 38)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `Starfury.docx`, `\Users\fredr\OneDrive\Desktop\SA-23E`
- claim: > The StarFury design document \Users\fredr\OneDrive\Desktop\SA-23E Mitchell-Hyundyne Starfury.docx was cached in pool memory [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bbc7f674a3cc].

### ✅ verified _(line 40)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `SRL.docx`, `\Users\fredr\OneDrive`
- claim: > Vibrainium research was present at \Users\fredr\OneDrive - Stark Research Labs\Research\Vibrainium - SRL.docx [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bbc7f674a3cc].

### ✅ verified _(line 42)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `\Users\fredr\OneDrive`
- claim: > The Adamantium intelligence file \Users\fredr\OneDrive - Stark Research Labs\Research\France DGSE Intel Analysis Adamantium .pptx was present in pool memory [CONFIRMED — exec_id 019e10d1-a143-7173-8c1…

### ✅ verified _(line 44)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `stark-research-labs.com.ost`, `\Users\fredr\AppData\Local\Microsoft\Outlook\frocba@stark-research-labs.com.ost`, `frocba@stark-research-labs.com`
- claim: > The full corporate email archive \Users\fredr\AppData\Local\Microsoft\Outlook\frocba@stark-research-labs.com.ost was present in pool memory, confirming complete corporate mailbox access [CONFIRMED — e…

### ✅ verified _(line 52)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `StarFury.zip`, `\Users\fredr\OneDrive\StarFury.zip`
- claim: > The archive \Users\fredr\OneDrive\StarFury.zip was placed in the personal OneDrive sync root for automatic cloud upload [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bbc7f674a3cc].

### ✅ verified _(line 54)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `StarFuryHeader.jpg`, `fighter_starfury.jpg`, `\Users\fredr\iCloudDrive\fighter_starfury.jpg`, `\Users\fredr\iCloudDrive\StarFuryHeader.jpg`
- claim: > Two StarFury images were placed in the iCloud sync folder: \Users\fredr\iCloudDrive\StarFuryHeader.jpg and \Users\fredr\iCloudDrive\fighter_starfury.jpg [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bb…

### ✅ verified _(line 60)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `Specs.xlsx`, `Data.xlsx`, `Data.docx`, `\Users\fredr\Stark`
- claim: > GunStar Death Blossom Data.docx, GunStar Upgrade Specs.xlsx, and Gunstar Test Harness Data.xlsx under \Users\fredr\Stark Research Labs\SRL-Projects - Gunstar\ were present as file objects [CONFIRMED —…

### ✅ verified _(line 62)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `Hydrogen_Hybrid_Tech.docx`, `KITT.pptx`, `Background.docx`, `\Users\fredr\Stark`
- claim: > The Future of KITT.pptx, Future of KITT - Technical Background.docx, and Hydrogen_Hybrid_Tech.docx under \Users\fredr\Stark Research Labs\Maria Hill - KITT\ were present as file objects [CONFIRMED — e…

### ✅ verified _(line 64)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `Airwolf_schematics.png`, `Wolves_Lair_Tech_Specs.pptx`, `\Users\fredr\Stark`
- claim: > Wolves_Lair_Tech_Specs.pptx and Airwolf_schematics.png under \Users\fredr\Stark Research Labs\SRL-Projects - Airwolf\ were present as file objects [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bbc7f674…

### ✅ verified _(line 66)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `SRL.docx`, `\Users\fredr\OneDrive`
- claim: > Vibrainium - SRL.docx and France DGSE Intel Analysis Adamantium .pptx under \Users\fredr\OneDrive - Stark Research Labs\Research\ were present as file objects [CONFIRMED — exec_id 019e10d1-a143-7173-8…

### ✅ verified _(line 68)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `stark-research-labs.com.ost`, `\Users\fredr\AppData\Local\Microsoft\Outlook`, `frocba@stark-research-labs.com`
- claim: > frocba@stark-research-labs.com.ost at \Users\fredr\AppData\Local\Microsoft\Outlook\ was present as a file object [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bbc7f674a3cc].

### ⚠ partial _(line 72)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `SDelete.zip`, `sdelete.exe`, `SDelete.lnk`, `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk`
- **missing**: `\Users\fredr\Downloads\SDelete\sdelete.exe,`, `\Users\fredr\Downloads\SDelete.zip,`
- claim: > \Users\fredr\Downloads\SDelete\sdelete.exe, \Users\fredr\Downloads\SDelete.zip, and \Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk were present in pool memory; the SDelete.lnk artif…

### ✅ verified _(line 74)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `sdelete64.exe`, `\Users\srl-h\Downloads\sdelete64.exe`
- claim: > \Users\srl-h\Downloads\sdelete64.exe was present in pool memory, indicating SDelete was also deployed under a second user account [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bbc7f674a3cc]. [GAP — ori…

### ⚠ partial _(line 82)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `9648`, `OneDrive.exe`, `StarFury.zip`, `\Users\fredr\OneDrive\StarFury.zip`
- **missing**: `13.107.136.9`, `52.179.224.121`, `52.114.75.149`, `2020-11-16T02:32:55Z`, `2020-11-13T19:56:50Z`, `2020-11-16T02:32:45Z`
- claim: > \Users\fredr\OneDrive\StarFury.zip was staged in the personal OneDrive sync root [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bbc7f674a3cc]. OneDrive.exe (pid 9648) maintained an ESTABLISHED connectio…

### ⚠ partial _(line 82)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `9648`, `13.107.136.9`, `52.179.224.121`, `52.114.75.149`, `2020-11-16T02:32:55Z`, `2020-11-13T19:56:50Z`, `2020-11-16T02:32:45Z`, `OneDrive.exe`
- **missing**: `StarFury.zip`, `\Users\fredr\OneDrive\StarFury.zip`
- claim: > \Users\fredr\OneDrive\StarFury.zip was staged in the personal OneDrive sync root [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bbc7f674a3cc]. OneDrive.exe (pid 9648) maintained an ESTABLISHED connectio…

### ⚠ partial _(line 82)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `9648`, `13.107.136.9`, `52.179.224.121`, `52.114.75.149`, `2020-11-16T02:32:55Z`, `2020-11-13T19:56:50Z`, `2020-11-16T02:32:45Z`, `OneDrive.exe`
- **missing**: `StarFury.zip`, `\Users\fredr\OneDrive\StarFury.zip`
- claim: > \Users\fredr\OneDrive\StarFury.zip was staged in the personal OneDrive sync root [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bbc7f674a3cc]. OneDrive.exe (pid 9648) maintained an ESTABLISHED connectio…

### ⚠ partial _(line 82)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `9648`, `13.107.136.9`, `52.179.224.121`, `52.114.75.149`, `2020-11-16T02:32:55Z`, `2020-11-13T19:56:50Z`, `2020-11-16T02:32:45Z`, `OneDrive.exe`
- **missing**: `StarFury.zip`, `\Users\fredr\OneDrive\StarFury.zip`
- claim: > \Users\fredr\OneDrive\StarFury.zip was staged in the personal OneDrive sync root [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bbc7f674a3cc]. OneDrive.exe (pid 9648) maintained an ESTABLISHED connectio…

### ✅ verified _(line 86)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `1248`, `81.30.144.115`, `2020-11-16T02:31:26Z`, `2020-11-16T02:34:58Z`, `2020-11-16T02:34:45Z`, `svchost.exe`
- claim: > svchost.exe (pid 1248) received 59 inbound RDP connections from 81.30.144.115 to local port 3389; pool-memory structures show port 51048 ESTABLISHED created 2020-11-16T02:34:58Z and port 5067 ESTABLIS…

### ✅ verified _(line 88)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `1248`, `213.202.233.104`, `2020-11-16T02:34:58Z`, `2020-11-16T02:35:53Z`, `2020-11-16T02:31:18Z`, `svchost.exe`
- claim: > svchost.exe (pid 1248) received 54 inbound RDP connections from 213.202.233.104 to local port 3389; pool-memory structures show port 45753 ESTABLISHED created 2020-11-16T02:34:58Z and port 40876 ESTAB…

### ✅ verified _(line 90)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `1248`, `201.193.188.114`, `2020-11-16T02:30:05Z`, `svchost.exe`
- claim: > svchost.exe (pid 1248) received 3 inbound RDP connections from 201.193.188.114, all CLOSED; earliest was port 63385 created 2020-11-16T02:30:05Z — the first RDP connection of the remote re-entry phase…

### ✅ verified _(line 98)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `MRC.exe`, `D:\Tools\MRC.exe`
- claim: > D:\Tools\MRC.exe is the confirmed D: drive artifact in UserAssist [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6]. [INFERRED: additional files may have been transferred to/from the USB; dis…

### ✅ verified _(line 102)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `StarFuryHeader.jpg`, `fighter_starfury.jpg`, `\Users\fredr\iCloudDrive\fighter_starfury.jpg`, `\Users\fredr\iCloudDrive\StarFuryHeader.jpg`
- claim: > \Users\fredr\iCloudDrive\StarFuryHeader.jpg and \Users\fredr\iCloudDrive\fighter_starfury.jpg were present in the iCloudDrive sync folder [CONFIRMED — exec_id 019e10d1-a143-7173-8c13-bbc7f674a3cc]. [G…

### ✅ verified _(line 110)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-13T22:09:17Z`
- claim: > Microsoft.XboxGamingOverlay_8wekyb3d8bbwe!App received last_updated 2020-11-13T22:09:17Z — the earliest post-22:00Z UserAssist write, consistent with the intruder's first mouse/keyboard input on the u…

### ✅ verified _(line 114)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T04:29:49Z`, `Microsoft.Office.WINWORD.EXE`
- claim: > Microsoft.Office.WINWORD.EXE.15 last_updated 2020-11-14T04:29:49Z (count 14, time_focused 0:02:56.842000) confirms Word documents were opened [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6]…

### ✅ verified _(line 116)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T04:49:43Z`, `AcroRd32.exe`
- claim: > %ProgramFiles%\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe last_updated 2020-11-14T04:49:43Z (count 6) confirms PDF files were opened [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6].

### ✅ verified _(line 118)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T04:39:15Z`, `regedit.exe`
- claim: > %windir%\regedit.exe last_updated 2020-11-14T04:39:15Z with count 1, focus_count 2, time_focused 0:03:40.124000 [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6]. [GAP — target registry key u…

### ✅ verified _(line 120)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T12:43:01Z`, `cmd.exe`
- claim: > %windir%\system32\cmd.exe last_updated 2020-11-14T12:43:01Z with count 1, time_focused 0:06:42.891000 [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6].

### ✅ verified _(line 122)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T14:09:15Z`, `Microsoft.Office.OUTLOOK.EXE`
- claim: > Microsoft.Office.OUTLOOK.EXE.15 last_updated 2020-11-14T14:09:15Z with count 4, time_focused 0:10:59.013000 [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6].

### ✅ verified _(line 126)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `StarFury.lnk`, `StarFury.zip`, `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\StarFury.lnk`, `\Users\fredr\OneDrive\StarFury.zip`
- claim: > \Users\fredr\OneDrive\StarFury.zip was placed in the personal OneDrive sync root; \Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\StarFury.lnk confirms Explorer navigation to the StarFury direct…

### ✅ verified _(line 130)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T13:50:02Z`, `DropboxUninstaller.exe`
- claim: > %ProgramFiles%\Dropbox\Client\DropboxUninstaller.exe last_updated 2020-11-14T13:50:02Z with count 1 — Dropbox uninstalled to remove sync artifact trail [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50a…

### ⚠ partial _(line 132)_
- tools: `vol3_filescan`
- exec_ids: `bbc7f674a3cc`
- matched: `SDelete.zip`, `sdelete.exe`, `SDelete.lnk`, `\Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk`
- **missing**: `\Users\fredr\Downloads\SDelete\sdelete.exe,`, `\Users\fredr\Downloads\SDelete.zip,`
- claim: > \Users\fredr\Downloads\SDelete\sdelete.exe, \Users\fredr\Downloads\SDelete.zip, and \Users\fredr\AppData\Roaming\Microsoft\Windows\Recent\SDelete.lnk confirm SDelete was downloaded and executed to wip…

### ⚠ partial _(line 136)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `1248`, `201.193.188.114`, `2020-11-16T02:30:05Z`, `svchost.exe`
- **missing**: `MRC.exe`
- claim: > The first RDP connection arrived from 201.193.188.114 port 63385 at created 2020-11-16T02:30:05Z (CLOSED, svchost.exe pid 1248) — preceding MRC.exe launch by ~65 seconds [CONFIRMED — exec_id 019e10cb-…

### ✅ verified _(line 138)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-16T02:31:13Z`, `ntuser.dat`, `MRC.exe`, `\C:\Users\fredr\ntuser.dat`, `C:\Users\fredr\ntuser.dat`, `D:\Tools\MRC.exe`
- claim: > D:\Tools\MRC.exe was recorded in UserAssist with last_updated 2020-11-16T02:31:13Z, count 1, focus_count 1, hive_name \??\C:\Users\fredr\ntuser.dat [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d…

### ⚠ partial _(line 140)_
- tools: `vol3_pstree`
- exec_ids: `60452ae865e1`
- matched: `29440`, `7464`, `2020-11-16T02:31:15Z`, `2020-11-11T08:13:41Z`, `explorer.exe`, `MRC.exe`
- **missing**: `D:\Tools\`
- claim: > MRC.exe (pid 29440, ppid 7464, threads 20, wow64 true, create_time 2020-11-16T02:31:15Z) was spawned from explorer.exe (pid 7464, ppid 7404, create_time 2020-11-11T08:13:41Z, session_id 1) [CONFIRMED …

### ⚠ partial _(line 142)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `81.30.144.115`, `213.202.233.104`
- **missing**: `MRC.exe`
- claim: > High-volume RDP sessions from 81.30.144.115 (59 connections) and 213.202.233.104 (54 connections) followed MRC.exe launch, with ESTABLISHED pool structures present at/after capture [CONFIRMED — exec_i…

### ✅ verified _(line 146)_
- tools: `vol3_malfind`
- exec_ids: `4444ba069b56`
- matched: `Teams.exe`, `SearchApp.exe`, `dllhost.exe`, `LockApp.exe`, `MsMpEng.exe`
- ✅ verified absences (negated): `29440`, `MRC.exe`
- claim: > vol3_malfind returned 16 findings with by_process counts: MsMpEng.exe (5), SearchApp.exe (6), dllhost.exe (1), LockApp.exe (1), RuntimeBroker. (1), Teams.exe (1), smartscreen.ex (1) — all attributable…

### ✅ verified _(line 148)_
- tools: `vol3_svcscan`
- exec_ids: `04faf3f3a86a`
- matched: `svchost.exe`
- claim: > Services reviewed showed only standard Windows binary paths including %SystemRoot%\system32\svchost.exe and System32\ drivers; no user-writable or anomalous binary paths identified [CONFIRMED — exec_i…

### ✅ verified _(line 159)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-13T22:09:17Z`
- claim: > ``` 2020-11-13T22:09:17Z  Microsoft.XboxGamingOverlay_8wekyb3d8bbwe!App last_updated                        (first UserAssist write in break-in window)                        [CONFIRMED — exec_id 019e…

### ✅ verified _(line 162)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T04:29:49Z`, `Microsoft.Office.WINWORD.EXE`
- claim: > 2020-11-14T04:29:49Z  Microsoft.Office.WINWORD.EXE.15 last_updated (count 14)                        [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6]

### ✅ verified _(line 165)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T04:39:15Z`, `regedit.exe`
- claim: > 2020-11-14T04:39:15Z  %windir%\regedit.exe last_updated (count 1, time_focused 0:03:40.124000)                        [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6]

### ✅ verified _(line 168)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T04:49:43Z`, `AcroRd32.exe`
- claim: > 2020-11-14T04:49:43Z  %ProgramFiles%\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe last_updated                        [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6]

### ✅ verified _(line 171)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T12:43:01Z`, `cmd.exe`
- claim: > 2020-11-14T12:43:01Z  %windir%\system32\cmd.exe last_updated (time_focused 0:06:42.891000)                        [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6]

### ✅ verified _(line 175)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T13:50:02Z`, `DropboxUninstaller.exe`
- claim: > 2020-11-14T13:50:02Z  %ProgramFiles%\Dropbox\Client\DropboxUninstaller.exe last_updated (count 1)                        — Dropbox removed, anti-forensics                        [CONFIRMED — exec_id 0…

### ✅ verified _(line 178)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-14T14:09:15Z`, `Microsoft.Office.OUTLOOK.EXE`
- claim: > 2020-11-14T14:09:15Z  Microsoft.Office.OUTLOOK.EXE.15 last_updated (time_focused 0:10:59.013000)                        [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6]

### ✅ verified _(line 184)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `1248`, `201.193.188.114`, `2020-11-16T02:30:05Z`, `svchost.exe`
- claim: > 2020-11-16T02:30:05Z  201.193.188.114 port 63385 inbound RDP to local 3389, CLOSED                        (svchost.exe pid 1248 — earliest remote re-entry connection)                        [CONFIRMED…

### ✅ verified _(line 187)_
- tools: `vol3_userassist`
- exec_ids: `50abd5d244d6`
- matched: `2020-11-16T02:31:13Z`, `MRC.exe`, `D:\Tools\MRC.exe`
- claim: > 2020-11-16T02:31:13Z  D:\Tools\MRC.exe last_updated in UserAssist (count 1, focus_count 1)                        [CONFIRMED — exec_id 019e10cb-6414-7711-b668-50abd5d244d6]

### ✅ verified _(line 190)_
- tools: `vol3_pstree`
- exec_ids: `60452ae865e1`
- matched: `29440`, `2020-11-16T02:31:15Z`, `explorer.exe`, `MRC.exe`
- claim: > 2020-11-16T02:31:15Z  MRC.exe created (pid 29440, ppid 7464/explorer.exe, wow64 true, threads 20)                        [CONFIRMED — exec_id 019e10cb-6b0d-74e0-bec2-60452ae865e1]

### ✅ verified _(line 194)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `1248`, `213.202.233.104`, `2020-11-16T02:31:18Z`, `svchost.exe`
- claim: > 2020-11-16T02:31:18Z  213.202.233.104 port 58072 inbound RDP to local 3389, CLOSED                        (svchost.exe pid 1248)                        [CONFIRMED — exec_id 019e10cb-8583-7b42-8e0b-729…

### ✅ verified _(line 198)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `1248`, `81.30.144.115`, `2020-11-16T02:31:26Z`, `svchost.exe`
- claim: > 2020-11-16T02:31:26Z  81.30.144.115 port 53145 inbound RDP to local 3389, CLOSED                        (svchost.exe pid 1248)                        [CONFIRMED — exec_id 019e10cb-8583-7b42-8e0b-729ae…

### ✅ verified _(line 201)_
- tools: `vol3_image_info`
- exec_ids: `5688d0d7063f`
- matched: `2020-11-16T02:32:38Z`
- claim: > 2020-11-16T02:32:38Z  *** SRL RAM CAPTURE *** system_time_utc 2020-11-16T02:32:38Z                        [CONFIRMED — exec_id 019e10cb-61a0-72b1-943d-5688d0d7063f]

### ✅ verified _(line 204)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `9648`, `13.107.136.9`, `2020-11-16T02:32:45Z`, `OneDrive.exe`
- claim: > 2020-11-16T02:32:45Z  OneDrive.exe (pid 9648) → 13.107.136.9:443 ESTABLISHED                        [CONFIRMED — exec_id 019e10cb-8583-7b42-8e0b-729ae8949921]

### ✅ verified _(line 207)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `1248`, `81.30.144.115`, `2020-11-16T02:34:45Z`, `svchost.exe`
- claim: > 2020-11-16T02:34:45Z  81.30.144.115 port 5067 ESTABLISHED (pool residue; svchost.exe pid 1248)                        [CONFIRMED — exec_id 019e10cb-8583-7b42-8e0b-729ae8949921]

### ✅ verified _(line 211)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `1248`, `81.30.144.115`, `213.202.233.104`, `2020-11-16T02:34:58Z`, `svchost.exe`
- claim: > 2020-11-16T02:34:58Z  81.30.144.115 port 51048 ESTABLISHED; 213.202.233.104 port 45753 ESTABLISHED                        (pool residue; svchost.exe pid 1248 — sessions active during acquisition)     …

### ✅ verified _(line 214)_
- tools: `vol3_netscan`
- exec_ids: `729ae8949921`
- matched: `1248`, `213.202.233.104`, `2020-11-16T02:35:53Z`, `svchost.exe`
- claim: > 2020-11-16T02:35:53Z  213.202.233.104 port 40876 ESTABLISHED (pool residue; svchost.exe pid 1248)                        [CONFIRMED — exec_id 019e10cb-8583-7b42-8e0b-729ae8949921] ```
