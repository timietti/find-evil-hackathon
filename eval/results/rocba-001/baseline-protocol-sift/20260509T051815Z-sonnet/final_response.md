Starting the investigation by setting up output directories and launching initial Volatility 3 scans in parallel.

Good — `/usr/local/bin/vol` is Volatility 3. Now launching the core scans in parallel.

Found something suspicious: `MRC.exe` running from `D:\Tools\`. Let me investigate this and check network connections.

Good — all scans completed. Now let me analyze the key findings in parallel.

Critical finding: RDP connections from external IPs `81.30.144.115`, `213.202.233.104`, `81.19.209.101` during the break-in window. Now investigating MRC.exe and getting full process context.

Massive RDP flood from 3 external IPs right at capture time. Now investigating MRC.exe deeply and looking for all suspicious network connections.

MRC.exe confirmed on `\Device\HarddiskVolume7\Tools\MRC.exe` — a USB drive (Volume7 vs Volume3 for C:). Now checking DLLs, userAssist, registry, and more.

MRC.exe uses MSVBVM60.DLL — this is "Mini Remote Control" (MRC), a Visual Basic 6 remote access tool. Now searching for all processes created during the break-in window.

Key timeline: WUDFHost (USB device) → smartscreen.exe → MRC.exe, all between 02:29-02:31 UTC. Now running UserAssist and checking filescan for D:\ artifacts.

Found corporate OneDrive at `C:\Users\fredr\OneDrive - Stark Research Labs`. Now searching filescan for D:\ drive content and SRL project files.

Critical project files found in memory. Let me get the complete picture of files accessed.

Massive findings: SRL projects Airwolf, Blue Thunder, Gunstar, KITT, Vibranium on device; `StarFury.zip` on OneDrive; `SDelete.zip`; and KAPE forensic tool on the USB drive (`D:\Tools\KAPE\`). Let me now investigate the critical artifacts.

The USB drive (`D:\Tools\`) contained a complete professional toolkit: **KAPE**, **AccessData FTK Imager**, **MRC.exe**, and EZ Tools. This is a targeted data-theft operation. Now pulling critical file details.

Now checking malfind results and looking for key additional artifacts.

Malfind only shows Windows Defender JIT pages — no code injection. Gathering final data points, then writing the report.

Found "Exported-PST.lnk" in Recent Items — someone exported Fred's email to a PST. Now compiling all evidence into the final report.

All output written and verified. Saving memory notes for future sessions.

---

## Findings Summary — Case ROCBA-001

### G1 — Key Projects Fred Had Access To [CONFIRMED]
Fred's laptop had nine SRL R&D projects in memory: **Airwolf**, **Blue Thunder**, **Gunstar** (Death Blossom, FTL Comms), **KITT** (Maria Hill — Hydrogen Hybrid Tech, Future of KITT), **Vibranium**, **Adamantium** (France DGSE Intel), **StarFury / SA-23E**, **Megaforce** (SharePoint), and **Ion Thruster Weaponization**.

### G2 — What Was Stolen [CONFIRMED + INFERRED]
Files confirmed accessed and staged during the break-in window:
- **KITT project documents** (3 versions of "Future of KITT" opened per Recent Items)
- **Airwolf** folder browsed
- **Vibranium** doc copied (copy "(1)" suffix in Office Recent)
- **StarFury** data — `StarFury.zip` created on personal OneDrive; images placed on iCloud
- **Fred's entire Outlook mailbox** — exported to `Exported-PST`, then the PST was deleted to Recycle Bin

### G3 — Transfer Destinations [CONFIRMED]
1. **Personal OneDrive** — `StarFury.zip` (confirmed in filescan; OneDrive.exe was actively syncing)
2. **Apple iCloud** — `StarFuryHeader.jpg`, `fighter_starfury.jpg` (iCloudDrive)
3. **USB drive `D:\`** — KAPE + FTK Imager used for on-device forensic collection/imaging to the USB
4. **Remote RDP sessions** — four external IPs had active/recent RDP sessions: `81.30.144.115`, `213.202.233.104`, `81.19.209.101`, `201.193.188.114`

### G4 — How [CONFIRMED + INFERRED]
Physical break-in → unlocked laptop → browser-based SRL file access → file archiving to personal cloud → SDelete anti-forensic cleanup → USB drive inserted with **KAPE** (artifact collection), **AccessData FTK Imager** (drive imaging), and **MRC.exe** (Mini Remote Control for remote relay) → remote RDP connections from accomplices.

### G5 — Timeline [CONFIRMED]
| Key Event | UTC |
|---|---|
| Intruder unlocked laptop | 2020-11-14 03:42:49 |
| Edge browser (SRL browsing) | 2020-11-14 04:12 – 04:59 |
| PDF reading (Adobe Reader) | 2020-11-14 04:28 – 04:54 |
| Office documents opened | 2020-11-14 14:17 |
| USB drive inserted (KAPE/FTK/MRC) | 2020-11-16 02:29:33 |
| MRC.exe launched | 2020-11-16 02:31:15 |
| RAM captured by SRL IR | 2020-11-16 02:32:38 |

**Total intrusion duration: ~46 hours 50 minutes.**

Full report: `/cases/find-evil-test/reports/rocba_findings.md`

BASELINE RUN COMPLETE