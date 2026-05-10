# Validator Report — 20260509T205030Z-sonnet

## Summary

- Total tagged claims:        **54**
  - CONFIRMED:                 46
  - INFERRED:                  4
  - HYPOTHESIS:                1
  - GAP:                       3
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           19 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                5 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           11 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           9 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 41.3%** (19 verified / 46 confirmed)

## Per-claim verdicts

### ❓ unverifiable _(line 56)_
- exec_ids: `09e686bb9d69`, `fcc917074804`, `2fce4c81a81b`, `7ec1c34cd439`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e0e82-ed76-7dc3-a3d1-09e686bb9d69, 019e0e82-ef87-7090-8704-fcc917074804, 019e0e82-f0f3-7a82-808e-2fce4c81a81b, 019e0e82-f276-7be0-ad78-7ec1c34cd439]

### ✅ verified _(line 64)_
- tools: `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `876a7d3267e3`, `c93158e72aa4`
- matched: `48869`, `adberdr813.exe`, `8e0fd39907d9086201affa2da9f29a95f347981254ee9a348071f20fd8c31e33`, `Zone.Identifier`, `nromanoff`, `Users/nromanoff/Downloads/adberdr813.exe`
- claim: > The file `Users/nromanoff/Downloads/adberdr813.exe` (inode 48869, 21,806,256 bytes, SHA256: `8e0fd39907d9086201affa2da9f29a95f347981254ee9a348071f20fd8c31e33`) is present in the nromanoff account's Do…

### ⚠ partial _(line 66)_
- tools: `tsk_fls_list`
- exec_ids: `876a7d3267e3`
- matched: `adberdr813.exe`
- **missing**: ` confirms `
- claim: > The Windows Error Reporting archive `ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e/Report.wer` confirms `adberdr813.exe` crash…

### ✅ verified _(line 76)_
- tools: `tsk_fls_list`
- exec_ids: `d465e8fe69ce`
- matched: `27184`, `27686`, `usboesrv.exe`, `Temp1_usb-over-ethernet.zip`, `usb-over-ethernet.zip`, `setup.exe`, `Users/rsydow/AppData/Local/Temp/2/Temp1_usb-over-ethernet.zip/`, `file_id.diz` (+4 more)
- claim: > On the DC, user `rsydow` extracted the trojanized `usb-over-ethernet.zip` from `SharedFolders/Public/Security Tools/usb-over-ethernet.zip` (inode 27686) into `Users/rsydow/AppData/Local/Temp/2/Temp1_u…

### ✅ verified _(line 87)_
- tools: `tsk_fls_list`
- exec_ids: `d465e8fe69ce`
- matched: `Users/rsydow/AppData/Local/Microsoft/Terminal Server Client/Cache/bcache22.bmc`
- claim: > **Evidence of RDP-based lateral movement:** - `Users/rsydow/AppData/Local/Microsoft/Terminal Server Client/Cache/bcache22.bmc` on DC confirms RDP client usage from rsydow's DC session [CONFIRMED — exe…

### ❓ unverifiable _(line 88)_
- exec_ids: `876a7d3267e3`, `9c09b215f1b6`
- note: claim has no extractable tokens (prose only)
- claim: > - vibranium user profiles on nromanoff disk (Win 7) and tdungan disk (Win XP) both show full user activity, not just traversal — confirming interactive RDP sessions [CONFIRMED — exec_id 019e0e83-7c1f-…

### ✅ verified _(line 89)_
- tools: `tsk_fls_list`
- exec_ids: `876a7d3267e3`
- matched: `TSTHEME.EXE`, `-2786BF6D.pf`, `TSTHEME.EXE-2786BF6D.pf`
- claim: > - Prefetch `TSTHEME.EXE-2786BF6D.pf` on nromanoff (Terminal Services theme) further supports RDP connectivity [CONFIRMED — exec_id 019e0e83-7c1f-7de0-ace5-876a7d3267e3]

### ✅ verified _(line 90)_
- tools: `tsk_fls_list`
- exec_ids: `876a7d3267e3`
- matched: `-BC6DAF49.pf`, `SC.EXE`, `SC.EXE-BC6DAF49.pf`
- claim: > - `SC.EXE-BC6DAF49.pf` on nromanoff: service control tool executed (installing spinlock/usboesrv as service) [CONFIRMED — exec_id 019e0e83-7c1f-7de0-ace5-876a7d3267e3]

### ✅ verified _(line 91)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `876a7d3267e3`, `9c09b215f1b6`
- matched: `WMIC.EXE`
- claim: > - `WMIC.EXE` Prefetch present on both nromanoff and tdungan (WMI-based lateral movement/remote execution) [CONFIRMED — exec_id 019e0e83-7c1f-7de0-ace5-876a7d3267e3, 019e0e83-b70f-7b30-822e-9c09b215f1b…

### ✅ verified _(line 92)_
- tools: `tsk_fls_list`
- exec_ids: `9c09b215f1b6`
- matched: `NET.EXE`, `NET1.EXE`
- claim: > - `NET.EXE` and `NET1.EXE` Prefetch on tdungan (network enumeration) [CONFIRMED — exec_id 019e0e83-b70f-7b30-822e-9c09b215f1b6]

### ⚠ partial _(line 95)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`
- exec_ids: `1d44c457af04`, `c773d8cfda42`
- matched: `7793`, `60927`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`
- **missing**: `spinlock.exe`, `WINDOWS/system32/spinlock.exe`, `Windows/System32/spinlock.exe`
- claim: > **Cross-host tool deployment (identical binaries):** - `spinlock.exe` on nromanoff `Windows/System32/spinlock.exe` (inode 60927) and tdungan `WINDOWS/system32/spinlock.exe` (inode 7793): **SHA256 iden…

### ⚠ partial _(line 96)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`
- exec_ids: `5481817d2e18`, `91769ea23f89`
- matched: `7736`, `420`, `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`
- **missing**: `a.exe`
- claim: > - `a.exe` on nromanoff (inode 420) and tdungan (inode 7736, 5366/RSydow, 7372/SRL-Helpdesk, 3108/tdungan): **SHA256 identical** (`598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`), 9,…

### ❓ unverifiable _(line 98)_
- exec_ids: `d465e8fe69ce`
- note: claim has no extractable tokens (prose only)
- claim: > **nfury status:** No malicious files found in disk listing; confirmed clean on disk. Memory-only run previously showed no active C2. [CONFIRMED — exec_id 019e0e83-1ff0-73b0-8b85-d465e8fe69ce (nfury wa…

### ❓ unverifiable _(line 113)_
- exec_ids: `d465e8fe69ce`, `0dbd88c3b813`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e0e83-1ff0-73b0-8b85-d465e8fe69ce, 019e0e88-343d-72a1-a05d-0dbd88c3b813]

### ✅ verified _(line 115)_
- tools: `tsk_fls_list`
- exec_ids: `d465e8fe69ce`
- matched: `spinlock.exe`
- claim: > No Prefetch on DC (Server 2008 R2 has Prefetch disabled by default). WER report confirms `spinlock.exe` ran and crashed (or was intentionally killed) before being sdeleted. Prefetch absence means spin…

### ❓ unverifiable _(line 125)_
- exec_ids: `876a7d3267e3`, `1d44c457af04`, `5481817d2e18`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e0e83-7c1f-7de0-ace5-876a7d3267e3, 019e0e85-4a40-7e03-bffa-1d44c457af04, 019e0e88-2fd6-7c70-914a-5481817d2e18]

### ✅ verified _(line 128)_
- tools: `tsk_fls_list`
- exec_ids: `876a7d3267e3`
- matched: `-1610A75A.pf`, `SPINLOCK.EXE`, `SPINLOCK.EXE-1610A75A.pf`
- claim: > Prefetch evidence of additional tools on nromanoff: - `SPINLOCK.EXE-1610A75A.pf` — execution confirmed [CONFIRMED — exec_id 019e0e83-7c1f-7de0-ace5-876a7d3267e3]

### ✅ verified _(line 129)_
- tools: `tsk_fls_list`
- exec_ids: `876a7d3267e3`
- matched: `-F91CBA0E.pf`, `a.exe`, `-8D56B1C4.pf`, `A.EXE`, `A.EXE-8D56B1C4.pf`, `A.EXE-F91CBA0E.pf`
- claim: > - `A.EXE-8D56B1C4.pf`, `A.EXE-F91CBA0E.pf` — a.exe executed at least twice [CONFIRMED — exec_id 019e0e83-7c1f-7de0-ace5-876a7d3267e3]

### ✅ verified _(line 132)_
- tools: `tsk_fls_list`
- exec_ids: `876a7d3267e3`
- matched: `-BC6DAF49.pf`, `SC.EXE`, `SC.EXE-BC6DAF49.pf`
- claim: > - `SC.EXE-BC6DAF49.pf` — service control (service installation) [CONFIRMED — exec_id 019e0e83-7c1f-7de0-ace5-876a7d3267e3]

### ✅ verified _(line 136)_
- tools: `tsk_fls_list`
- exec_ids: `876a7d3267e3`
- matched: `spinlock.exe`, `_MEI25602`, `_MEI39242`, `_MEI111242`, `Users/vibranium/AppData/Local/Temp/`, `_MEI138842`, `_MEI57722`, `_MEI29562`
- claim: > spinlock.exe PyInstaller extraction directories (`_MEI111242`, `_MEI138842`, `_MEI25602`, `_MEI29562`, `_MEI39242`, `_MEI57722`) under `Users/vibranium/AppData/Local/Temp/` — **6 separate PyInstaller …

### ✅ verified _(line 138)_
- tools: `tsk_fls_list`
- exec_ids: `876a7d3267e3`
- ✅ verified absences (negated): `usboesrv.exe`
- claim: > usboesrv.exe: **Not found on nromanoff** — the C2 implant was NOT deployed to nromanoff workstation. [CONFIRMED — exec_id 019e0e83-7c1f-7de0-ace5-876a7d3267e3]

### ❓ unverifiable _(line 151)_
- exec_ids: `9c09b215f1b6`, `7d9f4c93f901`, `f9adaf9adcbc`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e0e83-b70f-7b30-822e-9c09b215f1b6, 019e0e89-23d3-7353-a44d-7d9f4c93f901, 019e0e89-284c-7250-95e8-f9adaf9adcbc]

### 🔍 not_confirmed _(line 154)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > Prefetch evidence on tdungan: - `SPINLOCK.EXE-1F9810CF.pf` — execution confirmed [CONFIRMED]

### 🔍 not_confirmed _(line 155)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > - `HYDRAKATZ.EXE-27B49502.pf` — execution confirmed [CONFIRMED]

### 🔍 not_confirmed _(line 156)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > - `HYVY.EXE-2A94EF14.pf` — execution confirmed [CONFIRMED]

### 🔍 not_confirmed _(line 157)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > - `A.EXE-0F3A0E12.pf`, `A.EXE-0FBE37C1.pf`, `A.EXE-239305EA.pf`, `A.EXE-2E0C27A0.pf` — a.exe executed at least 4 separate times [CONFIRMED]

### 🔍 not_confirmed _(line 158)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > - `AT.EXE-2770DD18.pf` — Windows task scheduler (persistence via scheduled tasks) [CONFIRMED]

### 🔍 not_confirmed _(line 159)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > - `ZIPPER.EXE-2C9C69B1.pf` — file archiving tool executed (staging) [CONFIRMED]

### 🔍 not_confirmed _(line 160)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > - `FTP.EXE-0FFFB5A3.pf` — native Windows FTP client executed (exfiltration) [CONFIRMED]

### 🔍 not_confirmed _(line 161)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > - `DROPBOX.EXE-126FAE33.pf` — Dropbox client executed (possible secondary exfiltration channel) [CONFIRMED]

### 🔍 not_confirmed _(line 162)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > - `TASKLIST.EXE-10D94B23.pf` — enumeration of running processes [CONFIRMED]

### ✅ verified _(line 167)_
- tools: `tsk_fls_list`
- exec_ids: `9c09b215f1b6`
- matched: `RemotePIShell.exe`, `tdungan/Local Settings/Temp/_MEI72762/RemotePIShell.exe.manifest`, `tdungan`
- claim: > PyInstaller evidence on tdungan: - `tdungan/Local Settings/Temp/_MEI72762/RemotePIShell.exe.manifest` — `RemotePIShell.exe` (Python 2.5 PyInstaller RAT/interactive shell) was executed under `tdungan` …

### ✅ verified _(line 168)_
- tools: `tsk_fls_list`
- exec_ids: `9c09b215f1b6`
- matched: `spinlock.exe`, `vibranium/Local Settings/Temp/_MEI122362/spinlock.exe.manifest`
- claim: > - `vibranium/Local Settings/Temp/_MEI122362/spinlock.exe.manifest` — spinlock.exe also ran under vibranium account on tdungan [CONFIRMED — exec_id 019e0e83-b70f-7b30-822e-9c09b215f1b6]

### ❓ unverifiable _(line 187)_
- exec_ids: `9c09b215f1b6`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e0e83-b70f-7b30-822e-9c09b215f1b6]

### ❓ unverifiable _(line 197)_
- exec_ids: `9c09b215f1b6`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e0e83-b70f-7b30-822e-9c09b215f1b6]

### ⚠ partial _(line 201)_
- tools: `tsk_icat_extract`
- exec_ids: `fcabc8101490`
- matched: `13043`, `c6c69b86194ff0cae04d68f0ddc9c93f31f31379c8f955504d8b87b81742c407`
- **missing**: `EXFIL.pst`, ` (inode 13043, 16,778,240 bytes = 16 MB, SHA256: `
- claim: > `Documents and Settings/vibranium/Local Settings/Application Data/Microsoft/Outlook/EXFIL.pst` (inode 13043, 16,778,240 bytes = 16 MB, SHA256: `c6c69b86194ff0cae04d68f0ddc9c93f31f31379c8f955504d8b87b8…

### ❓ unverifiable _(line 211)_
- exec_ids: `9c09b215f1b6`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e0e83-b70f-7b30-822e-9c09b215f1b6]

### ⚠ partial _(line 214)_
- tools: `tsk_fls_list`
- exec_ids: `9c09b215f1b6`
- matched: `-0FFFB5A3.pf`, `FTP.EXE`, `FTP.EXE-0FFFB5A3.pf`
- **missing**: `96.255.98.154`
- claim: > **Exfiltration channels:** - `FTP.EXE-0FFFB5A3.pf` on tdungan: Windows native FTP client executed — documents/archives transferred via FTP to C2 `96.255.98.154` (C2 IP confirmed from prior memory run)…

### ✅ verified _(line 215)_
- tools: `tsk_fls_list`
- exec_ids: `9c09b215f1b6`
- matched: `-2C9C69B1.pf`, `ZIPPER.EXE`, `ZIPPER.EXE-2C9C69B1.pf`
- claim: > - `ZIPPER.EXE-2C9C69B1.pf` on tdungan: files zipped before transfer; ZIPPER.EXE binary sdeleted after use [CONFIRMED — exec_id 019e0e83-b70f-7b30-822e-9c09b215f1b6]

### ✅ verified _(line 216)_
- tools: `tsk_fls_list`
- exec_ids: `9c09b215f1b6`
- matched: `-126FAE33.pf`, `DROPBOX.EXE`, `DROPBOX.EXE-126FAE33.pf`
- claim: > - `DROPBOX.EXE-126FAE33.pf` on tdungan: Dropbox cloud upload as potential secondary exfiltration channel [CONFIRMED execution — exec_id 019e0e83-b70f-7b30-822e-9c09b215f1b6]

### ❌ failed _(line 220)_
- tools: `tsk_fls_list`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `d465e8fe69ce`, `876a7d3267e3`, `9c09b215f1b6`
- **missing**: `deleted_count: 0`
- 🚨 negation violations (claimed absent but found): `ZIPPER.EXE`
- claim: > The `deleted_count: 0` in all three tsk_fls_list results confirms that MFT entries for deleted files have been wiped (sdelete zeroes MFT records). No deleted file names are recoverable via FLS. The ZI…

### ✅ verified _(line 254)_
- tools: `tsk_fls_list`
- exec_ids: `9c09b215f1b6`
- matched: `4736`, `hydrakatz.exe`, `HYDRAKATZ.EXE`, `-27B49502.pf`, `HYDRAKATZ.EXE-27B49502.pf`, `WINDOWS/system32/hydrakatz.exe`
- claim: > `hydrakatz.exe` (Mimikatz variant) confirmed present at `WINDOWS/system32/hydrakatz.exe` (inode 4736) with execution confirmed via Prefetch `HYDRAKATZ.EXE-27B49502.pf`. This tool extracts LSASS-cached…

### ✅ verified _(line 267)_
- tools: `tsk_fls_list`
- exec_ids: `d465e8fe69ce`
- matched: `2438F9B04D7CF823C0B0BAB39930CD27`
- claim: > **Stored credential artifacts (DC — rsydow):** - `Users/rsydow/AppData/Local/Microsoft/Credentials/2438F9B04D7CF823C0B0BAB39930CD27` — DPAPI-protected stored credential [CONFIRMED — exec_id 019e0e83-1…

### ❓ unverifiable _(line 268)_
- exec_ids: `d465e8fe69ce`
- note: claim has no extractable tokens (prose only)
- claim: > - `Users/rsydow/AppData/Local/Microsoft/Vault/4BF4C442-9B8A-41A0-B380-DD4A704DDB28/Policy.vpol` — Windows Credential Manager vault [CONFIRMED — exec_id 019e0e83-1ff0-73b0-8b85-d465e8fe69ce]

### ❓ unverifiable _(line 271)_
- exec_ids: `9c09b215f1b6`
- note: claim has no extractable tokens (prose only)
- claim: > **vibranium DPAPI master keys on tdungan:** - `Documents and Settings/vibranium/Application Data/Microsoft/Protect/S-1-5-21-2036804247-3058324640-2116585241-1673/` — DPAPI master keys for SID -1673 (v…

### ❌ failed _(line 289)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`, `tsk_icat_extract`, `tsk_icat_extract`, `tsk_icat_extract`, `tsk_icat_extract`, `tsk_icat_extract`, `tsk_icat_extract`, `tsk_icat_extract`
- exec_ids: `1d44c457af04`, `c773d8cfda42`, `c93158e72aa4`, `fcabc8101490` (+5 more)
- **missing**: `tsk_icat_extract`
- claim: > All extracts confirmed via `tsk_icat_extract`. [CONFIRMED — exec_id 019e0e85-4a40-7e03-bffa-1d44c457af04, 019e0e85-4cee-7953-92a5-c773d8cfda42, 019e0e87-c15a-7102-a4ee-c93158e72aa4, 019e0e87-35ee-71c1…
