# Validator Report — iter_1

## Summary

- Total tagged claims:        **31**
  - CONFIRMED:                 22
  - INFERRED:                  5
  - HYPOTHESIS:                0
  - GAP:                       4
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           8 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                12 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           0 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 36.4%** (8 verified / 22 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **2** (cost: $0.0021)
  - ✅ VERIFIED:    0 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 2 (downgraded to failed)
  - ❓ UNRELATED:   0 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   0 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### ⚠ partial _(line 58)_
- tools: `ewf_info`
- exec_ids: `4c95c580e3cd`
- matched: `2.9.0.13`
- **missing**: `2016-11-04T17:47:41Z`
- claim: > **[CONFIRMED — exec_id `019ebaf9-01b0-7552-9311-4c95c580e3cd`]** EWF metadata confirms acquisition by Ovie Carroll on `2016-11-04T17:47:41Z` using FTK Imager (ADI 2.9.0.13), case number 20161104, evid…

### ⚠ partial _(line 60)_
- tools: `tsk_partition_table`
- exec_ids: `cfeafe68f55f`
- matched: `1411072`
- **missing**: `offset=1411072`
- claim: > **[CONFIRMED — exec_id `019ebaf9-026a-7542-b2a6-cfeafe68f55f`]** GPT partition table parsed. Slot 003 (Basic data partition) starts at sector `1411072`, length 230,883,328 sectors — the Windows C: vol…

### ✅ verified _(line 62)_
- tools: `tsk_fs_stat`
- exec_ids: `eaa8b74fe21f`
- matched: `A420A4D720A4B1AA`, `Windows`
- claim: > **[CONFIRMED — exec_id `019ebaf9-1802-7af1-8976-eaa8b74fe21f`]** NTFS volume confirmed on partition slot 003. Volume name `Windows`, serial `A420A4D720A4B1AA`, cluster size 4096 bytes.

### ⚠ partial _(line 68)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `263009`, `114124`, `SRUDB.dat`, `STARKSURFACE`, `S-1-5-21-3739107332-290452467-3466442662-1001`
- **missing**: `\Windows\Temp\STARKSURFACE-*.log`, `.\\Users\\PC User`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** MFT entry 263009 is directory `.\\Users\\PC User` (the sole interactive profile on the device). Computer hostname is `STARKSURFACE` (fr…

### ⚠ partial _(line 70)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `263010`, `2016-06-18T22:00:15Z`, `2016-10-30T23:19:25Z`, `NTUSER.DAT`, `PC User`
- **missing**: `record_changed 2016-06-18T22:00:15Z`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** NTUSER.DAT for `PC User` is MFT entry 263010, file size 4,194,304 bytes, `record_changed 2016-06-18T22:00:15Z`, last modified `2016-10-…

### ❌ failed _(line 96)_
- exec_ids: `458c571e8c0b`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNSUPPORTED** — The parsed MFT data contains only aggregate statistics (file counts by extension, total deleted/in-use files) with no specific file names, inode numbers, parent paths, timestamps, or classification metadata needed to verify the claim about thirteen specific Stark Enterprises documents.
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** All thirteen classified Stark Enterprises documents (spanning Level 7, Level 8, Level 12 classification tiers; topics: cell regeneratio…

### ⚠ partial _(line 98)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `2232`, `2016-06-29T16:20:16Z`, `research.docx`, `\Windows\Recent`, `\Users\PC`, `Rapid cell regeneration research.docx.lnk`, `\Users\PC User\AppData\Roaming\Microsoft\Windows\Recent\`
- **missing**: `modified=2016-06-29T16:20:16Z`, `record_changed=2016-06-29T16:20:16Z`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** Recent item LNK `Rapid cell regeneration research.docx.lnk` (inode 2232) in `\Users\PC User\AppData\Roaming\Microsoft\Windows\Recent\` …

### ✅ verified _(line 100)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `68394`, `2016-06-19T01:32:02Z`, `zebrafish.pdf`, `zebrafish.pdf:Zone.Identifier`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** `zebrafish.pdf` at inode 68394 carries an NTFS Zone.Identifier ADS (`zebrafish.pdf:Zone.Identifier`, 106 bytes), indicating it was down…

### ⚠ partial _(line 110)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `2016-06-30T14:47:38Z`, `\Users\PC`, `\Users\PC User\OneDrive\Documents\`
- **missing**: `record_changed=2016-06-30T14:47:38Z`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** Every classified document in `\Users\PC User\OneDrive\Documents\` carries `record_changed=2016-06-30T14:47:38Z`. This is a single atomi…

### ✅ verified _(line 112)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `10575`, `2016-06-30T14:46:54Z`, `ONEDRIVE.EXE`, `-CA84A5C1.pf`, `ONEDRIVE.EXE-CA84A5C1.pf`, `14:47:38Z`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** `ONEDRIVE.EXE-CA84A5C1.pf` (Prefetch, inode 10575) was **created** `2016-06-30T14:46:54Z` — 44 seconds before the bulk file record upda…

### ⚠ partial _(line 114)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `8936940e6e65`
- matched: `OneDrive.exe`, `\Users\PC`, `C:\Users\PC`, `OneDrive`
- **missing**: `NTUSER.DAT`, `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`
- claim: > **[CONFIRMED — exec_id `019ebaff-f908-7cc3-b810-8936940e6e65`]** NTUSER.DAT Run key (HKCU Run) has value `OneDrive` → `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`, co…

### ⚠ partial _(line 118)_
- tools: `ezt_srum_parse`
- exec_ids: `4d07dbeacf5c`
- matched: `network_usage`, `2016-09-29`
- **missing**: `114124`, `2016-11-04T17:47:02Z`, `SRUDB.dat`
- claim: > **[CONFIRMED — exec_id `019ebb02-8e6e-7de2-96db-4d07dbeacf5c`]** SRUDB.dat (inode 114124, 23 MB, last modified `2016-11-04T17:47:02Z`) was successfully parsed. The `network_usage` provider contains 27…

### ✅ verified _(line 134)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `10575`, `2016-06-30T14:46:54Z`, `NTUSER.DAT`, `OneDrive.exe`, `\Users\PC`, `\Users\PC User\OneDrive\Documents\`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** All 10 classified Stark documents in `\Users\PC User\OneDrive\Documents\` were placed in the OneDrive auto-sync folder. OneDrive.exe wa…

### ⚠ partial _(line 136)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `8936940e6e65`
- matched: `OneDrive.exe`, `\Users\PC`, `C:\Users\PC`, `"OneDrive"`
- **missing**: `263010`, `NTUSER.DAT`, `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`
- claim: > **[CONFIRMED — exec_id `019ebaff-f908-7cc3-b810-8936940e6e65`]** HKCU Run key: `"OneDrive"` value `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background` (inode 263010 / exec_id…

### ✅ verified _(line 142)_
- tools: `ezt_prefetch_parse`
- exec_ids: `1ff41e383eeb`
- matched: `2016-06-29T20:32:27Z`, `2016-06-30T01:12:53Z`, `2016-06-29T16:12:13Z`, `2016-06-30T01:40:51Z`, `2016-06-29T20:25:57Z`, `2016-06-30T01:56:46Z`, `VeraCrypt.exe`, `9E1B0240`
- claim: > **[CONFIRMED — exec_id `019ebb05-f629-78d2-aff8-1ff41e383eeb`]** VeraCrypt.exe (prefetch hash `9E1B0240`) ran exactly **6 times** on June 29–30, 2016: - `2016-06-29T16:12:13Z` (first run — 8 minutes a…

### ⚠ partial _(line 150)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `7775`, `32010`, `2016-06-29T16:03:13Z`, `2016-06-29T15:51:16Z`, `2016-06-29T16:12:33Z`, `2016-06-30T01:14:52Z`, `-6EA86AF5.pf`, `1.17.exe` (+3 more)
- **missing**: `created 2016-06-29T15:51:16Z`, `executed=Yes`, `\Users\PC User\Downloads\VeraCrypt Setup 1.17.exe`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** VeraCrypt Setup 1.17 was downloaded to `\Users\PC User\Downloads\VeraCrypt Setup 1.17.exe` (inode 32010, Zone.Identifier ADS present, `…

### ⚠ partial _(line 152)_
- tools: `ezt_shimcache_parse`
- exec_ids: `7a02c46d08e8`
- matched: `VeraCrypt.exe`, `1.17.exe`, `Format.exe`, `VeraCrypt Setup 1.17.exe`, `VeraCrypt Format.exe`
- **missing**: `executed=Yes`
- claim: > **[CONFIRMED — exec_id `019ebb07-bc98-7522-8fdd-7a02c46d08e8`]** Shimcache confirms `VeraCrypt.exe` `executed=Yes`, `VeraCrypt Format.exe` `executed=Yes`, `VeraCrypt Setup 1.17.exe` `executed=Yes`.

### ⚠ partial _(line 160)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `8936940e6e65`
- matched: `iCloudDrive.exe`, `iCloudServices.exe`, `ApplePhotoStreams.exe`, `iCloudPhotos.exe`, `C:\Program`, `iCloudPhotos`, `ApplePhotoStreams`, `C:\Program Files (x86)\Common Files\Apple\Internet Services\iCloudServices.exe` (+2 more)
- **missing**: `NTUSER.DAT`, `...iCloudPhotos.exe`, `...ApplePhotoStreams.exe`, `...iCloudDrive.exe`
- claim: > **[CONFIRMED — exec_id `019ebaff-f908-7cc3-b810-8936940e6e65`]** NTUSER.DAT HKCU Run keys include: - `iCloudServices` → `C:\Program Files (x86)\Common Files\Apple\Internet Services\iCloudServices.exe`…

### ✅ verified _(line 168)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `3100`, `2016-11-04T13:24:41Z`, `2016-11-04T17:41:23Z`, `-E72FEFE1.pf`, `DROPBOXUPDATE.EXE`, `DROPBOXUPDATE.EXE-E72FEFE1.pf`, `\Program Files (x86)\Dropbox\Client_12.4.22\`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** Dropbox Client 12.4.22 is installed (`\Program Files (x86)\Dropbox\Client_12.4.22\`, MFT confirmed). Dropbox update log exists through …

### ❌ failed _(line 174)_
- exec_ids: `7a02c46d08e8`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNSUPPORTED** — The parsed shimcache data shows only aggregated counts by extension, parent directory, and control set, with no individual entries, volume identifiers, or removable media designations that would support the claim of 'at least three distinct removable media volumes.'
- claim: > **[CONFIRMED — exec_id `019ebb07-bc98-7522-8fdd-7a02c46d08e8`]** Shimcache contains entries from at least three distinct removable media volumes:

### ✅ verified _(line 186)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `388`, `6422`, `3874`, `7683`, `2016-07-01T23:26:46Z`, `2016-07-01T23:29:41Z`, `2016-06-11T20:27:22Z`, `2016-07-01T23:24:22Z` (+5 more)
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** FTK Imager prefetch (inode 7683, `FTK IMAGER.EXE-9B6683F0.pf`) was **created** `2016-06-11T20:27:22Z` — before the JARVIS alert — and a…

### ✅ verified _(line 192)_
- tools: `ezt_mft_parse`
- exec_ids: `458c571e8c0b`
- matched: `4397`, `2016-06-30T01:56:46Z`, `VeraCrypt.exe`, `Format.exe`
- claim: > **[CONFIRMED — exec_id `019ebafa-b072-74b2-9132-458c571e8c0b`]** VeraCrypt installed and Format.exe run on 2016-06-29 (day before JARVIS alert). VeraCrypt.exe ran 6 times, last at `2016-06-30T01:56:46…
