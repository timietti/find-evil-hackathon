# Validator Report — iter_1

## Summary

- Total tagged claims:        **22**
  - CONFIRMED:                 19
  - INFERRED:                  2
  - HYPOTHESIS:                0
  - GAP:                       1
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           13 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                1 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           1 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           4 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 68.4%** (13 verified / 19 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **1** (cost: $0.0012)
  - ✅ VERIFIED:    0 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 0 (downgraded to failed)
  - ❓ UNRELATED:   1 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   0 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### ✅ verified _(line 31)_
- tools: `ewf_info`
- exec_ids: `d4b7e622d20a`
- matched: `4032d556cc866c23f1e797410e95603c`, `e0e72dfcef167dd358813726e82f6c235bc85ce7`, `Ovie Carroll`, `20161104-HD001`, `Fri Nov  4 17:47:41 2016`, `is_physical`
- claim: > **[CONFIRMED — exec_id `019ec807-6df2-7bb3-8df4-d4b7e622d20a`]** EWF metadata confirms examiner `Ovie Carroll`, evidence number `20161104-HD001`, acquisition date `Fri Nov  4 17:47:41 2016`, media MD5…

### ✅ verified _(line 33)_
- tools: `tsk_partition_table`
- exec_ids: `67b713439119`
- matched: `1411072`
- claim: > **[CONFIRMED — exec_id `019ec807-6faf-71a0-95c0-67b713439119`]** GPT partition table: C: drive is slot 003 starting at sector `1411072`, length 230,883,328 sectors.

### ✅ verified _(line 35)_
- tools: `tsk_fs_stat`
- exec_ids: `48daf866f7ec`
- matched: `A420A4D720A4B1AA`, `4096`, `Windows`, `NTFS`
- claim: > **[CONFIRMED — exec_id `019ec807-82df-7552-b064-48daf866f7ec`]** C: volume is `NTFS`, volume name `Windows`, serial `A420A4D720A4B1AA`, cluster size `4096` bytes.

### ✅ verified _(line 41)_
- tools: `ezt_mft_parse`
- exec_ids: `3a53f0cb5f8d`
- matched: `\Users\PC`, `live#3aanthony.vanko`, `\Users\PC User\`, `PC User`, `\Users\PC User\AppData\Roaming\Skype\live#3aanthony.vanko\`
- claim: > **[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** The Windows local account username is `PC User` (`\Users\PC User\`). The Skype cache at `\Users\PC User\AppData\Roaming\Skype\live#3aan…

### ✅ verified _(line 43)_
- tools: `ezt_srum_parse`
- exec_ids: `cd3bc5cc928f`
- matched: `PC User`, `S-1-5-21-3739107332-290452467-3466442662-1001`
- claim: > **[CONFIRMED — exec_id `019ec823-a631-7180-b917-cd3bc5cc928f`]** SRUM push-notification rows carry user_sid `S-1-5-21-3739107332-290452467-3466442662-1001` for the `PC User` account (same SID in every…

### ✅ verified _(line 45)_
- tools: `ezt_mft_parse`
- exec_ids: `3a53f0cb5f8d`
- matched: `STARKSURFACE-20160621-0643.log`, `STARKSURFACE-20160630-1025.log`, `STARKSURFACE`
- claim: > **[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** The machine name recorded in Windows Temp logs is `STARKSURFACE` (file `STARKSURFACE-20160621-0643.log`, `STARKSURFACE-20160630-1025.lo…

### ✅ verified _(line 61)_
- tools: `ezt_mft_parse`
- exec_ids: `3a53f0cb5f8d`
- matched: `2016-06-19T01:32:02Z`, `zebrafish.pdf`, `\Windows\Recent`, `\Users\PC`, `\Users\PC User\AppData\Roaming\Microsoft\Windows\Recent`, `708591`, `zebrafish.pdf:Zone.Identifier`, `zebrafish.pdf.lnk` (+4 more)
- claim: > **[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** `zebrafish.pdf` (entry `68394`, size `708591`) resides at `\Users\PC User\Documents\`. The Zone.Identifier ADS (`zebrafish.pdf:Zone.Ide…

### ✅ verified _(line 65)_
- tools: `ezt_mft_parse`
- exec_ids: `3a53f0cb5f8d`
- matched: `2016-06-29T16:20:16Z`, `2016-06-18T22:00:15Z`, `2016-06-30T14:47:38Z`, `2016-06-29T16:20:20Z`, `research.docx`, `\Users\PC`, `33351`, `2232` (+7 more)
- claim: > **[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** `Rapid cell regeneration research.docx` exists in two locations: `\Users\PC User\Documents\` (entry `31868`, size `480110`, record_chan…

### ✅ verified _(line 69)_
- tools: `ezt_mft_parse`
- exec_ids: `3a53f0cb5f8d`
- matched: `\Users\PC`, `\Users\PC User\OneDrive\Documents\`
- claim: > **[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** The following Stark Enterprises classified documents were found resident on the workstation in `\Users\PC User\OneDrive\Documents\` and…

### ❓ unverifiable _(line 88)_
- exec_ids: `3a53f0cb5f8d`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The ezt_mft_parse tool provides aggregate MFT statistics (file counts by extension, deletion status, timestomping indicators) but contains no specific file paths, classification markers, timestamps, file sizes, OneDrive identifiers, or any data that could structurally support claims about classified
- claim: > **[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** At minimum **7 classified documents** were staged locally on 2016-06-30 across Level 7, Level 8, and Level 12 classification tiers. The…

### ✅ verified _(line 96)_
- tools: `ezt_mft_parse`
- exec_ids: `3a53f0cb5f8d`
- matched: `2016-06-30T14:47:38Z`, `58961`, `56771`
- claim: > **[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** Directory entries with record_changed `2016-06-30T14:47:38Z` include the Level_8 (entry `56771`) and Level_12 (entry `58961`) subdirect…

### ✅ verified _(line 100)_
- tools: `ezt_mft_parse`
- exec_ids: `3a53f0cb5f8d`
- matched: `2016-06-30T14:25:38Z`, `STARKSURFACE-20160630-1025.log`, `395`
- claim: > **[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** The Windows Temp log `STARKSURFACE-20160630-1025.log` (entry `395`) was created `2016-06-30T14:25:38Z` — approximately 22 minutes befor…

### ⚠ partial _(line 106)_
- tools: `ezt_persistence_keys_parse`
- exec_ids: `5edfeb08a4bc`
- matched: `OneDrive.exe`, `C:\Users\PC`
- ✅ verified absences (negated): `\Users\PC User\OneDrive\`
- **missing**: `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`
- 🚨 negation violations (claimed absent but found): `\Users\PC`, `OneDrive`
- claim: > **[CONFIRMED — exec_id `019ec823-944e-7840-abd1-5edfeb08a4bc`]** OneDrive is configured to auto-start on login via HKCU Run: `OneDrive` → `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.e…

### ✅ verified _(line 108)_
- tools: `ezt_mft_parse`
- exec_ids: `3a53f0cb5f8d`
- matched: `\Users\PC`, `\Users\PC User\OneDrive\Documents\`, `\Users\PC User\OneDrive\`
- claim: > **[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** All seven classified documents are stored inside the local OneDrive folder at `\Users\PC User\OneDrive\Documents\` and its subdirectori…

### ✅ verified _(line 110)_
- tools: `ezt_mft_parse`
- exec_ids: `3a53f0cb5f8d`
- matched: `2016-06-30T14:52:37Z`, `2016-06-30T16:44:06Z`, `2016-06-30T15:08:01Z`, `2016-06-30T15:27:03Z`, `Update_2016-06-30_124406_c90-1344.log`, `Update_2016-06-30_110801_1b74-1b78.log`, `Update_2016-06-30_105237_1a24-53c.log`, `Update_2016-06-30_112703_19bc-19c0.log` (+4 more)
- claim: > **[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** Multiple OneDrive setup update logs from 2016-06-30 confirm the service was active on that date: - `Update_2016-06-30_105237_1a24-53c.l…

### 🔍 not_confirmed _(line 128)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | Goal | Finding | Confidence | |---|---|---| | G1 — Classified files on workstation | `zebrafish.pdf`, `Rapid cell regeneration research.docx`, Level 7/8/12 Stark documents all present on disk | [CON…

### 🔍 not_confirmed _(line 129)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | G2 — Bulk transfer on 2016-06-30 | 7 docs (~21.6 MB total) with `record_changed` `2016-06-30T14:47:38Z`; Level 8 CryoDNA file alone is ~19 MB | [CONFIRMED]

### 🔍 not_confirmed _(line 130)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | G3 — Exfil via OneDrive | Files staged in OneDrive sync folder; OneDrive auto-start configured; client active on 2016-06-30 | [CONFIRMED]

### 🔍 not_confirmed _(line 131)_
- note: claim is tagged CONFIRMED but cites no exec_id
- claim: > | | G4 — Attribution to Vanko | Windows account `PC User` owns Skype profile `live#3aanthony.vanko`; user SID `S-1-5-21-3739107332-290452467-3466442662-1001`; machine is `STARKSURFACE` (Stark-issued) …
