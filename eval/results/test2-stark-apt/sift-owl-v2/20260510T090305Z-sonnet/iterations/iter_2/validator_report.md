# Validator Report — iter_2

## Summary

- Total tagged claims:        **41**
  - CONFIRMED:                 35
  - INFERRED:                  3
  - HYPOTHESIS:                0
  - GAP:                       3
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           13 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                6 (some tokens found, some missing)
- ❌ failed:                 3 (no tokens found)
- ❓ unverifiable:           13 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 37.1%** (13 verified / 35 confirmed)

## Per-claim verdicts

### ❓ unverifiable _(line 37)_
- exec_ids: `315b2cefc7ab`
- note: claim has no extractable tokens (prose only)
- claim: > Two copies confirmed in DC MFT [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab]:

### ✅ verified _(line 48)_
- tools: `ezt_mft_parse`, `ezt_mft_parse`
- exec_ids: `69158614d792`, `225a1ef51bba`
- ✅ verified absences (negated): `usboesrv.exe`, `usboesrv`
- claim: > **No `usboesrv.exe` was found in nromanoff or tdungan MFT** [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba — both returned 0 rows for file_name…

### ✅ verified _(line 50)_
- tools: `ezt_shimcache_parse`
- exec_ids: `7d52002b8c38`
- ✅ verified absences (negated): `usboesrv.exe`
- claim: > The `usboesrv.exe` binary is absent from the DC ShimCache (0 matches across 962 entries) [CONFIRMED — exec_id 019e1123-20c8-79e3-a814-7d52002b8c38]. This is consistent with Windows Server 2008 R2 beha…

### ⚠ partial _(line 54)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- matched: `2012-04-04T18:28:42Z`, `NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004`
- **missing**: `file_size=0`, `.\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue`, `is_directory=true`
- claim: > The DC MFT contains exactly one spinlock-related entry: the WER crash directory `NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004` under `.\\ProgramData\\Microsoft\\Window…

### ❓ unverifiable _(line 60)_
- exec_ids: `69158614d792`, `fad7c6993479`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id 019e1123-26a3-7c51-be46-fad7c6993479]:

### ❓ unverifiable _(line 78)_
- exec_ids: `225a1ef51bba`, `37769fe4cd76`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba, exec_id 019e1123-2b73-75a0-ad0a-37769fe4cd76]:

### ❓ unverifiable _(line 98)_
- exec_ids: `fad7c6993479`, `69158614d792`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479, exec_id 019e1123-52f9-7f71-9651-69158614d792]:

### ⚠ partial _(line 104)_
- tools: `ezt_shimcache_parse`
- exec_ids: `7d52002b8c38`
- ✅ verified absences (negated): `TEMP\a.exe`, `C:\Windows\TEMP\a.exe`
- **missing**: `\Windows\TEMP\a.exe``, `C:\Windows\TEMP\a.exe``
- 🚨 negation violations (claimed absent but found): `a.exe`
- claim: > **DC ShimCache contains no `C:\Windows\TEMP\a.exe` entry** [CONFIRMED — exec_id 019e1123-20c8-79e3-a814-7d52002b8c38 — query for path filter `TEMP\a.exe` returned 0 rows].

### ❓ unverifiable _(line 110)_
- exec_ids: `fad7c6993479`, `69158614d792`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479, exec_id 019e1123-52f9-7f71-9651-69158614d792]:

### ❓ unverifiable _(line 124)_
- exec_ids: `fad7c6993479`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]:

### ❓ unverifiable _(line 134)_
- exec_ids: `69158614d792`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792]:

### ✅ verified _(line 147)_
- tools: `ezt_mft_parse`
- exec_ids: `69158614d792`
- matched: `48229`, `2011-08-28T22:35:45Z`, `AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e`
- claim: > WER crash archive `AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e` (MFT entry 48229) created 2011-08-28T22:35:45Z, confirming execution and crash on the same day as the downlo…

### ✅ verified _(line 149)_
- tools: `ezt_shimcache_parse`
- exec_ids: `fad7c6993479`
- matched: `2011-08-28T22:35:24Z`, `adberdr813.exe`
- claim: > ShimCache entry for `adberdr813.exe` shows LastModified 2011-08-28T22:35:24Z, Executed: No [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]. The "No" flag is consistent with the binary crash…

### ❓ unverifiable _(line 153)_
- exec_ids: `225a1ef51bba`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]:

### ❓ unverifiable _(line 169)_
- exec_ids: `225a1ef51bba`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]:

### ⚠ partial _(line 185)_
- tools: `ezt_mft_parse`
- exec_ids: `69158614d792`
- ✅ verified absences (negated): `EXFIL.pst`
- 🚨 negation violations (claimed absent but found): `0`
- claim: > **EXFIL.pst is on tdungan under vibranium's Outlook profile.** EXFIL.pst does not appear in nromanoff MFT (0 matches) [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792]; it does not appear in …

### ⚠ partial _(line 185)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- ✅ verified absences (negated): `EXFIL.pst`
- 🚨 negation violations (claimed absent but found): `0`
- claim: > **EXFIL.pst is on tdungan under vibranium's Outlook profile.** EXFIL.pst does not appear in nromanoff MFT (0 matches) [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792]; it does not appear in …

### ❓ unverifiable _(line 201)_
- exec_ids: `69158614d792`, `225a1ef51bba`, `315b2cefc7ab`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba, exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab]:

### ❓ unverifiable _(line 207)_
- exec_ids: `fad7c6993479`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]:

### ❌ failed _(line 221)_
- tools: `ezt_evtx_parse`, `ezt_evtx_parse`
- exec_ids: `4c35ed87f968`, `31d9c7732c3c`
- **missing**: `.Evt`, `.evtx`, `SecEvent.Evt`, `SysEvent.Evt`
- claim: > [CONFIRMED — exec_id 019e1124-5e07-71c1-8f43-4c35ed87f968, exec_id 019e1124-60e3-78c2-83e9-31d9c7732c3c]: Both `SecEvent.Evt` and `SysEvent.Evt` on tdungan returned 0 parsed events. EvtxECmd requires …

### ⚠ partial _(line 229)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- matched: `2012-03-20T17:57:59Z`, `2012-03-20T17:57:58Z`, `usboesrv.exe`, `Windows\System32\`
- **missing**: `96.255.98.154`, `Program Files\USB over Ethernet\`
- claim: > The DC MFT confirms usboesrv.exe was deployed to `Windows\System32\` at 2012-03-20T17:57:59Z and to `Program Files\USB over Ethernet\` at 2012-03-20T17:57:58Z [CONFIRMED — exec_id 019e1123-2e48-7b90-b…

### ❓ unverifiable _(line 235)_
- exec_ids: `225a1ef51bba`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]:

### ✅ verified _(line 244)_
- tools: `ezt_mft_parse`
- exec_ids: `69158614d792`
- ✅ verified absences (negated): `hotcorewin2k.sys`
- claim: > **hotcorewin2k.sys is not present in nromanoff MFT** (0 matches) [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792]. **hotcorewin2k.sys is not present in DC MFT** (0 matches) [CONFIRMED — exec…

### ✅ verified _(line 244)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- ✅ verified absences (negated): `hotcorewin2k.sys`
- claim: > **hotcorewin2k.sys is not present in nromanoff MFT** (0 matches) [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792]. **hotcorewin2k.sys is not present in DC MFT** (0 matches) [CONFIRMED — exec…

### ❓ unverifiable _(line 250)_
- exec_ids: `7d52002b8c38`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-20c8-79e3-a814-7d52002b8c38]:

### ❌ failed _(line 308)_
- tools: `ezt_mft_parse`, `ezt_shimcache_parse`
- exec_ids: `69158614d792`, `fad7c6993479`
- 🚨 negation violations (claimed absent but found): `2011-08-28T22:35:45Z`, `2011-08-28T22:33:18Z`, `adberdr813.exe`
- claim: > 1. **adberdr813.exe initial compromise confirmed 2011-08-28T22:33:18Z** on nromanoff — download, crash archive (2011-08-28T22:35:45Z), and ShimCache Executed=No (crash before flag write) all corrobora…

### ✅ verified _(line 310)_
- tools: `ezt_mft_parse`, `ezt_shimcache_parse`
- exec_ids: `315b2cefc7ab`, `7d52002b8c38`
- matched: `2012-03-20T17:57:58Z`, `2012-02-09T12:31:54Z`, `usboesrv.exe`
- claim: > 2. **usboesrv.exe deployed to DC on 2012-03-20T17:57:58Z–17:57:59Z** in both Program Files and System32, with temporal anomaly on Program Files copy (Modified 2012-02-09T12:31:54Z precedes Created). A…

### ✅ verified _(line 312)_
- tools: `ezt_mft_parse`, `ezt_mft_parse`
- exec_ids: `69158614d792`, `225a1ef51bba`
- matched: `2012-04-03T22:59:43Z`, `2012-04-03T22:53:39Z`, `spinlock.exe`
- claim: > 3. **spinlock.exe bears anti-forensic indicators on nromanoff** (Modified 2012-04-03T22:53:39Z precedes Created 2012-04-03T22:59:43Z; usec_zeros=true; copied=true). Identical 2,271,885-byte binary on …

### ✅ verified _(line 314)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- matched: `2012-04-04T18:28:42Z`, `NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004`
- claim: > 4. **spinlock executed and crashed on DC** — WER crash directory `NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004` created 2012-04-04T18:28:42Z is the only spinlock evide…

### ⚠ partial _(line 316)_
- tools: `ezt_shimcache_parse`, `ezt_shimcache_parse`
- exec_ids: `fad7c6993479`, `7d52002b8c38`
- matched: `2012-04-04T00:14:13Z`
- **missing**: `\Windows\TEMP\a.exe``, `C:\Windows\TEMP\a.exe``
- 🚨 negation violations (claimed absent but found): `a.exe`, `C:\Windows\TEMP\a.exe`
- claim: > 5. **a.exe ran ~30 times in 30 minutes on nromanoff** (2012-04-04T00:14:13Z–00:44:11Z), file regenerated each cycle. No `C:\Windows\TEMP\a.exe` entry in DC ShimCache (0 matches). [CONFIRMED — exec_id …

### ✅ verified _(line 318)_
- tools: `ezt_shimcache_parse`, `ezt_mft_parse`
- exec_ids: `fad7c6993479`, `69158614d792`
- matched: `2012-04-05T13:20:58Z`, `hydrakatz.exe`
- claim: > 6. **hydrakatz.exe** confirmed on nromanoff; last run 2012-04-05T13:20:58Z. [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479, exec_id 019e1123-52f9-7f71-9651-69158614d792]

### ❌ failed _(line 320)_
- tools: `ezt_mft_parse`, `ezt_mft_parse`, `ezt_mft_parse`
- exec_ids: `225a1ef51bba`, `69158614d792`, `315b2cefc7ab`
- 🚨 negation violations (claimed absent but found): `2012-04-05T16:11:13Z`, `2012-04-05T16:07:58Z`, `EXFIL.pst`
- claim: > 7. **EXFIL.pst on tdungan** (not nromanoff, not DC) under vibranium's Outlook profile, created 2012-04-05T16:07:58Z, modified 2012-04-05T16:11:13Z, 16,778,240 bytes, live on disk. [CONFIRMED — exec_id…

### ✅ verified _(line 322)_
- tools: `ezt_mft_parse`, `ezt_mft_parse`, `ezt_mft_parse`
- exec_ids: `225a1ef51bba`, `69158614d792`, `315b2cefc7ab`
- matched: `2012-03-21T03:14:07Z`, `2011-05-17T22:56:56Z`, `hotcorewin2k.sys`
- claim: > 8. **hotcorewin2k.sys Timestomped=true on tdungan** (Created/Modified forged to 2011-05-17T22:56:56Z; actual install record_changed 2012-03-21T03:14:07Z). Not present on nromanoff or DC. [CONFIRMED — …

### ✅ verified _(line 324)_
- tools: `ezt_mft_parse`, `ezt_mft_parse`, `ezt_mft_parse`
- exec_ids: `69158614d792`, `225a1ef51bba`, `315b2cefc7ab`
- matched: `2012-04-03T23:09:16Z`, `2012-04-04T16:40:20Z`, `2012-04-04T17:29:33Z`
- claim: > 9. **vibranium account present on all three hosts** with first activity: nromanoff 2012-04-03T23:09:16Z → tdungan 2012-04-04T16:40:20Z → DC 2012-04-04T17:29:33Z — confirming nromanoff was the lateral …

### ✅ verified _(line 326)_
- tools: `ezt_shimcache_parse`
- exec_ids: `fad7c6993479`
- matched: `2012-04-03T21:13:07Z`, `2012-04-04T01:46:37Z`, `PSEXESVC.EXE`
- claim: > 10. **PsExec repeatedly targeted nromanoff** — PSEXESVC.EXE ShimCache entries span 2012-04-03T21:13:07Z through 2012-04-04T01:46:37Z (positions 9, 158–162), all Executed=Yes. [CONFIRMED — exec_id 019e…
