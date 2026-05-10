# Validator Report — iter_1

## Summary

- Total tagged claims:        **44**
  - CONFIRMED:                 40
  - INFERRED:                  2
  - HYPOTHESIS:                0
  - GAP:                       2
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           15 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                7 (some tokens found, some missing)
- ❌ failed:                 4 (no tokens found)
- ❓ unverifiable:           14 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 37.5%** (15 verified / 40 confirmed)

## Per-claim verdicts

### ❓ unverifiable _(line 61)_
- exec_ids: `315b2cefc7ab`
- note: claim has no extractable tokens (prose only)
- claim: > **Two copies present in DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab]:

### ✅ verified _(line 70)_
- tools: `ezt_shimcache_parse`
- exec_ids: `7d52002b8c38`
- matched: `services.exe`
- ✅ verified absences (negated): `usboesrv.exe`
- claim: > The `usboesrv.exe` binary is **absent from the DC ShimCache** (0 matches in 962 entries) [CONFIRMED — exec_id 019e1123-20c8-79e3-a814-7d52002b8c38]. This is consistent with Windows Server 2008 R2 beha…

### ✅ verified _(line 74)_
- tools: `ezt_mft_parse`, `ezt_mft_parse`
- exec_ids: `69158614d792`, `225a1ef51bba`
- ✅ verified absences (negated): `usboesrv.exe`
- claim: > **No `usboesrv.exe` was found in nromanoff or tdungan MFT** [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792; exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba — both returned 0 rows].

### ❓ unverifiable _(line 78)_
- exec_ids: `69158614d792`, `fad7c6993479`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id 019e1123-26a3-7c51-be46-fad7c6993479]:

### ❓ unverifiable _(line 98)_
- exec_ids: `225a1ef51bba`, `37769fe4cd76`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba, exec_id 019e1123-2b73-75a0-ad0a-37769fe4cd76]:

### ⚠ partial _(line 115)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- matched: `2012-04-04T18:28:42Z`
- **missing**: `NonCritical_spinlock.exe_f55bbffa...`, `file_name: spinlock.exe`
- 🚨 negation violations (claimed absent but found): `spinlock.exe`
- claim: > **The spinlock.exe binary is absent from DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 matches on `file_name: spinlock.exe`]. A WER crash folder `NonCritical_spinlock.exe_f55bb…

### ⚠ partial _(line 115)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- matched: `2012-04-04T18:28:42Z`
- **missing**: `NonCritical_spinlock.exe_f55bbffa...`, `file_name: spinlock.exe`
- 🚨 negation violations (claimed absent but found): `spinlock.exe`
- claim: > **The spinlock.exe binary is absent from DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 matches on `file_name: spinlock.exe`]. A WER crash folder `NonCritical_spinlock.exe_f55bb…

### ❓ unverifiable _(line 125)_
- exec_ids: `fad7c6993479`, `69158614d792`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479, exec_id 019e1123-52f9-7f71-9651-69158614d792]:

### ❌ failed _(line 131)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- 🚨 negation violations (claimed absent but found): `a.exe`
- claim: > **No a.exe was found in DC MFT TEMP paths** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 relevant matches]; **not present in DC ShimCache TEMP entries** [CONFIRMED — exec_id 019e1123-2…

### ❌ failed _(line 131)_
- tools: `ezt_shimcache_parse`
- exec_ids: `7d52002b8c38`
- 🚨 negation violations (claimed absent but found): `a.exe`
- claim: > **No a.exe was found in DC MFT TEMP paths** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 relevant matches]; **not present in DC ShimCache TEMP entries** [CONFIRMED — exec_id 019e1123-2…

### ❓ unverifiable _(line 135)_
- exec_ids: `fad7c6993479`, `69158614d792`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479, exec_id 019e1123-52f9-7f71-9651-69158614d792]:

### ✅ verified _(line 148)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- ✅ verified absences (negated): `hydrakatz.exe`
- claim: > hydrakatz.exe is NOT in DC MFT or nromanoff file listing [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 matches]. Credential harvesting was confined to nromanoff.

### ❓ unverifiable _(line 152)_
- exec_ids: `fad7c6993479`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]:

### ❓ unverifiable _(line 162)_
- exec_ids: `69158614d792`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792]:

### ✅ verified _(line 177)_
- tools: `ezt_mft_parse`
- exec_ids: `69158614d792`
- matched: `2011-08-28T22:35:45Z`, `AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e`
- claim: > A WER crash archive `AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e` was created 2011-08-28T22:35:45Z [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792], confirming ex…

### ✅ verified _(line 179)_
- tools: `ezt_shimcache_parse`
- exec_ids: `fad7c6993479`
- matched: `2011-08-28T22:35:24Z`, `adberdr813.exe`
- claim: > ShimCache entry for `adberdr813.exe` shows LastModified 2011-08-28T22:35:24Z, **Executed: No** [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]. The "No" flag is consistent with the binary c…

### ❓ unverifiable _(line 183)_
- exec_ids: `225a1ef51bba`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]:

### ❓ unverifiable _(line 197)_
- exec_ids: `37769fe4cd76`
- note: claim has no extractable tokens (prose only)
- claim: > AdbeRdr910 is **absent from tdungan ShimCache** [CONFIRMED — exec_id 019e1123-2b73-75a0-ad0a-37769fe4cd76, 0 matches]. XP ShimCache capacity (96 entries per ControlSet) was likely exhausted; subsequen…

### ❓ unverifiable _(line 201)_
- exec_ids: `225a1ef51bba`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]:

### ✅ verified _(line 216)_
- tools: `ezt_mft_parse`
- exec_ids: `225a1ef51bba`
- matched: `2012-04-05T16:11:20Z`, `Content.IE5\O52ZG5AZ`
- claim: > The 3-minute window between creation and modification (16:07 → 16:11) is consistent with a scripted PST-building operation. Vibranium's browser temp folder (`Content.IE5\O52ZG5AZ`) was last modified 2…

### ✅ verified _(line 218)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- ✅ verified absences (negated): `EXFIL.pst`
- claim: > **EXFIL.pst was NOT found in DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 matches]. **EXFIL.pst was NOT found in nromanoff MFT** [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-6…

### ✅ verified _(line 218)_
- tools: `ezt_mft_parse`
- exec_ids: `69158614d792`
- ✅ verified absences (negated): `EXFIL.pst`
- claim: > **EXFIL.pst was NOT found in DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 matches]. **EXFIL.pst was NOT found in nromanoff MFT** [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-6…

### ❓ unverifiable _(line 226)_
- exec_ids: `69158614d792`, `225a1ef51bba`, `315b2cefc7ab`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba, exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab]:

### ❓ unverifiable _(line 240)_
- exec_ids: `fad7c6993479`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]:

### ⚠ partial _(line 254)_
- tools: `ezt_evtx_parse`, `ezt_evtx_parse`
- exec_ids: `4c35ed87f968`, `31d9c7732c3c`
- ✅ verified absences (negated): `.EVT`, `.Evt`
- **missing**: `log2timeline`, `evtxtract`, `.evtx`, `winevt`, `SecEvent.Evt`, `SysEvent.Evt`
- claim: > [CONFIRMED — exec_id 019e1124-5e07-71c1-8f43-4c35ed87f968; exec_id 019e1124-60e3-78c2-83e9-31d9c7732c3c]: Both `SecEvent.Evt` and `SysEvent.Evt` on tdungan returned 0 events. EvtxECmd does not support…

### ⚠ partial _(line 262)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- matched: `2012-03-20T17:57:59Z`, `Windows\System32\`
- ✅ verified absences (negated): `96.255.98.154`, `96.255.98.154:29932`
- 🚨 negation violations (claimed absent but found): `usboesrv.exe`
- claim: > [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab]: DC MFT shows `usboesrv.exe` placed in `Windows\System32\` on 2012-03-20T17:57:59Z. The dual-directory deployment pattern (Program Files + Sy…

### ❓ unverifiable _(line 268)_
- exec_ids: `225a1ef51bba`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]:

### ✅ verified _(line 279)_
- tools: `ezt_mft_parse`
- exec_ids: `69158614d792`
- ✅ verified absences (negated): `hotcorewin2k.sys`
- claim: > **hotcorewin2k.sys is absent from nromanoff MFT** [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, 0 matches] and **absent from DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cef…

### ✅ verified _(line 279)_
- tools: `ezt_mft_parse`
- exec_ids: `315b2cefc7ab`
- ✅ verified absences (negated): `hotcorewin2k.sys`
- claim: > **hotcorewin2k.sys is absent from nromanoff MFT** [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, 0 matches] and **absent from DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cef…

### ❓ unverifiable _(line 285)_
- exec_ids: `7d52002b8c38`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e1123-20c8-79e3-a814-7d52002b8c38]:

### ⚠ partial _(line 340)_
- tools: `ezt_mft_parse`, `ezt_shimcache_parse`
- exec_ids: `69158614d792`, `fad7c6993479`
- matched: `adberdr813.exe`
- **missing**: `2011-08-28T22:33Z`
- claim: > 1. **adberdr813.exe initial compromise timestamp confirmed as 2011-08-28T22:33Z** on nromanoff — WER crash and ShimCache both corroborate execution; "Executed:No" in ShimCache explained by crash befor…

### ✅ verified _(line 342)_
- tools: `ezt_mft_parse`, `ezt_shimcache_parse`
- exec_ids: `315b2cefc7ab`, `7d52002b8c38`
- matched: `usboesrv.exe`
- claim: > 2. **usboesrv.exe deployed to DC on 2012-03-20** with anti-forensic timestomping on the Program Files copy. Two copies confirm service-registration persistence pattern. Absent from shimcache (service …

### ✅ verified _(line 344)_
- tools: `ezt_mft_parse`, `ezt_mft_parse`
- exec_ids: `69158614d792`, `225a1ef51bba`
- matched: `spinlock.exe`
- claim: > 3. **spinlock.exe timestomped on nromanoff** (Created > Modified by 6 minutes), usec_zeros:true, copied:true — anti-forensic flags confirmed. Identical 2,271,885-byte binary on both nromanoff and tdun…

### ✅ verified _(line 346)_
- tools: `ezt_shimcache_parse`
- exec_ids: `fad7c6993479`
- matched: `a.exe`
- claim: > 4. **a.exe ran ~30 times in 30 minutes** on nromanoff (00:14–00:44Z on 2012-04-04) with file being regenerated each cycle — indicative of automated credential spraying or callback loop. [CONFIRMED — e…

### ✅ verified _(line 348)_
- tools: `ezt_shimcache_parse`, `ezt_mft_parse`
- exec_ids: `fad7c6993479`, `69158614d792`
- matched: `2012-04-05T13:20:58Z`, `hydrakatz.exe`
- claim: > 5. **hydrakatz.exe** confirmed on nromanoff; last run 2012-04-05T13:20:58Z via Prefetch. Not present on DC or tdungan. [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479, exec_id 019e1123-52f9-…

### ❌ failed _(line 350)_
- tools: `ezt_mft_parse`
- exec_ids: `225a1ef51bba`
- 🚨 negation violations (claimed absent but found): `2012-04-05T16:07`, `EXFIL.pst`
- claim: > 6. **EXFIL.pst is on tdungan** (not DC) under the vibranium Outlook profile, created 2012-04-05T16:07–16:11Z; 16MB, live on disk, likely exfiltrated via browser. [CONFIRMED — exec_id 019e1123-6e98-714…

### ⚠ partial _(line 352)_
- tools: `ezt_mft_parse`
- exec_ids: `225a1ef51bba`
- matched: `hotcorewin2k.sys`
- **missing**: `2012-03-21T03:14Z`
- claim: > 7. **hotcorewin2k.sys timestomped on tdungan** to appear as a 2011-05-17 file; actual installation 2012-03-21T03:14Z. Absent from DC and nromanoff. [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef…

### ❌ failed _(line 354)_
- tools: `ezt_mft_parse`, `ezt_mft_parse`, `ezt_mft_parse`
- exec_ids: `69158614d792`, `225a1ef51bba`, `315b2cefc7ab`
- **missing**: `2012-04-04T17:29Z`, `2012-04-03T23:09Z`, `2012-04-04T16:40Z`
- claim: > 8. **vibranium account present on all three hosts** with first activity: nromanoff (2012-04-03T23:09Z) → tdungan (2012-04-04T16:40Z) → DC (2012-04-04T17:29Z) — confirming nromanoff was the lateral mov…

### ⚠ partial _(line 356)_
- tools: `ezt_shimcache_parse`
- exec_ids: `fad7c6993479`
- matched: `PSEXESVC.EXE`
- **missing**: `2012-04-04T01:46Z`
- claim: > 9. **PsExec used against nromanoff** — PSEXESVC.EXE on nromanoff ShimCache (2012-04-04T01:46Z) confirms nromanoff was a PsExec target from another compromised host. [CONFIRMED — exec_id 019e1123-26a3-…

### ✅ verified _(line 358)_
- tools: `ezt_shimcache_parse`
- exec_ids: `7d52002b8c38`
- ✅ verified absences (negated): `2012-04-04T17:29Z`
- claim: > 10. **No attacker tools in DC ShimCache** — DC was used as a persistence/pivot platform (service-level, not interactive tool execution) until the vibranium account was activated on 2012-04-04T17:29Z. …
