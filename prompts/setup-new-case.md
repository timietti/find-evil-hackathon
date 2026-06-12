# Setup new case — instructions for Claude Code

> Paste this prompt into Claude Code (`claude` in the repo root)
> to scaffold a new SIFT-OWL case from a directory of evidence.
> You will not write any YAML or Markdown yourself — Claude does
> it from the templates already in the repo.

You are helping the user register a new investigation case for
SIFT-OWL, an autonomous DFIR agent that lives in this repo. You
have full Bash + Read + Write access.

The user will tell you where their evidence is — a single
directory path under `/cases/`. Possibly with a one- or
two-sentence case briefing ("our employee X is suspected of Y").
If they don't volunteer a briefing, ask once, briefly.

Your job, end-to-end, autonomously:

1. **Pick a short snake-case `<case-id>`** (e.g. `acme-incident-01`,
   `widget-corp-laptop`). Confirm it with the user in one line.

2. **Walk the evidence directory.** `find` it; for every regular
   file print path + size. Skip files under any `precooked/`,
   `analysis/`, `reports/`, or `notes/` subdirectory (those are
   not evidence).

3. **Hash each evidence file with sha256sum.** Print a one-line
   running summary as you go ("hashed 3/12: file.E01 → abcd…").
   On a large image (≥ 50 GB) this can take 5–10 minutes; warn
   the user up-front.

4. **Classify each file.** Use the extension + `file` command to
   decide `kind:`:
   - `.E01` / `.Ex01` / `.AD1` → `disk_image`
   - `.raw` / `.mem` / `.img` / `.vmem` / `.dmp` (and `file`
     reports a memory-like header) → `memory_image`
   - hive file names (`NTUSER.DAT`, `SYSTEM`, `SOFTWARE`,
     `Amcache.hve`, etc.) → `registry_hive`
   - `.evtx` → `event_log`
   - directory of triage artefacts (Velociraptor / KAPE / CyLR
     collection) → record as `triage_collection`, NOT inside the
     `evidence:` list (the harness only hashes single files).
   - anything else → ask the user once.

5. **Detect partition / filesystem info on disk images.** For
   each `disk_image`, run `ewfinfo` (if `.E01`) and
   `mmls <image>`. If GPT/MBR multi-partition: record
   `partition_table:`, `partition_count:`, and pick the main
   partition (largest NTFS slot) → record `main_partition: {
   slot, offset_sectors, length_sectors }`. The agent must pass
   `offset=<offset_sectors>` to `tsk_fs_stat` / `fls` / `icat`,
   so this field matters.

6. **Write `eval/cases/<case-id>/case.yaml`.** Use
   `eval/cases/test4-vanko/case.yaml` as the template — it is
   the most complete reference. Fill in:
   - `case_id`, `case_name`, `client` (or `null`), `victim` /
     `subject` blocks (use what the user told you; leave fields
     `null` if unknown — *do not invent*),
   - `system:` (OS / arch / hostname / user / timezone — leave
     `null` for fields to be discovered from evidence),
   - `evidence_dir:` = the root the user gave you,
   - `evidence:` = the list you just hashed, each with `path`,
     `kind`, `size_bytes`, `sha256`, plus any disk-image
     fields from step 5,
   - `triage_collection:` only if step 4 found one,
   - `goals:` = a copy of the four standard goals (G1 initial
     access, G2 persistence/scope, G3 impact, G4 attribution)
     unless the user gave you specific ones.

   **Never make up sha256 values.** If a hash failed, mark the
   file `sha256: null` and tell the user which one to retry.

7. **Write `eval/cases/<case-id>/case.md`.** A short
   human-readable briefing: case name, what we know, what we
   want to find out. 5–15 lines. Plain prose.

8. **Write `eval/agents/sift_owl_v2/prompt-<case-id>.md`.** Use
   `eval/agents/sift_owl_v2/prompt-test4-vanko.md` as the
   template. Replace ONLY the case-specific sections:
   - the header (case title + one-line briefing),
   - the evidence inventory section (paste the new evidence
     list, paths + sha256 + partition offsets),
   - the investigation-goals section (the four G1–G4 from
     step 6, in plain English),
   - any disk-specific hints (e.g. "pass `offset=<N>` to TSK
     because main partition starts at sector N" if relevant).

   **Keep verbatim** (do not edit):
   - the "Tool inventory" section,
   - the **W3-60 token-quoting style** paragraph + the
     Good/Bad table,
   - the citation-format paragraph + the `[CONFIRMED]` /
     `[INFERRED]` / `[HYPOTHESIS]` / `[GAP]` tag definitions,
   - the closing "When you are done, print
     `SIFT-OWL RUN COMPLETE` to stdout" line.

9. **Print a 5-line summary to the user:**
   ```
   Case registered: <case-id>
   case.yaml      : eval/cases/<case-id>/case.yaml
   case briefing  : eval/cases/<case-id>/case.md
   prompt         : eval/agents/sift_owl_v2/prompt-<case-id>.md
   To run:
     python -m eval.agents.sift_owl_v2.run_loop \
       --case <case-id> \
       --prompt-file eval/agents/sift_owl_v2/prompt-<case-id>.md \
       --model sonnet --max-budget-usd 5 --max-iterations 3
   ```

Constraints:

- **Read-only on the evidence.** Never modify, copy, mount, or
  extract anything under `/cases/`. Hashing only.
- **Truthful YAML.** Every value you write must come from
  `sha256sum` / `ewfinfo` / `mmls` / `file` output you ran in
  this session, or from what the user told you. Don't invent
  case briefings, hostnames, user accounts, or hashes.
- **Single autonomous run.** Don't ask the user questions other
  than (a) the case-id, (b) the case briefing if absent, (c)
  whether to proceed before the long hash step on large images.

Begin.
