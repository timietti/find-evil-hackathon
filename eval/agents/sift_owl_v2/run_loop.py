"""SIFT-OWL v2 — persistent self-correction loop.

Runs the v1 agent in iterations:
    iter 1: fresh case prompt → agent produces a report → validator scores it
    iter 2: case prompt + iter-1 report + validator demotion list
            → agent re-confirms or demotes each flagged claim
            → validator re-scores
    iter 3: ... (capped at --max-iterations, default 3)

Termination — any one fires (most-favorable wins):

    - 0 demoted claims at end of iter N (early exit on full convergence)
    - confirmed-and-verified count failed to improve from iter N-1 to iter N
      (no incremental gain → stop spending budget)
    - iter N reached --max-iterations
    - --max-budget-usd reached (per-iteration; budget split equally)

All iterations share ONE `audit/` directory + ONE `sift-mcp` server-side
audit log. That means `query_rows` on iter-N can drill into exec_ids
recorded by iter-(N-1) — the audit log is institutional memory across
the whole run, exactly as the architecture doc specifies.

Output:
    eval/results/<case>/sift-owl-v2/<run_id>/
      REPORT.md                      ← cross-iteration summary
      iterations/iter_1/
        prompt.md                    ← actual prompt sent
        transcript.jsonl, tool_calls.jsonl, final_response.md, summary.json
        validator_report.{md,json}   ← that iteration's verdict
      iterations/iter_2/
        ... (same shape)
      audit/
        exec_log.jsonl               ← shared across all iterations
        raw/                         ← shared
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import typer
import yaml
from rich.console import Console

from agents.validator.validate import validate_run, write_validator_report

REPO_ROOT = Path(__file__).resolve().parents[3]

app = typer.Typer(help="SIFT-OWL v2: agent + validator self-correction loop.")
console = Console()


# ---------------------------------------------------------------------------
# Built-in tool deny / MCP allow lists (same shape as v1).
# ---------------------------------------------------------------------------

DISALLOWED_BUILTINS = " ".join([
    "Bash", "Edit", "Write", "Read", "NotebookEdit",
    "WebFetch", "WebSearch", "Agent", "Skill", "AskUserQuestion",
])
ALLOWED_MCP_TOOLS = " ".join([
    # memory (vol3)
    "mcp__sift-owl__vol3_image_info",
    "mcp__sift-owl__vol3_psscan",
    "mcp__sift-owl__vol3_pstree",
    "mcp__sift-owl__vol3_cmdline",
    "mcp__sift-owl__vol3_netscan",
    "mcp__sift-owl__vol3_filescan",
    "mcp__sift-owl__vol3_malfind",
    "mcp__sift-owl__vol3_svcscan",
    "mcp__sift-owl__vol3_userassist",
    # disk (TSK + EWF)
    "mcp__sift-owl__ewf_info",
    "mcp__sift-owl__ewf_verify",
    "mcp__sift-owl__tsk_partition_table",
    "mcp__sift-owl__tsk_fs_stat",
    "mcp__sift-owl__tsk_fls_list",
    "mcp__sift-owl__tsk_icat_extract",
    # EZ Tools (extract-then-parse Windows artifacts)
    "mcp__sift-owl__ezt_mft_parse",
    "mcp__sift-owl__ezt_shimcache_parse",
    "mcp__sift-owl__ezt_evtx_parse",
    "mcp__sift-owl__ezt_amcache_parse",
    # drill helper
    "mcp__sift-owl__query_rows",
])


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Iteration-N prompt construction.
# ---------------------------------------------------------------------------

_FEEDBACK_HEADER = """\
---

## Validator feedback from iteration {N_minus_1}

The following CONFIRMED claims from your previous iteration's report were
DEMOTED by the rule-based validator. The validator checks whether every
testable token (PIDs, IPs, filenames, paths, timestamps, hashes) in a
CONFIRMED claim is structurally present in the parsed JSON of the cited
`exec_id`. Demoted statuses:

- **partial** — some tokens matched, some missing. Multi-source paragraph
  cites only one tool? Use multi-cite syntax `[CONFIRMED — exec_id A, exec_id B]`.
- **failed** — no tokens matched, OR a negated assertion was contradicted by
  the evidence. Re-check the claim against the cited tool's data.
- **not_confirmed** — `[CONFIRMED]` tag found without an `exec_id` citation.
  Cite explicitly per-claim, not "[All exec_id …]" once at the bottom.

You have full access to the shared audit log via `query_rows(exec_id, ...)` —
all exec_ids from your previous iteration are still reachable. Drill into
them to confirm or refute each flagged claim.

For EACH flagged claim below, you must do exactly one of:

  1. **Re-confirm with multi-cite**: keep the [CONFIRMED] tag and add the
     missing exec_ids: `[CONFIRMED — exec_id A, exec_id B]`. Use this when
     you can locate supporting evidence in another tool's data.
  2. **Demote to [INFERRED]**: if the claim is your reasoning derived from
     evidence, change the tag and add reasoning: `[INFERRED — exec_id A;
     reasoning: …]`.
  3. **Demote to [GAP]**: if the evidence to confirm just isn't available
     to you, mark it `[GAP — would need: …]`.

DO NOT remove flagged claims silently. Every flagged claim must appear
explicitly in your iteration {N} report with one of the three resolutions
above. Otherwise treat the prior report as a starting point — keep
verified claims as-is, and add any new evidence you discover.

### Demotion list — {n_flagged} claims

{flagged_block}

---

When you produce iteration {N}'s report, end with the line `SIFT-OWL RUN COMPLETE`.
"""


_FLAGGED_CLAIM_TEMPLATE = """\
**[{idx}] {status}** — cited tool(s): {tools} — exec_ids: {exec_ids}
{tokens_section}
> {snippet}

"""


def _format_flagged_claim(idx: int, verdict: dict) -> str:
    claim = verdict["claim"]
    tools = (
        ", ".join(verdict.get("tool_names", []) or [])
        or verdict.get("tool_name") or "—"
    )
    exec_ids = ", ".join(claim.get("exec_ids") or []) or "(none)"

    parts: list[str] = []
    if verdict.get("missing"):
        parts.append(
            f"missing tokens (claim says X but X not in cited tool's data): "
            + ", ".join(f"`{t}`" for t in verdict["missing"][:8])
            + (f" (+{len(verdict['missing']) - 8} more)" if len(verdict["missing"]) > 8 else "")
        )
    if verdict.get("negation_violations"):
        parts.append(
            f"negation violations (claim says NOT X but X IS in cited tool's data): "
            + ", ".join(f"`{t}`" for t in verdict["negation_violations"][:6])
        )
    if verdict.get("matched"):
        parts.append(
            f"already matched: "
            + ", ".join(f"`{t}`" for t in verdict["matched"][:6])
            + (f" (+{len(verdict['matched']) - 6} more)" if len(verdict["matched"]) > 6 else "")
        )
    if verdict.get("notes"):
        parts.append(f"validator note: {verdict['notes']}")
    tokens_section = "\n".join(f"- {p}" for p in parts) if parts else "_(no extracted tokens)_"

    snippet = (claim.get("text") or "").strip().replace("\n", " ")
    if len(snippet) > 280:
        snippet = snippet[:280] + "…"

    return _FLAGGED_CLAIM_TEMPLATE.format(
        idx=idx,
        status=verdict.get("status", "?"),
        tools=tools,
        exec_ids=exec_ids,
        tokens_section=tokens_section,
        snippet=snippet,
    )


# Demotion-worthy statuses — these go in the next iteration's feedback.
_DEMOTED_STATUSES = {"partial", "failed", "not_confirmed"}


def _flagged_verdicts(validator_report: dict) -> list[dict]:
    return [
        v for v in (validator_report.get("verdicts") or [])
        if v.get("status") in _DEMOTED_STATUSES
    ]


def build_followup_prompt(
    *,
    base_prompt: str,
    iteration_n: int,
    prev_response_text: str,
    prev_validator_report: dict,
) -> str:
    """Compose iteration N's prompt from the base prompt + iter (N-1) feedback."""
    flagged = _flagged_verdicts(prev_validator_report)
    flagged_block = (
        "\n".join(_format_flagged_claim(i + 1, v) for i, v in enumerate(flagged))
        or "_(no flagged claims — see termination logic)_"
    )
    feedback = _FEEDBACK_HEADER.format(
        N=iteration_n,
        N_minus_1=iteration_n - 1,
        n_flagged=len(flagged),
        flagged_block=flagged_block,
    )

    prev_response_block = (
        "## Iteration {prev_N}'s final report (for reference; build on it)\n\n"
        "<<<\n{body}\n>>>\n"
    ).format(prev_N=iteration_n - 1, body=prev_response_text.strip())

    return f"{base_prompt}\n\n{prev_response_block}\n\n{feedback}"


# ---------------------------------------------------------------------------
# One-iteration runner.
# ---------------------------------------------------------------------------


@dataclass
class IterationResult:
    iteration: int
    iter_dir: Path
    prompt_path: Path
    response_text: str
    summary: dict
    validator_report: dict
    duration_seconds: float
    cost_usd: float
    tool_use_count: int
    confirmed_count: int
    verified_count: int
    demoted_count: int  # partial + failed + not_confirmed
    exit_code: int


def _verify_evidence_unchanged(case: dict) -> dict:
    """Pre-/post-run hash check (lifted from v1 harness)."""
    import hashlib

    out = {}
    paths: list[tuple[Path, str | None]] = []
    for ev in case.get("evidence", []) or []:
        paths.append((Path(ev["path"]), ev.get("sha256")))
    for host in case.get("hosts", []) or []:
        for fld in ("disk_image", "memory_image"):
            p = host.get(fld)
            if p:
                paths.append((Path(p), None))
    for ev in case.get("disk_images", []) or []:
        paths.append((Path(ev["path"]), ev.get("sha256")))
    for ev in case.get("memory_images", []) or []:
        paths.append((Path(ev["path"]), ev.get("sha256")))

    seen: set[Path] = set()
    for path, expected_sha256 in paths:
        if path in seen:
            continue
        seen.add(path)
        if not path.exists():
            raise FileNotFoundError(f"Evidence missing: {path}")
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(8 << 20), b""):
                h.update(chunk)
        actual = h.hexdigest()
        out[str(path)] = {
            "expected_sha256": expected_sha256,
            "actual_sha256":   actual,
            "match":           expected_sha256 is None or actual == expected_sha256,
            "size_bytes":      path.stat().st_size,
        }
    return out


def _write_mcp_config(audit_dir: Path, evidence_root: str, target: Path) -> None:
    cfg = {
        "mcpServers": {
            "sift-owl": {
                "type": "stdio",
                "command": "sift-mcp",
                "args": [
                    "--audit-dir", str(audit_dir),
                    "--evidence-root", evidence_root,
                ],
                "env": {},
            }
        }
    }
    target.write_text(json.dumps(cfg, indent=2))


def _run_one_iteration(
    *,
    iteration: int,
    iter_dir: Path,
    audit_dir: Path,           # shared across iterations
    mcp_config_path: Path,     # shared
    prompt_text: str,
    case_evidence_dir: str,
    model: str,
    max_budget_usd: float,
    max_turns: int,
) -> IterationResult:
    iter_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = iter_dir / "prompt.md"
    transcript_path = iter_dir / "transcript.jsonl"
    tool_calls_path = iter_dir / "tool_calls.jsonl"
    final_response_path = iter_dir / "final_response.md"
    summary_path = iter_dir / "summary.json"
    prompt_path.write_text(prompt_text)

    cmd = [
        "claude", "-p", prompt_text,
        "--model", model,
        "--max-budget-usd", str(max_budget_usd),
        "--max-turns", str(max_turns),
        "--mcp-config", str(mcp_config_path),
        "--strict-mcp-config",
        "--allowed-tools", ALLOWED_MCP_TOOLS,
        "--disallowed-tools", DISALLOWED_BUILTINS,
        "--output-format", "stream-json",
        "--include-partial-messages",
        "--no-session-persistence",
        "--verbose",
    ]

    console.log(f"[bold]iter {iteration}: launching claude...[/]")
    t0 = time.time()
    proc = subprocess.Popen(
        cmd,
        cwd=iter_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    final_text_parts: list[str] = []
    n_tool_uses = 0
    result_event: dict | None = None

    with transcript_path.open("w") as transcript_fh, tool_calls_path.open("w") as tool_fh:
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                transcript_fh.write(line); transcript_fh.flush()
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if evt.get("type") == "assistant":
                    msg = evt.get("message") or {}
                    for blk in msg.get("content", []) or []:
                        if blk.get("type") == "tool_use":
                            n_tool_uses += 1
                            tool_fh.write(json.dumps({
                                "ts": _now_iso(),
                                "tool": blk.get("name"),
                                "input": blk.get("input"),
                                "id": blk.get("id"),
                            }) + "\n"); tool_fh.flush()
                        elif blk.get("type") == "text":
                            txt = blk.get("text", "")
                            if txt:
                                final_text_parts.append(txt)
                if evt.get("type") == "result":
                    result_event = evt
        except KeyboardInterrupt:
            proc.terminate(); proc.wait(timeout=10); raise

    rc = proc.wait()
    duration = time.time() - t0
    response_text = "\n\n".join(final_text_parts) if final_text_parts else ""
    final_response_path.write_text(response_text)

    cost = float((result_event or {}).get("total_cost_usd") or 0.0)
    summary = {
        "iteration":     iteration,
        "exit_code":     rc,
        "wall_seconds":  round(duration, 2),
        "tool_use_count": n_tool_uses,
        "cost_usd":      cost,
        "result":        result_event or {},
    }
    summary_path.write_text(json.dumps(summary, indent=2))

    # Validator. validate_run() reads `<iter_dir>/final_response.md` and
    # `<iter_dir>/audit/exec_log.jsonl`. We need the validator to use the
    # SHARED audit dir, not a per-iteration one. Symlink-trick: create
    # `<iter_dir>/audit -> <audit_dir>` so validate_run finds the audit log.
    iter_audit_link = iter_dir / "audit"
    if not iter_audit_link.exists():
        iter_audit_link.symlink_to(audit_dir)

    rv, verdicts = validate_run(iter_dir)
    write_validator_report(iter_dir, rv, verdicts)
    validator_report = json.loads((iter_dir / "validator_report.json").read_text())

    flagged = _flagged_verdicts(validator_report)

    return IterationResult(
        iteration=iteration,
        iter_dir=iter_dir,
        prompt_path=prompt_path,
        response_text=response_text,
        summary=summary,
        validator_report=validator_report,
        duration_seconds=duration,
        cost_usd=cost,
        tool_use_count=n_tool_uses,
        confirmed_count=rv.confirmed_count,
        verified_count=rv.verified,
        demoted_count=len(flagged),
        exit_code=rc,
    )


# ---------------------------------------------------------------------------
# Top-level loop runner.
# ---------------------------------------------------------------------------


def _load_case(case_id: str) -> dict:
    case_yaml = REPO_ROOT / "eval" / "cases" / case_id / "case.yaml"
    with case_yaml.open() as fh:
        return yaml.safe_load(fh)


@app.callback(invoke_without_command=True)
def main(
    case: str = typer.Option(..., "--case"),
    prompt_file: str = typer.Option(
        ..., "--prompt-file",
        help="Path (or basename in eval/agents/sift_owl_v1/) to the base case prompt.",
    ),
    model: str = typer.Option("sonnet", "--model"),
    max_budget_usd: float = typer.Option(
        10.0, "--max-budget-usd",
        help="TOTAL budget across all iterations. Each iter gets budget/iter_count.",
    ),
    max_turns_per_iter: int = typer.Option(120, "--max-turns-per-iter"),
    max_iterations: int = typer.Option(3, "--max-iterations"),
    skip_post_hash: bool = typer.Option(False, "--skip-post-hash"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    if shutil.which("claude") is None:
        raise RuntimeError("claude CLI not on PATH")
    if shutil.which("sift-mcp") is None:
        raise RuntimeError("sift-mcp not on PATH")

    case_data = _load_case(case)
    evidence_dir = case_data.get("evidence_dir") or "/cases"

    # Resolve prompt-file path (mirrors v1 logic).
    prompt_path = Path(prompt_file)
    if not prompt_path.is_absolute():
        # Try v1 prompts dir first, fall back to v2 dir
        for candidate_root in (
            REPO_ROOT / "eval" / "agents" / "sift_owl_v1",
            REPO_ROOT / "eval" / "agents" / "sift_owl_v2",
        ):
            if (candidate_root / prompt_file).exists():
                prompt_path = candidate_root / prompt_file
                break
        else:
            prompt_path = REPO_ROOT / "eval" / "agents" / "sift_owl_v1" / prompt_file
    if not prompt_path.exists():
        raise FileNotFoundError(f"prompt missing: {prompt_path}")
    base_prompt = prompt_path.read_text()

    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{model}"
    run_dir = REPO_ROOT / "eval" / "results" / case / "sift-owl-v2" / run_id
    audit_dir = run_dir / "audit"
    iters_dir = run_dir / "iterations"
    audit_dir.mkdir(parents=True, exist_ok=True)
    iters_dir.mkdir(parents=True, exist_ok=True)

    mcp_config_path = run_dir / "mcp_config.json"
    _write_mcp_config(
        audit_dir=audit_dir,
        evidence_root=evidence_dir,
        target=mcp_config_path,
    )

    console.log(f"[bold]Hashing evidence (pre-run)...[/]")
    pre_hashes = _verify_evidence_unchanged(case_data)
    for p, info in pre_hashes.items():
        if not info["match"]:
            raise RuntimeError(f"pre-run hash mismatch for {p}")
    console.log(f"[green]Pre-run hashes match.[/] ({len(pre_hashes)} files)")

    meta = {
        "run_id":          run_id,
        "case":            case,
        "model":           model,
        "max_budget_usd":  max_budget_usd,
        "max_iterations":  max_iterations,
        "started_utc":     _now_iso(),
        "evidence_dir":    evidence_dir,
        "pre_run_hashes":  pre_hashes,
        "prompt_file":     str(prompt_path),
        "claude_version":  subprocess.check_output(["claude", "--version"], text=True).strip(),
        "harness_git_rev": subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True,
        ).stdout.strip() or "unknown",
    }

    if dry_run:
        meta["dry_run"] = True
        (run_dir / "run_meta.json").write_text(json.dumps(meta, indent=2, default=str))
        console.print("[yellow]DRY RUN — not invoking claude.[/]")
        return

    # Per-iteration budget so the cumulative total stays within --max-budget-usd
    per_iter_budget = max_budget_usd / max_iterations

    iterations: list[IterationResult] = []
    total_cost = 0.0
    prev_verified = -1

    for n in range(1, max_iterations + 1):
        iter_dir = iters_dir / f"iter_{n}"
        if n == 1:
            prompt_text = base_prompt
        else:
            prev = iterations[-1]
            prompt_text = build_followup_prompt(
                base_prompt=base_prompt,
                iteration_n=n,
                prev_response_text=prev.response_text,
                prev_validator_report=prev.validator_report,
            )

        result = _run_one_iteration(
            iteration=n,
            iter_dir=iter_dir,
            audit_dir=audit_dir,
            mcp_config_path=mcp_config_path,
            prompt_text=prompt_text,
            case_evidence_dir=evidence_dir,
            model=model,
            max_budget_usd=per_iter_budget,
            max_turns=max_turns_per_iter,
        )
        iterations.append(result)
        total_cost += result.cost_usd

        console.print(
            f"[bold]iter {n}[/] complete: "
            f"verified={result.verified_count}/{result.confirmed_count} "
            f"(demoted={result.demoted_count}) "
            f"cost=${result.cost_usd:.3f}  "
            f"wall={result.duration_seconds/60:.1f}m"
        )

        # Termination: 0 demoted = full convergence.
        if result.demoted_count == 0:
            console.print("[green]Convergence: 0 demoted claims. Stopping.[/]")
            break
        # Termination: no improvement in verified count.
        if n >= 2 and result.verified_count <= prev_verified:
            console.print(
                f"[yellow]No improvement: verified={result.verified_count} "
                f"≤ prev={prev_verified}. Stopping.[/]"
            )
            break
        prev_verified = result.verified_count

    # Compose top-level REPORT.md
    last = iterations[-1]
    report_lines = [
        f"# SIFT-OWL v2 — {case} (self-correcting loop)",
        "",
        f"- Run ID: `{run_id}`",
        f"- Iterations completed: **{len(iterations)} / {max_iterations}**",
        f"- Total cost: **${total_cost:.4f}**",
        f"- Total wall: **{sum(r.duration_seconds for r in iterations)/60:.1f} min**",
        "",
        "## Iteration progression",
        "",
        "| iter | wall | cost | tools | confirmed | verified | demoted |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in iterations:
        report_lines.append(
            f"| {r.iteration} "
            f"| {r.duration_seconds/60:.1f} m "
            f"| ${r.cost_usd:.3f} "
            f"| {r.tool_use_count} "
            f"| {r.confirmed_count} "
            f"| {r.verified_count} "
            f"| {r.demoted_count} |"
        )
    report_lines += [
        "",
        f"**Final verified rate: {last.verified_count}/{last.confirmed_count} "
        f"({last.verified_count/last.confirmed_count*100:.1f}%)** if "
        f"`confirmed_count` > 0 else N/A.",
        "",
        "## Final report (iteration {N})".format(N=last.iteration),
        "",
        last.response_text or "_(no response captured)_",
    ]
    (run_dir / "REPORT.md").write_text("\n".join(report_lines))

    meta["finished_utc"]   = _now_iso()
    meta["total_cost_usd"] = total_cost
    meta["iterations"]     = [
        {
            "iteration":       r.iteration,
            "exit_code":       r.exit_code,
            "wall_seconds":    r.duration_seconds,
            "cost_usd":        r.cost_usd,
            "tool_use_count":  r.tool_use_count,
            "confirmed_count": r.confirmed_count,
            "verified_count":  r.verified_count,
            "demoted_count":   r.demoted_count,
        }
        for r in iterations
    ]
    if not skip_post_hash:
        post = _verify_evidence_unchanged(case_data)
        meta["post_run_hashes"]    = post
        meta["evidence_unchanged"] = all(i["match"] for i in post.values())
    (run_dir / "run_meta.json").write_text(json.dumps(meta, indent=2, default=str))

    console.print(f"[bold green]SIFT-OWL v2 run complete.[/] → {run_dir}")
    console.print_json(data={
        "iterations":   len(iterations),
        "total_cost":   round(total_cost, 4),
        "final_verified_rate":
            f"{last.verified_count}/{last.confirmed_count}" if last.confirmed_count else "n/a",
    })


if __name__ == "__main__":
    app()
