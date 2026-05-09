"""SIFT-OWL v0 harness — Claude Code as MCP client to sift-mcp.

Launches `claude -p --strict-mcp-config --mcp-config <ours>` with a deny-list
that removes Bash, Edit, Write, Read, and the rest of the built-in side-effect
tools. The agent's only available operations are the 9 typed forensic functions
registered by `sift-mcp`. Every claim it makes can be traced back to a specific
`exec_id` in `audit/exec_log.jsonl`.

Mirrors the shape of `eval/baselines/protocol_sift/run.py` so we can compare
the two runs apples-to-apples in a final REPORT.md.

Usage:
    python -m eval.agents.sift_owl_v0.run \\
        --case rocba-001 --model sonnet --max-budget-usd 5

Output: eval/results/<case_id>/sift-owl-v0/<run_id>/
    transcript.jsonl       — raw stream-json from Claude Code
    tool_calls.jsonl       — one row per tool call (parsed from transcript)
    final_response.md      — agent's final text response
    summary.json           — wall, tokens, cost, tool count, evidence-unchanged
    run_meta.json          — invocation params, env, evidence hashes
    audit/exec_log.jsonl   — per-MCP-call audit log written by sift-mcp
    audit/raw/             — raw subprocess outputs for each tool call
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import typer
import yaml
from rich.console import Console

REPO_ROOT = Path(__file__).resolve().parents[3]
AGENT_DIR = REPO_ROOT / "eval" / "agents" / "sift_owl_v0"
PROMPT_PATH = AGENT_DIR / "prompt.md"

app = typer.Typer(help="Run SIFT-OWL v0 against a case.")
console = Console()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_case(case_id: str) -> dict:
    case_yaml = REPO_ROOT / "eval" / "cases" / case_id / "case.yaml"
    if not case_yaml.exists():
        raise FileNotFoundError(f"No case.yaml at {case_yaml}")
    with case_yaml.open() as fh:
        return yaml.safe_load(fh)


def _verify_evidence_unchanged(case: dict) -> dict:
    """Hash every evidence file in the case manifest. Returns map of
    path -> {expected, actual, size, match}."""
    import hashlib

    out = {}
    for ev in case.get("evidence", []):
        path = Path(ev["path"])
        if not path.exists():
            raise FileNotFoundError(f"Evidence missing: {path}")
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(8 << 20), b""):
                h.update(chunk)
        out[str(path)] = {
            "expected_sha256": ev.get("sha256"),
            "actual_sha256": h.hexdigest(),
            "size_bytes": path.stat().st_size,
        }
        out[str(path)]["match"] = (
            out[str(path)]["actual_sha256"] == ev.get("sha256")
        )
    return out


def _write_mcp_config(audit_dir: Path, evidence_root: str, target_path: Path) -> None:
    """Write the Claude-Code MCP server config that points at sift-mcp."""
    config = {
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
    target_path.write_text(json.dumps(config, indent=2))


# Built-in Claude Code tools we explicitly deny so the agent has ONLY our MCP
# tools available. Architectural enforcement of trust boundary TB1.
DISALLOWED_BUILTINS = " ".join([
    "Bash", "Edit", "Write", "Read", "NotebookEdit",
    "WebFetch", "WebSearch",
    "Agent",            # disallow subagent recursion
    "Skill",            # don't accidentally pull the Protocol SIFT skill files
    "AskUserQuestion",  # autonomous run; no human-in-the-loop
])

# Claude Code requires explicit allow-listing for MCP tools too — the same
# permission system that gates Bash gates `mcp__<server>__<tool>`. The first
# v0 run (20260509T164738Z) failed because we hadn't allow-listed these:
# all 5 attempted calls returned permission_denials.
ALLOWED_MCP_TOOLS = " ".join([
    "mcp__sift-owl__vol3_image_info",
    "mcp__sift-owl__vol3_psscan",
    "mcp__sift-owl__vol3_pstree",
    "mcp__sift-owl__vol3_cmdline",
    "mcp__sift-owl__vol3_netscan",
    "mcp__sift-owl__vol3_filescan",
    "mcp__sift-owl__vol3_malfind",
    "mcp__sift-owl__vol3_svcscan",
    "mcp__sift-owl__vol3_userassist",
])


@app.callback(invoke_without_command=True)
def main(
    case: str = typer.Option(..., "--case"),
    model: str = typer.Option("sonnet", "--model"),
    max_budget_usd: float = typer.Option(5.0, "--max-budget-usd"),
    max_turns: int = typer.Option(80, "--max-turns"),
    skip_post_hash: bool = typer.Option(False, "--skip-post-hash"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    if shutil.which("claude") is None:
        raise RuntimeError("`claude` CLI not on PATH")
    if shutil.which("sift-mcp") is None:
        raise RuntimeError("`sift-mcp` not on PATH (run `pip install -e .`)")
    if not PROMPT_PATH.exists():
        raise FileNotFoundError(f"prompt missing: {PROMPT_PATH}")

    case_data = _load_case(case)
    evidence_dir = case_data["evidence_dir"]

    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{model}"
    out_dir = REPO_ROOT / "eval" / "results" / case / "sift-owl-v0" / run_id
    audit_dir = out_dir / "audit"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_dir.mkdir(parents=True, exist_ok=True)

    transcript_path = out_dir / "transcript.jsonl"
    summary_path = out_dir / "summary.json"
    tool_calls_path = out_dir / "tool_calls.jsonl"
    final_response_path = out_dir / "final_response.md"
    meta_path = out_dir / "run_meta.json"
    mcp_config_path = out_dir / "mcp_config.json"

    _write_mcp_config(
        audit_dir=audit_dir,
        evidence_root=evidence_dir,
        target_path=mcp_config_path,
    )
    prompt_text = PROMPT_PATH.read_text()

    console.log("[bold]Hashing evidence (pre-run)...[/]")
    pre_hashes = _verify_evidence_unchanged(case_data)
    for p, info in pre_hashes.items():
        if not info["match"]:
            raise RuntimeError(f"pre-run hash mismatch for {p}")
    console.log("[green]Pre-run hashes match.[/]")

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

    meta = {
        "run_id": run_id,
        "case": case,
        "model": model,
        "max_budget_usd": max_budget_usd,
        "max_turns": max_turns,
        "started_utc": _now_iso(),
        "cwd": str(out_dir),  # note: NOT the evidence dir — agent has no FS anyway
        "evidence_dir": evidence_dir,
        "pre_run_hashes": pre_hashes,
        "claude_version": subprocess.check_output(
            ["claude", "--version"], text=True
        ).strip(),
        "sift_mcp_inspect": subprocess.check_output(
            ["sift-mcp", "inspect", "--audit-dir", str(audit_dir),
             "--evidence-root", evidence_dir], text=True,
        ),
        "disallowed_builtins": DISALLOWED_BUILTINS,
        "mcp_config": json.loads(mcp_config_path.read_text()),
        "harness_git_rev": subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True,
        ).stdout.strip() or "unknown",
        "cmd": cmd,
    }

    if dry_run:
        meta["dry_run"] = True
        meta_path.write_text(json.dumps(meta, indent=2, default=str))
        console.print("[yellow]DRY RUN — not invoking claude.[/]")
        console.print_json(data={
            "run_id": run_id, "case": case, "model": model,
            "max_budget_usd": max_budget_usd,
            "audit_dir": str(audit_dir),
            "out_dir": str(out_dir),
            "disallowed_builtins": DISALLOWED_BUILTINS,
        })
        return

    console.log(f"[bold]Launching SIFT-OWL v0 on {case}[/]")
    console.log(f"[dim]Output → {out_dir}[/]")
    t_start = time.time()

    proc = subprocess.Popen(
        cmd,
        # IMPORTANT: launch from the *output* dir, NOT the evidence dir. The
        # agent has Bash/Write/Edit/Read disabled anyway, but cwd pinning
        # keeps Claude Code's auto-discovery (CLAUDE.md, .mcp.json, etc.)
        # from picking up anything in /cases/.
        cwd=out_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    n_lines = 0
    n_tool_uses = 0
    final_text_parts: list[str] = []

    with transcript_path.open("w") as transcript_fh, tool_calls_path.open("w") as tool_fh:
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                transcript_fh.write(line); transcript_fh.flush()
                n_lines += 1
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
                            }) + "\n")
                            tool_fh.flush()
                        elif blk.get("type") == "text":
                            txt = blk.get("text", "")
                            if txt:
                                final_text_parts.append(txt)
                if evt.get("type") == "result":
                    meta["result_event"] = evt
        except KeyboardInterrupt:
            console.print("[yellow]Interrupted; terminating claude[/]")
            proc.terminate(); proc.wait(timeout=10)
            raise

    rc = proc.wait()
    t_end = time.time()

    final_response_path.write_text(
        "\n\n".join(final_text_parts) if final_text_parts else ""
    )

    summary = {
        "run_id": run_id,
        "case": case,
        "model": model,
        "exit_code": rc,
        "wall_seconds": round(t_end - t_start, 2),
        "transcript_lines": n_lines,
        "tool_use_count": n_tool_uses,
        "result": meta.get("result_event", {}),
    }
    summary_path.write_text(json.dumps(summary, indent=2))

    if not skip_post_hash:
        console.log("[bold]Hashing evidence (post-run)...[/]")
        post = _verify_evidence_unchanged(case_data)
        meta["post_run_hashes"] = post
        meta["evidence_unchanged"] = all(i["match"] for i in post.values())
        if not meta["evidence_unchanged"]:
            console.print("[bold red]EVIDENCE SPOLIATION DETECTED[/]")

    meta["finished_utc"] = _now_iso()
    meta_path.write_text(json.dumps(meta, indent=2, default=str))

    console.print(f"[bold green]SIFT-OWL v0 run complete.[/] → {out_dir}")
    console.print_json(data=summary)


if __name__ == "__main__":
    app()
