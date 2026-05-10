"""Protocol SIFT baseline harness.

Invokes vanilla Claude Code (Protocol SIFT global config + skill files) against a case,
captures the full stream-json transcript, and produces structured per-tool-call metrics.

Usage:
    python -m eval.baselines.protocol_sift.run \\
        --case rocba-001 \\
        --model sonnet \\
        --max-budget-usd 5 \\
        --max-turns 80

Output: eval/results/<case_id>/baseline-protocol-sift/<run_id>/
    transcript.jsonl       — raw stream-json from Claude Code
    tool_calls.jsonl       — one row per tool call (parsed from transcript)
    summary.json           — wall_ms, total_tokens, total_cost, tool_call_count, ...
    final_response.md      — agent's final text response
    run_meta.json          — invocation params, environment, evidence hashes
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import typer
import yaml
from rich.console import Console

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PROMPT_PATH = REPO_ROOT / "eval" / "baselines" / "protocol_sift" / "prompt.md"

app = typer.Typer(help="Run the Protocol SIFT baseline.")
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
    """Hash evidence files at session start and end. Return both hashes."""
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


@app.callback(invoke_without_command=True)
def main(
    case: str = typer.Option(..., "--case", help="Case ID, e.g. rocba-001"),
    model: str = typer.Option("sonnet", "--model"),
    max_budget_usd: float = typer.Option(5.0, "--max-budget-usd"),
    max_turns: int = typer.Option(80, "--max-turns"),
    skip_post_hash: bool = typer.Option(
        False,
        "--skip-post-hash",
        help="Skip the post-run evidence-hash verification (saves ~5 min on 18 GB image).",
    ),
    skip_pre_hash: bool = typer.Option(
        False,
        "--skip-pre-hash",
        help="Skip the pre-run hash check. Useful for multi-host cases (~58 GB) "
        "where intake hashes are already canonical.",
    ),
    prompt_file: Path = typer.Option(
        DEFAULT_PROMPT_PATH,
        "--prompt-file",
        help="Prompt to inject as the first user message. Defaults to ROCBA prompt.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print the claude invocation, do not execute."
    ),
) -> None:
    if shutil.which("claude") is None:
        raise RuntimeError("`claude` CLI not on PATH — install Claude Code first.")
    if not prompt_file.exists():
        raise FileNotFoundError(f"Prompt file missing: {prompt_file}")

    case_data = _load_case(case)
    evidence_dir = case_data["evidence_dir"]

    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{model}"
    out_dir = REPO_ROOT / "eval" / "results" / case / "baseline-protocol-sift" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    transcript_path = out_dir / "transcript.jsonl"
    summary_path = out_dir / "summary.json"
    tool_calls_path = out_dir / "tool_calls.jsonl"
    final_response_path = out_dir / "final_response.md"
    meta_path = out_dir / "run_meta.json"

    prompt_text = prompt_file.read_text()

    # Pre-run evidence hash check (validates we have what we expect, no spoliation yet)
    if skip_pre_hash:
        console.log("[yellow]Pre-run hash check skipped (--skip-pre-hash).[/]")
        pre_hashes = {}
    else:
        console.log("[bold]Hashing evidence (pre-run) — this is slow for large images...[/]")
        pre_hashes = _verify_evidence_unchanged(case_data)
        for path, info in pre_hashes.items():
            if not info["match"]:
                raise RuntimeError(
                    f"Evidence hash mismatch BEFORE run for {path}. "
                    f"Expected {info['expected_sha256']}, got {info['actual_sha256']}."
                )
        console.log("[green]Pre-run hashes match.[/]")

    cmd = [
        "claude",
        "-p",
        prompt_text,
        "--model", model,
        "--max-budget-usd", str(max_budget_usd),
        "--max-turns", str(max_turns),
        "--output-format", "stream-json",
        "--include-partial-messages",
        "--include-hook-events",
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
        "cwd": evidence_dir,
        "evidence_dir": evidence_dir,
        "prompt_file": str(prompt_file),
        "pre_run_hashes": pre_hashes,
        "claude_version": subprocess.check_output(
            ["claude", "--version"], text=True
        ).strip(),
        "cmd": cmd,
        "harness_git_rev": subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True,
        ).stdout.strip() or "unknown",
    }

    if dry_run:
        meta["dry_run"] = True
        meta_path.write_text(json.dumps(meta, indent=2))
        console.print("[yellow]DRY RUN — not invoking claude.[/]")
        console.print_json(data=meta)
        return

    # Stream invocation
    console.log(f"[bold]Launching baseline:[/] {' '.join(cmd[:3])} ...")
    console.log(f"[dim]Output → {out_dir}[/]")
    t_start = time.time()

    proc = subprocess.Popen(
        cmd,
        cwd=evidence_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    n_lines = 0
    n_tool_uses = 0
    final_text_parts: list[str] = []

    with transcript_path.open("w") as transcript_fh, tool_calls_path.open(
        "w"
    ) as tool_fh:
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                transcript_fh.write(line)
                transcript_fh.flush()
                n_lines += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Capture tool uses
                if evt.get("type") == "assistant":
                    msg = evt.get("message") or {}
                    for blk in msg.get("content", []) or []:
                        if blk.get("type") == "tool_use":
                            n_tool_uses += 1
                            tool_fh.write(
                                json.dumps(
                                    {
                                        "ts": _now_iso(),
                                        "tool": blk.get("name"),
                                        "input": blk.get("input"),
                                        "id": blk.get("id"),
                                    }
                                )
                                + "\n"
                            )
                            tool_fh.flush()
                        elif blk.get("type") == "text":
                            txt = blk.get("text", "")
                            if txt:
                                final_text_parts.append(txt)
                # Result message at the end has total cost / tokens
                if evt.get("type") == "result":
                    meta["result_event"] = evt
        except KeyboardInterrupt:
            console.print(
                "[yellow]Interrupted — terminating claude subprocess.[/]"
            )
            proc.terminate()
            proc.wait(timeout=10)
            raise

    rc = proc.wait()
    t_end = time.time()

    # Concatenate final text (best-effort; final response is the last text block sequence)
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

    # Post-run evidence hash verification (chain of custody)
    if not skip_post_hash:
        console.log("[bold]Hashing evidence (post-run)...[/]")
        post_hashes = _verify_evidence_unchanged(case_data)
        meta["post_run_hashes"] = post_hashes
        meta["evidence_unchanged"] = all(
            info["match"] for info in post_hashes.values()
        )
        if not meta["evidence_unchanged"]:
            console.print("[bold red]EVIDENCE SPOLIATION DETECTED ![/]")
        else:
            console.log("[green]Post-run hashes match — evidence intact.[/]")

    meta["finished_utc"] = _now_iso()
    meta_path.write_text(json.dumps(meta, indent=2))

    console.print(f"[bold green]Baseline run complete.[/] → {out_dir}")
    console.print_json(data=summary)


if __name__ == "__main__":
    app()
