"""SIFT-OWL v1 harness — fixes the v0 overflow bug.

Same shape as v0 but:
  1. The MCP server now truncates row lists to 50 (DEFAULT_ROW_LIMIT) at the
     boundary, so tool results stay under Claude Code's per-tool-result cap.
  2. Adds `query_rows` to the agent's tool surface so it can drill into the
     full row list of any prior call by exec_id + filter.
  3. Updated prompt teaches the agent the truncation + drill pattern.

Output dir layout, audit log shape, evidence-hash protocol — all match v0
verbatim so the comparison REPORT.md can diff them mechanically.

Usage:
    python -m eval.agents.sift_owl_v1.run \\
        --case rocba-001 --model sonnet --max-budget-usd 5
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
AGENT_DIR = REPO_ROOT / "eval" / "agents" / "sift_owl_v1"
DEFAULT_PROMPT_PATH = AGENT_DIR / "prompt.md"

app = typer.Typer(help="Run SIFT-OWL v1 against a case.")
console = Console()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_case(case_id: str) -> dict:
    case_yaml = REPO_ROOT / "eval" / "cases" / case_id / "case.yaml"
    with case_yaml.open() as fh:
        return yaml.safe_load(fh)


def _evidence_paths(case: dict) -> list[tuple[Path, str | None]]:
    """Collect all evidence paths from a case.yaml regardless of its shape.

    Three case-yaml shapes are recognised:
      * ROCBA-001 style: top-level `evidence: [{path, sha256, ...}]`.
      * STARK-APT style: `hosts: [{disk_image, memory_image, ...}]`,
        with separately-listed `evidence_sha256`.
      * SHIELDBASE style: separate `disk_images:` + `memory_images:` lists.

    Returns list of (path, expected_sha256) tuples.
    """
    out: list[tuple[Path, str | None]] = []

    # Shape 1: flat `evidence` list (ROCBA).
    for ev in case.get("evidence", []) or []:
        out.append((Path(ev["path"]), ev.get("sha256")))

    # Shape 2: `hosts` with disk_image + memory_image (STARK-APT).
    sha_map = case.get("evidence_sha256", {}) or {}
    # We don't know the key naming convention reliably; fall back to None match
    # if the case.yaml didn't tabulate sha256 against host fields.
    for host in case.get("hosts", []) or []:
        for fld in ("disk_image", "memory_image"):
            p = host.get(fld)
            if p:
                # Try to match sha256 by short host id; e.g. "win7_64_nfury_disk"
                hid = host.get("id", "")
                key_d = f"{hid.replace('-', '_')}_disk"
                key_m = f"{hid.replace('-', '_')}_memory"
                expected = sha_map.get(key_d if fld == "disk_image" else key_m)
                out.append((Path(p), expected))

    # Shape 3: split `disk_images` / `memory_images` lists (SHIELDBASE).
    for ev in case.get("disk_images", []) or []:
        out.append((Path(ev["path"]), ev.get("sha256")))
    for ev in case.get("memory_images", []) or []:
        out.append((Path(ev["path"]), ev.get("sha256")))

    # Deduplicate while preserving order
    seen, dedup = set(), []
    for p, s in out:
        if p in seen:
            continue
        seen.add(p)
        dedup.append((p, s))
    return dedup


def _verify_evidence_unchanged(case: dict) -> dict:
    import hashlib
    out = {}
    for path, expected_sha256 in _evidence_paths(case):
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
            "size_bytes":      path.stat().st_size,
            "match":           (expected_sha256 is None) or (actual == expected_sha256),
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


# Built-ins denied — same as v0.
DISALLOWED_BUILTINS = " ".join([
    "Bash", "Edit", "Write", "Read", "NotebookEdit",
    "WebFetch", "WebSearch", "Agent", "Skill", "AskUserQuestion",
])

# Allow-list grew by one (`query_rows`) compared to v0.
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
    # drill helper
    "mcp__sift-owl__query_rows",
])


@app.callback(invoke_without_command=True)
def main(
    case: str = typer.Option(..., "--case"),
    model: str = typer.Option("sonnet", "--model"),
    max_budget_usd: float = typer.Option(5.0, "--max-budget-usd"),
    max_turns: int = typer.Option(80, "--max-turns"),
    prompt_file: str = typer.Option(
        None, "--prompt-file",
        help=(
            "Override prompt file. Defaults to `prompt.md` next to this script "
            "for ROCBA; pass `prompt-test2-stark-apt.md` for STARK-APT-001, etc."
        ),
    ),
    skip_post_hash: bool = typer.Option(False, "--skip-post-hash"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    if shutil.which("claude") is None:
        raise RuntimeError("`claude` CLI not on PATH")
    if shutil.which("sift-mcp") is None:
        raise RuntimeError("`sift-mcp` not on PATH (run `pip install -e .`)")

    prompt_path = Path(prompt_file) if prompt_file else DEFAULT_PROMPT_PATH
    if not prompt_path.is_absolute():
        prompt_path = AGENT_DIR / prompt_path
    if not prompt_path.exists():
        raise FileNotFoundError(f"prompt missing: {prompt_path}")

    case_data = _load_case(case)
    # `evidence_dir` is the path Claude Code uses as the evidence-root for the
    # MCP server's `--evidence-root` allow-list. For multi-host cases it's the
    # parent directory enclosing all host evidence.
    evidence_dir = case_data.get("evidence_dir") or "/cases"

    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{model}"
    out_dir   = REPO_ROOT / "eval" / "results" / case / "sift-owl-v1" / run_id
    audit_dir = out_dir / "audit"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_dir.mkdir(parents=True, exist_ok=True)

    transcript_path     = out_dir / "transcript.jsonl"
    summary_path        = out_dir / "summary.json"
    tool_calls_path     = out_dir / "tool_calls.jsonl"
    final_response_path = out_dir / "final_response.md"
    meta_path           = out_dir / "run_meta.json"
    mcp_config_path     = out_dir / "mcp_config.json"

    _write_mcp_config(
        audit_dir=audit_dir,
        evidence_root=evidence_dir,
        target=mcp_config_path,
    )
    prompt_text = prompt_path.read_text()

    console.log("[bold]Hashing evidence (pre-run)...[/]")
    pre = _verify_evidence_unchanged(case_data)
    for p, info in pre.items():
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
        "run_id":              run_id,
        "case":                case,
        "model":               model,
        "max_budget_usd":      max_budget_usd,
        "max_turns":           max_turns,
        "prompt_file":         str(prompt_path),
        "started_utc":         _now_iso(),
        "cwd":                 str(out_dir),
        "evidence_dir":        evidence_dir,
        "pre_run_hashes":      pre,
        "claude_version": subprocess.check_output(
            ["claude", "--version"], text=True,
        ).strip(),
        "sift_mcp_inspect":    subprocess.check_output(
            ["sift-mcp", "inspect", "--audit-dir", str(audit_dir),
             "--evidence-root", evidence_dir], text=True,
        ),
        "disallowed_builtins": DISALLOWED_BUILTINS,
        "allowed_mcp_tools":   ALLOWED_MCP_TOOLS,
        "mcp_config":          json.loads(mcp_config_path.read_text()),
        "harness_git_rev":     subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True,
        ).stdout.strip() or "unknown",
        "cmd":                 cmd,
    }

    if dry_run:
        meta["dry_run"] = True
        meta_path.write_text(json.dumps(meta, indent=2, default=str))
        console.print("[yellow]DRY RUN — not invoking claude.[/]")
        return

    console.log(f"[bold]Launching SIFT-OWL v1 on {case}[/]")
    console.log(f"[dim]Output → {out_dir}[/]")
    t_start = time.time()

    proc = subprocess.Popen(
        cmd,
        cwd=out_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    n_lines = 0; n_tool_uses = 0
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
                                "ts":    _now_iso(),
                                "tool":  blk.get("name"),
                                "input": blk.get("input"),
                                "id":    blk.get("id"),
                            }) + "\n"); tool_fh.flush()
                        elif blk.get("type") == "text":
                            txt = blk.get("text", "")
                            if txt: final_text_parts.append(txt)
                if evt.get("type") == "result":
                    meta["result_event"] = evt
        except KeyboardInterrupt:
            proc.terminate(); proc.wait(timeout=10); raise

    rc = proc.wait()
    t_end = time.time()

    final_response_path.write_text(
        "\n\n".join(final_text_parts) if final_text_parts else ""
    )

    summary = {
        "run_id":           run_id,
        "case":             case,
        "model":            model,
        "exit_code":        rc,
        "wall_seconds":     round(t_end - t_start, 2),
        "transcript_lines": n_lines,
        "tool_use_count":   n_tool_uses,
        "result":           meta.get("result_event", {}),
    }
    summary_path.write_text(json.dumps(summary, indent=2))

    if not skip_post_hash:
        post = _verify_evidence_unchanged(case_data)
        meta["post_run_hashes"] = post
        meta["evidence_unchanged"] = all(i["match"] for i in post.values())

    meta["finished_utc"] = _now_iso()
    meta_path.write_text(json.dumps(meta, indent=2, default=str))

    console.print(f"[bold green]SIFT-OWL v1 run complete.[/] → {out_dir}")
    console.print_json(data=summary)


if __name__ == "__main__":
    app()
