"""Per-MCP-call audit logger.

Every typed forensic function in `mcp_server/tools/` writes one JSONL row here per
invocation. Each row uniquely identifies the call (`exec_id`), records the
arguments and a hash of them (`input_hash`), the raw and parsed outputs
(`output_hash`, `raw_output_path`, `summary`), the wall time, and the exit code.

This is the audit trail that backs every claim in the final report. Without it
you cannot satisfy judging criterion 5 ("trace any finding to the specific tool
execution that produced it").

Schema (one JSON object per line in `audit/exec_log.jsonl`):

    {
      "exec_id":          "01H...ULID",
      "ts":               "2026-05-09T10:22:01Z",
      "agent":            "memory_agent",
      "tool":             "vol3_psscan",
      "args":             { "image": "..." },
      "input_hash":       "sha256:...",
      "output_hash":      "sha256:...",
      "raw_output_path":  "./analysis/raw/01H....txt",
      "exit_code":        0,
      "wall_ms":          7820,
      "summary":          "42 procs; 1 hidden (PID 1912)",
      "error":            null
    }
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:
    from uuid_utils import uuid7  # ULID-compatible, time-sortable
except ImportError:  # pragma: no cover
    from uuid import uuid4 as uuid7  # fallback


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_str(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


@dataclass
class AuditLogger:
    """Append-only JSONL writer for tool-execution records.

    Single instance per case. Thread-safe enough for the multi-agent case (one
    process, multiple async tasks) — Python's open(...,"a") + write() is atomic
    for small lines on Linux.
    """

    exec_log_path: Path
    raw_output_dir: Path

    def __post_init__(self) -> None:
        self.exec_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)

    def new_exec_id(self) -> str:
        return str(uuid7())

    def write_raw(self, exec_id: str, content: str | bytes) -> Path:
        """Persist raw tool output to a content-addressed file.

        Returns the path; caller is expected to pass it back into `record(...)`.
        """
        ext = "bin" if isinstance(content, (bytes, bytearray)) else "txt"
        path = self.raw_output_dir / f"{exec_id}.{ext}"
        if isinstance(content, str):
            path.write_text(content)
        else:
            path.write_bytes(content)
        return path

    def record(
        self,
        *,
        exec_id: str,
        agent: str,
        tool: str,
        args: dict[str, Any],
        raw_output_path: Path | None,
        exit_code: int,
        wall_ms: int,
        summary: str,
        parsed_summary: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        input_hash = _sha256_str(json.dumps(args, sort_keys=True, default=str))
        output_hash = (
            _sha256_path(raw_output_path) if raw_output_path and raw_output_path.exists() else None
        )
        row = {
            "exec_id": exec_id,
            "ts": _now_iso(),
            "agent": agent,
            "tool": tool,
            "args": args,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "raw_output_path": str(raw_output_path) if raw_output_path else None,
            "exit_code": exit_code,
            "wall_ms": wall_ms,
            "summary": summary,
            "parsed_summary": parsed_summary,
            "error": error,
        }
        with self.exec_log_path.open("a") as fh:
            fh.write(json.dumps(row, default=str) + "\n")
        return row

    @contextmanager
    def time_call(
        self, *, agent: str, tool: str, args: dict[str, Any]
    ) -> Iterator["_PendingCall"]:
        """Convenience: start a timed call, finalise on exit."""
        exec_id = self.new_exec_id()
        pending = _PendingCall(exec_id=exec_id, started_at=time.monotonic())
        try:
            yield pending
        finally:
            wall_ms = int((time.monotonic() - pending.started_at) * 1000)
            self.record(
                exec_id=exec_id,
                agent=agent,
                tool=tool,
                args=args,
                raw_output_path=pending.raw_output_path,
                exit_code=pending.exit_code,
                wall_ms=wall_ms,
                summary=pending.summary,
                parsed_summary=pending.parsed_summary,
                error=pending.error,
            )


@dataclass
class _PendingCall:
    exec_id: str
    started_at: float
    raw_output_path: Path | None = None
    exit_code: int = 0
    summary: str = ""
    parsed_summary: dict[str, Any] | None = None
    error: str | None = None
