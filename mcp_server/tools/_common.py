"""Shared helpers for typed MCP tool functions.

Two responsibilities:

1. **Path validation** — every evidence path passed in by an agent must resolve
   inside an allowed root (default `/cases/`). Symlinks are resolved before the
   prefix check, so `/cases/foo -> /etc/passwd` is rejected.

2. **Subprocess invocation** — never use `shell=True`. Build argv as a list,
   stream stdout to a file (so 100 MB Vol3 outputs don't sit in RAM), enforce a
   hard wall-clock timeout, and return a `RunResult` that audit can log.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator


# Allow-list of evidence roots. SIFT-OWL refuses to operate on paths outside these.
DEFAULT_EVIDENCE_ROOTS: tuple[Path, ...] = (
    Path("/cases").resolve(),
)


class PathValidationError(ValueError):
    """Raised when a caller-supplied path falls outside the allow-list."""


class ToolError(RuntimeError):
    """Raised when a forensic tool subprocess fails (non-zero exit, timeout)."""


def validate_evidence_path(
    path: str | os.PathLike[str],
    *,
    must_exist: bool = True,
    allowed_roots: tuple[Path, ...] = DEFAULT_EVIDENCE_ROOTS,
) -> Path:
    """Resolve and validate an evidence path.

    - Resolves symlinks.
    - Asserts the resolved path is inside one of `allowed_roots`.
    - Asserts existence by default.

    Returns the resolved Path.
    """
    raw = Path(path)
    try:
        resolved = raw.resolve(strict=must_exist)
    except FileNotFoundError as exc:
        raise PathValidationError(f"Evidence path does not exist: {raw}") from exc

    for root in allowed_roots:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise PathValidationError(
        f"Path {resolved} is outside allowed evidence roots {[str(r) for r in allowed_roots]}"
    )


@dataclass
class RunResult:
    """Outcome of a single forensic-tool subprocess run."""

    argv: list[str]
    exit_code: int
    wall_ms: int
    stdout_path: Path
    stderr_path: Path
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def run_subprocess(
    argv: list[str],
    *,
    output_dir: Path,
    name: str,
    timeout_s: float = 600,
    env: dict[str, str] | None = None,
) -> RunResult:
    """Run a forensic CLI as a subprocess. Stdout/stderr stream to disk.

    `argv` MUST be a list (no `shell=True`). `output_dir` is created if missing.
    `name` is used to build the output file basenames (`{name}.stdout`, `{name}.stderr`).
    """
    if not argv or not isinstance(argv, list):
        raise ValueError("argv must be a non-empty list")
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / f"{name}.stdout"
    stderr_path = output_dir / f"{name}.stderr"

    started = time.monotonic()
    timed_out = False
    error: str | None = None
    rc = -1

    with stdout_path.open("wb") as out_fh, stderr_path.open("wb") as err_fh:
        try:
            proc = subprocess.Popen(
                argv,
                stdout=out_fh,
                stderr=err_fh,
                env=env if env is not None else os.environ.copy(),
            )
            try:
                rc = proc.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                proc.wait(timeout=10)
                rc = -1
                error = f"timeout after {timeout_s}s"
        except FileNotFoundError as exc:
            error = f"executable not found: {argv[0]} ({exc})"
        except Exception as exc:  # noqa: BLE001 — surface anything as audit-loggable error
            error = f"{type(exc).__name__}: {exc}"

    wall_ms = int((time.monotonic() - started) * 1000)
    return RunResult(
        argv=argv,
        exit_code=rc,
        wall_ms=wall_ms,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timed_out=timed_out,
        error=error,
    )


# ---------------------------------------------------------------------------
# Pydantic models — every typed MCP function defines its input schema here so
# that the function signature is enforced *before* we touch the filesystem.
# ---------------------------------------------------------------------------


class _StrictModel(BaseModel):
    """Reject unknown fields; agents must use the published schema."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ImageInfoArgs(_StrictModel):
    """Input schema for `vol3_image_info`."""

    image: str = Field(description="Absolute path to the memory image file.")

    @field_validator("image")
    @classmethod
    def _check_image(cls, v: str) -> str:
        if not v:
            raise ValueError("image must be a non-empty path")
        return v


class _ImageOnlyArgs(_StrictModel):
    """Shared schema for plugins that take only an image path."""

    image: str = Field(description="Absolute path to the memory image file.")


class PsScanArgs(_ImageOnlyArgs):
    pass


class PsTreeArgs(_ImageOnlyArgs):
    pass


class CmdlineArgs(_ImageOnlyArgs):
    """Cmdline can optionally narrow to a single PID, but we expose all-procs only.

    Per-PID filtering re-parses the same memory regions; the agent should run
    once and slice the parsed output rather than burning a Vol3 invocation per
    PID. If we ever need filtered output, add `pid: int | None` here.
    """


class NetScanArgs(_ImageOnlyArgs):
    pass


class FileScanArgs(_ImageOnlyArgs):
    pass


class MalfindArgs(_ImageOnlyArgs):
    pass


class SvcScanArgs(_ImageOnlyArgs):
    pass


class UserAssistArgs(_ImageOnlyArgs):
    pass


class DllListArgs(_ImageOnlyArgs):
    """Optional pid filter — narrowing to one PID is much faster + smaller."""

    pid: int | None = Field(
        default=None, ge=0,
        description="Optional PID to narrow to. Omit to enumerate all processes.",
    )


class HandlesArgs(_ImageOnlyArgs):
    """Per-PID required. Scanning all procs is multi-hour on big images."""

    pid: int = Field(
        ge=0,
        description="PID to enumerate handles for. Required — full-system scan is too slow.",
    )


class EnvarsArgs(_ImageOnlyArgs):
    """Environment variables per process. Optional pid filter."""

    pid: int | None = Field(
        default=None, ge=0,
        description="Optional PID to narrow to. Omit to enumerate all processes.",
    )


class ScheduledTasksArgs(_ImageOnlyArgs):
    pass


class HashdumpArgs(_ImageOnlyArgs):
    pass


class CachedumpArgs(_ImageOnlyArgs):
    pass


class SkeletonKeyArgs(_ImageOnlyArgs):
    pass


# ---------------------------------------------------------------------------
# Disk-side args.
# ---------------------------------------------------------------------------


class EwfVerifyArgs(_StrictModel):
    image: str = Field(description="Absolute path to the E01 image.")


class EwfInfoArgs(_StrictModel):
    image: str = Field(description="Absolute path to the E01 image.")


class TskPartitionTableArgs(_StrictModel):
    image: str = Field(description="Absolute path to the E01 image.")


class TskFsStatArgs(_StrictModel):
    image: str = Field(description="Absolute path to the E01 image.")
    offset: int | None = Field(
        default=None, ge=0,
        description=(
            "Partition start sector. Omit for logical-drive images "
            "(those without a partition table)."
        ),
    )


class TskFlsListArgs(_StrictModel):
    image: str = Field(description="Absolute path to the E01 image.")
    offset: int | None = Field(default=None, ge=0)


class TskIcatExtractArgs(_StrictModel):
    image: str = Field(description="Absolute path to the E01 image.")
    inode: int = Field(ge=0, description="Inode / MFT entry number to extract.")
    offset: int | None = Field(default=None, ge=0)


class QueryRowsArgs(_StrictModel):
    """Input schema for the `query_rows` follow-up tool.

    Lets the agent drill into the full row list of a previously-completed
    Vol3 plugin call, by exec_id, with optional filtering and pagination.
    Solves the v0 "tool result overflow" problem: the agent gets the
    summary + top 50 rows from the original call; if it needs to find a
    specific row (e.g. PID 29440 in psscan, or all files matching
    `StarFury` in filescan), it issues a query_rows call.
    """

    exec_id: str = Field(
        description="The `exec_id` of a previously-completed MCP tool call.",
    )
    filter_field: str | None = Field(
        default=None,
        description=(
            "Field name to filter on (e.g. 'pid', 'image', 'name', "
            "'foreign_addr'). Omit for no filter."
        ),
    )
    filter_value: str | None = Field(
        default=None,
        description=(
            "Value to match. For string fields: case-insensitive "
            "substring match. For numeric fields: parsed and compared "
            "as int. For booleans: 'true'/'false'."
        ),
    )
    limit: int = Field(
        default=50,
        ge=1, le=500,
        description="Maximum number of matching rows to return (1..500).",
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Number of leading matching rows to skip.",
    )
