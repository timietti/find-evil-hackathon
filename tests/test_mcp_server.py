"""End-to-end tests for the FastMCP server.

Spawns `sift-mcp` as a subprocess and connects via the official MCP stdio
client. Validates:

1. Protocol-only: server starts, initialises, lists exactly 9 tools, all
   with the names we registered. Fast (no evidence file required).

2. Round-trip: a `vol3_image_info` MCP call against the ROCBA-001 evidence
   returns a parsed result matching what the in-process function returned
   in `test_vol3_image_info.py`. Gated on evidence presence.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROCBA_IMG = Path("/cases/find-evil-test/Rocba-Memory.raw")
HAS_VOL = shutil.which("vol") is not None
HAS_IMG = ROCBA_IMG.exists()
HAS_SIFT_MCP = shutil.which("sift-mcp") is not None

REQUIRES_E2E = pytest.mark.skipif(
    not (HAS_VOL and HAS_IMG and HAS_SIFT_MCP),
    reason="needs sift-mcp on PATH, vol on PATH, and ROCBA-001 evidence",
)
REQUIRES_SERVER = pytest.mark.skipif(
    not HAS_SIFT_MCP, reason="sift-mcp not on PATH (run `pip install -e .`)"
)

EXPECTED_TOOLS = {
    "vol3_image_info",
    "vol3_psscan",
    "vol3_pstree",
    "vol3_cmdline",
    "vol3_netscan",
    "vol3_filescan",
    "vol3_malfind",
    "vol3_svcscan",
    "vol3_userassist",
}


def _server_params(audit_dir: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command="sift-mcp",
        args=["--audit-dir", str(audit_dir)],
        env={**os.environ},
    )


@REQUIRES_SERVER
@pytest.mark.asyncio
async def test_mcp_server_lists_all_9_tools(tmp_path: Path) -> None:
    """Protocol-only: spawn server, init, list tools. No evidence needed."""
    async with stdio_client(_server_params(tmp_path / "audit")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_resp = await session.list_tools()
            names = {t.name for t in tools_resp.tools}
    assert names == EXPECTED_TOOLS, (
        f"missing or unexpected tools.\n"
        f"  expected: {sorted(EXPECTED_TOOLS)}\n"
        f"  got:      {sorted(names)}"
    )


@REQUIRES_SERVER
@pytest.mark.asyncio
async def test_mcp_server_tool_schemas_have_image_arg(tmp_path: Path) -> None:
    """Every registered tool exposes a single `image: str` arg."""
    async with stdio_client(_server_params(tmp_path / "audit")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_resp = await session.list_tools()
            for tool in tools_resp.tools:
                schema = tool.inputSchema
                assert "image" in (schema.get("properties") or {}), (
                    f"tool {tool.name} missing `image` property: {schema}"
                )


@REQUIRES_E2E
@pytest.mark.asyncio
async def test_mcp_server_vol3_image_info_round_trip(tmp_path: Path) -> None:
    """End-to-end: call vol3_image_info over the wire, assert ROCBA profile.

    This is the real proof-of-life — proves the server can validate paths,
    invoke Vol3, parse the output, audit-log, and serialise the result back
    over the MCP wire protocol.
    """
    audit_dir = tmp_path / "audit"
    async with stdio_client(_server_params(audit_dir)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "vol3_image_info",
                arguments={"image": str(ROCBA_IMG)},
            )

    # FastMCP returns a CallToolResult with content blocks; the structured
    # result for a tool returning a dict is in `structuredContent`.
    assert result.isError is False, f"tool error: {result}"

    payload = result.structuredContent
    assert payload is not None, "expected structuredContent for dict-returning tool"
    # FastMCP wraps non-{} dicts under a `result` key — handle both shapes.
    if "result" in payload and isinstance(payload["result"], dict):
        payload = payload["result"]

    assert payload["os"] == "Windows 10/11"
    assert payload["build"] == "19041"
    assert payload["arch"] == "x64"
    assert payload["cpus"] == 4
    assert payload["system_time_utc"] == "2020-11-16T02:32:38Z"
    assert payload["symbols_resolved"] is True
    assert payload["exec_id"]

    # The audit log on disk should have exactly one row, matching the exec_id.
    log_path = audit_dir / "exec_log.jsonl"
    assert log_path.exists(), "audit log was not created"
    rows = [
        json.loads(line)
        for line in log_path.read_text().splitlines()
        if line.strip()
    ]
    assert len(rows) == 1
    assert rows[0]["tool"] == "vol3_image_info"
    assert rows[0]["exec_id"] == payload["exec_id"]
