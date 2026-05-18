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
    # vol3 (memory)
    "vol3_image_info",
    "vol3_psscan",
    "vol3_pstree",
    "vol3_cmdline",
    "vol3_netscan",
    "vol3_filescan",
    "vol3_malfind",
    "vol3_svcscan",
    "vol3_userassist",
    "vol3_dlllist",
    "vol3_handles",
    "vol3_scheduled_tasks",
    "vol3_hashdump",
    "vol3_cachedump",
    "vol3_skeleton_key_check",
    "vol3_envars",
    # disk (TSK + EWF)
    "ewf_verify",
    "ewf_info",
    "tsk_partition_table",
    "tsk_fs_stat",
    "tsk_fls_list",
    "tsk_icat_extract",
    # EZ Tools (extract-then-parse)
    "ezt_mft_parse",
    "ezt_shimcache_parse",
    "ezt_evtx_parse",
    "ezt_amcache_parse",
    "ezt_prefetch_parse",
    "ezt_jumplist_parse",
    "ezt_recyclebin_parse",
    "ezt_srum_parse",
    "ezt_task_xml_parse",
    "ezt_persistence_keys_parse",
    # threat hunt + carving + hashing (Phase 3)
    "yara_scan_extract",
    "vol3_vadyarascan",
    "bulk_extract",
    "strings_extract",
    "hash_file",
    # query helper
    "query_rows",
}

# Tools whose first/required arg is `image: str`. Excludes query_rows
# (`exec_id`), and the EZ Tools (which take `extract_exec_id`).
TOOLS_WITH_IMAGE_ARG = EXPECTED_TOOLS - {
    "query_rows",
    "ezt_mft_parse",
    "ezt_shimcache_parse",
    "ezt_evtx_parse",
    "ezt_amcache_parse",
    "ezt_prefetch_parse",
    "ezt_jumplist_parse",
    "ezt_recyclebin_parse",
    "ezt_srum_parse",
    "ezt_task_xml_parse",
    "ezt_persistence_keys_parse",
    "yara_scan_extract",
    "strings_extract",
    "hash_file",
}
TOOLS_WITH_EXTRACT_EXEC_ID_ARG = {
    "ezt_mft_parse",
    "ezt_shimcache_parse",
    "ezt_evtx_parse",
    "ezt_amcache_parse",
    "ezt_prefetch_parse",
    "ezt_jumplist_parse",
    "ezt_recyclebin_parse",
    "ezt_srum_parse",
    "ezt_task_xml_parse",
    "ezt_persistence_keys_parse",
    "yara_scan_extract",
    "strings_extract",
    "hash_file",
}


def _server_params(audit_dir: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command="sift-mcp",
        args=["--audit-dir", str(audit_dir)],
        env={**os.environ},
    )


@REQUIRES_SERVER
@pytest.mark.asyncio
async def test_mcp_server_lists_all_tools(tmp_path: Path) -> None:
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
async def test_mcp_server_tool_schemas(tmp_path: Path) -> None:
    """Every vol3_* tool takes `image: str`; query_rows takes `exec_id: str`."""
    async with stdio_client(_server_params(tmp_path / "audit")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_resp = await session.list_tools()
            for tool in tools_resp.tools:
                props = tool.inputSchema.get("properties") or {}
                if tool.name in TOOLS_WITH_IMAGE_ARG:
                    assert "image" in props, (
                        f"tool {tool.name} missing `image` property: {props}"
                    )
                elif tool.name in TOOLS_WITH_EXTRACT_EXEC_ID_ARG:
                    assert "extract_exec_id" in props, (
                        f"tool {tool.name} missing `extract_exec_id`: {props}"
                    )
                elif tool.name == "query_rows":
                    assert "exec_id" in props, (
                        f"query_rows missing `exec_id` property: {props}"
                    )
                    assert "filter_field" in props
                    assert "filter_value" in props
                    assert "limit" in props
                    assert "offset" in props
                else:
                    pytest.fail(f"unexpected tool {tool.name}")


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


@REQUIRES_E2E
@pytest.mark.asyncio
async def test_mcp_server_psscan_truncates_and_query_rows_drills_in(
    tmp_path: Path,
) -> None:
    """End-to-end: vol3_psscan returns capped rows + query_rows finds one PID.

    Reproduces the exact pattern v0 needed but couldn't perform: get a top-N
    sample from a row-rich plugin, then drill into a specific PID.
    """
    audit_dir = tmp_path / "audit"
    async with stdio_client(_server_params(audit_dir)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Step 1: vol3_psscan — should return ≤ 50 rows + truncation flags.
            ps_result = await session.call_tool(
                "vol3_psscan",
                arguments={"image": str(ROCBA_IMG)},
            )
            assert ps_result.isError is False
            payload = ps_result.structuredContent
            if "result" in payload and isinstance(payload["result"], dict):
                payload = payload["result"]

            assert payload["count"] >= 50  # ROCBA has 2200+ procs
            assert len(payload["processes"]) <= 50
            assert payload.get("processes_truncated") is True
            assert payload["processes_total"] == payload["count"]
            ps_exec_id = payload["exec_id"]
            assert ps_exec_id

            # Step 2: query_rows for PID 4 (System) — must succeed.
            q_result = await session.call_tool(
                "query_rows",
                arguments={
                    "exec_id": ps_exec_id,
                    "filter_field": "pid",
                    "filter_value": "4",
                    "limit": 5,
                },
            )
            assert q_result.isError is False
            qpayload = q_result.structuredContent
            if "result" in qpayload and isinstance(qpayload["result"], dict):
                qpayload = qpayload["result"]

            assert qpayload["tool"] == "vol3_psscan"
            assert qpayload["matched_rows"] == 1, (
                f"expected exactly 1 PID 4 match; got {qpayload['matched_rows']}"
            )
            assert qpayload["rows"][0]["pid"] == 4
            assert qpayload["rows"][0]["image"] == "System"

            # Step 3: query_rows substring match on image="csrss" — at least 1.
            q2 = await session.call_tool(
                "query_rows",
                arguments={
                    "exec_id": ps_exec_id,
                    "filter_field": "image",
                    "filter_value": "csrss",
                },
            )
            qp2 = q2.structuredContent
            if "result" in qp2 and isinstance(qp2["result"], dict):
                qp2 = qp2["result"]
            assert qp2["matched_rows"] >= 1
            assert all("csrss" in r["image"].lower() for r in qp2["rows"])

            # Step 4: query_rows for nonexistent exec_id — should error cleanly.
            qbad = await session.call_tool(
                "query_rows",
                arguments={
                    "exec_id": "01H0000000000000000000000000",
                    "filter_field": "pid",
                    "filter_value": "1",
                },
            )
            assert qbad.isError is True
