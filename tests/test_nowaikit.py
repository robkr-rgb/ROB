"""NowAIKit integration tests against a fake MCP server.

What matters here is not that a query works. It is that:
  - a write tool the server offers is still unreachable from ROB
  - a capped read is declared as a gap rather than silently truncated
  - the agent's five tool contracts do not grow because this path exists
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from rob.nowaikit import (
    ALLOWED_TOOLS,
    MCP_ROW_LIMIT,
    NowAIKitClient,
    NowAIKitError,
    ToolNotPermitted,
)

FAKE = str(pathlib.Path(__file__).parent / "fake_nowaikit.py")


@pytest.fixture
def client():
    c = NowAIKitClient.stdio([sys.executable, FAKE])
    yield c
    c.close()


def test_handshake_lists_tools(client):
    assert "query_records" in client.tool_names
    assert len(client.tool_names) >= 7


def test_read_returns_normalised_records(client):
    rows = client.rows("sys_script", ["sys_id", "name", "active"])
    assert len(rows) == 2 and rows[0]["name"] == "Rule A"


def test_count_uses_aggregate(client):
    assert client.count("sys_script") == 2


def test_write_tools_are_unreachable_even_though_the_server_offers_them(client):
    """The server exposes create_record and update_record. ROB still cannot call them."""
    assert "create_record" in client.tool_names
    for tool in ("create_record", "update_record", "delete_record"):
        with pytest.raises(ToolNotPermitted) as exc:
            client.call(tool, {"table": "incident", "fields": {"state": "7"}})
        assert "read allowlist" in str(exc.value)


def test_allowlist_contains_no_write_verbs():
    for tool in ALLOWED_TOOLS:
        assert not tool.startswith(("create_", "update_", "delete_", "commit_", "publish_", "switch_"))


def test_default_cap_matches_the_native_extractor(client):
    """A caller who omits cap must get the gap, not a silent truncation."""
    from rob.extractor import DEFAULT_CAP
    from rob.nowaikit import DEFAULT_CAP as MCP_DEFAULT

    assert MCP_DEFAULT == DEFAULT_CAP > MCP_ROW_LIMIT
    assert client.rows("cmdb_ci", ["sys_id", "name"]) == []
    assert any("exposes no offset" in e for e in client.access_errors)


def test_capped_read_is_declared_a_gap_not_truncated(client):
    """A silently truncated CMDB read would produce confident, wrong findings."""
    rows = client.rows("cmdb_ci", ["sys_id", "name"], cap=50000)
    assert rows == [], "a capped read must return nothing, so dependent rules go silent"
    assert any("exposes no offset" in e for e in client.access_errors)
    assert any("cmdb_ci" in e for e in client.access_errors)


def test_small_table_under_the_cap_is_returned_normally(client):
    assert len(client.rows("sys_report", ["sys_id", "title", "is_public"], cap=20000)) == 1
    assert not client.access_errors


def test_missing_table_degrades_per_table(client):
    assert client.rows("sys_not_extracted", ["sys_id"]) == []
    assert client.count("sys_script") == 2, "one table's outcome must not poison the next"


def test_capability_report_states_the_binding_limit(client):
    report = client.capability_report()
    assert report["supports_offset"] is False
    assert report["row_limit_per_call"] == MCP_ROW_LIMIT
    assert "create_record" in report["write_tools_present"]
    assert not report["read_tools_missing"]
    assert "Not suitable as the bulk extraction path" in report["verdict"]


def test_unknown_tool_on_the_allowlist_still_fails_closed(client):
    client.tool_names = {"query_records"}
    with pytest.raises(NowAIKitError):
        client.call("get_table_schema", {"table": "incident"})


def test_agent_surface_does_not_grow_because_of_this_path():
    """D-012 holds: adding a data path must not add an agent capability."""
    from rob.agent import TOOL_NAMES, tool_schemas

    assert TOOL_NAMES == ("scan", "findings", "fixpack", "apply", "baseline_diff")
    names = {s["name"] for s in tool_schemas()}
    assert not names & set(ALLOWED_TOOLS)


def test_snapshot_shape_is_unchanged_by_the_transport(client):
    """Rules must not be able to tell which path fetched the data."""
    from rob.extractor import build_snapshot

    snap = build_snapshot(client, "mcp-instance", progress=lambda *_: None)
    assert snap["instance_id"] == "mcp-instance"
    assert "sys_script" in snap["tables"]
    assert isinstance(snap["aggregates"].get("extraction_errors"), list)
    assert any("cmdb_ci" in e for e in snap["aggregates"]["extraction_errors"])
