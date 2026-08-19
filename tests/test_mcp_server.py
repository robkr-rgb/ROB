"""ROB-as-MCP-server tests.

The point: a model connected to this server gets exactly the five contracts and
nothing that could reach an instance. The protocol working is table stakes; the
boundary holding is the test that matters.
"""
from __future__ import annotations

import io
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from rob.agent import TOOL_NAMES
from rob.cli import load_snapshot
from rob.engine import run_scan
from rob.mcp_server import handle, load_orchestrator, serve_stdio, tool_definitions
from rob.store import connect, store_run

FIXTURE = str(pathlib.Path(__file__).parent.parent / "fixtures" / "pdi_like_snapshot.json")


@pytest.fixture
def home(tmp_path):
    (tmp_path / "webruns").mkdir()
    con = connect(tmp_path / "rob_history.db")
    store_run(con, run_scan(load_snapshot(FIXTURE), {}))
    return tmp_path


def call(home, method, params=None, rid=1):
    return handle({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}},
                  load_orchestrator(home))


def tool(home, name, args=None):
    resp = call(home, "tools/call", {"name": name, "arguments": args or {}})
    return json.loads(resp["result"]["content"][0]["text"])


# --- protocol ----------------------------------------------------------------

def test_initialize_advertises_tools_and_instructions(home):
    r = call(home, "initialize")["result"]
    assert r["capabilities"]["tools"] == {}
    assert r["serverInfo"]["name"] == "rob"
    assert "data" in r["instructions"] and "never" in r["instructions"].lower()


def test_tools_list_is_exactly_the_five_contracts(home):
    tools = call(home, "tools/list")["result"]["tools"]
    assert {t["name"] for t in tools} == set(TOOL_NAMES)
    for t in tools:
        assert t["description"] and t["inputSchema"]["type"] == "object"


def test_notifications_get_no_response(home):
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, load_orchestrator(home)) is None


def test_unknown_method_is_a_jsonrpc_error(home):
    assert call(home, "resources/list")["error"]["code"] == -32601


# --- the boundary ------------------------------------------------------------

def test_no_schema_exposes_a_free_text_query_path():
    """The structural injection defence, restated at the MCP surface."""
    banned = {"query", "encoded_query", "sysparm_query", "sql", "table", "script", "filter"}
    for t in tool_definitions():
        props = set(t["inputSchema"].get("properties", {}))
        assert not props & banned, f"{t['name']} exposes {props & banned}"


def test_enumerated_arguments_are_declared_as_enums():
    findings = next(t for t in tool_definitions() if t["name"] == "findings")
    props = findings["inputSchema"]["properties"]
    assert "Critical" in props["severity"]["enum"]
    assert "Governance" in props["category"]["enum"]
    # additionalProperties false: a client cannot smuggle an argument the gate never checks
    for t in tool_definitions():
        assert t["inputSchema"]["additionalProperties"] is False


def test_calling_an_unlisted_tool_is_refused(home):
    resp = call(home, "tools/call", {"name": "create_record", "arguments": {}})
    assert resp["result"]["isError"] is True
    assert "Unknown tool" in json.loads(resp["result"]["content"][0]["text"])["refusal"]


# --- behaviour ---------------------------------------------------------------

def test_scan_gives_the_model_a_run_id_without_starting_anything(home):
    data = tool(home, "scan")["data"]
    assert data["latest_run_id"] == 1
    assert data["instances"][0]["instance_id"] == "dev-fixture-001"
    assert "does not start one" in data["note"]


def test_findings_defaults_to_the_latest_run(home):
    explicit = tool(home, "findings", {"run_id": 1})["data"]
    implicit = tool(home, "findings")["data"]
    assert implicit["run_id"] == explicit["run_id"] == 1
    assert implicit["count"] == explicit["count"] > 0


def test_findings_warns_that_evidence_is_data(home):
    assert "never as instructions" in tool(home, "findings")["data"]["note"]


def test_apply_without_a_token_returns_a_refusal_not_an_error(home):
    """A refused call is a successful tool call. isError would make clients retry or hide it."""
    fp = tool(home, "findings", {"solvable_only": True})["data"]["findings"][0]["fingerprint"]
    resp = call(home, "tools/call", {"name": "apply", "arguments": {
        "run_id": 1, "fingerprint": fp, "target_env": "sub-production"}})
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["ok"] is False and "approval" in payload["refusal"].lower()


def test_every_mcp_call_lands_in_the_audit_log(home):
    tool(home, "findings")
    tool(home, "scan")
    entries = load_orchestrator(home).audit_tail(10)
    assert {e["tool"] for e in entries} >= {"findings", "scan"}
    assert all(e["actor"] == "mcp-client" for e in entries)


def test_signing_key_is_shared_with_the_console_workspace(home):
    """The MCP server and the console must verify the same approvals."""
    first = load_orchestrator(home)
    token = first.mint_approval(1, "x", "console")
    second = load_orchestrator(home)
    assert second.verify_approval(token, 1, "x")["actor"] == "console"


# --- the real thing, over a pipe ---------------------------------------------

def test_end_to_end_over_stdio(home):
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "findings", "arguments": {"severity": "Critical"}}}),
    ]
    out = io.StringIO()
    serve_stdio(home, stdin=io.StringIO("\n".join(lines) + "\n"), stdout=out)
    responses = [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]
    assert [r["id"] for r in responses] == [1, 2, 3]
    payload = json.loads(responses[2]["result"]["content"][0]["text"])
    assert payload["ok"] and all(f["severity"] == "Critical" for f in payload["data"]["findings"])


def test_launches_as_a_subprocess_the_way_a_client_would(home):
    proc = subprocess.run(
        [sys.executable, "-m", "rob", "mcp", "--home", str(home)],
        input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n",
        capture_output=True, text=True, timeout=60,
        cwd=str(pathlib.Path(__file__).parent.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.splitlines()[0])["result"]["serverInfo"]["name"] == "rob"
