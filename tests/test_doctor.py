"""Doctor tests.

Doctor exists to tell the truth about an installation, so the tests are about
it not lying: a broken rule pack must fail rather than read as missing, an
optional absence must not read as broken, and the MCP contract check must
actually notice if the security boundary changes.
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from rob.doctor import FAIL, NOTE, OK, report, run


def states(home):
    checks, _ = run(home)
    return {c.name: c for c in checks}


def test_a_clean_empty_workspace_has_no_failures(tmp_path):
    checks, failures = run(tmp_path)
    assert failures == 0
    assert all(c.fix for c in checks if c.state == NOTE), "every optional gap must say what it costs"


def test_optional_pieces_are_notes_not_failures(tmp_path):
    s = states(tmp_path)
    for name in ("Executor", "Reference sources", "Scan history"):
        assert s[name].state == NOTE, f"{name} is optional and must not read as broken"
        assert s[name].fix, f"{name} must say what to do"


def test_the_mcp_contract_check_would_notice_a_widened_boundary(monkeypatch):
    """The five contracts are the security boundary. It must not change quietly."""
    import rob.doctor as doctor
    from rob import mcp_server

    # Capture before patching: a replacement that calls the patched name is a
    # recursion, not a test.
    real = mcp_server.tool_definitions

    def widened():
        return real() + [{"name": "run_script", "description": "x",
                          "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}}]

    monkeypatch.setattr(mcp_server, "tool_definitions", widened)
    assert doctor._mcp().state == FAIL


def test_an_open_schema_is_a_failure(monkeypatch):
    """additionalProperties:false is what stops a client smuggling an argument."""
    import copy

    import rob.doctor as doctor
    from rob import mcp_server

    real = mcp_server.tool_definitions

    def leaky():
        tools = copy.deepcopy(real())
        tools[0]["inputSchema"]["additionalProperties"] = True
        return tools

    monkeypatch.setattr(mcp_server, "tool_definitions", leaky)
    check = doctor._mcp()
    assert check.state == FAIL and "extra arguments" in check.detail


def test_a_loose_config_file_is_flagged(tmp_path):
    """The signing key mints approvals, so its file mode matters."""
    cfg = tmp_path / "web_config.json"
    cfg.write_text(json.dumps({"agent_signing_key": "ab" * 32}))
    cfg.chmod(0o644)
    assert states(tmp_path)["Approval signing key"].state == NOTE
    cfg.chmod(0o600)
    assert states(tmp_path)["Approval signing key"].state == OK


def test_a_writable_posture_is_surfaced_not_hidden(tmp_path):
    (tmp_path / "web_config.json").write_text(json.dumps({
        "agent_signing_key": "ab" * 32,
        "autonomy_ceilings": {"_default": "A2"},
        "global_dry_run": False,
        "executor": {"kind": "nowaikit", "command": "x"},
    }))
    s = states(tmp_path)
    assert s["Global dry run"].detail.startswith("OFF")
    assert "Combined posture" in s and "can write" in s["Combined posture"].detail


def test_report_returns_nonzero_only_on_failure(tmp_path, capsys):
    assert report(tmp_path) == 0
    out = capsys.readouterr().out
    assert "ROB is sound" in out and "0 failing" in out
