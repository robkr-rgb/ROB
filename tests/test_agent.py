"""Agent orchestrator tests (D-012).

The point of these is not that the happy path works. It is that the refusals
hold: a forged approval, a borrowed approval, an expired one, a production
target, an unmeasured rule, an instance below the required autonomy ceiling,
and an argument the agent invented. Every one of those must be refused, and
every attempt must land in the audit log.
"""
from __future__ import annotations

import datetime as dt
import http.client
import json
import pathlib
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from http.server import ThreadingHTTPServer

from rob.agent import (
    APPROVAL_TTL_SECONDS,
    TOOL_NAMES,
    ApprovalError,
    Orchestrator,
    tool_schemas,
)
from rob.cli import load_snapshot
from rob.engine import run_scan
from rob.store import connect, store_run
from rob.web import AppState, make_handler

FIXTURE = str(pathlib.Path(__file__).parent.parent / "fixtures" / "pdi_like_snapshot.json")
KEY = bytes.fromhex("ab" * 32)


@pytest.fixture(scope="module")
def orch(tmp_path_factory):
    home = tmp_path_factory.mktemp("agenthome")
    (home / "webruns").mkdir()
    (home / "baselines").mkdir()
    result = run_scan(load_snapshot(FIXTURE), {})
    con = connect(home / "rob_history.db")
    run_id = store_run(con, result)
    o = Orchestrator(home, KEY, {"global_dry_run": True, "autonomy_ceilings": {"_default": "A1"}})
    o.run_id = run_id
    o.result = result
    return o


def first_solvable(orch):
    res = orch.findings(orch.run_id, solvable_only=True)
    assert res.ok and res.data["findings"]
    return res.data["findings"][0]


# --- contract shape ----------------------------------------------------------

def test_only_five_tools_exist():
    assert TOOL_NAMES == ("scan", "findings", "fixpack", "apply", "baseline_diff")
    assert {s["name"] for s in tool_schemas()} == set(TOOL_NAMES)


def test_no_tool_accepts_a_free_text_query():
    """The structural defence against injection: there is nothing to inject into."""
    banned = ("query", "encoded_query", "sql", "table", "script", "filter", "gliderecord")
    for schema in tool_schemas():
        for param in schema["parameters"]:
            assert param.lower() not in banned, f"{schema['name']} exposes a free-text parameter '{param}'"


def test_unknown_tool_is_refused_not_raised(orch):
    res = orch.call("delete_everything", {})
    assert not res.ok and "Unknown tool" in res.refusal


def test_enumerated_filters_reject_invented_values(orch):
    assert not orch.findings(orch.run_id, severity="Apocalyptic").ok
    assert not orch.findings(orch.run_id, category="Whatever").ok
    assert not orch.findings(orch.run_id, tier="T9").ok
    assert orch.findings(orch.run_id, severity="High").ok


# --- findings and fixpack ----------------------------------------------------

def test_findings_returns_traces_and_filters(orch):
    res = orch.findings(orch.run_id, severity="High")
    assert res.ok
    for f in res.data["findings"]:
        assert f["severity"] == "High"
        assert f["score_trace"]["impact"] and f["score_trace"]["likelihood"]
        assert f["fingerprint"] and f["rule_id"]


def test_findings_refuses_unknown_run(orch):
    res = orch.findings(999999)
    assert not res.ok and "no stored findings" in res.refusal


def test_fixpack_refuses_when_there_is_none(orch):
    res = orch.findings(orch.run_id)
    guidance = [f for f in res.data["findings"] if not f["solvable"]]
    if guidance:
        r = orch.fixpack(orch.run_id, guidance[0]["fingerprint"])
        assert not r.ok and "no fix-pack" in r.refusal


# --- approval tokens ---------------------------------------------------------

def test_apply_without_a_token_is_refused(orch):
    f = first_solvable(orch)
    res = orch.apply(orch.run_id, f["fingerprint"], "", "sub-production")
    assert not res.ok and "No approval token" in res.refusal


def test_forged_token_is_refused(orch):
    f = first_solvable(orch)
    good = orch.mint_approval(orch.run_id, f["fingerprint"], "operator")
    raw_hex, _sig = good.rsplit(".", 1)
    forged = raw_hex + "." + "0" * 64
    res = orch.apply(orch.run_id, f["fingerprint"], forged, "sub-production")
    assert not res.ok and "signature is invalid" in res.refusal


def test_token_minted_with_another_key_is_refused(orch, tmp_path):
    f = first_solvable(orch)
    attacker = Orchestrator(tmp_path, bytes.fromhex("cd" * 32), {})
    token = attacker.mint_approval(orch.run_id, f["fingerprint"], "operator")
    res = orch.apply(orch.run_id, f["fingerprint"], token, "sub-production")
    assert not res.ok and "signature is invalid" in res.refusal


def test_token_cannot_be_reused_for_a_different_finding(orch):
    res = orch.findings(orch.run_id, solvable_only=True)
    a, b = res.data["findings"][0], res.data["findings"][1]
    token = orch.mint_approval(orch.run_id, a["fingerprint"], "operator")
    out = orch.apply(orch.run_id, b["fingerprint"], token, "sub-production")
    assert not out.ok and "bound to a different finding" in out.refusal


def test_expired_token_is_refused(orch, monkeypatch):
    f = first_solvable(orch)
    token = orch.mint_approval(orch.run_id, f["fingerprint"], "operator")
    import rob.agent as agent_mod

    monkeypatch.setattr(
        agent_mod, "_now",
        lambda: dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=APPROVAL_TTL_SECONDS + 60),
    )
    with pytest.raises(ApprovalError) as exc:
        orch.verify_approval(token, orch.run_id, f["fingerprint"])
    assert "expired" in str(exc.value)


# --- gates -------------------------------------------------------------------

def test_production_target_is_refused_before_anything_else(orch):
    f = first_solvable(orch)
    token = orch.mint_approval(orch.run_id, f["fingerprint"], "operator")
    res = orch.apply(orch.run_id, f["fingerprint"], token, "production")
    assert not res.ok and "sub-production only" in res.refusal


def test_autonomy_ceiling_blocks_apply(orch):
    """Default ceiling is A1 (propose only). Applying needs A2."""
    f = first_solvable(orch)
    token = orch.mint_approval(orch.run_id, f["fingerprint"], "operator")
    res = orch.apply(orch.run_id, f["fingerprint"], token, "sub-production")
    assert not res.ok and "autonomy ceiling A1" in res.refusal


def test_authorised_apply_refuses_when_no_executor_is_configured(orch):
    """Every authorisation gate passed. The remaining blocker is capability, and
    the refusal says which one, rather than pretending the fix was applied."""
    orch.config.update({"autonomy_ceilings": {"_default": "A2"}, "global_dry_run": False})
    try:
        f = first_solvable(orch)
        token = orch.mint_approval(orch.run_id, f["fingerprint"], "operator")
        res = orch.apply(orch.run_id, f["fingerprint"], token, "sub-production")
        assert not res.ok
        assert "No execution mechanism is configured" in res.refusal
        assert "by hand" in res.refusal
    finally:
        orch.config.update({"autonomy_ceilings": {"_default": "A1"}, "global_dry_run": True})


def test_apply_never_reaches_the_executor_without_authorisation(orch):
    """Order matters: an unauthorised call is refused for being unauthorised,
    not for the executor being absent. Configure an executor and the ceiling
    refusal must still come first."""
    orch.config["executor"] = {"kind": "nowaikit", "command": "false"}
    try:
        f = first_solvable(orch)
        token = orch.mint_approval(orch.run_id, f["fingerprint"], "operator")
        res = orch.apply(orch.run_id, f["fingerprint"], token, "sub-production")
        assert not res.ok and "autonomy ceiling A1" in res.refusal
    finally:
        orch.config.pop("executor", None)


def test_scan_is_discovery_and_never_starts_an_extraction(orch):
    """scan() gives the agent a run_id. Starting a scan stays an operator action,
    because extraction touches a customer instance and the person doing it should
    see which instance and which credential profile first."""
    res = orch.scan()
    assert res.ok
    assert res.data["latest_run_id"] == orch.run_id
    assert "does not start one" in res.data["note"]
    assert not orch.scan(categories=["Telepathy"]).ok


# --- baseline ----------------------------------------------------------------

def test_baseline_diff_refuses_without_a_signed_baseline(orch):
    res = orch.baseline_diff("dev-fixture-001", "missing")
    assert not res.ok and "No signed baseline" in res.refusal


def test_baseline_version_binding_excludes_changed_rules(orch):
    from rob.rules import RULE_REGISTRY

    instance = orch.result.snapshot.instance_id
    (orch.baselines_dir).mkdir(exist_ok=True)
    rule = RULE_REGISTRY["ROB-SEC-003"]
    (orch.baselines_dir / "b1.json").write_text(json.dumps({
        "scope": {"instances": [instance]},
        "rules": [
            {"rule_id": "ROB-SEC-003", "version": rule.VERSION},
            {"rule_id": "ROB-CMDB-001", "version": "0.0-signed-against-an-old-version"},
        ],
    }))
    res = orch.baseline_diff(instance, "b1")
    assert res.ok
    assert any(d["rule_id"] == "ROB-SEC-003" for d in res.data["drift"])
    assert any(m["rule_id"] == "ROB-CMDB-001" for m in res.data["version_mismatch"])
    assert not any(d["rule_id"] == "ROB-CMDB-001" for d in res.data["drift"])


# --- audit -------------------------------------------------------------------

def test_every_call_including_refusals_is_audited(orch):
    before = len(orch.audit_tail(1000))
    orch.findings(orch.run_id)
    orch.call("nonsense", {})
    orch.apply(orch.run_id, "nope", "", "production")
    after = orch.audit_tail(1000)
    assert len(after) >= before + 2
    tools = [e["tool"] for e in after]
    assert "apply" in tools and "findings" in tools
    for e in after:
        assert "approval_token" not in json.dumps(e.get("args", {})) or e["args"].get("approval_token") in (None, "<redacted>")


# --- console over real HTTP --------------------------------------------------

@pytest.fixture(scope="module")
def server(tmp_path_factory):
    home = tmp_path_factory.mktemp("agentweb")
    state = AppState(home)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield ("127.0.0.1", httpd.server_address[1], state)
    httpd.shutdown()


def req(server, method, path, body=None, cookie=None):
    host, port, _ = server
    c = http.client.HTTPConnection(host, port, timeout=10)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie:
        headers["Cookie"] = cookie
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    return r, r.read().decode()


def login(server) -> str:
    req(server, "POST", "/setup", urllib.parse.urlencode({"password": "pw12345678", "password2": "pw12345678"}))
    r, _ = req(server, "POST", "/login", urllib.parse.urlencode({"password": "pw12345678"}))
    return r.getheader("Set-Cookie").split(";")[0]


def test_agent_console_requires_auth_and_then_renders(server):
    cookie = login(server)
    r, _ = req(server, "GET", "/agent")
    assert r.status in (302, 303), "agent console must not be reachable unauthenticated"

    r, body = req(server, "GET", "/agent", cookie=cookie)
    assert r.status == 200 and "Agent console" in body

    # Run a scan from the bundled snapshot, then the console has something to show.
    req(server, "POST", "/scan", urllib.parse.urlencode({"snapshot_path": FIXTURE}), cookie=cookie)
    state = server[2]
    for _ in range(200):
        _r, status = req(server, "GET", "/scan/status", cookie=cookie)
        if json.loads(status)["state"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert state.job["state"] == "done", state.job.get("error")
    r, body = req(server, "GET", "/agent", cookie=cookie)
    assert r.status == 200
    assert "What ROB can fix" in body and "Autonomy ceiling" in body and "Audit trail" in body


def test_console_approval_mints_a_token_and_reports_the_refusal(server):
    cookie = login(server)
    _r, body = req(server, "GET", "/agent", cookie=cookie)
    assert "Approve &amp; apply" in body
    state = server[2]
    from rob.store import connect as _connect, list_runs as _list_runs

    runs = _list_runs(_connect(state.db_path))
    run_id = runs[-1]["run_id"]
    res = state.orchestrator.findings(run_id, solvable_only=True, actor="test")
    fp = res.data["findings"][0]["fingerprint"]
    r, body = req(server, "POST", "/agent/approve",
                  urllib.parse.urlencode({"run_id": run_id, "fingerprint": fp}), cookie=cookie)
    assert r.status == 200 and "Approval recorded" in body
    # Dry run is on by default in a fresh workspace, so nothing executes.
    assert "dry-run is on" in body or "ceiling" in body
    assert "Fix-pack" in body


def test_tool_console_returns_the_agent_envelope(server):
    cookie = login(server)
    state = server[2]
    runs_body = json.dumps({"run_id": 1, "severity": "High"})
    r, body = req(server, "POST", "/agent/tool",
                  urllib.parse.urlencode({"tool": "findings", "args": runs_body}), cookie=cookie)
    assert r.status == 200 and "&quot;tool&quot;: &quot;findings&quot;" in body
    r, body = req(server, "POST", "/agent/tool",
                  urllib.parse.urlencode({"tool": "findings", "args": "not json"}), cookie=cookie)
    assert r.status == 200 and "Tool call" in body
    assert state.orchestrator.audit_path.exists()


# --- console rendering of a real execution -----------------------------------

def test_console_renders_a_dry_run_preview_not_a_refusal(tmp_path):
    """With an executor configured and dry run on, the operator should see what
    would happen, not a wall of text explaining why nothing did."""
    import pathlib as _p
    import urllib.parse as _u

    from rob.cli import load_snapshot as _load
    from rob.engine import run_scan as _scan
    from rob.store import connect as _connect, store_run as _store
    from rob.web import AppState, make_handler
    from http.server import ThreadingHTTPServer

    fake = str(_p.Path(__file__).parent / "fake_nowaikit_write.py")
    home = tmp_path / "home"
    home.mkdir()
    (home / "webruns").mkdir()
    snap_path = _p.Path(__file__).parent.parent / "fixtures" / "pdi_like_snapshot.json"
    result = _scan(_load(str(snap_path)), {})
    run_id = _store(_connect(home / "rob_history.db"), result)
    rd = home / "webruns" / f"run_{run_id}"
    rd.mkdir()
    (rd / "snapshot.json").write_text(snap_path.read_text())

    state = AppState(home)
    state.config.update({
        "autonomy_ceilings": {"_default": "A2"},
        "global_dry_run": True,
        "executor": {"kind": "nowaikit", "command": f"{sys.executable} {fake}"},
    })
    state.save_config()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        port = httpd.server_address[1]

        def req(method, path, body=None, cookie=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            h = {"Content-Type": "application/x-www-form-urlencoded"}
            if cookie:
                h["Cookie"] = cookie
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            return r, r.read().decode()

        req("POST", "/setup", _u.urlencode({"password": "pw12345678", "password2": "pw12345678"}))
        r, _ = req("POST", "/login", _u.urlencode({"password": "pw12345678"}))
        cookie = r.getheader("Set-Cookie").split(";")[0]

        r, page = req("GET", "/agent", cookie=cookie)
        assert "Executor" in page and "W-C" in page

        fp = next(f["fingerprint"] for f in state.orchestrator.findings(run_id, solvable_only=True).data["findings"]
                  if f["rule_id"] == "ROB-SEC-003")
        r, page = req("POST", "/agent/approve",
                      _u.urlencode({"run_id": run_id, "fingerprint": fp}), cookie=cookie)
        assert r.status == 200
        assert "Dry run - nothing was changed" in page
        assert "Live value now" in page, "the preview must show live state, not the pack's stale copy"
    finally:
        httpd.shutdown()
