"""Declarative remediation (D-028): the fix ships inside the rule spec.

Four groups:
  1. Governance: the gate refuses blocks the executor would refuse at apply
     time, blocks that break the autonomy model, and blocks that compile to
     nothing on the rule's own fixtures.
  2. Compilation: each remediation primitive produces correct, complete,
     idempotence-aware operations over the FULL offender set.
  3. Inputs: a value the snapshot cannot supply is a declared question. The
     executor refuses an unbound plan; bind_inputs resolves it exactly once.
  4. End to end: the four shipped blocks produce executable packs through the
     engine with no per-rule Python.
"""
from __future__ import annotations

import copy

import pytest

from rob.engine import run_scan
from rob.executor import ExecutionRefused, NowAIKitExecutor, WriteClient
from rob.fixpacks.declarative import bind_inputs, generate_declarative, unresolved_inputs
from rob.models import Snapshot
from rob.rules.pack import PackError, load_specs, validate


def snap(tables: dict) -> Snapshot:
    return Snapshot(instance_id="t", taken_at="2026-09-03T00:00:00Z", tables=tables)


def rem_spec(**over) -> dict:
    spec = {
        "id": "ROB-TST-001",
        "version": "0.1",
        "category": "Technical Debt",
        "title": "Test rule with a declared fix",
        "tier": "T1",
        "owner": "Platform team",
        "confidence": "provisional",
        "autonomy": "A1",
        "basis": ["A primary source label"],
        "detect": {"type": "presence", "table": "sys_script", "affected_area": "sys_script",
                   "where": [{"field": "active", "equals": True}]},
        "severity": {"impact": "Moderate", "likelihood": "Likely", "effort": "Low", "assumptions": "Standard change"},
        "why": "{count} thing(s) found.",
        "remediation": "Fix them.",
        "optimisation": "Prevent them.",
        "false_positives": ["Some acceptable case"],
        "fixture_cases": [
            {"name": "trigger", "triggers": True,
             "tables": {"sys_script": [{"sys_id": "a1", "name": "x", "active": True}]}},
            {"name": "no trigger", "triggers": False, "tables": {"sys_script": []}},
        ],
        "remediation_pack": {
            "kind": "update_fields",
            "set": {"active": False},
            "scope_statement": "Deactivates only the listed records.",
        },
    }
    spec.update(over)
    return spec


def finding_for(spec, s):
    from rob.rules.declarative import DeclarativeRule

    return DeclarativeRule(spec).detect(s, {})[0]


# --- 1. governance -----------------------------------------------------------

@pytest.mark.parametrize(
    "mutate,fragment",
    [
        (lambda s: s["remediation_pack"].update(kind="run_script"), "kind must be one of"),
        (lambda s: s["remediation_pack"].update(scope_statement="  "), "scope_statement"),
        (lambda s: s["remediation_pack"].update(set={}), "non-empty 'set'"),
        (lambda s: s["remediation_pack"].update(set={"x": {"nested": "dict"}}), "must be a scalar"),
        (lambda s: s["detect"].update(table="sys_user_has_role"), "may ever write"),
        (lambda s: s["remediation_pack"].update(
            set={"run_as": {"$input": "svc"}}), "not declared in"),
        (lambda s: s["detect"].update(type="staleness"), "requires a presence detection"),
    ],
)
def test_gate_refuses_bad_blocks(mutate, fragment):
    spec = rem_spec()
    mutate(spec)
    with pytest.raises(PackError, match=fragment):
        validate(spec)


def test_gate_refuses_a3_with_inputs():
    spec = rem_spec(autonomy="A3", confidence="validated")
    spec["remediation_pack"].update(
        set={"run_as": {"$input": "svc"}}, inputs={"svc": "which account"})
    with pytest.raises(PackError, match="standing approval cannot answer a question"):
        validate(spec)


def test_gate_refuses_transform_unknown():
    spec = rem_spec()
    spec["remediation_pack"] = {"kind": "transform_field", "field": "endpoint",
                                "transform": "rot13", "scope_statement": "x"}
    with pytest.raises(PackError, match="unknown transform"):
        validate(spec)


def test_gate_refuses_set_expected_properties_on_wrong_detection():
    spec = rem_spec()
    spec["remediation_pack"] = {"kind": "set_expected_properties", "scope_statement": "x"}
    with pytest.raises(PackError, match="value_match"):
        validate(spec)


def test_gate_refuses_block_that_proves_nothing():
    # The fix sets active=False, but every triggering fixture record already
    # has active=False... which cannot trigger this rule; instead use a
    # transform that never fires on the fixture value.
    spec = rem_spec()
    spec["remediation_pack"] = {
        "kind": "transform_field", "field": "name", "transform": "http_to_https",
        "scope_statement": "x",
    }
    with pytest.raises(PackError, match="no executable operations on any triggering fixture"):
        validate(spec)


def test_valid_block_passes_the_gate():
    validate(rem_spec())  # must not raise


# --- 2. compilation ----------------------------------------------------------

def test_update_fields_covers_all_offenders_not_the_evidence_sample():
    rows = [{"sys_id": f"r{i:02d}", "name": f"n{i}", "active": True} for i in range(25)]
    s = snap({"sys_script": rows})
    spec = rem_spec()
    pack = generate_declarative(spec, finding_for(spec, s), s)
    assert len(pack.operations) == 25  # evidence caps at 10; the fix must not
    assert all(op["kind"] == "update_record" and op["after"] == {"active": False}
               for op in pack.operations)
    assert all(op["before"] == {"active": True} for op in pack.operations)
    assert pack.is_executable and pack.is_complete()


def test_update_fields_skips_oob_records():
    s = snap({"sys_script": [
        {"sys_id": "a1", "name": "custom", "active": True},
        {"sys_id": "a2", "name": "vendor", "active": True, "oob": True},
    ]})
    spec = rem_spec()
    pack = generate_declarative(spec, finding_for(spec, s), s)
    assert [op["key"] for op in pack.operations] == ["a1"]


def test_transform_field_rewrites_scheme_and_keeps_the_rest():
    s = snap({"sys_rest_message": [
        {"sys_id": "m1", "name": "sync", "insecure_transport": True,
         "rest_endpoint": "http://vendor.example.com:8080/api?x=1"},
    ]})
    spec = rem_spec()
    spec["detect"] = {"type": "presence", "table": "sys_rest_message",
                      "affected_area": "sys_rest_message",
                      "where": [{"field": "insecure_transport", "equals": True}]}
    spec["remediation_pack"] = {"kind": "transform_field", "field": "rest_endpoint",
                                "transform": "http_to_https", "scope_statement": "x"}
    pack = generate_declarative(spec, finding_for(spec, s), s)
    op = pack.operations[0]
    assert op["after"] == {"rest_endpoint": "https://vendor.example.com:8080/api?x=1"}
    assert op["before"] == {"rest_endpoint": "http://vendor.example.com:8080/api?x=1"}


def test_transform_field_skips_records_already_secure():
    # A record matched for another reason but already https yields no operation.
    s = snap({"sys_rest_message": [
        {"sys_id": "m1", "name": "sync", "insecure_transport": True,
         "rest_endpoint": "https://ok.example.com/api"},
    ]})
    spec = rem_spec()
    spec["detect"] = {"type": "presence", "table": "sys_rest_message",
                      "affected_area": "sys_rest_message",
                      "where": [{"field": "insecure_transport", "equals": True}]}
    spec["remediation_pack"] = {"kind": "transform_field", "field": "rest_endpoint",
                                "transform": "http_to_https", "scope_statement": "x"}
    assert generate_declarative(spec, finding_for(spec, s), s) is None


def test_set_expected_properties_compiles_the_expect_map():
    s = snap({"sys_properties": [
        {"name": "glide.ui.session_timeout", "value": "480"},
        {"name": "glide.other", "value": "right"},
    ]})
    spec = rem_spec()
    spec["detect"] = {"type": "value_match", "table": "sys_properties",
                      "affected_area": "sys_properties",
                      "expect": {"glide.ui.session_timeout": "60",
                                 "glide.other": "right",
                                 "glide.custom.thing": "<customer specific>"}}
    spec["remediation_pack"] = {"kind": "set_expected_properties", "scope_statement": "x"}
    pack = generate_declarative(spec, finding_for(spec, s), s)
    assert len(pack.operations) == 1  # correct value and customer-specific both excluded
    op = pack.operations[0]
    assert op["kind"] == "set_property" and op["key"] == "glide.ui.session_timeout"
    assert op["after"] == {"value": "60"} and op["before"] == {"value": "480"}
    assert "was not set" not in pack.backout  # existing property restores by value


def test_backout_carries_previous_values():
    s = snap({"sys_script": [{"sys_id": "a1", "name": "x", "active": True}]})
    spec = rem_spec()
    pack = generate_declarative(spec, finding_for(spec, s), s)
    assert '"previous"' in pack.backout and '"active": true' in pack.backout


# --- 3. inputs ---------------------------------------------------------------

def input_pack():
    s = snap({"sysauto_script": [
        {"sys_id": "j1", "name": "job", "active": True, "run_as": "u9", "run_as_inactive": True},
    ]})
    spec = rem_spec()
    spec["detect"] = {"type": "presence", "table": "sysauto_script",
                      "affected_area": "sysauto_script",
                      "where": [{"field": "run_as_inactive", "equals": True}]}
    spec["remediation_pack"] = {
        "kind": "update_fields",
        "set": {"run_as": {"$input": "service_account_sys_id"}},
        "inputs": {"service_account_sys_id": "which service account"},
        "scope_statement": "x",
    }
    return generate_declarative(spec, finding_for(spec, s), s)


def test_inputs_are_declared_questions_not_guesses():
    pack = input_pack()
    assert unresolved_inputs(pack.operations) == ["service_account_sys_id"]
    assert "SUPPLIED AT APPROVAL" in pack.fix_artefact
    assert "service_account_sys_id" in pack.instructions


def test_executor_refuses_an_unbound_plan():
    class Silent:
        tool_names: list = []

        def call(self, *a, **k):  # pragma: no cover - must never be reached
            raise AssertionError("no call may happen on an unbound plan")

    with pytest.raises(ExecutionRefused, match="unbound inputs"):
        NowAIKitExecutor(Silent()).preflight(input_pack())


def test_bind_inputs_resolves_and_refuses_partial():
    pack = input_pack()
    with pytest.raises(ValueError, match="Unbound inputs"):
        bind_inputs(pack, {})
    bound = bind_inputs(pack, {"service_account_sys_id": "svc123"})
    assert bound.operations[0]["after"] == {"run_as": "svc123"}
    assert unresolved_inputs(bound.operations) == []
    # The original pack is untouched: binding is a new plan, not a mutation.
    assert unresolved_inputs(pack.operations) == ["service_account_sys_id"]


# --- 4. end to end -----------------------------------------------------------

SHIPPED = {"ROB-OPS-001", "ROB-OPS-002", "ROB-INT-001", "ROB-INT-002"}


def shipped_specs():
    return {s["id"]: s for s in load_specs() if s["id"] in SHIPPED}


def test_shipped_blocks_survive_the_gate_and_prove_on_fixtures():
    specs = shipped_specs()
    assert set(specs) == SHIPPED
    for spec in specs.values():
        assert spec["version"] == "0.2"  # adding a fix is a logic change
        validate(copy.deepcopy(spec))


def test_engine_generates_executable_packs_with_no_per_rule_python():
    from rob.fixpacks import FIXPACK_GENERATORS

    assert not (SHIPPED & set(FIXPACK_GENERATORS)), "these rules must have no hand-written generator"
    tables: dict = {}
    for spec in shipped_specs().values():
        for case in spec["fixture_cases"]:
            if case.get("triggers"):
                for t, rows in case["tables"].items():
                    tables.setdefault(t, []).extend(copy.deepcopy(rows))
    result = run_scan(snap(tables), include_shadow=True)
    packs = {p.rule_id: p for p in result.fixpacks if p.rule_id in SHIPPED}
    assert set(packs) == SHIPPED
    for p in packs.values():
        assert p.is_executable and p.is_complete()
    # INT packs rewrite the endpoint; OPS-002 deactivates; OPS-001 asks.
    assert packs["ROB-INT-001"].operations[0]["after"]["rest_endpoint"].startswith("https://")
    assert packs["ROB-OPS-002"].operations[0]["after"] == {"active": False}
    assert unresolved_inputs(packs["ROB-OPS-001"].operations) == ["service_account_sys_id"]


# --- 5. the approval flow asks the question ---------------------------------

INPUT_RULE = "ROB-TST-901"


def input_rule_spec() -> dict:
    spec = rem_spec(id=INPUT_RULE, tier="T1", confidence="validated",
                    title="Jobs needing a service account")
    spec["detect"] = {"type": "presence", "table": "sysauto_script",
                      "affected_area": "sysauto_script (test)",
                      "where": [{"field": "run_as_inactive", "equals": True}],
                      "label_field": "name"}
    spec["fixture_cases"] = [
        {"name": "trigger", "triggers": True, "tables": {"sysauto_script": [
            {"sys_id": "j1", "name": "job", "active": True, "run_as": "u9", "run_as_inactive": True}]}},
        {"name": "no trigger", "triggers": False, "tables": {"sysauto_script": []}},
    ]
    spec["remediation_pack"] = {
        "kind": "update_fields", "slug": "repoint",
        "set": {"run_as": {"$input": "service_account_sys_id"}},
        "inputs": {"service_account_sys_id": "which service account should own these jobs"},
        "scope_statement": "Changes only run_as on the listed jobs.",
    }
    validate(spec)
    return spec


def orch_with_input_rule(tmp_path, monkeypatch, dry_run: bool):
    """Orchestrator + stored run for a validated rule whose fix asks a question."""
    import json as _json
    import pathlib
    import sys as _sys

    from rob.agent import Orchestrator
    from rob.rules import RULE_REGISTRY
    from rob.rules.declarative import DeclarativeRule
    from rob.store import connect, store_run

    spec = input_rule_spec()
    monkeypatch.setitem(RULE_REGISTRY, INPUT_RULE, DeclarativeRule(spec))
    seed = {"sysauto_script": {"j1": {
        "sys_id": "j1", "name": "job", "active": True, "run_as": "u9", "run_as_inactive": True}}}
    monkeypatch.setenv("FAKE_SEED", _json.dumps(seed))

    home = tmp_path / "home"
    (home / "webruns").mkdir(parents=True)
    snapshot = snap({"sysauto_script": [dict(seed["sysauto_script"]["j1"])]})
    result = run_scan(snapshot)
    run_id = store_run(connect(home / "rob_history.db"), result)
    rd = home / "webruns" / f"run_{run_id}"
    rd.mkdir()
    (rd / "snapshot.json").write_text(_json.dumps(
        {"instance_id": "t", "taken_at": snapshot.taken_at, "tables": snapshot.tables, "aggregates": {}}))

    fake = str(pathlib.Path(__file__).parent / "fake_nowaikit_write.py")
    orch = Orchestrator(home, b"k" * 32, {
        "autonomy_ceilings": {"_default": "A2"},
        "global_dry_run": dry_run,
        "executor": {"kind": "nowaikit", "command": f"{_sys.executable} {fake}"},
    })
    return orch, run_id


def test_orchestrator_lists_declared_inputs_with_prompts():
    from rob.agent import Orchestrator

    o = Orchestrator.__new__(Orchestrator)  # remediation_inputs reads only the registry
    assert Orchestrator.remediation_inputs(o, "ROB-OPS-001") == [
        {"name": "service_account_sys_id",
         "prompt": "sys_id of the service account that should own scheduled execution for these jobs. "
                   "Create or identify it first and grant it only the roles the jobs need."}]
    assert Orchestrator.remediation_inputs(o, "ROB-INT-001") == []
    assert Orchestrator.remediation_inputs(o, "ROB-SEC-003") == []


def test_apply_refuses_without_inputs_and_names_the_question(tmp_path, monkeypatch):
    orch, run_id = orch_with_input_rule(tmp_path, monkeypatch, dry_run=False)
    fp = f"{INPUT_RULE}:sysauto_script (test)"
    token = orch.mint_approval(run_id, fp, actor="test")
    res = orch.apply(run_id, fp, token, "sub-production", actor="test")
    assert not res.ok
    assert "approver-supplied values" in res.refusal
    assert "service_account_sys_id" in res.refusal
    assert "which service account" in res.refusal  # the prompt travels with the refusal


def test_apply_binds_inputs_and_executes_through_the_declarative_path(tmp_path, monkeypatch):
    """Covers the _load_fixpack fallback too: ROB-TST-901 has no hand-written
    generator, so the pack is regenerated from the spec's remediation block."""
    orch, run_id = orch_with_input_rule(tmp_path, monkeypatch, dry_run=False)
    fp = f"{INPUT_RULE}:sysauto_script (test)"
    token = orch.mint_approval(run_id, fp, actor="test")
    res = orch.apply(run_id, fp, token, "sub-production", actor="test",
                     inputs={"service_account_sys_id": "svc42"})
    assert res.ok and res.data["applied"] is True and res.data["verified"]
    assert res.data["operations_applied"] == ["j1"]
    # The answer is part of the audited approval, in full.
    last = [e for e in orch.audit_tail(10) if e["tool"] == "apply"][-1]
    assert last["args"]["inputs"] == {"service_account_sys_id": "svc42"}


def test_console_asks_before_minting_then_applies_with_the_answer(tmp_path, monkeypatch):
    import http.client
    import threading
    import urllib.parse as _u
    from http.server import ThreadingHTTPServer

    from rob.web import AppState, make_handler

    orch, run_id = orch_with_input_rule(tmp_path, monkeypatch, dry_run=True)
    state = AppState(tmp_path / "home")
    state.config.update(orch.config)
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

        _r, listing = req("GET", "/agent", cookie=cookie)
        assert "Review &amp; approve" in listing and "asks: service_account_sys_id" in listing

        fp = f"{INPUT_RULE}:sysauto_script (test)"
        _r, ask = req("POST", "/agent/approve",
                      _u.urlencode({"run_id": run_id, "fingerprint": fp}), cookie=cookie)
        assert "This fix has a question" in ask and "which service account" in ask
        assert "Approval recorded" not in ask  # no token exists yet

        _r, done = req("POST", "/agent/approve",
                       _u.urlencode({"run_id": run_id, "fingerprint": fp,
                                     "input_service_account_sys_id": "svc42"}), cookie=cookie)
        assert "Approval recorded" in done
        assert "Dry run - nothing was changed" in done  # dry run on: preview, with values bound
        assert "would change" in done
    finally:
        httpd.shutdown()


def test_compiled_pack_applies_through_the_wc_executor():
    """The whole chain: spec block -> compiled pack -> W-C apply -> verified
    change on the (fake) instance. This is the claim the feature makes."""
    import json as _json
    import pathlib
    import sys

    fake = str(pathlib.Path(__file__).parent / "fake_nowaikit_write.py")
    seed = {"sys_rest_message": {"m1": {
        "sys_id": "m1", "name": "Vendor sync", "insecure_transport": True,
        "rest_endpoint": "http://vendor.example.com/api"}}}
    spec = shipped_specs()["ROB-INT-001"]
    s = snap({"sys_rest_message": [dict(seed["sys_rest_message"]["m1"])]})
    pack = generate_declarative(spec, finding_for(spec, s), s)

    client = WriteClient.stdio([sys.executable, fake], env={"FAKE_SEED": _json.dumps(seed)})
    try:
        ex = NowAIKitExecutor(client, "dev-fake")
        preview = ex.apply(pack, dry_run=True)
        assert preview["dry_run"] and not preview["preview"][0]["already_correct"]
        out = ex.apply(pack)
        assert out["applied"] == ["m1"] and not out["verification_failures"]
        live = client.call("get_record", {"table": "sys_rest_message", "sys_id": "m1"})
        assert live["record"]["rest_endpoint"] == "https://vendor.example.com/api"
        # Backout captured live before the write, per executor design decision 3.
        assert "http://vendor.example.com/api" in out["backout_state"]
    finally:
        client.close()
