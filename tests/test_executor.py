"""W-C executor tests (D-019).

The executor writes to a customer instance, so the tests are mostly about what
it refuses and what it reverses. In order of importance:

  1. it will not run a background script, even though the server offers one
  2. it will not touch a security or identity table, even with an approval
  3. backout is read from the live instance before the first write
  4. a failure mid-way rolls back what already landed
  5. it is idempotent: re-applying a correct state writes nothing
"""
from __future__ import annotations

import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from rob.executor import (
    FORBIDDEN_TABLES,
    ExecutionFailed,
    ExecutionRefused,
    NowAIKitExecutor,
    WriteClient,
    assert_executor_configured,
)
from rob.models import FixPack
from rob.nowaikit import NowAIKitError, ToolNotPermitted

FAKE = str(pathlib.Path(__file__).parent / "fake_nowaikit_write.py")


def client(env=None):
    return WriteClient.stdio([sys.executable, FAKE], env=env)


def pack(operations, name="fixpack-test"):
    return FixPack(
        finding_fingerprint="ROB-SEC-003:sys_properties", rule_id="ROB-SEC-003", name=name,
        fix_artefact="x", fix_artefact_filename="f.js", dry_run="d", instructions="i",
        backout="b", backout_filename="b.js", scope_statement="s", operations=operations,
    )


def prop_op(key, after, before=None):
    return {"kind": "set_property", "table": "sys_properties", "key": key,
            "before": {"value": before}, "after": {"value": after}, "label": f"{key} -> {after}"}


@pytest.fixture
def ex():
    c = client()
    yield NowAIKitExecutor(c, "dev-test")
    c.close()


# --- 1. the capability that is deliberately not used -------------------------

def test_executor_refuses_to_run_a_background_script(ex):
    """NowAIKit offers execute_background_script and run_fix_script. ROB's fix
    artefacts are JavaScript, so calling them would have been the quick path.
    A script cannot be previewed, bounded or reversed per record."""
    assert "execute_background_script" in ex.client.tool_names
    for tool in ("execute_background_script", "run_fix_script"):
        with pytest.raises(ToolNotPermitted) as exc:
            ex.client.call(tool, {"script": "gs.setProperty('x','y')"})
        assert "deliberately excluded" in str(exc.value)


def test_executor_cannot_create_records(ex):
    """create_record is on the server and off the executor's list: a fix that
    invents records is not a fix this executor is trusted to apply."""
    assert "create_record" in ex.client.tool_names
    with pytest.raises(ToolNotPermitted):
        ex.client.call("create_record", {"table": "incident", "fields": {}})


# --- 2. tables it will never write -------------------------------------------

@pytest.mark.parametrize("table", ["sys_security_acl", "sys_user", "sys_user_has_role", "sys_user_group"])
def test_security_and_identity_tables_are_refused_even_with_approval(ex, table):
    p = pack([{"kind": "update_record", "table": table, "key": "abc",
               "before": {}, "after": {"active": "false"}}])
    with pytest.raises(ExecutionRefused) as exc:
        ex.preflight(p)
    assert "never writes" in str(exc.value) and "W-B" in str(exc.value)


def test_forbidden_list_covers_the_obvious_identity_surface():
    for t in ("sys_user", "sys_user_has_role", "sys_security_acl", "sys_user_group"):
        assert t in FORBIDDEN_TABLES


def test_unknown_operation_kind_is_refused(ex):
    with pytest.raises(ExecutionRefused) as exc:
        ex.preflight(pack([{"kind": "run_script", "table": "x", "key": "y", "after": {}}]))
    assert "Unknown operation kind" in str(exc.value)


def test_a_script_only_fixpack_is_refused_with_an_explanation(ex):
    with pytest.raises(ExecutionRefused) as exc:
        ex.preflight(pack([]))
    assert "no machine-applicable operations" in str(exc.value)
    assert "by hand" in str(exc.value)


# --- 3. dry run and live backout ---------------------------------------------

def test_dry_run_writes_nothing_and_reads_live_state(ex):
    p = pack([prop_op("glide.ui.security.allow_codetag", "false", before="stale-generation-time-value")])
    out = ex.apply(p, dry_run=True)
    assert out["dry_run"] is True
    # Backout comes from the instance, not from what the pack recorded at scan time
    assert out["preview"][0]["live_before"]["value"] == "true"
    after = ex.client.call("query_records", {"table": "sys_properties",
                                             "query": "name=glide.ui.security.allow_codetag",
                                             "fields": "value", "limit": 1})
    assert after["records"][0]["value"] == "true", "dry run must not change anything"


def test_dry_run_marks_operations_that_are_already_correct(ex):
    out = ex.apply(pack([prop_op("glide.stale.property", "old")]), dry_run=True)
    assert out["preview"][0]["already_correct"] is True


# --- 4. applying, verifying, completing --------------------------------------

def test_apply_writes_verifies_and_completes_an_update_set(ex):
    p = pack([prop_op("glide.ui.security.allow_codetag", "false"),
              prop_op("glide.basicauth.required.xml", "true")])
    out = ex.apply(p)
    assert out["applied"] == ["glide.ui.security.allow_codetag", "glide.basicauth.required.xml"]
    assert not out["verification_failures"]
    assert all(v["verified"] for v in out["verification"])
    assert out["change_reference"], "every change must land in a named update set"
    assert out["rollback_artefact"]["xml"] == "<unload/>"
    # verification reads back from the instance rather than trusting the write call
    now = ex.client.call("query_records", {"table": "sys_properties",
                                           "query": "name=glide.ui.security.allow_codetag",
                                           "fields": "value", "limit": 1})
    assert now["records"][0]["value"] == "false"


def test_backout_state_is_captured_before_the_first_write(ex):
    p = pack([prop_op("glide.ui.security.allow_codetag", "false")])
    out = ex.apply(p)
    state = json.loads(out["backout_state"])
    assert state[0]["before"]["value"] == "true", "must record the value from before the write"


def test_apply_is_idempotent(ex):
    p = pack([prop_op("glide.stale.property", "old")])
    out = ex.apply(p)
    assert out["applied"] == [] and out["skipped_already_correct"] == ["glide.stale.property"]


def test_a_missing_record_stops_the_run_rather_than_guessing(ex):
    p = pack([{"kind": "update_record", "table": "cmdb_rel_ci", "key": "does-not-exist",
               "before": {}, "after": {"child": "x"}}])
    with pytest.raises(ExecutionFailed) as exc:
        ex.apply(p)
    assert "no longer exists" in str(exc.value) and "re-scan" in str(exc.value).lower()


# --- 5. failure and rollback -------------------------------------------------

def test_a_failure_partway_rolls_back_what_already_landed():
    """The one that matters. Two writes, the second fails, the first must revert."""
    c = client(env={"FAKE_FAIL_ON": "glide.basicauth.required.xml"})
    ex = NowAIKitExecutor(c, "dev-test")
    try:
        p = pack([prop_op("glide.ui.security.allow_codetag", "false"),
                  prop_op("glide.basicauth.required.xml", "true")])
        with pytest.raises(ExecutionFailed) as exc:
            ex.apply(p)
        assert exc.value.applied == ["glide.ui.security.allow_codetag"]
        assert exc.value.rolled_back == ["glide.ui.security.allow_codetag"]
        assert not exc.value.residual
        restored = c.call("query_records", {"table": "sys_properties",
                                            "query": "name=glide.ui.security.allow_codetag",
                                            "fields": "value", "limit": 1})
        assert restored["records"][0]["value"] == "true", "rollback must restore the live value"
    finally:
        c.close()


# --- configuration -----------------------------------------------------------

def test_unconfigured_workspace_refuses_cheaply():
    """Before spawning anything: a slow no is still a no."""
    for cfg in ({}, {"executor": {}}, {"executor": {"kind": "scoped_app"}}):
        with pytest.raises(ExecutionRefused) as exc:
            assert_executor_configured(cfg)
        assert "No execution mechanism is configured" in str(exc.value)


def test_configured_workspace_passes_the_cheap_check():
    assert_executor_configured({"executor": {"kind": "nowaikit", "command": "x"}}) is None


# --- the real fix-pack -------------------------------------------------------

def test_the_sec003_fixpack_produces_applicable_operations():
    """End to end from a scan: the canonical T1 fix-pack must be executable."""
    from rob.cli import load_snapshot
    from rob.engine import run_scan

    result = run_scan(load_snapshot(str(pathlib.Path(__file__).parent.parent / "fixtures" / "pdi_like_snapshot.json")), {})
    sec003 = next(p for p in result.fixpacks if p.rule_id == "ROB-SEC-003")
    assert sec003.is_executable and len(sec003.operations) >= 5
    for op in sec003.operations:
        assert op["kind"] == "set_property"
        assert op["table"] == "sys_properties" and op["table"] not in FORBIDDEN_TABLES
        assert op["after"]["value"] and not str(op["after"]["value"]).startswith("<"), \
            "a customer-specific baseline is a value ROB must not set"


def test_packs_without_operations_are_honestly_marked():
    from rob.cli import load_snapshot
    from rob.engine import run_scan

    result = run_scan(load_snapshot(str(pathlib.Path(__file__).parent.parent / "fixtures" / "pdi_like_snapshot.json")), {})
    executable = [p.name for p in result.fixpacks if p.is_executable]
    manual = [p.name for p in result.fixpacks if not p.is_executable]
    assert executable and manual, "most packs are scripts; that is expected, not a gap"


# --- the whole chain: gates, then a real application -------------------------

def test_orchestrator_end_to_end_approval_to_applied_change(tmp_path):
    """Every gate passes, an executor is configured, and a property actually moves.

    This is the first test in the project where ROB changes something. It runs
    against the fake instance, and it asserts the update set reference exists,
    because a change without one is not a change ROB is willing to make.
    """
    from rob.agent import Orchestrator
    from rob.cli import load_snapshot
    from rob.engine import run_scan
    from rob.store import connect, store_run

    home = tmp_path
    (home / "webruns").mkdir()
    snapshot_path = pathlib.Path(__file__).parent.parent / "fixtures" / "pdi_like_snapshot.json"
    result = run_scan(load_snapshot(str(snapshot_path)), {})
    con = connect(home / "rob_history.db")
    run_id = store_run(con, result)
    run_dir = home / "webruns" / f"run_{run_id}"
    run_dir.mkdir()
    (run_dir / "snapshot.json").write_text(snapshot_path.read_text())

    orch = Orchestrator(home, bytes.fromhex("ab" * 32), {
        "autonomy_ceilings": {"_default": "A2"},
        "global_dry_run": True,
        "executor": {"kind": "nowaikit", "command": f"{sys.executable} {FAKE}"},
    })
    fp = "ROB-SEC-003:sys_properties (hardening baseline)"
    findings = orch.findings(run_id, solvable_only=True)
    fp = next(f["fingerprint"] for f in findings.data["findings"] if f["rule_id"] == "ROB-SEC-003")

    # Dry run first: approval verified, live preview returned, nothing written.
    token = orch.mint_approval(run_id, fp, "operator")
    preview = orch.apply(run_id, fp, token, "sub-production")
    assert preview.ok and preview.data["applied"] is False
    assert preview.data["reason"] == "global_dry_run"
    assert preview.data["preview"], "a dry run should still say what would happen"

    # Then for real.
    orch.config["global_dry_run"] = False
    token = orch.mint_approval(run_id, fp, "operator")
    applied = orch.apply(run_id, fp, token, "sub-production")
    assert applied.ok and applied.data["applied"] is True
    assert applied.data["verified"] is True
    assert applied.data["change_reference"], "no change record, no change"
    assert applied.data["operations_applied"], "something must actually have moved"
    assert json.loads(applied.data["backout_state"])

    # And the audit log carries it, with the token redacted.
    entry = next(e for e in orch.audit_tail(20) if e["tool"] == "apply" and e["ok"])
    assert entry["args"]["approval_token"] == "<redacted>"
    assert "update set" in entry["outcome"]
