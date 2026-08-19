"""Extractor tests with a mocked ServiceNow API: no network, canned responses.
Verifies transforms, PII minimisation, read-only behaviour and that the built
snapshot feeds the engine without errors."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from rob.engine import run_scan
from rob.extractor import PROPERTY_BASELINE_NAMES, build_snapshot
from rob.models import Snapshot


class FakeClient:
    """Mimics SNClient.rows/count with canned per-table responses."""

    def __init__(self):
        self.queries: list[tuple] = []
        self.data = {
            "sys_script": [
                {"sys_id": "b" * 32, "name": "Busy rule", "active": "true", "collection": "incident",
                 "when": "before", "condition": "", "filter_condition": "",
                 "script": "var gr = new GlideRecord('sys_user_group'); gr.query(); // long enough to count as non-trivial logic",
                 "sys_created_by": "rob.admin"},
                {"sys_id": "c" * 32, "name": "OOB rule", "active": "true", "collection": "incident",
                 "when": "after", "condition": "", "filter_condition": "",
                 "script": "var gr = new GlideRecord('task_sla'); gr.query(); // shipped by vendor baseline install",
                 "sys_created_by": "system"},
            ],
            "sys_script_client": [
                {"sys_id": "d" * 32, "name": "Sync lookup", "active": "true", "table": "incident",
                 "script": "var r = ga.getXMLWait();", "sys_created_by": "rob.admin"},
            ],
            "sys_script_include": [
                {"sys_id": "e" * 32, "name": "Utils", "active": "true",
                 "script": "var G = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4';", "sys_created_by": "rob.admin"},
            ],
            "sys_user": [
                {"sys_id": "f" * 32, "user_name": "admin", "active": "true", "last_login_time": "2026-08-10 08:00:00"},
                {"sys_id": "a1" + "0" * 30, "user_name": "old.admin", "active": "true", "last_login_time": "2025-01-01 08:00:00"},
            ],
            "sys_user_has_role": [
                {"user": {"value": "f" * 32}, "inherited": "false"},
                {"user": {"value": "a1" + "0" * 30}, "inherited": "false"},
            ],
            "sys_db_object": [{"sys_id": "t1" + "0" * 30, "name": "u_secrets"}],
            "sys_dictionary": [{"name": "u_secrets", "element": "u_password_hint"}],
            "sys_security_acl_role": [],
            "sys_security_acl": [],
            "sys_properties": [{"name": "glide.ui.session_timeout", "value": "480"}],
            "sys_upgrade_history_log": [
                {"sys_id": {"value": "u1" + "0" * 30}, "upgrade_history": {"value": "up1"},
                 "type": {"display_value": "Business Rule"}, "disposition": {"display_value": "Skipped"},
                 "resolution_status": {"display_value": ""}},
                {"sys_id": {"value": "u2" + "0" * 30}, "upgrade_history": {"value": "up1"},
                 "type": {"display_value": "Client Script"}, "disposition": {"display_value": "Inserted"},
                 "resolution_status": {"display_value": ""}},
            ],
            "wf_workflow": [
                {"sys_id": "w1" + "0" * 30, "name": "Custom Approval", "table": "change_request", "sys_created_by": "rob.admin"},
            ],
            "wf_context": [
                {"workflow_version.workflow": {"value": "w1" + "0" * 30}},
                {"workflow_version.workflow": {"value": "w1" + "0" * 30}},
            ],
            "cmdb_ci": [
                {"sys_id": {"value": f"ci{i}" + "0" * 28}, "sys_class_name": {"display_value": "cmdb_ci_win_server"},
                 "name": {"display_value": f"SRV{i}"}, "operational_status": {"display_value": "Operational"},
                 "owned_by": {"value": ""}, "managed_by": {"value": ""}, "support_group": {"value": ""},
                 "sys_updated_on": {"display_value": "2026-01-01 00:00:00"}, "last_discovered": {"display_value": ""},
                 "serial_number": {"display_value": f"SN{i}"}, "correlation_id": {"display_value": ""}}
                for i in range(60)
            ],
            "cmdb_rel_ci": [
                {"sys_id": "r1" + "0" * 30, "parent": "ci0" + "0" * 28, "child": "missing" + "0" * 25, "type": "Runs on::Runs"},
            ],
            "cmdb_ci_business_app": [
                {"sys_id": {"value": "ba1" + "0" * 29}, "name": {"display_value": "App One"},
                 "life_cycle_stage": {"display_value": "Operational"}},
            ],
            "cmdb_ci_service": [],
            "service_offering": [],
        }

    def rows(self, table, fields, query="", cap=20000, display=False):
        self.queries.append(("rows", table, tuple(fields), query))
        return list(self.data.get(table, []))

    def count(self, table, query=""):
        self.queries.append(("count", table, query))
        return 42


@pytest.fixture(scope="module")
def snap():
    return build_snapshot(FakeClient(), "fake-pdi", progress=lambda *_: None)


def test_snapshot_shape(snap):
    assert snap["instance_id"] == "fake-pdi"
    assert snap["taken_at"].endswith("Z")
    for table in ["sys_script", "sys_user", "cmdb_ci", "sys_properties"]:
        assert table in snap["tables"]


def test_pii_minimisation(snap):
    client = FakeClient()
    build_snapshot(client, "x", progress=lambda *_: None)
    user_fields = next(entry[2] for entry in client.queries if entry[0] == "rows" and entry[1] == "sys_user")
    for banned in ("email", "phone", "first_name", "last_name", "name"):
        assert banned not in user_fields
    # Derived, not raw: login recency becomes a day count
    assert all("last_login_time" not in u for u in snap["tables"]["sys_user"])
    assert any(u["days_since_login"] > 365 for u in snap["tables"]["sys_user"])


def test_properties_read_by_name_only():
    client = FakeClient()
    build_snapshot(client, "x", progress=lambda *_: None)
    prop_query = next(entry[3] for entry in client.queries if entry[0] == "rows" and entry[1] == "sys_properties")
    assert prop_query.startswith("nameIN")
    for name in PROPERTY_BASELINE_NAMES:
        assert name in prop_query


def test_oob_heuristic_and_transforms(snap):
    scripts = {r["name"]: r for r in snap["tables"]["sys_script"]}
    assert scripts["OOB rule"]["oob"] is True
    assert scripts["Busy rule"]["oob"] is False
    logs = snap["tables"]["sys_upgrade_history_log"]
    assert len(logs) == 1 and logs[0]["application"] == "Business Rule"  # non-skipped filtered out
    assert snap["aggregates"]["wf_context_executions_90d"]["w1" + "0" * 30] == 2


def test_snapshot_feeds_engine(snap):
    result = run_scan(Snapshot(snap["instance_id"], snap["taken_at"], snap["tables"], snap["aggregates"]), {})
    triggered = {f.rule_id for f in result.findings}
    # Rules whose data exists in the fake instance must fire; UPG-002 must skip cleanly (no aggregates).
    for expected in ["ROB-TD-002", "ROB-TD-003", "ROB-SEC-001", "ROB-SEC-002", "ROB-SEC-003", "ROB-CMDB-001"]:
        assert expected in triggered, expected
    assert "ROB-UPG-002" not in triggered
    assert not result.skipped_rules


def test_oob_ledger_is_definitive():
    """OOB detection v3: presence in the customer-authored sys_update_xml
    ledger decides; timestamps and creators are ignored when the ledger exists."""
    from rob.extractor import _is_oob
    import datetime as dt

    touched = {"sys_script_include_" + "a" * 32}
    cutoff = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)
    # Vendor include installed at provision time (same-day timestamp, normal creator):
    vendor = {"sys_id": "b" * 32, "sys_created_by": "admin", "sys_created_on": "2026-08-02 10:00:00"}
    assert _is_oob(vendor, cutoff, touched, "sys_script_include") is True
    # Customer include, present in the ledger:
    custom = {"sys_id": "a" * 32, "sys_created_by": "admin", "sys_created_on": "2026-08-02 10:00:00"}
    assert _is_oob(custom, cutoff, touched, "sys_script_include") is False
    # No ledger: falls back to heuristic (old creation date => OOB)
    old = {"sys_id": "c" * 32, "sys_created_by": "some.dev", "sys_created_on": "2007-05-01 10:00:00"}
    assert _is_oob(old, cutoff, None, "sys_script_include") is True


def test_build_snapshot_uses_ledger():
    client = FakeClient()
    client.data["sys_update_xml"] = [{"name": "sys_script_" + "b" * 32}]  # only 'Busy rule' is customer work
    snap = build_snapshot(client, "x", progress=lambda *_: None)
    scripts = {r["name"]: r for r in snap["tables"]["sys_script"]}
    assert scripts["Busy rule"]["oob"] is False
    assert scripts["OOB rule"]["oob"] is True
    includes = {r["name"]: r for r in snap["tables"]["sys_script_include"]}
    assert includes["Utils"]["oob"] is True  # not in ledger => vendor


def _churn_client():
    """A fake instance with a customisation ledger worth aggregating."""
    client = FakeClient()
    client.data["sys_update_xml"] = [
        # Two updates to the same business rule, both in the Default set, one author.
        {"name": "sys_script_" + "b" * 32, "type": "Business Rule", "target_name": "Busy rule",
         "update_set": {"display_value": "Default"}, "action": "INSERT_OR_UPDATE",
         "sys_created_by": "rob.admin", "sys_updated_on": "2026-08-01 10:00:00"},
        {"name": "sys_script_" + "b" * 32, "type": "Business Rule", "target_name": "Busy rule",
         "update_set": {"display_value": "Default"}, "action": "INSERT_OR_UPDATE",
         "sys_created_by": "other.dev", "sys_updated_on": "2026-08-05 10:00:00"},
        # One update authored solely by a user the fake instance never lists as active.
        {"name": "sys_script_include_" + "e" * 32, "type": "Script Include", "target_name": "Utils",
         "update_set": {"display_value": "REL-2024-02"}, "action": "INSERT_OR_UPDATE",
         "sys_created_by": "old.admin", "sys_updated_on": "2024-02-01 10:00:00"},
    ]
    return client


def test_churn_aggregates_the_ledger_per_artefact():
    client = _churn_client()
    snap = build_snapshot(client, "x", progress=lambda *_: None)
    churn = {c["name"]: c for c in snap["tables"]["sys_update_xml_churn"]}
    busy = churn["sys_script_" + "b" * 32]
    assert busy["update_count"] == 2
    assert busy["author_count"] == 2
    assert busy["in_default_update_set"] is True
    assert busy["target_name"] == "Busy rule"
    assert busy["type"] == "Business Rule"
    # Most recent update wins the age, not the first one seen.
    assert busy["days_since_update"] is not None


def test_churn_flags_orphaned_authorship_only_when_every_author_is_inactive():
    client = _churn_client()
    # old.admin is the sole author of the script include; deactivate them.
    client.data["sys_user"] = [
        {"sys_id": "f" * 32, "user_name": "admin", "active": "true", "last_login_time": "2026-08-10 08:00:00"},
        {"sys_id": "a1" + "0" * 30, "user_name": "old.admin", "active": "false", "last_login_time": "2025-01-01 08:00:00"},
    ]
    snap = build_snapshot(client, "x", progress=lambda *_: None)
    churn = {c["name"]: c for c in snap["tables"]["sys_update_xml_churn"]}
    assert churn["sys_script_include_" + "e" * 32]["author_inactive"] is True
    # The business rule has one active author among two, so it is not orphaned.
    assert churn["sys_script_" + "b" * 32]["author_inactive"] is False


def test_ledger_is_read_once_and_reused():
    """One sys_update_xml read serves both OOB detection and churn analysis."""
    client = _churn_client()
    build_snapshot(client, "x", progress=lambda *_: None)
    reads = [q for q in client.queries if q[0] == "rows" and q[1] == "sys_update_xml"]
    assert len(reads) == 1, "sys_update_xml is routinely the largest table in an instance; read it once"


def test_scope_and_integration_transforms_are_derived_not_left_to_rules():
    client = FakeClient()
    client.data["sys_app"] = [
        {"sys_id": "ap1", "name": "Platform Extensions", "scope": "global", "active": "true",
         "version": "1.0", "sys_created_by": "rob.admin", "sys_created_on": "2025-01-01 00:00:00"},
        {"sys_id": "ap2", "name": "Vendor Risk", "scope": "x_acme_vr", "active": "true",
         "version": "2.1", "sys_created_by": "rob.admin", "sys_created_on": "2025-01-01 00:00:00"},
    ]
    client.data["sys_scope_privilege"] = [
        {"sys_id": "pv1", "source_scope": "x_acme_vr", "target_scope": "Global", "target_name": "incident",
         "target_type": "Table", "status": "Requested", "operation": "Write"},
    ]
    client.data["sys_rest_message"] = [
        {"sys_id": "rm1", "name": "Vendor sync", "rest_endpoint": "http://vendor.example/api",
         "authentication_type": "Basic", "authentication_profile": {"value": "ap"},
         "sys_created_by": "rob.admin", "sys_created_on": "2025-01-01 00:00:00"},
    ]
    snap = build_snapshot(client, "x", progress=lambda *_: None)
    apps = {a["name"]: a for a in snap["tables"]["sys_app"]}
    assert apps["Platform Extensions"]["is_global"] is True
    assert apps["Vendor Risk"]["is_global"] is False
    # Display values are normalised to lower case so rule specs can match literals.
    priv = snap["tables"]["sys_scope_privilege"][0]
    assert (priv["status"], priv["operation"], priv["target_type"]) == ("requested", "write", "table")
    assert snap["tables"]["sys_rest_message"][0]["insecure_transport"] is True
