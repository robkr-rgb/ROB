"""Tests for the declarative rule pack layer (D-014).

Three groups:
  1. Governance: the validator must reject specs that break RULE_AUTHORING.md.
  2. Primitives: each detection primitive is proven to trigger and not trigger.
  3. Pack fixture cases: every shipped rule's declared cases are executed.

Group 3 is the important one. RULE_AUTHORING.md requires a test proving the
rule triggers AND a test proving the false-positive control holds. At library
scale that cannot be hand-written per rule, so the spec carries the cases and
this module generates the tests from them.
"""
from __future__ import annotations

import copy
import json

import pytest

from rob.engine import run_scan
from rob.models import Snapshot
from rob.rules.declarative import DETECTORS, DeclarativeRule, MissingSnapshotData
from rob.rules.pack import PackError, load_specs, logic_hash, validate


def snap(tables: dict, aggregates: dict | None = None) -> Snapshot:
    return Snapshot(instance_id="t", taken_at="2026-08-17T00:00:00Z", tables=tables, aggregates=aggregates or {})


def base_spec(**over) -> dict:
    spec = {
        "id": "ROB-TST-001",
        "version": "0.1",
        "category": "Technical Debt",
        "title": "Test rule",
        "tier": "T2",
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
            {"name": "trigger", "triggers": True, "tables": {"sys_script": [{"sys_id": "1", "name": "x", "active": True}]}},
            {"name": "no trigger", "triggers": False, "tables": {"sys_script": []}},
        ],
    }
    spec.update(over)
    return spec


# --- 1. governance -----------------------------------------------------------

@pytest.mark.parametrize(
    "mutate,fragment",
    [
        (lambda s: s.pop("false_positives"), "missing required field 'false_positives'"),
        (lambda s: s.update(false_positives="none that I can think of"), "false-positive analysis is mandatory"),
        (lambda s: s.update(id="TD-001"), "rule ID must match"),
        (lambda s: s.update(id="ROB-TD-1"), "rule ID must match"),
        (lambda s: s.update(basis=[]), "missing required field 'basis'"),
        (lambda s: s.update(confidence="probably-fine"), "confidence must be one of"),
        (lambda s: s.update(autonomy="A4"), "autonomy must be one of"),
        (lambda s: s.update(autonomy="A3"), "A3 requires tier T1"),
        (lambda s: s.update(autonomy="A3", tier="T1"), "A3 requires confidence 'validated'"),
        (lambda s: s["detect"].update(type="telepathy"), "unknown detection primitive"),
        (lambda s: s["detect"].pop("affected_area"), "affected_area is required"),
        (lambda s: s["severity"].update(impact="Catastrophic"), "severity.impact must be one of"),
        (lambda s: s["severity"].update(modifiers=["vibes"]), "unknown severity modifier"),
        (lambda s: s["detect"].update(where=[{"field": "active", "sortof": True}]), "exactly one known operator"),
        (lambda s: s.update(fixture_cases=[{"name": "t", "triggers": True, "tables": {}}]), "must NOT trigger"),
        (lambda s: s.update(fixture_cases=[{"name": "f", "triggers": False, "tables": {}}]), "must trigger the rule"),
    ],
)
def test_validator_rejects_governance_breaches(mutate, fragment):
    spec = base_spec()
    mutate(spec)
    with pytest.raises(PackError) as exc:
        validate(spec)
    assert fragment in str(exc.value)


def test_validator_accepts_a3_only_on_validated_t1():
    validate(base_spec(tier="T1", autonomy="A3", confidence="validated"))


def test_duplicate_rule_ids_rejected():
    with pytest.raises(PackError) as exc:
        validate(base_spec(), seen={"ROB-TST-001": "other-pack.json"})
    assert "duplicate rule ID" in str(exc.value)


def test_logic_hash_ignores_prose_but_catches_logic():
    a = base_spec()
    b = base_spec(why="Completely different explanatory prose.", remediation="Different words.")
    assert logic_hash(a) == logic_hash(b), "wording changes must not force a version bump"
    c = copy.deepcopy(a)
    c["detect"]["where"] = [{"field": "active", "equals": False}]
    assert logic_hash(a) != logic_hash(c), "a detection change must force a version bump"


def test_lock_file_matches_shipped_packs():
    """Guards the pilot failure mode: logic edited, VERSION left alone, findings stamped stale."""
    from rob.rules.pack import LOCK_FILE, read_lock

    assert LOCK_FILE.exists(), "run write_lock after adding a pack"
    lock, specs = read_lock(), load_specs()
    assert set(lock) == {s["id"] for s in specs}
    for s in specs:
        assert lock[s["id"]]["logic_hash"] == logic_hash(s), (
            f"{s['id']}: logic differs from the lock. Bump VERSION and refresh pack.lock.json."
        )
        assert lock[s["id"]]["version"] == s["version"]


# --- 2. primitives -----------------------------------------------------------

def run_spec(spec: dict, tables: dict, aggregates: dict | None = None):
    validate(spec)
    return DeclarativeRule(spec).detect(snap(tables, aggregates), {})


def test_every_primitive_has_a_test():
    """A new primitive without a test is a gap; fail loudly rather than silently."""
    tested = {
        "presence", "pattern_match", "value_match", "count_threshold",
        "field_empty_rate", "staleness", "duplicate_key",
        "dangling_reference", "cross_table_join",
    }
    assert set(DETECTORS) == tested, f"untested primitives: {set(DETECTORS) - tested}"


def test_presence_flags_matches_and_excludes_oob():
    spec = base_spec()
    rows = [{"sys_id": "1", "name": "a", "active": True},
            {"sys_id": "2", "name": "b", "active": False},
            {"sys_id": "3", "name": "c", "active": True, "oob": True}]
    f = run_spec(spec, {"sys_script": rows})
    assert len(f) == 1 and f[0].evidence_total == 1


def test_pattern_match_strips_line_comments_and_counts_hits():
    spec = base_spec(detect={
        "type": "pattern_match", "tables": ["sys_script"], "affected_area": "Server scripts",
        "patterns": ["\\bgs\\.sql\\s*\\("], "where": [{"field": "active", "equals": True}],
    })
    rows = [
        {"sys_id": "1", "name": "hit", "active": True, "script": "gs.sql('a'); gs.sql('b');"},
        {"sys_id": "2", "name": "comment", "active": True, "script": "// gs.sql('x')"},
    ]
    f = run_spec(spec, {"sys_script": rows})
    assert len(f) == 1 and f[0].evidence_total == 1
    assert f[0].evidence[0].data["matches"] == 2


def test_pattern_match_absence_mode_flags_missing_construct():
    spec = base_spec(detect={
        "type": "pattern_match", "match": "none", "tables": ["sys_script"], "affected_area": "sys_script",
        "patterns": ["\\bfunction\\b"], "absence_label": "no function wrapper",
        "where": [{"field": "script", "empty": False}],
    })
    rows = [{"sys_id": "1", "name": "bare", "active": True, "script": "current.update();"},
            {"sys_id": "2", "name": "wrapped", "active": True, "script": "function executeRule() {}"},
            {"sys_id": "3", "name": "empty", "active": True, "script": ""}]
    f = run_spec(spec, {"sys_script": rows})
    assert f[0].evidence_total == 1
    assert "bare" in f[0].evidence[0].summary and "no function wrapper" in f[0].evidence[0].summary


def test_absence_mode_must_exclude_empty_fields():
    """Without the guard, every empty record is flagged. The validator refuses it."""
    spec = base_spec(detect={
        "type": "pattern_match", "match": "none", "tables": ["sys_script"], "affected_area": "sys_script",
        "patterns": ["\\bfunction\\b"],
    })
    with pytest.raises(PackError) as exc:
        validate(spec)
    assert "must exclude empty fields" in str(exc.value)


def test_pattern_match_unless_pattern_suppresses():
    spec = base_spec(detect={
        "type": "pattern_match", "tables": ["sys_script"], "affected_area": "Server scripts",
        "patterns": ["\\beval\\s*\\("], "unless_patterns": ["GlideScopedEvaluator"],
    })
    rows = [{"sys_id": "1", "name": "safe", "active": True,
             "script": "var e = new GlideScopedEvaluator(); eval(x);"}]
    assert run_spec(spec, {"sys_script": rows}) == []


def test_value_match_reports_deviation_and_missing():
    spec = base_spec(detect={
        "type": "value_match", "table": "sys_properties", "affected_area": "System properties",
        "expect": {"glide.a": "false", "glide.b": "true"}, "report_missing": True,
    })
    rows = [{"name": "glide.a", "value": "true"}]
    f = run_spec(spec, {"sys_properties": rows})
    assert f[0].evidence_total == 2
    summaries = " ".join(e.summary for e in f[0].evidence)
    assert "is 'true', expected 'false'" in summaries and "is not set" in summaries


def test_value_match_is_case_and_whitespace_insensitive():
    spec = base_spec(detect={"type": "value_match", "table": "sys_properties",
                             "affected_area": "System properties", "expect": {"glide.a": "false"}})
    assert run_spec(spec, {"sys_properties": [{"name": "glide.a", "value": " False "}]}) == []


def test_count_threshold_above_and_below():
    above = base_spec(detect={"type": "count_threshold", "table": "sys_user_has_role", "affected_area": "admins",
                              "threshold": 2, "direction": "above"})
    rows = [{"sys_id": str(i), "name": f"u{i}"} for i in range(4)]
    assert run_spec(above, {"sys_user_has_role": rows})[0].evidence_total == 4
    assert run_spec(above, {"sys_user_has_role": rows[:2]}) == []


def test_field_empty_rate_groups_and_respects_min_group_size():
    spec = base_spec(detect={
        "type": "field_empty_rate", "table": "cmdb_ci", "affected_area": "cmdb_ci",
        "target_field": "owned_by", "group_by": "sys_class_name",
        "max_empty_rate": 0.5, "min_group_size": 3,
    })
    rows = (
        [{"sys_id": f"a{i}", "name": f"a{i}", "sys_class_name": "cmdb_ci_server", "owned_by": ""} for i in range(4)]
        + [{"sys_id": "b1", "name": "b1", "sys_class_name": "cmdb_ci_db", "owned_by": ""}]  # below min_group_size
        + [{"sys_id": f"c{i}", "name": f"c{i}", "sys_class_name": "cmdb_ci_app", "owned_by": "someone"} for i in range(4)]
    )
    f = run_spec(spec, {"cmdb_ci": rows})
    assert [x.affected_area for x in f] == ["cmdb_ci_server"]


def test_staleness_uses_precomputed_age_not_the_clock():
    spec = base_spec(detect={"type": "staleness", "table": "cmdb_ci", "affected_area": "cmdb_ci",
                             "age_field": "days_since_update", "older_than_days": 90})
    rows = [{"sys_id": "1", "name": "old", "days_since_update": 400},
            {"sys_id": "2", "name": "fresh", "days_since_update": 10},
            {"sys_id": "3", "name": "unknown", "days_since_update": None}]
    f = run_spec(spec, {"cmdb_ci": rows})
    assert f[0].evidence_total == 1 and "old" in f[0].evidence[0].summary


def test_duplicate_key_ignores_incomplete_identity():
    spec = base_spec(detect={"type": "duplicate_key", "table": "cmdb_ci", "affected_area": "cmdb_ci",
                             "key_fields": ["name", "serial_number"]})
    rows = [
        {"sys_id": "1", "name": "SRV1", "serial_number": "AB"},
        {"sys_id": "2", "name": "srv1", "serial_number": "ab"},   # duplicate, case-insensitive
        {"sys_id": "3", "name": "SRV2", "serial_number": ""},     # incomplete identity: not evidence
        {"sys_id": "4", "name": "SRV2", "serial_number": ""},
    ]
    f = run_spec(spec, {"cmdb_ci": rows})
    assert f[0].evidence_total == 1


def test_dangling_reference_flags_broken_pointers():
    spec = base_spec(detect={"type": "dangling_reference", "table": "cmdb_rel_ci", "affected_area": "cmdb_rel_ci",
                             "target_table": "cmdb_ci", "reference_fields": ["parent", "child"]})
    tables = {"cmdb_ci": [{"sys_id": "ok"}], "cmdb_rel_ci": [{"sys_id": "r1", "parent": "ok", "child": "gone"}]}
    f = run_spec(spec, tables)
    assert f[0].evidence_total == 1 and "child" in f[0].evidence[0].summary


def test_missing_target_table_raises_rather_than_guessing():
    spec = base_spec(detect={"type": "dangling_reference", "table": "cmdb_rel_ci", "affected_area": "cmdb_rel_ci",
                             "target_table": "cmdb_ci", "reference_fields": ["parent"]})
    with pytest.raises(MissingSnapshotData):
        run_spec(spec, {"cmdb_rel_ci": [{"sys_id": "r1", "parent": "x"}]})


def test_cross_table_join_finds_unlinked_records():
    spec = base_spec(detect={
        "type": "cross_table_join", "table": "cmdb_ci_business_app", "affected_area": "cmdb_ci_business_app",
        "join_table": "cmdb_rel_ci", "join_field": "parent", "key_field": "sys_id",
    })
    tables = {
        "cmdb_ci_business_app": [{"sys_id": "app1", "name": "Linked"}, {"sys_id": "app2", "name": "Orphan"}],
        "cmdb_rel_ci": [{"sys_id": "r1", "parent": "app1"}],
    }
    f = run_spec(spec, tables)
    assert f[0].evidence_total == 1 and "Orphan" in f[0].evidence[0].summary


def test_conditional_modifier_and_effort_escalation_apply_at_volume():
    spec = base_spec(severity={
        "impact": "Moderate", "likelihood": "Likely", "effort": "Low", "assumptions": "x",
        "conditional_modifiers": [{"modifier": "aggregation", "when_total_at_least": 3}],
        "effort_escalation": [{"when_total_at_least": 3, "effort": "High"}],
    })
    few = run_spec(spec, {"sys_script": [{"sys_id": "1", "name": "a", "active": True}]})
    many = run_spec(spec, {"sys_script": [{"sys_id": str(i), "name": f"a{i}", "active": True} for i in range(5)]})
    assert "aggregation" not in few[0].score.modifiers_applied
    assert "aggregation" in many[0].score.modifiers_applied
    assert few[0].score.effort == "Low" and many[0].score.effort == "High"


# --- 3. shipped pack fixture cases -------------------------------------------

SPECS = load_specs()


def test_packs_load_and_are_non_empty():
    assert SPECS, "no rule packs loaded"


@pytest.mark.parametrize("spec", SPECS, ids=[s["id"] for s in SPECS])
def test_pack_rule_fixture_cases(spec):
    """Execute the trigger and false-positive-control cases declared in the spec."""
    rule = DeclarativeRule(spec)
    for case in spec["fixture_cases"]:
        findings = rule.detect(snap(case["tables"], case.get("aggregates")), {})
        if case["triggers"]:
            assert findings, f"{spec['id']} case '{case['name']}' should trigger but did not"
            for f in findings:
                assert f.why_it_matters and f.remediation and f.owner
                assert f.score and f.score.final_severity and f.score.final_priority
                assert f.confidence == spec["confidence"] and f.autonomy == spec["autonomy"]
                assert "{" not in f.why_it_matters, "unsubstituted template placeholder in why"
        else:
            assert not findings, f"{spec['id']} case '{case['name']}' must not trigger (false-positive control)"


@pytest.mark.parametrize("spec", SPECS, ids=[s["id"] for s in SPECS])
def test_pack_rule_declares_only_extracted_tables(spec):
    """A rule whose data is not extracted would silently never fire. Catch it at build time."""
    import re as _re

    extractor = (__import__("pathlib").Path(__file__).parent.parent / "rob" / "extractor.py").read_text()
    extracted = set(_re.findall(r'T\["([a-z_]+)"\]', extractor))
    for table in DeclarativeRule(spec).source_tables:
        assert table in extracted, f"{spec['id']} reads {table}, which the extractor does not populate"


def test_shipped_pack_rules_start_in_shadow():
    """Imported rules are unmeasured by definition. Nothing enters a customer report unproven."""
    for spec in SPECS:
        assert spec["confidence"] != "validated", (
            f"{spec['id']} claims validated confidence. Record the measured false-positive rate first."
        )


def test_shadow_findings_are_withheld_then_promotable():
    tables = {"sys_script_client": [
        {"sys_id": "1", "name": "Debug", "active": True, "oob": False, "table": "incident",
         "script": "console.log('x'); localStorage.setItem('a','b');"}
    ]}
    s = snap(tables)
    quiet = run_scan(s, {}, {}, include_shadow=False)
    loud = run_scan(s, {}, {}, include_shadow=True)
    assert not [f for f in quiet.findings if f.rule_id in ("ROB-TD-006", "ROB-SEC-004")]
    assert {f.rule_id for f in quiet.shadow_findings} >= {"ROB-TD-006", "ROB-SEC-004"}
    assert {f.rule_id for f in loud.findings} >= {"ROB-TD-006", "ROB-SEC-004"}
    assert not loud.shadow_findings


def test_pack_json_is_stable_on_disk():
    """Packs are data, so they must round-trip without surprises."""
    from rob.rules.pack import PACK_DIR

    for path in PACK_DIR.glob("*.json"):
        json.loads(path.read_text())
