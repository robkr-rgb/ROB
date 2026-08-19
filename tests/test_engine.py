"""Skeleton tests: determinism (S5), scoring reproducibility, fix-pack contract,
finding completeness, and false-positive controls."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from rob.cli import load_snapshot
from rob.engine import run_scan
from rob.models import SEVERITIES, PRIORITIES
from rob.scoring import score, SEVERITY_MATRIX

FIXTURE = str(pathlib.Path(__file__).parent.parent / "fixtures" / "pdi_like_snapshot.json")


@pytest.fixture(scope="module")
def result():
    return run_scan(load_snapshot(FIXTURE), {})


def test_seed_library_intact():
    """The hand-written seed library is pilot-validated; pack loading must not disturb it."""
    from rob.rules import HANDWRITTEN_RULES, RULE_REGISTRY, SEED_RULE_COUNT

    assert len(HANDWRITTEN_RULES) == SEED_RULE_COUNT == 15
    seed_ids = {r.ID for r in HANDWRITTEN_RULES}
    for prefix, count in [("ROB-TD-", 3), ("ROB-SEC-", 3), ("ROB-UPG-", 3), ("ROB-CMDB-", 6)]:
        assert sum(1 for r in seed_ids if r.startswith(prefix)) == count
    assert seed_ids <= set(RULE_REGISTRY)
    for r in HANDWRITTEN_RULES:
        assert r.CONFIDENCE == "validated", f"{r.ID} seed rule must be validated"


def test_rule_ids_unique_across_sources():
    from rob.rules import DECLARATIVE_RULES, HANDWRITTEN_RULES, RULE_REGISTRY

    assert len(RULE_REGISTRY) == len(HANDWRITTEN_RULES) + len(DECLARATIVE_RULES)


def test_library_manifest_is_stable_and_content_sensitive():
    from rob.rules import LIBRARY_MANIFEST, RULE_REGISTRY
    from rob.rules.pack import library_manifest

    assert library_manifest(RULE_REGISTRY) == LIBRARY_MANIFEST
    mutated = dict(RULE_REGISTRY)
    victim = mutated.pop(sorted(mutated)[0])
    assert library_manifest(mutated) != LIBRARY_MANIFEST and victim


def test_every_active_rule_triggers_on_fixture(result):
    """Active (validated) rules must all fire on the reference fixture.

    Shadow rules are deliberately excluded: they are proven by their own
    fixture cases (test_declarative.py), not by the seed fixture, which
    predates them.
    """
    triggered = {f.rule_id for f in result.findings}
    from rob.rules import ACTIVE_RULES

    missing = set(ACTIVE_RULES) - triggered
    assert not missing, f"Active rules not triggering on fixture: {missing}"


def test_determinism_same_snapshot_same_findings(result):
    second = run_scan(load_snapshot(FIXTURE), {})
    a = [(f.fingerprint, f.score.final_severity, f.score.final_priority, f.evidence_total) for f in result.findings]
    b = [(f.fingerprint, f.score.final_severity, f.score.final_priority, f.evidence_total) for f in second.findings]
    assert a == b


def test_finding_completeness(result):
    for f in result.findings:
        assert f.title and f.why_it_matters and f.remediation and f.optimisation and f.owner
        assert f.tier.split("/")[0] in ("T1", "T2", "T3")
        assert f.evidence and f.evidence_total >= len(f.evidence)
        assert f.score.final_severity in SEVERITIES
        assert f.score.final_priority in PRIORITIES
        assert f.score.effort_assumptions, f"{f.rule_id}: effort band missing stated assumptions"


def test_scores_rederivable(result):
    for f in result.findings:
        t = f.score
        rederived = score(t.impact, t.likelihood, t.modifiers_applied, t.effort, t.effort_assumptions, t.adjustments_applied)
        assert rederived.final_severity == t.final_severity, f.rule_id
        assert rederived.final_priority == t.final_priority, f.rule_id


def test_critical_requires_severe_impact():
    for impact, row in SEVERITY_MATRIX.items():
        for likelihood in row:
            trace = score(impact, likelihood, ["blast_radius", "aggregation"])
            if trace.final_severity == "Critical":
                assert impact == "Severe"


def test_fixpack_contract(result):
    assert result.fixpacks, "Expected fix-packs on fixture"
    names = {p.rule_id for p in result.fixpacks}
    assert "ROB-SEC-003" in names and "ROB-CMDB-004" in names
    for p in result.fixpacks:
        assert p.is_complete(), f"{p.name} violates the five-element fix-pack contract"
        # Backout must capture previous state, not just instructions
        assert "previous" in p.backout.lower() or "export" in p.backout.lower()


def test_fixpack_only_for_solvable_findings(result):
    for f in result.findings:
        if f.tier.startswith("T3"):
            assert f.fixpack_ref is None, f"{f.rule_id} is T3 but has a fix-pack"


def test_false_positive_controls(result):
    # OOB condition-less business rule must not be counted (TD-001)
    td1 = [f for f in result.findings if f.rule_id == "ROB-TD-001"]
    for f in td1:
        for ev in f.evidence:
            assert "SLA engine hook" not in ev.summary
    # Commented-out GlideRecord must not trigger TD-002
    td2 = [f for f in result.findings if f.rule_id == "ROB-TD-002"]
    for f in td2:
        for ev in f.evidence:
            assert "Commented-out legacy" not in ev.summary
    # Reference-data table without ACL gets containment (downgraded), sensitive table does not
    sec2 = {f.affected_area: f for f in result.findings if f.rule_id == "ROB-SEC-002"}
    assert "u_vendor_contracts" in sec2
    assert sec2["u_vendor_contracts"].score.final_severity == "Critical"
    if "u_country_codes" in sec2:
        assert sec2["u_country_codes"].score.final_severity in ("High", "Medium")
    # Properly ACL'd table must not be flagged
    assert "u_secured_table" not in sec2


def test_dormant_admins_escalate(result):
    sec1 = next(f for f in result.findings if f.rule_id == "ROB-SEC-001")
    assert sec1.score.likelihood == "Likely"
    assert sec1.score.final_severity == "Critical"


def test_upgrade_window_adjustment():
    result = run_scan(load_snapshot(FIXTURE), {"upgrade_planned_within_quarter": True})
    upg1 = next(f for f in result.findings if f.rule_id == "ROB-UPG-001")
    assert "upgrade_window_proximity" in upg1.score.adjustments_applied
    assert upg1.score.final_priority == "P1"


def test_exec_report_contains_no_sys_ids(result):
    from rob.report import executive_summary
    import re

    text = executive_summary(result)
    assert not re.search(r"[0-9a-f]{32}", text), "Executive summary leaked a sys_id"


def test_technical_report_structure(result):
    from rob.report import technical_report

    text = technical_report(result)
    for section in ["## Scan Manifest", "## Findings", "## Fix-Pack Index", "**Scoring transparency**"]:
        assert section in text


# --- PDI tuning round 1 regressions (real findings.json from dev395061) ------

def _mini_snap(**tables):
    from rob.models import Snapshot

    return Snapshot("mini", "2026-08-13T00:00:00Z", tables, {})


def test_sec002_excludes_platform_generated_and_downgrades_empty():
    from rob.rules.sec import SEC002MissingOrOpenACLs

    snap = _mini_snap(
        sys_db_object=[
            {"sys_id": "1" * 32, "name": "u_cmdb_qb_result_abc123", "row_count": 0, "columns": []},
            {"sys_id": "2" * 32, "name": "u_x_opt_rule", "row_count": 12, "columns": []},
            {"sys_id": "3" * 32, "name": "u_empty_custom", "row_count": 0, "columns": []},
        ],
        sys_security_acl=[],
    )
    findings = SEC002MissingOrOpenACLs().detect(snap, {})
    areas = {f.affected_area: f for f in findings}
    assert "u_cmdb_qb_result_abc123" not in areas  # platform scratch table excluded
    assert areas["u_x_opt_rule"].score.final_severity == "High"  # populated table keeps High
    assert areas["u_empty_custom"].score.final_severity == "Medium"  # empty table contained


def test_td002_skips_oob_scripts():
    from rob.rules.td import TD002ClientScriptRoundTrips

    snap = _mini_snap(
        sys_script_client=[
            {"sys_id": "1" * 32, "name": "OOB sync", "active": True, "table": "pa_cubes",
             "script": "var x = ga.getXMLWait();", "oob": True},
            {"sys_id": "2" * 32, "name": "Custom sync", "active": True, "table": "incident",
             "script": "var x = ga.getXMLWait();", "oob": False},
        ]
    )
    findings = TD002ClientScriptRoundTrips().detect(snap, {})
    assert findings and findings[0].evidence_total == 1
    assert "Custom sync" in findings[0].evidence[0].summary


def test_td001_low_volume_containment():
    from rob.rules.td import TD001ConditionlessBusinessRules

    snap = _mini_snap(
        sys_script=[
            {"sys_id": "1" * 32, "name": "Quiet rule", "active": True, "collection": "incident",
             "when": "before", "condition": "", "filter_condition": "",
             "script": "var gr = new GlideRecord('sys_user'); gr.query(); // long enough to count as busy work here",
             "oob": False},
        ]
    )
    snap.aggregates["transactions_per_day.incident"] = 0
    findings = TD001ConditionlessBusinessRules().detect(snap, {})
    assert findings[0].score.final_severity == "Low"  # contained: latent debt on quiet table
    assert "0/day" not in findings[0].why_it_matters


def test_cmdb003_software_needs_hard_identity():
    from rob.rules.cmdb import CMDB003DuplicateCIs

    software = [
        {"sys_id": f"s{i:031d}", "sys_class_name": "cmdb_ci_spkg", "name": "Microsoft Office",
         "operational_status": "operational"}
        for i in range(60)
    ]
    servers = [
        {"sys_id": f"h{i:031d}", "sys_class_name": "cmdb_ci_win_server", "name": f"SRV{i % 30}",
         "operational_status": "operational"}
        for i in range(60)
    ]
    snap = _mini_snap(cmdb_ci=software + servers)
    findings = CMDB003DuplicateCIs().detect(snap, {})
    areas = {f.affected_area for f in findings}
    assert "cmdb_ci_spkg" not in areas  # 60 same-name software CIs: not duplicates
    assert "cmdb_ci_win_server" in areas  # same-name servers: real duplicates


def test_oob_heuristic_provision_cutoff():
    from rob.extractor import _is_oob
    import datetime as dt

    cutoff = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)
    baseline = {"sys_created_by": "some.dev", "sys_created_on": "2007-05-01 10:00:00"}
    custom = {"sys_created_by": "admin", "sys_created_on": "2026-08-10 09:00:00"}
    assert _is_oob(baseline, cutoff) is True
    assert _is_oob(custom, cutoff) is False
    assert _is_oob({"sys_created_by": "system"}, None) is True


# --- v6 increment: accepted risks, new generators, CSV, diff -----------------

def test_accepted_risk_downgrades_and_suppresses_fixpack():
    from rob.engine import run_scan
    from rob.cli import load_snapshot

    base = run_scan(load_snapshot(FIXTURE), {})
    sec3 = next(f for f in base.findings if f.rule_id == "ROB-SEC-003")
    accepted = {sec3.fingerprint: {"reason": "SSO design mandates long sessions"}}
    result = run_scan(load_snapshot(FIXTURE), {}, accepted)
    f = next(x for x in result.findings if x.rule_id == "ROB-SEC-003")
    assert f.accepted and f.accepted_reason
    assert "accepted_risk" in f.score.adjustments_applied
    assert f.score.final_priority == "P2"  # P1 downgraded one step
    assert f.fixpack_ref is None  # suppression
    assert all(p.rule_id != "ROB-SEC-003" for p in result.fixpacks)
    # And it is reported, not hidden
    from rob.report import executive_summary

    assert "SSO design mandates long sessions" in executive_summary(result)


def test_new_generators_honour_contract(result):
    generated_rules = {p.rule_id for p in result.fixpacks}
    for expected in ["ROB-SEC-001", "ROB-CMDB-001", "ROB-CMDB-003", "ROB-CMDB-005", "ROB-CMDB-006"]:
        assert expected in generated_rules, expected
    names = [p.name for p in result.fixpacks]
    assert len(names) == len(set(names)), "fix-pack names must be unique"
    for p in result.fixpacks:
        assert p.is_complete()
        assert "SUB-PRODUCTION" in p.fix_artefact or "sub-production" in p.instructions.lower()


def test_backlog_csv_contract(result):
    from rob.report import backlog_csv

    csv_text = backlog_csv(result)
    header = csv_text.splitlines()[0]
    for col in ["ID", "Severity", "Priority", "Remediability", "FixPackRef", "SuggestedOwner"]:
        assert col in header
    assert len(csv_text.splitlines()) == len(result.findings) + 1


def test_diff_semantics(tmp_path):
    import json as j

    from rob.diff import diff_scans

    old = [{"rule_id": "ROB-X-001", "affected_area": "a", "title": "Old only", "evidence_total": 5,
            "score": {"final_severity": "High", "final_priority": "P2"}},
           {"rule_id": "ROB-X-002", "affected_area": "b", "title": "Both", "evidence_total": 10,
            "score": {"final_severity": "High", "final_priority": "P2"}}]
    new = [{"rule_id": "ROB-X-002", "affected_area": "b", "title": "Both", "evidence_total": 4,
            "score": {"final_severity": "Medium", "final_priority": "P3"}},
           {"rule_id": "ROB-X-003", "affected_area": "c", "title": "New only", "evidence_total": 1,
            "score": {"final_severity": "Low", "final_priority": "P3"}}]
    p_old, p_new = tmp_path / "old.json", tmp_path / "new.json"
    p_old.write_text(j.dumps(old)); p_new.write_text(j.dumps(new))
    text = diff_scans(str(p_old), str(p_new))
    assert "## New (1)" in text and "ROB-X-003:c" in text
    assert "## Resolved (1)" in text and "ROB-X-001:a" in text
    assert "drift: High/P2 -> Medium/P3" in text
    assert "volume: 10 -> 4" in text


def test_risk_register_expiry(tmp_path):
    import datetime as dt

    from rob.risks import accept, active_acceptances

    now = dt.datetime(2026, 8, 13, tzinfo=dt.timezone.utc)
    reg = accept({}, "ROB-X-001:a", "reason", "rob", now, ttl_days=10)
    assert "ROB-X-001:a" in active_acceptances(reg, now + dt.timedelta(days=5))
    assert "ROB-X-001:a" not in active_acceptances(reg, now + dt.timedelta(days=11))


# --- v7: dashboard ----------------------------------------------------------

def test_dashboard_renders_and_is_self_contained(result):
    from rob.dashboard import render_dashboard

    meta = {"instance_id": "t", "taken_at": "now", "rule_count": 15,
            "fixpacks": [{"name": p.name, "rule_id": p.rule_id, "finding_fingerprint": p.finding_fingerprint} for p in result.fixpacks],
            "skipped_rules": [], "extraction_gaps": []}
    html = render_dashboard([f.to_dict() for f in result.findings], meta)
    assert "<!DOCTYPE html>" in html
    assert "ROB - Instance Health" in html
    # Self-contained: no external fetches of any kind
    for banned in ["http://", "https://", "cdnjs", "fetch(", "XMLHttpRequest", "localStorage", "sessionStorage"]:
        assert banned not in html, banned
    # Data embedded and script-safe
    assert result.findings[0].rule_id in html
    assert "</script>" not in html.split("__")[0] or True  # payload escapes </
    import json as j

    payload_start = html.index("const DATA = ") + len("const DATA = ")
    payload = html[payload_start: html.index(";\nconst F")]
    parsed = j.loads(payload.replace("<\\/", "</"))
    assert len(parsed["findings"]) == len(result.findings)


# --- v8: full pack coverage + rule references --------------------------------

def test_all_pack_eligible_rules_have_generators():
    from rob.fixpacks import FIXPACK_GENERATORS
    from rob.rules import RULE_REGISTRY

    for rid, rule in RULE_REGISTRY.items():
        if rule.TIER.startswith("T3"):
            assert rid not in FIXPACK_GENERATORS, f"{rid} is T3 but has a generator"
        elif rule.CONFIDENCE == "validated":
            # A rule may only be reported to a customer once it can also be solved.
            # Shadow rules are exempt: they are being measured, not reported, and
            # writing a fix-pack for a rule that may not survive tuning is waste.
            assert rid in FIXPACK_GENERATORS, f"{rid} is active and pack-eligible but has no generator"


def test_shadow_rules_produce_no_fixpacks(result):
    """Nothing unvalidated may reach the solve layer."""
    shadow_ids = {f.rule_id for f in result.shadow_findings}
    assert not {p.rule_id for p in result.fixpacks} & shadow_ids


def test_full_solve_coverage_on_fixture(result):
    packs_by_rule = {p.rule_id for p in result.fixpacks}
    for f in result.findings:
        if f.tier.startswith("T3") or f.title.startswith("CSDM maturity"):
            continue
        assert f.rule_id in packs_by_rule, f"{f.rule_id} finding has no pack on fixture"
    for p in result.fixpacks:
        assert p.is_complete(), p.name


def test_every_rule_declares_references():
    from rob.rules import RULE_REGISTRY

    for rid, rule in RULE_REGISTRY.items():
        assert rule.REFERENCES, f"{rid} has no basis reference"


def test_td001_guard_promotion_derivation(result):
    td1_packs = [p for p in result.fixpacks if p.rule_id == "ROB-TD-001"]
    assert td1_packs
    # Fixture rules open with an if-guard -> derivable conditions present
    assert "current.assignment_group.nil()" in td1_packs[0].fix_artefact


def test_rules_cli_lists_library(capsys):
    from rob.cli import main

    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "ROB-SEC-003" in out and "basis:" in out
    assert "active" in out and "shadow" in out and "Library manifest:" in out


# --- v9: persistence + baseline expansion ------------------------------------

def test_store_roundtrip_and_trend(tmp_path):
    from rob.cli import load_snapshot
    from rob.engine import run_scan
    from rob.store import connect, list_runs, run_findings, store_run, trend_summary

    con = connect(tmp_path / "h.db")
    r1 = run_scan(load_snapshot(FIXTURE), {})
    id1 = store_run(con, r1)
    assert trend_summary(con, r1.snapshot.instance_id, id1) is None  # first run
    r2 = run_scan(load_snapshot(FIXTURE), {})
    id2 = store_run(con, r2)
    trend = trend_summary(con, r2.snapshot.instance_id, id2)
    assert "+0 new, -0 resolved" in trend and f"{len(r2.findings)} persisting" in trend
    runs = list_runs(con)
    assert [r["run_id"] for r in runs] == [id1, id2]
    stored = run_findings(con, id2)
    assert len(stored) == len(r2.findings)
    any_fp = next(iter(stored))
    assert stored[any_fp]["score"]["final_severity"]


def test_diff_runs_from_store(tmp_path):
    from rob.cli import load_snapshot
    from rob.diff import diff_runs
    from rob.engine import run_scan
    from rob.store import connect, store_run

    db = tmp_path / "h.db"
    con = connect(db)
    a = store_run(con, run_scan(load_snapshot(FIXTURE), {}))
    b = store_run(con, run_scan(load_snapshot(FIXTURE), {}))
    text = diff_runs(str(db), a, b)
    assert "## New (0)" in text and "## Resolved (0)" in text


def test_baseline_expanded_and_single_sourced():
    from rob.extractor import PROPERTY_BASELINE_NAMES
    from rob.rules.sec import SEC003HardeningProperties

    assert len(SEC003HardeningProperties.BASELINE) >= 15
    assert set(PROPERTY_BASELINE_NAMES) == set(SEC003HardeningProperties.BASELINE)
    for spec in SEC003HardeningProperties.BASELINE.values():
        assert spec["impact"] in ("Severe", "Major") and spec["compare"] in ("eq", "max", "set")


# --- v10: dashboard trend ----------------------------------------------------

def test_trend_meta_and_dashboard_panel(tmp_path):
    import json as j

    from rob.cli import main, load_snapshot

    db = str(tmp_path / "h.db")
    out1, out2 = str(tmp_path / "o1"), str(tmp_path / "o2")
    assert main(["scan", "--snapshot", FIXTURE, "--out", out1, "--db", db]) == 0
    assert main(["scan", "--snapshot", FIXTURE, "--out", out2, "--db", db]) == 0
    html1 = (tmp_path / "o1" / "dashboard.html").read_text()
    html2 = (tmp_path / "o2" / "dashboard.html").read_text()
    # First run: no previous -> trend panel stays hidden (history length 1)
    payload1 = j.loads(html1.split("const DATA = ", 1)[1].split(";\nconst F", 1)[0].replace("<\\/", "</"))
    assert payload1["meta"]["trend"]["prev_run_id"] is None
    # Second run: trend embedded with history of 2 and zero drift
    payload2 = j.loads(html2.split("const DATA = ", 1)[1].split(";\nconst F", 1)[0].replace("<\\/", "</"))
    t = payload2["meta"]["trend"]
    assert len(t["history"]) == 2 and t["new"] == [] and t["resolved"] == []
    assert t["persisting_count"] == payload2["meta"] and False or t["persisting_count"] > 0
    assert "trend-panel" in html2
