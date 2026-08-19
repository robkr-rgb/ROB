"""Scheduled scan and notification tests.

The proactive half. What matters: the diff is fingerprint-level so an operator
learns what moved, notification failure never loses the finding, and no
language model is anywhere near this path.
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from rob.cli import load_snapshot
from rob.models import Snapshot
from rob.schedule import (
    diff_findings,
    is_noteworthy,
    notify,
    render_summary,
    run_scheduled_scan,
    severity_counts,
)

FIXTURE = str(pathlib.Path(__file__).parent.parent / "fixtures" / "pdi_like_snapshot.json")


def sev(name):
    return {"score": {"final_severity": name, "final_priority": "P2"}, "evidence_total": 1,
            "title": f"{name} thing", "affected_area": "t", "owner": "Platform team"}


# --- diffing -----------------------------------------------------------------

def test_diff_is_fingerprint_level_not_counts():
    """'17 findings again' tells an operator nothing. 'the ACL one is gone' does."""
    prev = {"A": sev("High"), "B": sev("High")}
    cur = {"B": sev("High"), "C": sev("Critical")}
    d = diff_findings(prev, cur)
    assert d == {"new": ["C"], "resolved": ["A"], "changed": []}


def test_diff_catches_a_finding_that_got_worse():
    prev = {"A": sev("Medium")}
    cur = {"A": sev("Critical")}
    assert diff_findings(prev, cur)["changed"] == ["A"]


def test_diff_catches_a_finding_that_grew():
    prev, cur = {"A": sev("High")}, {"A": dict(sev("High"), evidence_total=40)}
    assert diff_findings(prev, cur)["changed"] == ["A"]


def test_identical_runs_produce_no_delta():
    same = {"A": sev("High")}
    assert diff_findings(same, dict(same)) == {"new": [], "resolved": [], "changed": []}


def test_severity_counts_are_ordered_worst_first():
    counts = severity_counts({"a": sev("Low"), "b": sev("Critical"), "c": sev("High")})
    assert list(counts) == ["Critical", "High", "Low"]


# --- when to speak -----------------------------------------------------------

def test_no_change_is_silent_by_default():
    assert not is_noteworthy({"new": [], "resolved": [], "changed": []}, {})


def test_always_notify_breaks_the_silence():
    """Silence reads the same as a broken scheduler, so an operator can opt out of it."""
    assert is_noteworthy({"new": [], "resolved": [], "changed": []}, {}, always=True)


def test_a_resolved_finding_is_worth_saying():
    assert is_noteworthy({"new": [], "resolved": ["A"], "changed": []}, {})


# --- the summary -------------------------------------------------------------

def test_summary_is_readable_and_leaks_no_sys_ids():
    findings = {"ROB-SEC-001:x": dict(sev("Critical"), score={"final_severity": "Critical", "final_priority": "P1"})}
    text = render_summary("dev12345", 7, findings, {"new": ["ROB-SEC-001:x"], "resolved": [], "changed": []}, [], [])
    assert "dev12345" in text and "run 7" in text
    assert "P1 items" in text and "New (1)" in text
    assert "changes nothing without an approval" in text
    import re
    assert not re.search(r"\b[0-9a-f]{32}\b", text), "executive-facing text must not carry sys_ids"


def test_summary_declares_extraction_gaps():
    text = render_summary("i", 1, {"a": sev("High")}, None,
                          ["cmdb_ci: 403 Forbidden"], ["ROB-UPG-002: missing data"])
    assert "Extraction gaps declared" in text and "cmdb_ci" in text
    assert "Rules skipped for missing data: 1" in text


def test_summary_says_so_on_a_first_run():
    assert "nothing to compare" in render_summary("i", 1, {"a": sev("High")}, None, [], [])


# --- delivery ----------------------------------------------------------------

def test_notify_with_nothing_configured_does_nothing():
    assert notify({}, "s", "b") == []


def test_a_broken_channel_is_reported_not_raised():
    """A dead webhook must not suppress the email, and must not crash the scan."""
    delivered = notify({"webhook": {"url": "http://127.0.0.1:1/nope"}}, "s", "b")
    assert len(delivered) == 1 and delivered[0].startswith("webhook:FAILED")


# --- the whole run -----------------------------------------------------------

def test_first_run_then_second_run_produces_a_real_delta(tmp_path):
    snap = load_snapshot(FIXTURE)
    first = run_scheduled_scan(tmp_path, snap, progress=lambda *_: None)
    assert first["run_id"] == 1 and first["delta"] is None
    assert first["counts"]["Critical"] == 3

    out = pathlib.Path(first["out_dir"])
    for name in ("dashboard.html", "executive_summary.md", "technical_report.md", "backlog.csv"):
        assert (out / name).exists()
    assert list((out / "fixpacks").iterdir())

    # Same instance, the business rules cleaned up. Note the choice: emptying
    # sys_security_acl would ADD findings, because SEC-002 flags tables WITHOUT
    # an ACL. Removing scripts is what actually resolves something.
    tables = dict(snap.tables)
    tables["sys_script"] = []
    second = run_scheduled_scan(
        tmp_path, Snapshot(snap.instance_id, "2026-08-18T00:00:00Z", tables, snap.aggregates),
        progress=lambda *_: None)
    assert second["run_id"] == 2
    assert second["delta"]["resolved"], "removing the offending records must resolve findings"


def test_shadow_findings_stay_out_of_the_notification(tmp_path):
    outcome = run_scheduled_scan(tmp_path, load_snapshot(FIXTURE), progress=lambda *_: None)
    assert outcome["shadow_withheld"] > 0
    assert "shadow" not in outcome["summary"].lower()


def test_notification_fires_on_a_first_run_even_without_config_change(tmp_path):
    calls = []
    outcome = run_scheduled_scan(
        tmp_path, load_snapshot(FIXTURE),
        notify_config={"webhook": {"url": "http://127.0.0.1:1/nope"}},
        progress=lambda m: calls.append(m))
    assert outcome["notified"], "a first run is always worth reporting"
