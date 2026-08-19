"""Health score: the number and, more importantly, the arithmetic behind it."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from rob.health import domain_breakdown, grade, health_score, priority_buckets, verdict


def f(sev, cat="Security", pri="P2"):
    return {"score": {"final_severity": sev, "final_priority": pri}, "category": cat}


def test_clean_instance_scores_100():
    r = health_score([])
    assert r["score"] == 100 and r["grade"] == "A"


def test_build_up_sums_to_the_score():
    findings = [f("Critical")] * 2 + [f("High")] * 5 + [f("Medium", "CMDB")] * 7
    r = health_score(findings)
    assert round(sum(b["value"] for b in r["build"])) == r["score"], (
        "the printed derivation must reconstruct the printed number")


def test_one_critical_outweighs_a_pile_of_mediums():
    assert health_score([f("Critical")])["score"] < health_score([f("Medium")] * 8)["score"]


def test_informational_findings_do_not_move_the_score():
    assert health_score([f("Informational")] * 20)["score"] == 100


def test_breadth_penalty_applies_only_across_domains_and_is_capped():
    one = health_score([f("Medium", "Security")] * 6)
    many = health_score([f("Medium", c) for c in ("Security", "CMDB", "Technical Debt",
                                                  "Governance", "Data Model", "Integrations")])
    assert all(b["label"] != "Coverage-weighted breadth penalty" for b in one["build"])
    penalty = next(b for b in many["build"] if "breadth" in b["label"])
    assert penalty["value"] == -6.0, "capped, because breadth is a modifier not the headline"


def test_score_is_clamped_and_deterministic():
    findings = [f("Critical")] * 40
    assert health_score(findings)["score"] == 0
    assert health_score(findings) == health_score(findings)


def test_grades_are_ordered():
    assert grade(95) == "A" and grade(74) == "B" and grade(68) == "B-"
    assert grade(62) == "C+" and grade(20) == "E"


def test_verdict_leads_with_criticals_and_never_invents_them():
    crit = verdict([f("Critical")] * 2, health_score([f("Critical")] * 2))
    assert "2 critical" in crit and "cannot" in crit
    clean = verdict([], health_score([]))
    assert "did not look at" in clean
    calm = verdict([f("Medium")], health_score([f("Medium")]))
    assert "nothing high or critical" in calm.lower()


def test_breakdowns_are_stable_orderings():
    findings = [f("High", "CMDB"), f("High", "Security"), f("High", "Security")]
    assert domain_breakdown(findings) == [("Security", 2), ("CMDB", 1)]
    assert list(priority_buckets(findings)) == ["P1", "P2", "P3", "P4"]
