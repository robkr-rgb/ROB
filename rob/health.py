"""Instance health score: one number, and the arithmetic that produced it.

The console shows a 0-100 score and a grade. A score nobody can reconstruct is
a score nobody should trust, so this module returns the build-up alongside the
number and the console prints it verbatim ('How the score is built'). Same
principle as ScoreTrace on a finding: the derivation is the product, not the
digit.

Deterministic: no clock, no randomness, no configuration. Two runs over the
same findings produce the same score on any machine.
"""
from __future__ import annotations

# Deduction per finding, by severity. Ratios matter more than absolutes:
# one Critical must outweigh any realistic pile of Mediums, because a
# average of many small things is how a genuinely unsafe instance scores well.
SEVERITY_WEIGHT = {
    "Critical": 9.0,
    "High": 3.0,
    "Medium": 1.0,
    "Low": 0.25,
    "Informational": 0.0,
}

# Breadth penalty: findings spread across many domains describe a systemic
# problem, not a local one. Capped, because breadth is a modifier and never
# the headline.
BREADTH_PER_DOMAIN = 1.5
BREADTH_CAP = 6.0

# Calibrated against the reference design's own examples: 74 reads as B,
# 68 as B-, 62 as C+. Even ~7-point bands, so a grade change means a real
# change rather than a rounding artefact.
GRADE_BANDS = (
    (94, "A"), (87, "A-"), (80, "B+"), (73, "B"), (66, "B-"),
    (60, "C+"), (54, "C"), (48, "C-"), (42, "D+"), (36, "D"), (30, "D-"),
)


def grade(score: int) -> str:
    for floor, letter in GRADE_BANDS:
        if score >= floor:
            return letter
    return "E"


def health_score(findings: list[dict], *, domains_scanned: int = 0) -> dict:
    """Score a run. `findings` are stored finding dicts (score.final_severity).

    Returns the score, the grade, and an ordered build-up of every line that
    moved it, so the console can render the derivation without recomputing it.
    """
    counts: dict[str, int] = {}
    domains: set[str] = set()
    for f in findings:
        sev = ((f.get("score") or {}).get("final_severity")) or "Informational"
        counts[sev] = counts.get(sev, 0) + 1
        if f.get("category"):
            domains.add(str(f["category"]))

    build: list[dict] = [{"label": "Starting position", "value": 100.0, "detail": ""}]
    total = 100.0
    for sev in ("Critical", "High", "Medium", "Low", "Informational"):
        n = counts.get(sev, 0)
        weight = SEVERITY_WEIGHT[sev]
        if not n or not weight:
            continue
        delta = n * weight
        total -= delta
        build.append({
            "label": f"{n} {sev.lower()} × {weight:g}",
            "value": -delta,
            "detail": "",
        })

    breadth = min(BREADTH_CAP, BREADTH_PER_DOMAIN * len(domains)) if len(domains) > 1 else 0.0
    if breadth:
        total -= breadth
        build.append({
            "label": "Coverage-weighted breadth penalty",
            "value": -breadth,
            "detail": f"{len(domains)} domains affected",
        })

    score = int(max(0, min(100, round(total))))
    return {
        "score": score,
        "grade": grade(score),
        "build": build,
        "counts": counts,
        "domains": sorted(domains),
        "domains_scanned": domains_scanned or len(domains),
    }


def severity_breakdown(findings: list[dict]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = ((f.get("score") or {}).get("final_severity")) or "Informational"
        counts[sev] = counts.get(sev, 0) + 1
    return [(s, counts.get(s, 0)) for s in ("Critical", "High", "Medium", "Low")]


def domain_breakdown(findings: list[dict]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.get("category") or "Uncategorised"] = counts.get(f.get("category") or "Uncategorised", 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def priority_buckets(findings: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {"P1": [], "P2": [], "P3": [], "P4": []}
    for f in findings:
        p = ((f.get("score") or {}).get("final_priority")) or "P4"
        out.setdefault(p, []).append(f)
    return out


def verdict(findings: list[dict], score_info: dict) -> str:
    """One sentence an executive can act on. Rules, not prose generation.

    Written here rather than by a language model because the console must say
    the same thing every time it renders the same run (D-012).
    """
    counts = score_info["counts"]
    crit, high = counts.get("Critical", 0), counts.get("High", 0)
    total = sum(counts.values())
    if not total:
        return "Nothing in the active ruleset fired on this instance. The gaps below are what it did not look at."
    if crit:
        noun = "finding is" if crit == 1 else "findings are"
        return (f"{crit} critical {noun} open on this instance. "
                "Everything else on the list can wait — these cannot.")
    if high >= 3:
        return (f"No criticals, but {high} high findings are open. "
                "This is a backlog problem rather than an emergency.")
    if high:
        return (f"{high} high finding{'s' if high > 1 else ''} and nothing critical. "
                "The instance is in reasonable shape; clear these before they age.")
    return ("Nothing high or critical is open. What remains is maintainability work "
            "that is worth scheduling rather than reacting to.")
