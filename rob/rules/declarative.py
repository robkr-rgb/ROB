"""Declarative rules: a rule described by a spec record instead of a method.

Why this exists (D-014): the seed library is 15 hand-written Rule subclasses.
The triaged catalogue (scanner/rule-catalogue-triage.md) puts a realistic
library at roughly 150 rules, and most of them reduce to a handful of detection
shapes. Writing 150 Python classes to express nine shapes is the wrong trade.

What this is NOT: a way to bypass rule governance. A spec IS the specification
required by RULE_AUTHORING.md - it carries objective, data sources, detection
logic, severity logic, false-positive analysis and fixture cases, all validated
before load (see pack.py). Rules that do not fit a primitive stay hand-written.

Determinism is preserved: primitives read only the snapshot, iterate in sorted
order, and never consult wall-clock time or randomness.
"""
from __future__ import annotations

import re

from ..models import Evidence, Finding, Snapshot
from .base import EVIDENCE_CAP, Rule, s

class MissingSnapshotData(KeyError):
    """A declared data source was not extracted (permission gap or manifest gap).

    Distinct from a plain KeyError so that a coding defect inside a primitive
    surfaces as a failure rather than being mistaken for a data gap and quietly
    reported as a skipped rule. Rules go silent on missing data; they never guess,
    and ROB never mislabels its own bugs as the customer's permissions.
    """


# --------------------------------------------------------------------------
# where-clause matching
# --------------------------------------------------------------------------

def _get(rec: dict, field: str):
    return rec.get(field)


def _cond(rec: dict, c: dict) -> bool:
    """One condition. Exactly one operator key beyond 'field' is expected."""
    v = _get(rec, c["field"])
    if "equals" in c:
        return v == c["equals"]
    if "not_equals" in c:
        return v != c["not_equals"]
    if "in" in c:
        return v in c["in"]
    if "not_in" in c:
        return v not in c["not_in"]
    if "empty" in c:
        return (not v) if c["empty"] else bool(v)
    if "contains" in c:
        return isinstance(v, str) and c["contains"] in v
    if "not_contains" in c:
        return not (isinstance(v, str) and c["not_contains"] in v)
    if "gt" in c:
        return isinstance(v, (int, float)) and v > c["gt"]
    if "gte" in c:
        return isinstance(v, (int, float)) and v >= c["gte"]
    if "lt" in c:
        return isinstance(v, (int, float)) and v < c["lt"]
    if "lte" in c:
        return isinstance(v, (int, float)) and v <= c["lte"]
    raise ValueError(f"Unsupported condition: {c}")


CONDITION_OPS = {
    "equals", "not_equals", "in", "not_in", "empty",
    "contains", "not_contains", "gt", "gte", "lt", "lte",
}


def _where(records: list[dict], conditions: list[dict] | None) -> list[dict]:
    if not conditions:
        return list(records)
    return [r for r in records if all(_cond(r, c) for c in conditions)]


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------

def _strip_comments(script: str) -> str:
    """Line comments only, matching the hand-written rules' behaviour.

    Deliberately conservative: block comments are left in place rather than
    stripped with a regex that would eat string literals containing '/*'.
    Comment-borne matches are the known false-positive class for every
    pattern rule and are declared as such in each spec.
    """
    out = []
    for line in script.splitlines():
        if "//" in line:
            line = line.split("//", 1)[0]
        out.append(line)
    return "\n".join(out)


def _fmt(template: str, **kw) -> str:
    try:
        return template.format(**kw)
    except (KeyError, IndexError):
        return template


def _emit(rule, spec, affected_area, evidence, total, **fmt_kw) -> Finding:
    sev = spec["severity"]
    modifiers = list(sev.get("modifiers", []))
    for cond in sev.get("conditional_modifiers", []):
        if total >= cond.get("when_total_at_least", 10 ** 9):
            modifiers.append(cond["modifier"])
    effort = sev.get("effort", "Medium")
    for esc in sev.get("effort_escalation", []):
        if total >= esc["when_total_at_least"]:
            effort = esc["effort"]
    kw = dict(count=total, total=total, area=affected_area, **fmt_kw)
    return rule.finding(
        affected_area=affected_area,
        evidence=evidence,
        evidence_total=total,
        why=_fmt(spec["why"], **kw),
        remediation=_fmt(spec["remediation"], **kw),
        optimisation=_fmt(spec.get("optimisation", ""), **kw),
        trace=s(
            sev["impact"],
            sev["likelihood"],
            modifiers,
            effort=effort,
            assumptions=sev.get("assumptions", ""),
        ),
    )


def _tables(spec) -> list[str]:
    t = spec.get("tables") or ([spec["table"]] if "table" in spec else [])
    return list(t)


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def p_pattern_match(rule, snap: Snapshot, params: dict, spec: dict) -> list[Finding]:
    """Regex/substring match over a script-bearing field across one or more tables.

    Two modes, declared by `match`:
      "any"  (default) - flag records where at least one pattern matches.
                         Covers the class B anti-pattern checks (gs.sql, cache
                         flush, console.log, localStorage, DOM access, dot-walk).
      "none"           - flag records where NO pattern matches. Covers the
                         "required construct is absent" checks (a client script
                         with no function wrapper, an onChange script with no
                         isLoading guard). Use a `where` condition to exclude
                         empty fields, otherwise every empty record is flagged.
    """
    field = spec.get("field", "script")
    mode = spec.get("match", "any")
    patterns = [re.compile(p) for p in spec["patterns"]]
    antipatterns = [re.compile(p) for p in spec.get("unless_patterns", [])]
    strip = spec.get("strip_comments", True)
    offenders: list[tuple[str, dict, int]] = []
    total_hits = 0
    for table in _tables(spec):
        for rec in _where(snap.t(table), spec.get("where")):
            if spec.get("exclude_oob", True) and rec.get("oob"):
                continue
            body = rec.get(field, "") or ""
            if strip:
                body = _strip_comments(body)
            if any(a.search(body) for a in antipatterns):
                continue
            hits = sum(len(p.findall(body)) for p in patterns)
            if mode == "none":
                if hits == 0:
                    offenders.append((table, rec, 0))
            elif hits:
                offenders.append((table, rec, hits))
                total_hits += hits
    if not offenders:
        return []
    offenders.sort(key=lambda x: (-x[2], x[0], str(x[1].get("sys_id", ""))))
    absent_label = spec.get("absence_label", "required construct not found")
    evidence = [
        Evidence(
            summary=(
                f"{table}/{rec.get('name', rec.get('sys_id', '?'))}: {absent_label}"
                if mode == "none"
                else f"{table}/{rec.get('name', rec.get('sys_id', '?'))}: {n} match(es)"
            ),
            record_ref=f"{table}/{rec.get('sys_id', '')}",
            data={"matches": n},
        )
        for table, rec, n in offenders[:EVIDENCE_CAP]
    ]
    return [_emit(rule, rule.spec, spec["affected_area"], evidence, len(offenders), hits=total_hits)]


def p_value_match(rule, snap: Snapshot, params: dict, spec: dict) -> list[Finding]:
    """Key/value records (system properties and similar) compared to expected values.

    Reports both deviating values and, when report_missing is set, keys that are
    absent entirely. This is the shape most A3-eligible rules take.
    """
    table = spec["table"]
    key_f, val_f = spec.get("key_field", "name"), spec.get("value_field", "value")
    expect: dict = spec["expect"]
    present = {r.get(key_f): r for r in snap.t(table)}
    deviations = []
    for key in sorted(expect):
        want = expect[key]
        rec = present.get(key)
        if rec is None:
            if spec.get("report_missing", False):
                deviations.append((key, None, want))
            continue
        got = rec.get(val_f)
        if str(got).strip().lower() != str(want).strip().lower():
            deviations.append((key, got, want))
    if not deviations:
        return []
    evidence = [
        Evidence(
            summary=(f"'{k}' is not set (expected '{w}')" if g is None else f"'{k}' is '{g}', expected '{w}'"),
            record_ref=f"{table}/{k}",
            data={"expected": w, "actual": g},
        )
        for k, g, w in deviations[:EVIDENCE_CAP]
    ]
    return [_emit(rule, rule.spec, spec["affected_area"], evidence, len(deviations))]


def p_presence(rule, snap: Snapshot, params: dict, spec: dict) -> list[Finding]:
    """Records that match a condition set and should not exist."""
    table = spec["table"]
    matches = _where(snap.t(table), spec.get("where"))
    if spec.get("exclude_oob", True):
        matches = [m for m in matches if not m.get("oob")]
    if not matches:
        return []
    label = spec.get("label_field", "name")
    matches.sort(key=lambda r: str(r.get(label, r.get("sys_id", ""))))
    evidence = [
        Evidence(
            summary=_fmt(spec.get("evidence_template", "{label}"), label=r.get(label, r.get("sys_id", "?")), **r)
            if spec.get("evidence_template") else f"{table}/{r.get(label, r.get('sys_id', '?'))}",
            record_ref=f"{table}/{r.get('sys_id', '')}",
        )
        for r in matches[:EVIDENCE_CAP]
    ]
    return [_emit(rule, rule.spec, spec["affected_area"], evidence, len(matches))]


def p_count_threshold(rule, snap: Snapshot, params: dict, spec: dict) -> list[Finding]:
    """Cardinality of a filtered set above (or below) a declared threshold."""
    table = spec["table"]
    matches = _where(snap.t(table), spec.get("where"))
    n = len(matches)
    threshold = spec["threshold"]
    direction = spec.get("direction", "above")
    breached = n > threshold if direction == "above" else n < threshold
    if not breached:
        return []
    label = spec.get("label_field", "name")
    template = spec.get("evidence_template")
    evidence = [
        Evidence(
            summary=(_fmt(template, label=r.get(label, r.get("sys_id", "?")), **r) if template
                     else f"{r.get(label, r.get('sys_id', '?'))}"),
            record_ref=f"{table}/{r.get('sys_id', '')}",
        )
        for r in sorted(matches, key=lambda r: str(r.get(label, "")))[:EVIDENCE_CAP]
    ]
    return [_emit(rule, rule.spec, spec["affected_area"], evidence, n, threshold=threshold)]


def p_field_empty_rate(rule, snap: Snapshot, params: dict, spec: dict) -> list[Finding]:
    """Share of records with an empty target field, per group, against a threshold."""
    table = spec["table"]
    target = spec["target_field"]
    group_by = spec.get("group_by")
    min_group = spec.get("min_group_size", 1)
    threshold = spec["max_empty_rate"]
    rows = _where(snap.t(table), spec.get("where"))
    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(str(r.get(group_by)) if group_by else spec["affected_area"], []).append(r)
    findings = []
    for gname in sorted(groups):
        members = groups[gname]
        if len(members) < min_group:
            continue
        empties = [m for m in members if not m.get(target)]
        rate = len(empties) / len(members)
        if rate <= threshold:
            continue
        evidence = [
            Evidence(summary=f"{m.get('name', m.get('sys_id', '?'))}: '{target}' is empty",
                     record_ref=f"{table}/{m.get('sys_id', '')}")
            for m in sorted(empties, key=lambda m: str(m.get("name", "")))[:EVIDENCE_CAP]
        ]
        findings.append(_emit(rule, rule.spec, gname, evidence, len(empties),
                              rate=round(rate * 100), group_total=len(members)))
    return findings


def p_staleness(rule, snap: Snapshot, params: dict, spec: dict) -> list[Finding]:
    """Numeric age field beyond a declared window.

    Takes a precomputed age field from the snapshot (the extractor derives these)
    rather than parsing timestamps at rule time, so rules stay clock-free and
    therefore deterministic.
    """
    table = spec["table"]
    age_f = spec["age_field"]
    days = spec["older_than_days"]
    rows = [r for r in _where(snap.t(table), spec.get("where"))
            if isinstance(r.get(age_f), (int, float)) and r[age_f] > days]
    if not rows:
        return []
    rows.sort(key=lambda r: -r[age_f])
    evidence = [
        Evidence(summary=f"{r.get('name', r.get('sys_id', '?'))}: {r[age_f]} days since update",
                 record_ref=f"{table}/{r.get('sys_id', '')}")
        for r in rows[:EVIDENCE_CAP]
    ]
    return [_emit(rule, rule.spec, spec["affected_area"], evidence, len(rows), days=days)]


def p_duplicate_key(rule, snap: Snapshot, params: dict, spec: dict) -> list[Finding]:
    """Two or more records sharing a declared identity key."""
    table = spec["table"]
    keys = spec["key_fields"]
    rows = _where(snap.t(table), spec.get("where"))
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        k = tuple(str(r.get(f, "")).strip().lower() for f in keys)
        if any(not part for part in k):
            continue  # incomplete identity is not evidence of duplication
        groups.setdefault(k, []).append(r)
    dupes = {k: v for k, v in groups.items() if len(v) > 1}
    if not dupes:
        return []
    evidence = [
        Evidence(summary=f"{len(v)} records share {dict(zip(keys, k))}",
                 record_ref=f"{table}/{v[0].get('sys_id', '')}")
        for k, v in sorted(dupes.items())[:EVIDENCE_CAP]
    ]
    return [_emit(rule, rule.spec, spec["affected_area"], evidence, len(dupes))]


def p_dangling_reference(rule, snap: Snapshot, params: dict, spec: dict) -> list[Finding]:
    """Reference field pointing at a record that does not exist in the snapshot.

    Only runs when the target table was extracted; otherwise a permission gap
    would masquerade as data corruption. Missing target table raises KeyError so
    the engine records a skipped rule rather than emitting a false finding.
    """
    table, target = spec["table"], spec["target_table"]
    if target not in snap.tables:
        raise MissingSnapshotData(target)
    valid = {r.get(spec.get("target_field", "sys_id")) for r in snap.t(target)}
    ref_fields = spec["reference_fields"]
    broken = []
    for r in _where(snap.t(table), spec.get("where")):
        for f in ref_fields:
            v = r.get(f)
            if v and v not in valid:
                broken.append((r, f, v))
    if not broken:
        return []
    broken.sort(key=lambda x: (str(x[0].get("sys_id", "")), x[1]))
    evidence = [
        Evidence(summary=f"{table}/{r.get('sys_id', '?')} field '{f}' references missing {target} {v}",
                 record_ref=f"{table}/{r.get('sys_id', '')}")
        for r, f, v in broken[:EVIDENCE_CAP]
    ]
    return [_emit(rule, rule.spec, spec["affected_area"], evidence, len(broken))]


def p_cross_table_join(rule, snap: Snapshot, params: dict, spec: dict) -> list[Finding]:
    """Records in A with no matching record in B on a declared key.

    The CSDM linkage shape: business applications with no application service,
    services with no offering, and similar.
    """
    left, right = spec["table"], spec["join_table"]
    if right not in snap.tables:
        raise MissingSnapshotData(right)
    right_key = spec["join_field"]
    right_values = {r.get(right_key) for r in _where(snap.t(right), spec.get("join_where"))}
    left_key = spec.get("key_field", "sys_id")
    orphans = [r for r in _where(snap.t(left), spec.get("where")) if r.get(left_key) not in right_values]
    if not orphans:
        return []
    label = spec.get("label_field", "name")
    orphans.sort(key=lambda r: str(r.get(label, "")))
    evidence = [
        Evidence(summary=f"{r.get(label, r.get('sys_id', '?'))} has no matching {right} record",
                 record_ref=f"{left}/{r.get('sys_id', '')}")
        for r in orphans[:EVIDENCE_CAP]
    ]
    return [_emit(rule, rule.spec, spec["affected_area"], evidence, len(orphans))]


DETECTORS = {
    "pattern_match": p_pattern_match,
    "value_match": p_value_match,
    "presence": p_presence,
    "count_threshold": p_count_threshold,
    "field_empty_rate": p_field_empty_rate,
    "staleness": p_staleness,
    "duplicate_key": p_duplicate_key,
    "dangling_reference": p_dangling_reference,
    "cross_table_join": p_cross_table_join,
}


class DeclarativeRule(Rule):
    """A Rule whose detection is a validated spec record, not a method body."""

    def __init__(self, spec: dict):
        self.ID = spec["id"]
        self.VERSION = spec["version"]
        self.CATEGORY = spec["category"]
        self.TITLE = spec["title"]
        self.TIER = spec["tier"]
        self.OWNER = spec["owner"]
        self.REFERENCES = tuple(spec["basis"])
        self.CONFIDENCE = spec["confidence"]
        self.AUTONOMY = spec["autonomy"]
        self.DOC_TOPICS = tuple(spec.get("doc_topics", ()))
        self.spec = spec

    @property
    def source_tables(self) -> list[str]:
        d = self.spec["detect"]
        out = _tables(d)
        for k in ("target_table", "join_table"):
            if d.get(k):
                out.append(d[k])
        return sorted(set(out))

    def detect(self, snap: Snapshot, params: dict) -> list[Finding]:
        d = self.spec["detect"]
        return DETECTORS[d["type"]](self, snap, params, d)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DeclarativeRule {self.ID} v{self.VERSION} {self.spec['detect']['type']}>"
