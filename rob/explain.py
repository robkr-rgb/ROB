"""Plain-language explanation of a rule, generated from its own specification.

The console used to show a rule as a row: an ID, a title and a tier. That is
enough to recognise a rule you already know and useless for one you do not,
which is most of them once the library passes fifty. A finding that says what
is wrong without saying how it was decided is exactly the "descriptive, not
actionable" failure the product principles reject.

So the explanation is generated from the rule rather than written twice. A
declarative rule already carries its detection primitive, its data sources, its
severity inputs and its false-positive analysis; this module turns those into
sentences. Hand-written rules carry less structure, so they get a shorter
explanation and say so rather than inventing detail.

Nothing here is a language model. Same reason as everywhere else in ROB: the
console must say the same thing every time it renders the same rule.
"""
from __future__ import annotations

TIER_MEANING = {
    "T1": "ROB can generate an executable fix for this, and the change is reversible per record.",
    "T2": "ROB can prepare the fix, but a human decides and applies it.",
    "T3": "This is guidance. The remedy is a design decision, not an edit ROB can make.",
}

AUTONOMY_MEANING = {
    "A0": "Observe only. ROB reports it and proposes nothing automatic.",
    "A1": "Propose. ROB writes the fix-pack; a human applies it.",
    "A2": "Approve per fix. ROB can apply it after you approve that specific finding.",
    "A3": "Standing approval. Only under a signed baseline, and only for validated T1 rules.",
}

CONFIDENCE_MEANING = {
    "validated": "Measured against real instances. Findings are reported normally.",
    "provisional": "Under measurement. Findings are withheld from reports until a false-positive rate exists.",
    "unvalidated": "Not yet measured. Findings are withheld entirely.",
}

# How each detection primitive works, in one sentence a platform owner can read.
PRIMITIVE_MEANING = {
    "pattern_match": "Reads the script body and looks for a set of patterns.",
    "value_match": "Compares configured values against an expected baseline.",
    "presence": "Lists records that match a condition and should not exist.",
    "count_threshold": "Counts matching records and reports when the count passes a threshold.",
    "field_empty_rate": "Measures how often a field is empty, per group, against a maximum rate.",
    "staleness": "Finds records whose age passes a declared window.",
    "duplicate_key": "Groups records by an identity key and reports the groups with more than one member.",
    "dangling_reference": "Follows a reference field and reports the ones pointing at records that do not exist.",
    "cross_table_join": "Finds records in one table with no matching record in another.",
}

_OPS = {
    "equals": "is", "not_equals": "is not", "in": "is one of", "not_in": "is not one of",
    "contains": "contains", "not_contains": "does not contain", "gt": "is greater than",
    "gte": "is at least", "lt": "is less than", "lte": "is at most",
}


def _condition(c: dict) -> str:
    field = c.get("field", "?")
    if "empty" in c:
        return f"`{field}` is {'empty' if c['empty'] else 'not empty'}"
    for op, word in _OPS.items():
        if op in c:
            v = c[op]
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            elif isinstance(v, bool):
                v = "true" if v else "false"
            return f"`{field}` {word} {v}"
    return f"`{field}` matches a condition"


def tables_of(spec: dict) -> list[str]:
    d = spec.get("detect", {})
    out = list(d.get("tables") or ([d["table"]] if d.get("table") else []))
    for k in ("target_table", "join_table"):
        if d.get(k):
            out.append(d[k])
    return sorted(set(out))


def detection_sentences(spec: dict) -> list[str]:
    """How this rule decides, as a short ordered list."""
    d = spec.get("detect") or {}
    kind = d.get("type", "")
    lines: list[str] = []
    tables = tables_of(spec)
    if tables:
        lines.append("Reads " + ", ".join(f"`{t}`" for t in tables) + ".")
    if PRIMITIVE_MEANING.get(kind):
        lines.append(PRIMITIVE_MEANING[kind])

    where = d.get("where") or []
    if where:
        lines.append("Considers only records where " + " and ".join(_condition(c) for c in where) + ".")
    if d.get("exclude_oob", True) and kind in ("pattern_match", "presence"):
        lines.append("Vendor-shipped records are excluded: only customer-authored artefacts are considered.")

    if kind == "pattern_match":
        n = len(d.get("patterns") or [])
        field = d.get("field", "script")
        if d.get("match") == "none":
            lines.append(f"Flags records whose `{field}` contains none of {n} required pattern(s).")
        else:
            lines.append(f"Flags records whose `{field}` matches any of {n} pattern(s).")
        if d.get("unless_patterns"):
            lines.append(f"Skips records that also match {len(d['unless_patterns'])} exemption pattern(s).")
        if d.get("strip_comments", True):
            lines.append("Line comments are stripped first, so commented-out code does not count.")
    elif kind == "count_threshold":
        direction = "above" if d.get("direction", "above") == "above" else "below"
        lines.append(f"Reports when the count is {direction} {d.get('threshold')}.")
    elif kind == "staleness":
        lines.append(f"Reports records older than {d.get('older_than_days')} days, "
                     f"measured from `{d.get('age_field')}`.")
    elif kind == "field_empty_rate":
        pct = round(float(d.get("max_empty_rate", 0)) * 100)
        grp = d.get("group_by")
        lines.append(f"Reports when more than {pct}% of `{d.get('target_field')}` values are empty"
                     + (f", grouped by `{grp}`." if grp else "."))
        if d.get("min_group_size"):
            lines.append(f"Groups smaller than {d['min_group_size']} records are ignored.")
    elif kind == "duplicate_key":
        lines.append("Identity key: " + ", ".join(f"`{f}`" for f in d.get("key_fields", [])) + ".")
        lines.append("Records with any part of the key empty are skipped, because an incomplete "
                     "identity is not evidence of duplication.")
    elif kind == "dangling_reference":
        lines.append("Checks " + ", ".join(f"`{f}`" for f in d.get("reference_fields", []))
                     + f" against `{d.get('target_table')}`.")
        lines.append("If the target table was not extracted the rule goes silent, so a permission "
                     "gap can never look like data corruption.")
    elif kind == "cross_table_join":
        lines.append(f"Reports records with no matching `{d.get('join_table')}` record.")
    return lines


def severity_sentences(spec: dict) -> list[str]:
    sev = spec.get("severity") or {}
    out = []
    if sev.get("impact") and sev.get("likelihood"):
        out.append(f"Starts at impact {sev['impact']} × likelihood {sev['likelihood']} on the severity matrix.")
    for m in sev.get("modifiers", []):
        out.append(f"Always applies the {m.replace('_', ' ')} modifier.")
    for cm in sev.get("conditional_modifiers", []):
        out.append(f"Applies the {cm['modifier'].replace('_', ' ')} modifier once {cm['when_total_at_least']} "
                   "or more records match.")
    if sev.get("effort"):
        out.append(f"Effort is {sev['effort']} by default"
                   + (f", rising once {sev['effort_escalation'][0]['when_total_at_least']} records match."
                      if sev.get("effort_escalation") else "."))
    if sev.get("assumptions"):
        out.append(sev["assumptions"])
    return out


def explain(rule, spec: dict | None = None) -> dict:
    """Everything the console needs to describe one rule.

    `spec` is the declarative record where there is one. Hand-written rules pass
    None and get the structural half only, which is the honest outcome: a Python
    rule carries no machine-readable false-positive analysis, and inventing one
    would be worse than saying it is in the source.
    """
    tier = getattr(rule, "TIER", "")
    base_tier = tier.split("/")[0] if tier else ""
    out = {
        "id": getattr(rule, "ID", ""),
        "title": getattr(rule, "TITLE", ""),
        "category": getattr(rule, "CATEGORY", ""),
        "version": getattr(rule, "VERSION", ""),
        "tier": tier,
        "tier_meaning": TIER_MEANING.get(base_tier, ""),
        "autonomy": getattr(rule, "AUTONOMY", ""),
        "autonomy_meaning": AUTONOMY_MEANING.get(getattr(rule, "AUTONOMY", ""), ""),
        "confidence": getattr(rule, "CONFIDENCE", ""),
        "confidence_meaning": CONFIDENCE_MEANING.get(getattr(rule, "CONFIDENCE", ""), ""),
        "owner": getattr(rule, "OWNER", ""),
        "basis": list(getattr(rule, "REFERENCES", ()) or ()),
        "topics": list(getattr(rule, "DOC_TOPICS", ()) or ()),
        "declarative": spec is not None,
        "tables": [],
        "detection": [],
        "severity": [],
        "false_positives": [],
        "why": "",
        "remediation": "",
        "optimisation": "",
    }
    if spec:
        out["tables"] = tables_of(spec)
        out["detection"] = detection_sentences(spec)
        out["severity"] = severity_sentences(spec)
        out["false_positives"] = list(spec.get("false_positives") or [])
        out["why"] = spec.get("why", "")
        out["remediation"] = spec.get("remediation", "")
        out["optimisation"] = spec.get("optimisation", "")
        out["primitive"] = (spec.get("detect") or {}).get("type", "")
    else:
        out["detection"] = ["This rule is hand-written Python. Its detection logic lives in "
                            "`rob/rules/` and its specification in `scanner/scan-rules.md`."]
        out["primitive"] = "hand-written"
    return out
