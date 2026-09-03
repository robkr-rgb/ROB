"""Declarative remediation: a fix-pack compiled from the rule's own spec.

Why this exists (D-028): the fix-pack layer had the same problem the rule
library had before D-014. Twelve hand-written generator modules cover twelve
rules, and every new rule needs new Python before its finding is anything
more than advice. At library scale that guarantees the fix library lags the
rule library forever, which is the opposite of the product promise: ROB
proposes AND solves.

A rule spec may therefore carry a `remediation_pack` block. The block is
validated by the same governance gate as detection (pack.py), proven against
the rule's own triggering fixtures at load time, and compiled here into a
full five-element FixPack with typed W-C operations. Add a rule with a
remediation block and the executable fix ships with it. No new Python.

What this is NOT: a script generator. Every remediation primitive reduces to
typed record operations the W-C executor can preview, bound, verify and
reverse one record at a time. A fix that cannot be expressed that way (logic
rewrites, merges, anything needing judgement per record) does not belong in
a block; it stays a hand-written generator or a human instruction.

Primitives (deliberately few, like the nine detection primitives):

  update_fields             set declared field values on every offending
                            record. Values are literals or named inputs
                            supplied by the approver at approval time.
  transform_field           compute the new value from the record's current
                            value via a named, tested transform. The
                            endpoint http->https shape.
  set_expected_properties   for value_match rules: the detection's own
                            `expect` map IS the fix. The SEC-003 shape,
                            generalised to any future property rule.

Selection re-runs the rule's own filter over the snapshot, so operations
cover every offender, not just the capped evidence sample.

Inputs: a value the snapshot cannot supply (which service account should own
a job) is declared, not guessed. Operations carry an {"$input": name}
placeholder, the executor refuses to run an unbound plan, and bind_inputs()
resolves placeholders once a human has supplied values at approval time.
A rule with inputs can never be A3: standing approval cannot answer a
question.
"""
from __future__ import annotations

import json

from ..models import Finding, FixPack, Snapshot


# --- transforms --------------------------------------------------------------
# Named, deterministic, and total: a transform returns None to mean "this
# record needs no change", never raises on odd input.

def t_http_to_https(value):
    if isinstance(value, str) and value.startswith("http://"):
        return "https://" + value[len("http://"):]
    return None


TRANSFORMS = {"http_to_https": t_http_to_https}

REMEDIATION_KINDS = ("update_fields", "transform_field", "set_expected_properties")


def is_input(v) -> bool:
    return isinstance(v, dict) and "$input" in v


def unresolved_inputs(operations: list[dict]) -> list[str]:
    """Names of inputs still unbound across a pack's operations."""
    names = []
    for op in operations:
        for v in (op.get("after") or {}).values():
            if is_input(v) and v["$input"] not in names:
                names.append(v["$input"])
    return names


def bind_inputs(pack: FixPack, values: dict[str, str]) -> FixPack:
    """New FixPack with input placeholders resolved. Refuses partial binding:
    a half-bound plan is exactly the ambiguity the placeholder exists to
    prevent."""
    missing = [n for n in unresolved_inputs(pack.operations) if n not in values]
    if missing:
        raise ValueError(f"Unbound inputs: {missing}. Supply a value for every declared input.")
    ops = []
    for op in pack.operations:
        after = {k: (values[v["$input"]] if is_input(v) else v) for k, v in (op.get("after") or {}).items()}
        ops.append({**op, "after": after})
    return FixPack(
        finding_fingerprint=pack.finding_fingerprint, rule_id=pack.rule_id, name=pack.name,
        fix_artefact=pack.fix_artefact, fix_artefact_filename=pack.fix_artefact_filename,
        dry_run=pack.dry_run, instructions=pack.instructions, backout=pack.backout,
        backout_filename=pack.backout_filename, scope_statement=pack.scope_statement,
        operations=ops,
    )


# --- selection ---------------------------------------------------------------

def _select_offenders(spec: dict, snap: Snapshot) -> list[dict]:
    """Every record the rule's own presence filter matches. The full set, not
    the evidence sample: a fix that silently stops at ten records is a lie."""
    from ..rules.declarative import _where  # local: avoids a module-level import cycle

    det = spec["detect"]
    rows = _where(snap.t(det["table"]), det.get("where"))
    if det.get("exclude_oob", True):
        rows = [r for r in rows if not r.get("oob")]
    return sorted(rows, key=lambda r: str(r.get("sys_id", "")))


def _property_deviations(spec: dict, snap: Snapshot) -> list[dict]:
    det = spec["detect"]
    key_f, val_f = det.get("key_field", "name"), det.get("value_field", "value")
    present = {r.get(key_f): r for r in snap.t(det["table"])}
    out = []
    for key in sorted(det["expect"]):
        want = det["expect"][key]
        if isinstance(want, str) and want.startswith("<"):
            continue  # customer-specific: a value ROB cannot name it must not set
        rec = present.get(key)
        got = rec.get(val_f) if rec else None
        if rec is None or str(got).strip().lower() != str(want).strip().lower():
            out.append({"key": key, "current": got, "target": want, "exists": rec is not None})
    return out


# --- artefact rendering ------------------------------------------------------

def _label(rec: dict) -> str:
    return str(rec.get("name") or rec.get("sys_id") or "?")


def _js_value(v) -> str:
    return json.dumps("<SUPPLIED AT APPROVAL: " + v["$input"] + ">" if is_input(v) else v)


def _render_record_pack(rule_id: str, table: str, changes: list[dict], block: dict, fingerprint: str) -> FixPack:
    """changes: [{record, after: {field: value}}], values may be input placeholders."""
    fix_lines = [
        f"// ROB fix-pack {rule_id}: declared field updates, one block per record.",
        "// Each block is individually approvable: delete any block you do not approve.",
        "// Apply as a background script in SUB-PRODUCTION first.",
    ]
    dry_lines = ["// Dry-run (read-only): current values of every field this fix-pack would change."]
    for ch in changes:
        rec, after = ch["record"], ch["after"]
        sid = rec.get("sys_id", "")
        fix_lines.append(f"// {table}/{_label(rec)}")
        fix_lines.append(f"(function() {{ var gr = new GlideRecord('{table}'); if (gr.get('{sid}')) {{")
        for f, v in after.items():
            fix_lines.append(f"  gr.setValue('{f}', {_js_value(v)});")
        fix_lines.append("  gr.update(); } })();")
        fields_js = json.dumps(sorted(after))
        dry_lines.append(
            f"(function() {{ var gr = new GlideRecord('{table}'); "
            f"if (gr.get('{sid}')) {{ {fields_js}.forEach(function(f) {{ "
            f"gs.info('{table}/{sid} ' + f + '=' + gr.getValue(f)); }}); }} "
            f"else {{ gs.info('{table}/{sid} <missing>'); }} }})();"
        )
    before_state = [
        {"table": table, "sys_id": ch["record"].get("sys_id", ""),
         "previous": {f: ch["record"].get(f) for f in ch["after"]}}
        for ch in changes
    ]
    backout = (
        "// Backout: restore field values captured at generation time.\n"
        "// Previous state (JSON):\n"
        + "\n".join("// " + line for line in json.dumps(before_state, indent=2).splitlines())
    )
    operations = [
        {
            "kind": "update_record",
            "table": table,
            "key": ch["record"].get("sys_id", ""),
            "before": {f: ch["record"].get(f) for f in ch["after"]},
            "after": dict(ch["after"]),
            "label": f"{table}/{_label(ch['record'])}: "
                     + ", ".join(f"{f} -> {('<input:' + v['$input'] + '>') if is_input(v) else v!r}"
                                 for f, v in ch["after"].items()),
        }
        for ch in changes
    ]
    inputs = block.get("inputs", {})
    input_note = (
        ["", "Inputs to supply at approval time:"]
        + [f"  - {name}: {prompt}" for name, prompt in sorted(inputs.items())]
        if inputs else []
    )
    instructions = "\n".join(
        [
            "1. Environment: sub-production instance first (production goes through your own change process).",
            "2. Run the dry-run script (read-only) and confirm current values match this pack's backout state; if they differ, re-scan before applying.",
            "3. Strike any record block you do not approve from the fix artefact.",
            "4. Apply the fix artefact, or approve for gated execution (per-record approval in the console).",
            "5. Verify: re-run the dry-run; every field should report its target value.",
            f"6. Record the change reference against finding {fingerprint}.",
        ]
        + input_note
        + ([f"", f"Rule-specific steps: {block['instructions_extra']}"] if block.get("instructions_extra") else [])
    )
    return FixPack(
        finding_fingerprint=fingerprint,
        rule_id=rule_id,
        name=f"fixpack-{rule_id}-{block.get('slug', 'declared-fix')}",
        fix_artefact="\n".join(fix_lines),
        fix_artefact_filename="fix_declared_field_updates.js",
        dry_run="\n".join(dry_lines),
        instructions=instructions,
        backout=backout,
        backout_filename="backout_previous_field_values.json",
        scope_statement=block["scope_statement"],
        operations=operations,
    )


# --- the generator -----------------------------------------------------------

def generate_declarative(spec: dict, finding: Finding, snap: Snapshot) -> FixPack | None:
    """Compile a spec's remediation_pack block against the snapshot."""
    block = spec.get("remediation_pack")
    if not block:
        return None
    kind = block["kind"]
    det = spec["detect"]

    if kind == "set_expected_properties":
        deviations = _property_deviations(spec, snap)
        if not deviations:
            return None
        fix = "\n".join(
            [f"// ROB fix-pack {spec['id']}: set properties to their declared expected values.",
             "// Each line is individually approvable: delete any line you do not approve."]
            + [f"gs.setProperty('{d['key']}', '{d['target']}');" for d in deviations]
        )
        dry = "\n".join(
            f"gs.info('{d['key']} current=' + gs.getProperty('{d['key']}', '<not set>') + ' -> target={d['target']}');"
            for d in deviations
        )
        before = [{"name": d["key"], "previous_value": d["current"]} for d in deviations]
        backout = (
            "// Backout: restore previous values captured at generation time.\n"
            "// Previous state (JSON):\n"
            + "\n".join("// " + line for line in json.dumps(before, indent=2).splitlines())
            + "\n"
            + "\n".join(
                f"gs.setProperty('{d['key']}', '{d['current']}');" if d["exists"]
                else f"// {d['key']} was not set; delete the property to restore, do not set a value."
                for d in deviations
            )
        )
        operations = [
            {"kind": "set_property", "table": det["table"], "key": d["key"],
             "before": {"value": d["current"]}, "after": {"value": d["target"]},
             "label": f"{d['key']}: {d['current']!r} -> {d['target']!r}"}
            for d in deviations
        ]
        instructions = "\n".join([
            "1. Environment: sub-production instance first.",
            "2. Run the dry-run script (read-only) and confirm current values match the backout state.",
            "3. Strike any line you do not approve.",
            "4. Apply, or approve for gated execution.",
            f"5. Record the change reference against finding {finding.fingerprint}.",
        ])
        return FixPack(
            finding_fingerprint=finding.fingerprint, rule_id=spec["id"],
            name=f"fixpack-{spec['id']}-{block.get('slug', 'expected-properties')}",
            fix_artefact=fix, fix_artefact_filename="fix_set_expected_properties.js",
            dry_run=dry, instructions=instructions, backout=backout,
            backout_filename="backout_restore_previous_properties.js",
            scope_statement=block["scope_statement"], operations=operations,
        )

    offenders = _select_offenders(spec, snap)
    changes: list[dict] = []
    if kind == "update_fields":
        declared = block["set"]
        for rec in offenders:
            after = {}
            for f, v in declared.items():
                after[f] = {"$input": v["$input"]} if is_input(v) else v
            # Idempotence: skip records already at the declared literal values.
            literal = {f: v for f, v in after.items() if not is_input(v)}
            if literal and all(rec.get(f) == v for f, v in literal.items()) and len(literal) == len(after):
                continue
            changes.append({"record": rec, "after": after})
    elif kind == "transform_field":
        field, tname = block["field"], block["transform"]
        transform = TRANSFORMS[tname]
        for rec in offenders:
            new = transform(rec.get(field))
            if new is None or new == rec.get(field):
                continue
            changes.append({"record": rec, "after": {field: new}})
    else:  # pragma: no cover - pack.py validation refuses unknown kinds
        raise ValueError(f"Unknown remediation kind '{kind}'")

    if not changes:
        return None
    return _render_record_pack(spec["id"], det["table"], changes, block, finding.fingerprint)
