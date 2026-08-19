"""Fix-pack generator for ROB-SEC-003 (hardening properties). Tier T1.

The canonical gated-execution candidate: mechanical, reversible, per-property
approvable. The fix artefact is a background-script style payload; the backout
captures every previous value before any change.
"""
from __future__ import annotations

import json

from ..models import Finding, FixPack, Snapshot


def generate(finding: Finding, snap: Snapshot) -> FixPack | None:
    deviations = []
    for ev in finding.evidence:
        # Evidence format: "<name> = <current> (baseline: <target>)"
        name = ev.record_ref.split("/", 1)[1] if ev.record_ref else None
        if not name:
            continue
        current = {p["name"]: p.get("value") for p in snap.t("sys_properties")}.get(name)
        baseline = ev.summary.split("(baseline: ", 1)[1].rstrip(")") if "(baseline: " in ev.summary else None
        if baseline is None:
            continue
        deviations.append({"name": name, "current": current, "baseline": baseline, "impact": ev.data.get("impact")})

    if not deviations:
        return None

    fix_lines = [
        "// ROB fix-pack ROB-SEC-003: set hardening properties to baseline.",
        "// Each line is individually approvable: delete any line you do not approve.",
        "// Apply as a background script in SUB-PRODUCTION first.",
    ]
    for d in deviations:
        if d["baseline"].startswith("<"):
            fix_lines.append(f"// {d['name']}: baseline is customer-specific ({d['baseline']}); set manually after deciding the value.")
        else:
            fix_lines.append(f"gs.setProperty('{d['name']}', '{d['baseline']}');")
    fix_artefact = "\n".join(fix_lines)

    dry_run = (
        "// Dry-run (read-only): shows every property this fix-pack would change and its current value.\n"
        + "\n".join(
            f"gs.info('{d['name']} current=' + gs.getProperty('{d['name']}', '<not set>') + ' -> baseline={d['baseline']}');"
            for d in deviations
        )
    )

    backout_state = json.dumps(
        [{"name": d["name"], "previous_value": d["current"]} for d in deviations], indent=2
    )
    backout = (
        "// Backout: restore previous values captured at generation time.\n"
        "// Previous state (JSON):\n"
        + "\n".join("// " + line for line in backout_state.splitlines())
        + "\n"
        + "\n".join(
            (
                f"gs.setProperty('{d['name']}', '{d['current']}');"
                if d["current"] is not None
                else f"// {d['name']} was not set; delete the property to restore, do not set it to a value."
            )
            for d in deviations
        )
    )

    instructions = "\n".join(
        [
            "1. Environment: sub-production instance first (MVP policy: production changes go through your own change process).",
            "2. Required role: admin. Change model: standard change per property (assumption from finding effort band).",
            "3. Run the dry-run script (read-only) and confirm the listed current values match this fix-pack's backout state; if they differ, re-scan before applying.",
            "4. Strike any line you do not approve from the fix artefact.",
            "5. Apply the fix artefact as a background script. Expected duration: under 1 minute.",
            "6. Verify: re-run the dry-run; every property should now report its baseline value.",
            "7. Record the change reference against finding " + finding.fingerprint + ".",
        ]
    )

    scope = (
        "Touches ONLY the sys_properties records named in the fix artefact. Does not modify ACLs, roles, users or "
        "any other configuration. No ordering dependencies. Intentional deviations (e.g. SSO-driven session values) "
        "should be struck and documented rather than applied."
    )

    # Machine-applicable plan (W-C). Customer-specific baselines are excluded:
    # a value ROB cannot name is a value ROB must not set.
    operations = [
        {
            "kind": "set_property",
            "table": "sys_properties",
            "key": d["name"],
            "before": {"value": d["current"]},
            "after": {"value": d["baseline"]},
            "label": f"{d['name']}: {d['current']!r} -> {d['baseline']!r}",
        }
        for d in deviations
        if not d["baseline"].startswith("<")
    ]

    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-SEC-003",
        name="fixpack-ROB-SEC-003-hardening-properties",
        fix_artefact=fix_artefact,
        fix_artefact_filename="fix_set_hardening_properties.js",
        dry_run=dry_run,
        instructions=instructions,
        backout=backout,
        backout_filename="backout_restore_previous_properties.js",
        scope_statement=scope,
        operations=operations,
    )
