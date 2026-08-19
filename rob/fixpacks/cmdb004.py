"""Fix-pack generator for ROB-CMDB-004: dangling relationship cleanup. Tier T1 sub-case.

Only the T1 sub-case (dangling cmdb_rel_ci deletion) gets a fix artefact.
The T3 sub-case (orphan relationship building) is design work and stays guidance.
"""
from __future__ import annotations

import json

from ..models import Finding, FixPack, Snapshot


def generate(finding: Finding, snap: Snapshot) -> FixPack | None:
    cis = {c["sys_id"]: c for c in snap.t("cmdb_ci")}
    dangling = []
    for rel in snap.t("cmdb_rel_ci"):
        parent, child = cis.get(rel.get("parent")), cis.get(rel.get("child"))
        if parent is None or child is None or parent.get("operational_status") == "retired" or child.get("operational_status") == "retired":
            dangling.append(rel)
    if not dangling:
        return None

    sys_ids = [r["sys_id"] for r in dangling]

    fix_artefact = (
        "// ROB fix-pack ROB-CMDB-004 (T1 sub-case): delete dangling cmdb_rel_ci records.\n"
        "// Targets ONLY relationships whose parent or child is missing or retired.\n"
        "// Apply in SUB-PRODUCTION first.\n"
        "var ids = " + json.dumps(sys_ids) + ";\n"
        "var gr = new GlideRecord('cmdb_rel_ci');\n"
        "gr.addQuery('sys_id', 'IN', ids.join(','));\n"
        "gr.query();\n"
        "var n = 0;\n"
        "while (gr.next()) { gr.deleteRecord(); n++; }\n"
        "gs.info('ROB-CMDB-004: deleted ' + n + ' dangling relationships (expected " + str(len(sys_ids)) + ")');"
    )

    dry_run = (
        "// Dry-run (read-only): lists every relationship this fix-pack would delete.\n"
        "var ids = " + json.dumps(sys_ids) + ";\n"
        "var gr = new GlideRecord('cmdb_rel_ci');\n"
        "gr.addQuery('sys_id', 'IN', ids.join(','));\n"
        "gr.query();\n"
        "while (gr.next()) { gs.info(gr.sys_id + ': ' + gr.parent.getDisplayValue() + ' -> ' + gr.child.getDisplayValue()); }\n"
        "// Expected count: " + str(len(sys_ids))
    )

    backout_records = json.dumps(
        [
            {"sys_id": r["sys_id"], "parent": r.get("parent"), "child": r.get("child"), "type": r.get("type")}
            for r in dangling
        ],
        indent=2,
    )
    backout = (
        "// Backout: full export of the deleted relationship records (JSON below).\n"
        "// Restore by re-inserting into cmdb_rel_ci from this export.\n" + backout_records
    )

    instructions = "\n".join(
        [
            "1. Environment: sub-production first. Required role: admin (or itil with cmdb_rel_ci delete).",
            "2. Change model: standard change (assumption from finding effort band: dangling repair is Low effort).",
            f"3. Run the dry-run script; confirm the count matches {len(sys_ids)} and spot-check 5 listed relationships.",
            "4. If counts differ, the instance changed since the snapshot: re-scan, do not apply.",
            "5. Apply the fix artefact as a background script.",
            "6. Verify: re-run the dry-run; expected count 0.",
            "7. Record the change reference against finding " + finding.fingerprint + ".",
        ]
    )

    scope = (
        "Deletes ONLY the cmdb_rel_ci records enumerated in the backout export (relationships referencing missing "
        "or retired CIs). Does not touch any CI record, orphan CIs (T3 guidance handles those) or any other "
        "relationship. No ordering dependencies."
    )

    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-CMDB-004",
        name="fixpack-ROB-CMDB-004-dangling-relationships",
        fix_artefact=fix_artefact,
        fix_artefact_filename="fix_delete_dangling_relationships.js",
        dry_run=dry_run,
        instructions=instructions,
        backout=backout,
        backout_filename="backout_dangling_relationships_export.json",
        scope_statement=scope,
    )
