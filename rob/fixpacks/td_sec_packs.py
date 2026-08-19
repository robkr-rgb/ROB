"""Fix-pack generators for TD-001/002/003, SEC-002 and CMDB-002. Tier T2.

These are the script-editing and policy-driven packs: the highest review
burden in the library, so itemisation and decision points are explicit.
Honest solvability: where a fix cannot be derived mechanically, the item is
listed as needs-human rather than guessed.
"""
from __future__ import annotations

import re

from ..models import Finding, FixPack, Snapshot
from .common import jexport, slug

_IF_GUARD = re.compile(r"^\s*if\s*\((.+?)\)\s*[{\n]", re.DOTALL)


def td001(finding: Finding, snap: Snapshot) -> FixPack | None:
    table = finding.affected_area
    rules = [
        r for r in snap.t("sys_script")
        if r.get("active") and not r.get("oob") and r.get("collection") == table
        and not r.get("condition") and not r.get("filter_condition")
    ]
    if not rules:
        return None
    derivable, manual = [], []
    for r in rules:
        m = _IF_GUARD.match(r.get("script", ""))
        if m and len(m.group(1)) < 200 and "GlideRecord" not in m.group(1):
            derivable.append({"sys_id": r["sys_id"], "name": r["name"], "condition": m.group(1).strip()})
        else:
            manual.append({"sys_id": r["sys_id"], "name": r["name"]})

    fix_lines = [
        f"// ROB fix-pack ROB-TD-001 ({table}): promote leading if-guards to rule conditions.",
        "// Each LINE is individually approvable. The guard stays in the script (harmless double-check)",
        "// until you remove it during review. Apply in SUB-PRODUCTION first.",
        "var LINES = " + jexport(derivable) + ";",
        "LINES.forEach(function(l) {",
        "  var br = new GlideRecord('sys_script');",
        "  if (br.get(l.sys_id) && !br.condition.toString()) { br.condition = l.condition; br.update(); }",
        "});",
        f"gs.info('ROB-TD-001 {table}: conditions set on ' + LINES.length + ' rules');",
    ]
    if manual:
        fix_lines += ["", "// NEEDS-HUMAN (no derivable guard; write the condition from the rule's intent):"]
        fix_lines += [f"// - {m['name']} (sys_script/{m['sys_id']})" for m in manual]

    dry_run = (
        f"// Dry-run (read-only): lists condition-less active rules on {table}.\n"
        "var br = new GlideRecord('sys_script');\n"
        f"br.addQuery('collection', '{table}'); br.addQuery('active', true);\n"
        "br.addNullQuery('condition'); br.addNullQuery('filter_condition');\n"
        "br.query();\n"
        "while (br.next()) { gs.info(br.name + ' (' + br.when + ')'); }\n"
        f"// Expected: {len(rules)} rule(s); {len(derivable)} auto-fixable, {len(manual)} needs-human"
    )

    backout = (
        "// Backout: previous state - every listed rule had an EMPTY condition at generation time.\n"
        "// To reverse, clear the condition field on the sys_ids below.\n" + jexport([d["sys_id"] for d in derivable])
    )

    instructions = "\n".join(
        [
            "1. Environment: sub-production first. Required role: admin.",
            "2. Change model: standard change per rule (finding effort band).",
            "3. Run the dry-run; confirm the rule list matches this pack.",
            "4. Review each derived condition (strike lines you do not approve); handle NEEDS-HUMAN items separately.",
            "5. Apply, then exercise one transaction on the table and confirm behaviour is unchanged.",
            f"6. Record the change reference against finding {finding.fingerprint}.",
        ]
    )
    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-TD-001",
        name=f"fixpack-ROB-TD-001-conditions-{slug(table)}",
        fix_artefact="\n".join(fix_lines),
        fix_artefact_filename="fix_promote_guards_to_conditions.js",
        dry_run=dry_run,
        instructions=instructions,
        backout=backout,
        backout_filename="backout_condition_sysids.json",
        scope_statement=(
            f"Sets ONLY the condition field of the listed condition-less business rules on {table}, and only where "
            "it is still empty at apply time. Scripts are not modified. NEEDS-HUMAN items are untouched."
        ),
    )


_SYNC_REF = re.compile(r"(\w+)\s*=\s*g_form\.getReference\(\s*(['\"][^'\"]+['\"])\s*\)\s*;")


def td002(finding: Finding, snap: Snapshot) -> FixPack | None:
    offenders = [
        c for c in snap.t("sys_script_client")
        if c.get("active") and not c.get("oob")
        and ("getXMLWait" in c.get("script", "") or "GlideRecord(" in c.get("script", "") or _SYNC_REF.search(c.get("script", "")))
    ]
    if not offenders:
        return None
    proposals, manual = [], []
    for c in offenders:
        script = c.get("script", "")
        m = _SYNC_REF.search(script)
        if m and "getXMLWait" not in script and "GlideRecord(" not in script:
            var, field = m.group(1), m.group(2)
            refactored = script.replace(
                m.group(0),
                f"g_form.getReference({field}, function({var}) {{ /* ROB: continue logic inside this callback */ }});",
            )
            proposals.append({"sys_id": c["sys_id"], "name": c["name"], "proposed_script": refactored})
        else:
            manual.append({"sys_id": c["sys_id"], "name": c["name"], "reason": "getXMLWait/GlideRecord pattern: refactor to GlideAjax by hand"})

    fix_artefact = "\n".join(
        [
            "// ROB fix-pack ROB-TD-002: async refactors for client scripts.",
            "// DECISION POINT: each proposed_script must be reviewed - logic after the original synchronous",
            "// call may need to move inside the callback. Each PROPOSAL is individually approvable.",
            "// Apply in SUB-PRODUCTION first and test the form.",
            "var PROPOSALS = " + jexport(proposals) + ";",
            "PROPOSALS.forEach(function(p) {",
            "  var cs = new GlideRecord('sys_script_client');",
            "  if (cs.get(p.sys_id)) { cs.script = p.proposed_script; cs.update(); }",
            "});",
            "gs.info('ROB-TD-002: applied ' + PROPOSALS.length + ' refactors');",
            "",
            "// NEEDS-HUMAN (manual GlideAjax refactor):",
        ]
        + [f"// - {m['name']} ({m['reason']})" for m in manual]
    )

    backout_state = [
        {"sys_id": p["sys_id"], "name": p["name"], "previous_script": next(c.get("script", "") for c in offenders if c["sys_id"] == p["sys_id"])}
        for p in proposals
    ]
    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-TD-002",
        name="fixpack-ROB-TD-002-async-refactors",
        fix_artefact=fix_artefact,
        fix_artefact_filename="fix_apply_async_refactors.js",
        dry_run=(
            "// Dry-run (read-only): shows current script of each refactor candidate.\n"
            "var ids = " + jexport([p["sys_id"] for p in proposals]) + ";\n"
            "var cs = new GlideRecord('sys_script_client');\n"
            "cs.addQuery('sys_id', 'IN', ids.join(',')); cs.query();\n"
            "while (cs.next()) { gs.info(cs.name + ' | ' + cs.sys_updated_on); }\n"
            f"// Expected: {len(proposals)} auto-refactorable, {len(manual)} needs-human"
        ),
        instructions="\n".join(
            [
                "1. Environment: sub-production first. Required role: admin.",
                "2. Change model: standard change; one form test per refactored script (finding effort band).",
                "3. DECISION POINT: review every proposed_script; move dependent logic into the callback where needed.",
                "4. Apply approved proposals; test each affected form.",
                "5. NEEDS-HUMAN items: refactor to GlideAjax with callback manually.",
                f"6. Record the change reference against finding {finding.fingerprint}.",
            ]
        ),
        backout=(
            "// Backout: previous script bodies captured at generation time (restore per sys_id).\n" + jexport(backout_state)
        ),
        backout_filename="backout_previous_scripts.json",
        scope_statement=(
            "Replaces ONLY the script field of the listed client scripts with the reviewed proposals. "
            "No UI policies, business rules or other scripts touched. NEEDS-HUMAN items untouched."
        ),
    )


def td003(finding: Finding, snap: Snapshot) -> FixPack | None:
    from .common import js_list
    from ..rules.base import SYS_ID_RE

    worksheet = []
    for table in ("sys_script", "sys_script_include", "sys_script_client"):
        for rec in snap.t(table):
            if not rec.get("active") or rec.get("oob"):
                continue
            literals = sorted(set(SYS_ID_RE.findall(rec.get("script", ""))))
            if literals:
                worksheet.append({"table": table, "sys_id": rec["sys_id"], "name": rec.get("name", ""), "literals": literals})
    if not worksheet:
        return None
    all_literals = sorted({lit for w in worksheet for lit in w["literals"]})

    fix_artefact = "\n".join(
        [
            "// ROB fix-pack ROB-TD-003 step 1 of 2: create resolvable properties for each hard-coded sys_id.",
            "// Property names are generated as rob.const.<n>; RENAME them meaningfully (DECISION POINT)",
            "// before step 2 (editing the scripts to use gs.getProperty), which is per-artefact review work",
            "// itemised in the worksheet file.",
            "var LITERALS = " + js_list(all_literals) + ";",
            "LITERALS.forEach(function(lit, i) {",
            "  var name = 'rob.const.' + i;",
            "  if (!gs.getProperty(name, '')) { gs.setProperty(name, lit); gs.info('created ' + name + ' = ' + lit); }",
            "});",
        ]
    )
    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-TD-003",
        name="fixpack-ROB-TD-003-sysid-constants",
        fix_artefact=fix_artefact,
        fix_artefact_filename="fix_create_constant_properties.js",
        dry_run=(
            "// Dry-run (read-only): resolves each literal to its record so you can name the property.\n"
            "var LITERALS = " + js_list(all_literals[:200]) + ";\n"
            "LITERALS.forEach(function(lit) {\n"
            "  var gr = new GlideRecord('sys_metadata');\n"
            "  gs.info(lit + ' -> ' + (gr.get(lit) ? gr.getClassDisplayValue() + ': ' + gr.getDisplayValue() : 'not sys_metadata (check target table)'));\n"
            "});"
        ),
        instructions="\n".join(
            [
                "1. Environment: sub-production first. Required role: admin.",
                "2. Run the dry-run to see what each literal points at; rename properties meaningfully in the fix script.",
                "3. Apply step 1 (property creation - additive, zero risk).",
                "4. Step 2 is the worksheet: per artefact, replace literals with gs.getProperty('<name>') during normal maintenance.",
                f"5. Record the change reference against finding {finding.fingerprint}.",
            ]
        ),
        backout=(
            "// Backout: previous state - none of the rob.const.* properties existed at generation time.\n"
            "// Delete properties named rob.const.* to reverse step 1. Worksheet (artefact -> literals):\n" + jexport(worksheet)
        ),
        backout_filename="backout_worksheet_and_property_list.json",
        scope_statement=(
            "Step 1 ONLY creates new sys_properties (additive; never overwrites an existing property). "
            "No script is modified by this pack; script edits are the itemised worksheet, done under review."
        ),
    )


def sec002(finding: Finding, snap: Snapshot) -> FixPack | None:
    table = finding.affected_area
    fix_artefact = "\n".join(
        [
            f"// ROB fix-pack ROB-SEC-002 ({table}): create read/write ACL skeletons.",
            "// DECISION POINT: set ROLE_NAME to the role that should access this table before applying.",
            "// Apply in SUB-PRODUCTION first and test with a non-admin user.",
            "var ROLE_NAME = '<ROLE_TO_SET>';",
            "if (ROLE_NAME.indexOf('<') === 0) { gs.error('Set ROLE_NAME first'); } else {",
            "['read', 'write'].forEach(function(op) {",
            "  var acl = new GlideRecord('sys_security_acl');",
            f"  acl.initialize(); acl.name = '{table}'; acl.operation = op; acl.active = true;",
            f"  acl.description = 'Created by ROB fix-pack ROB-SEC-002 for {table}';",
            "  var aclId = acl.insert();",
            "  var role = new GlideRecord('sys_user_role');",
            "  if (role.get('name', ROLE_NAME)) {",
            "    var m = new GlideRecord('sys_security_acl_role');",
            "    m.initialize(); m.acl = aclId; m.sys_user_role = role.sys_id; m.insert();",
            "  } else { gs.error('Role not found: ' + ROLE_NAME); }",
            "});",
            "}",
        ]
    )
    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-SEC-002",
        name=f"fixpack-ROB-SEC-002-acl-{slug(table)}",
        fix_artefact=fix_artefact,
        fix_artefact_filename="fix_create_acls.js",
        dry_run=(
            f"// Dry-run (read-only): confirms {table} still has no active row-level read ACL.\n"
            "var acl = new GlideRecord('sys_security_acl');\n"
            f"acl.addQuery('name', '{table}'); acl.addQuery('active', true); acl.query();\n"
            f"gs.info('{table}: ' + acl.getRowCount() + ' active ACL(s) (expected 0 before applying)');"
        ),
        instructions="\n".join(
            [
                "1. Environment: sub-production first. Required roles: admin + security_admin (elevate to apply ACLs).",
                "2. Change model: normal change; security review; one test pass with a non-admin user (finding effort band).",
                "3. DECISION POINT: set ROLE_NAME to the table's legitimate consumer role.",
                "4. Run the dry-run; if ACLs already exist, someone fixed it - re-scan instead of applying.",
                "5. Apply, then verify a non-admin user without the role can no longer list the table.",
                f"6. Record the change reference against finding {finding.fingerprint}.",
            ]
        ),
        backout=(
            "// Backout: previous state - the table had NO active ACLs at generation time.\n"
            f"// To reverse, delete ACLs on '{table}' whose description marks them as created by this pack\n"
            "// (deleting returns the table to inherited/no-ACL behaviour)."
        ),
        backout_filename="backout_delete_created_acls.txt",
        scope_statement=(
            f"Creates ONLY read/write ACL records for {table} (marked in description) plus their role mappings. "
            "Touches no data rows and no other table's security. Requires security_admin elevation."
        ),
    )


def cmdb002(finding: Finding, snap: Snapshot) -> FixPack | None:
    cls = finding.affected_area
    stale = [
        c for c in snap.t("cmdb_ci")
        if c.get("sys_class_name") == cls and c.get("operational_status") == "operational"
        and (
            (c.get("days_since_discovery") or 0) > 45
            if c.get("days_since_discovery") is not None
            else (c.get("days_since_update") or 0) > 180
        )
    ]
    if not stale:
        return None
    items = [{"sys_id": c["sys_id"], "name": c.get("name", "")} for c in stale]
    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-CMDB-002",
        name=f"fixpack-ROB-CMDB-002-retirement-{slug(cls)}",
        fix_artefact="\n".join(
            [
                f"// ROB fix-pack ROB-CMDB-002 ({cls}): retire stale CIs per your lifecycle policy.",
                "// DECISION POINT: confirm the lifecycle policy (retirement threshold) matches this list,",
                "// and check discovery coverage gaps FIRST - a CI missed by discovery is not necessarily dead.",
                "// Each ITEM is individually approvable. Apply in SUB-PRODUCTION first.",
                "var ITEMS = " + jexport(items) + ";",
                "ITEMS.forEach(function(it) {",
                f"  var ci = new GlideRecord('{cls}');",
                "  if (ci.get(it.sys_id)) { ci.operational_status = 6; /* retired */ ci.update(); }",
                "});",
                f"gs.info('ROB-CMDB-002 {cls}: retired ' + ITEMS.length + ' stale CIs');",
            ]
        ),
        fix_artefact_filename="fix_retire_stale_cis.js",
        dry_run=(
            f"// Dry-run (read-only): counts operational {cls} CIs in this pack's retirement list.\n"
            "var ids = " + jexport([i["sys_id"] for i in items[:2000]]) + ";\n"
            f"var ci = new GlideRecord('{cls}');\n"
            "ci.addQuery('sys_id', 'IN', ids.join(',')); ci.addQuery('operational_status', 1); ci.query();\n"
            f"gs.info('Still operational: ' + ci.getRowCount() + ' (expected {len(items)}; fewer means drift - re-scan)');"
        ),
        instructions="\n".join(
            [
                "1. Environment: sub-production first. Required role: itil/admin with CMDB write.",
                "2. DECISION POINT: CMDB owner confirms the lifecycle policy and strikes CIs that are merely un-discovered.",
                "3. Run the dry-run; drift means re-scan before applying.",
                "4. Apply; CIs are retired, never deleted (history and relationships remain).",
                f"5. Record the change reference against finding {finding.fingerprint}.",
            ]
        ),
        backout=(
            "// Backout: previous state - every listed CI was operational_status=1 (operational) at generation time.\n"
            "// To reverse, set operational_status back to 1 on the sys_ids below.\n" + jexport([i["sys_id"] for i in items])
        ),
        backout_filename="backout_previously_operational.json",
        scope_statement=(
            f"Sets ONLY operational_status to retired on the listed {cls} CIs. Nothing is deleted; no relationships, "
            "no other fields, no other classes. Discovery schedule gaps are separate follow-up work."
        ),
    )
