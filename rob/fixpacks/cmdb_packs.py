"""Fix-pack generators for CMDB rules 001, 003, 005, 006. Tier T2.

Each pack is mapping- or proposal-driven where the rule requires human input:
the pack ships a complete, runnable artefact with clearly marked decision
points rather than pretending the input is not needed (honest solvability).
"""
from __future__ import annotations

from collections import defaultdict

from ..models import Finding, FixPack, Snapshot
from .common import jexport, js_list, slug


def cmdb001(finding: Finding, snap: Snapshot) -> FixPack | None:
    cls = finding.affected_area
    unowned = [
        c
        for c in snap.t("cmdb_ci")
        if c.get("sys_class_name") == cls
        and c.get("operational_status") == "operational"
        and not (c.get("owned_by") or c.get("managed_by") or c.get("support_group"))
    ]
    if not unowned:
        return None

    fix_artefact = "\n".join(
        [
            f"// ROB fix-pack ROB-CMDB-001 ({cls}): mapping-driven ownership backfill.",
            "// DECISION POINT: complete the MAPPING below (name pattern -> ownership) before applying.",
            "// CIs matching no pattern are logged and left untouched. Apply in SUB-PRODUCTION first.",
            "var MAPPING = [",
            "  // { pattern: /^WINSRV/, support_group: '<group name>', managed_by: '<user_name>' },",
            "];",
            f"var ids = {js_list([c['sys_id'] for c in unowned])};",
            f"var gr = new GlideRecord('{cls}');",
            "gr.addQuery('sys_id', 'IN', ids.join(','));",
            "gr.query();",
            "var applied = 0, unmatched = 0;",
            "while (gr.next()) {",
            "  var hit = null;",
            "  for (var i = 0; i < MAPPING.length; i++) { if (MAPPING[i].pattern.test(gr.name)) { hit = MAPPING[i]; break; } }",
            "  if (!hit) { gs.info('No mapping: ' + gr.name); unmatched++; continue; }",
            "  if (hit.support_group) gr.support_group.setDisplayValue(hit.support_group);",
            "  if (hit.managed_by) gr.managed_by.setDisplayValue(hit.managed_by);",
            "  if (hit.owned_by) gr.owned_by.setDisplayValue(hit.owned_by);",
            "  gr.update(); applied++;",
            "}",
            f"gs.info('ROB-CMDB-001 {cls}: ownership applied=' + applied + ', unmatched=' + unmatched + ' (candidates {len(unowned)})');",
        ]
    )

    dry_run = "\n".join(
        [
            f"// Dry-run (read-only): counts fully unowned operational {cls} CIs.",
            f"var gr = new GlideAggregate('{cls}');",
            "gr.addQuery('operational_status', 1);",
            "gr.addNullQuery('owned_by'); gr.addNullQuery('managed_by'); gr.addNullQuery('support_group');",
            "gr.addAggregate('COUNT'); gr.query();",
            f"if (gr.next()) gs.info('{cls} fully unowned: ' + gr.getAggregate('COUNT') + ' (expected {len(unowned)})');",
        ]
    )

    backout = (
        "// Backout: previous ownership state of every candidate CI (all fields were empty at generation).\n"
        "// To reverse, clear owned_by/managed_by/support_group on the sys_ids below.\n"
        + jexport([{"sys_id": c["sys_id"], "name": c.get("name"), "previous": {"owned_by": "", "managed_by": "", "support_group": ""}} for c in unowned[:5000]])
    )

    instructions = "\n".join(
        [
            "1. Environment: sub-production first. Required role: itil/admin with CMDB write.",
            "2. Change model: normal change (assumption from finding effort band).",
            "3. DECISION POINT: complete the MAPPING array with your name-pattern -> ownership rules.",
            f"4. Run the dry-run; confirm the unowned count is close to {len(unowned)} (drift means re-scan first).",
            "5. Apply; review the 'No mapping' log lines and extend the mapping iteratively.",
            f"6. Record the change reference against finding {finding.fingerprint}.",
        ]
    )

    scope = (
        f"Touches ONLY the ownership fields (owned_by, managed_by, support_group) of currently-unowned operational "
        f"{cls} CIs enumerated in the backout export. Never overwrites populated ownership. No other class or field."
    )

    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-CMDB-001",
        name=f"fixpack-ROB-CMDB-001-ownership-{slug(cls)}",
        fix_artefact=fix_artefact,
        fix_artefact_filename="fix_ownership_backfill.js",
        dry_run=dry_run,
        instructions=instructions,
        backout=backout,
        backout_filename="backout_previous_ownership.json",
        scope_statement=scope,
    )


def cmdb003(finding: Finding, snap: Snapshot) -> FixPack | None:
    cls = finding.affected_area
    operational = [c for c in snap.t("cmdb_ci") if c.get("sys_class_name") == cls and c.get("operational_status") == "operational"]
    rel_counts: dict[str, int] = defaultdict(int)
    for rel in snap.t("cmdb_rel_ci"):
        rel_counts[rel.get("parent", "")] += 1
        rel_counts[rel.get("child", "")] += 1
    groups: dict[str, list[dict]] = defaultdict(list)
    for c in operational:
        key = c.get("name", "").lower().strip()
        groups[key].append(c)
    dup_groups = {k: v for k, v in groups.items() if len(v) > 1}
    if not dup_groups:
        return None

    plan = []
    for name, members in sorted(dup_groups.items()):
        survivor = max(members, key=lambda c: (rel_counts.get(c["sys_id"], 0), c.get("days_since_discovery") is not None))
        plan.append({"name": name, "survivor": survivor["sys_id"], "retire": [m["sys_id"] for m in members if m["sys_id"] != survivor["sys_id"]]})

    fix_artefact = "\n".join(
        [
            f"// ROB fix-pack ROB-CMDB-003 ({cls}): merge duplicate groups.",
            "// Survivor proposed by relationship count and discovery recency.",
            "// Each PLAN entry is individually approvable: delete entries you do not approve.",
            "// Apply in SUB-PRODUCTION first.",
            "var PLAN = " + jexport(plan) + ";",
            "PLAN.forEach(function(g) {",
            "  g.retire.forEach(function(dupId) {",
            "    var rel = new GlideRecord('cmdb_rel_ci');",
            "    rel.addQuery('parent', dupId); rel.query();",
            "    while (rel.next()) { rel.parent = g.survivor; rel.update(); }",
            "    rel = new GlideRecord('cmdb_rel_ci');",
            "    rel.addQuery('child', dupId); rel.query();",
            "    while (rel.next()) { rel.child = g.survivor; rel.update(); }",
            f"    var ci = new GlideRecord('{cls}');",
            "    if (ci.get(dupId)) { ci.operational_status = 6; /* retired */ ci.update(); }",
            "  });",
            "});",
            f"gs.info('ROB-CMDB-003 {cls}: processed ' + PLAN.length + ' duplicate groups');",
        ]
    )

    dry_run = "\n".join(
        [
            f"// Dry-run (read-only): lists each duplicate group, proposed survivor and retire set.",
            "var PLAN = " + jexport(plan) + ";",
            "PLAN.forEach(function(g) { gs.info(g.name + ' -> survivor ' + g.survivor + ', retire ' + g.retire.join(',')); });",
            f"gs.info('Groups: ' + PLAN.length + ' (expected {len(plan)})');",
        ]
    )

    backout = (
        "// Backout: previous operational status of retired CIs and original relationship endpoints.\n"
        + jexport({"retired_were_operational": [sid for g in plan for sid in g["retire"]],
                   "note": "Relationships were re-pointed to survivors; restore from the plan below if needed",
                   "plan": plan})
    )

    instructions = "\n".join(
        [
            "1. Environment: sub-production first. Required role: itil/admin with CMDB write.",
            "2. Change model: normal change.",
            "3. Run the dry-run; review every group's survivor choice (strike disputed groups from PLAN).",
            "4. Apply; duplicates are retired, never deleted, so task history remains reachable.",
            "5. Fix the ingestion source separately (identification rules), or duplicates will return.",
            f"6. Record the change reference against finding {finding.fingerprint}.",
        ]
    )

    scope = (
        f"Touches ONLY: operational_status of listed duplicate {cls} CIs (set to retired) and cmdb_rel_ci endpoint "
        "re-pointing to survivors. No CI is deleted. Does not fix the ingestion source (separate work)."
    )

    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-CMDB-003",
        name=f"fixpack-ROB-CMDB-003-dedup-{slug(cls)}",
        fix_artefact=fix_artefact,
        fix_artefact_filename="fix_merge_duplicates.js",
        dry_run=dry_run,
        instructions=instructions,
        backout=backout,
        backout_filename="backout_dedup_plan.json",
        scope_statement=scope,
    )


def cmdb005(finding: Finding, snap: Snapshot) -> FixPack | None:
    if finding.tier.startswith("T3"):
        return None  # maturity-observation variant gets guidance, not a pack
    apps = {a["sys_id"]: a for a in snap.t("cmdb_ci_business_app") if a.get("lifecycle_stage", "operational") == "operational"}
    service_ids = {sv["sys_id"] for sv in snap.t("cmdb_ci_service")}
    linked = set()
    for rel in snap.t("cmdb_rel_ci"):
        if rel.get("parent") in service_ids:
            linked.add(rel.get("child"))
        if rel.get("child") in service_ids:
            linked.add(rel.get("parent"))
    unlinked = [a for sid, a in apps.items() if sid not in linked]
    if not unlinked:
        return None

    proposals = [{"app_sys_id": a["sys_id"], "app_name": a.get("name", ""), "service_name": f"{a.get('name', '')} Service"} for a in sorted(unlinked, key=lambda x: x.get("name", ""))]
    marker = "Created by ROB fix-pack ROB-CMDB-005"

    fix_artefact = "\n".join(
        [
            "// ROB fix-pack ROB-CMDB-005: create application services for unlinked business applications.",
            "// DECISION POINT: review each proposed service name against your naming convention.",
            "// Each PROPOSAL is individually approvable: delete entries you do not approve.",
            "// Apply in SUB-PRODUCTION first.",
            "var PROPOSALS = " + jexport(proposals) + ";",
            "PROPOSALS.forEach(function(p) {",
            "  var svc = new GlideRecord('cmdb_ci_service_discovered');",
            "  svc.initialize();",
            "  svc.name = p.service_name;",
            f"  svc.short_description = '{marker}';",
            "  svc.service_classification = 'Application Service';",
            "  var svcId = svc.insert();",
            "  var rel = new GlideRecord('cmdb_rel_ci');",
            "  rel.initialize();",
            "  rel.parent = svcId;",
            "  rel.child = p.app_sys_id;",
            "  rel.type.setDisplayValue('Consumes::Consumed by');",
            "  rel.insert();",
            "});",
            "gs.info('ROB-CMDB-005: created ' + PROPOSALS.length + ' application services with CSDM linkage');",
        ]
    )

    dry_run = "\n".join(
        [
            "// Dry-run (read-only): confirms each listed business application is still unlinked.",
            "var PROPOSALS = " + jexport([p["app_sys_id"] for p in proposals]) + ";",
            "PROPOSALS.forEach(function(appId) {",
            "  var rel = new GlideRecord('cmdb_rel_ci');",
            "  rel.addQuery('child', appId).addOrCondition('parent', appId);",
            "  rel.query();",
            "  var app = new GlideRecord('cmdb_ci_business_app'); app.get(appId);",
            "  gs.info(app.name + ': ' + rel.getRowCount() + ' existing relationships');",
            "});",
        ]
    )

    backout = (
        "// Backout: restore previous state (the created records did not exist) by deleting\n"
        "// the services and relationships this pack created.\n"
        f"// All created services carry short_description '{marker}'.\n"
        "var svc = new GlideRecord('cmdb_ci_service_discovered');\n"
        f"svc.addQuery('short_description', '{marker}');\n"
        "svc.query();\n"
        "while (svc.next()) {\n"
        "  var rel = new GlideRecord('cmdb_rel_ci');\n"
        "  rel.addQuery('parent', svc.sys_id.toString()); rel.query();\n"
        "  while (rel.next()) { rel.deleteRecord(); }\n"
        "  svc.deleteRecord();\n"
        "}\n"
        "// Created-set reference (JSON):\n" + jexport(proposals)
    )

    instructions = "\n".join(
        [
            "1. Environment: sub-production first. Required role: itil/admin with CMDB write.",
            "2. Change model: normal change; CMDB owner review of naming convention (DECISION POINT).",
            "3. Adjust the application service class in the script if your CSDM standard uses a different one.",
            "4. Run the dry-run; any app showing existing relationships changed since the snapshot - re-scan.",
            "5. Apply; verify a spot-checked app now shows its service via Consumes relationship.",
            f"6. Record the change reference against finding {finding.fingerprint}.",
        ]
    )

    scope = (
        "Creates ONLY new application service records (marked in short_description) and one Consumes relationship "
        "per listed application. Modifies no existing record. Backout deletes exactly the marked set."
    )

    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-CMDB-005",
        name="fixpack-ROB-CMDB-005-application-services",
        fix_artefact=fix_artefact,
        fix_artefact_filename="fix_create_application_services.js",
        dry_run=dry_run,
        instructions=instructions,
        backout=backout,
        backout_filename="backout_delete_created_services.js",
        scope_statement=scope,
    )


def cmdb006(finding: Finding, snap: Snapshot) -> FixPack | None:
    if finding.tier.startswith("T3"):
        return None
    unclassified = [
        sv for sv in snap.t("cmdb_ci_service")
        if sv.get("operational_status") == "operational"
        and (not sv.get("service_classification") or sv.get("service_classification") == "unspecified")
    ]
    if not unclassified:
        return None
    lines = [{"sys_id": sv["sys_id"], "name": sv.get("name", ""), "proposed": "Application Service"} for sv in sorted(unclassified, key=lambda x: x.get("name", ""))]

    fix_artefact = "\n".join(
        [
            "// ROB fix-pack ROB-CMDB-006: batch service classification.",
            "// DECISION POINT: the proposed classification is derived (Application Service default);",
            "// change 'proposed' per line where a service is Business/Technical instead.",
            "// Each LINE is individually approvable: delete lines you do not approve.",
            "// Apply in SUB-PRODUCTION first.",
            "var LINES = " + jexport(lines) + ";",
            "LINES.forEach(function(l) {",
            "  var svc = new GlideRecord('cmdb_ci_service');",
            "  if (svc.get(l.sys_id) && !svc.service_classification) {",
            "    svc.service_classification = l.proposed;",
            "    svc.update();",
            "  }",
            "});",
            "gs.info('ROB-CMDB-006: classified ' + LINES.length + ' services');",
        ]
    )

    dry_run = "\n".join(
        [
            "// Dry-run (read-only): counts operational services without classification.",
            "var gr = new GlideAggregate('cmdb_ci_service');",
            "gr.addQuery('operational_status', 1);",
            "gr.addNullQuery('service_classification');",
            "gr.addAggregate('COUNT'); gr.query();",
            f"if (gr.next()) gs.info('Unclassified services: ' + gr.getAggregate('COUNT') + ' (expected {len(lines)})');",
        ]
    )

    backout = (
        "// Backout: previous state export - every listed service had EMPTY service_classification at generation time.\n"
        "// To reverse, clear service_classification on the sys_ids below.\n" + jexport([l["sys_id"] for l in lines])
    )

    instructions = "\n".join(
        [
            "1. Environment: sub-production first. Required role: itil/admin with CMDB write.",
            "2. Change model: normal change; CMDB owner reviews each proposed classification (DECISION POINT).",
            f"3. Run the dry-run; confirm the count is close to {len(lines)}.",
            "4. Apply (the script never overwrites an already-set classification).",
            "5. Offering linkage is NOT in this pack: no offerings exist on this instance yet; treat as follow-up design work.",
            f"6. Record the change reference against finding {finding.fingerprint}.",
        ]
    )

    scope = (
        "Sets ONLY service_classification on the listed services, and only where it is still empty at apply time. "
        "Does not create offerings or relationships (explicitly out of scope for this pack)."
    )

    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-CMDB-006",
        name="fixpack-ROB-CMDB-006-service-classification",
        fix_artefact=fix_artefact,
        fix_artefact_filename="fix_classify_services.js",
        dry_run=dry_run,
        instructions=instructions,
        backout=backout,
        backout_filename="backout_unclassified_sysids.json",
        scope_statement=scope,
    )
