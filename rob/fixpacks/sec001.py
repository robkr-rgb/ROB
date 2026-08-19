"""Fix-pack generator for ROB-SEC-001: privileged access migration. Tier T2.

Creates (if absent) an access-reviewed admin group, migrates direct admin
grants into it, and disables dormant admin accounts. Every account is an
individually approvable block: delete any block you do not approve.
"""
from __future__ import annotations

from ..models import Finding, FixPack, Snapshot
from .common import jexport

GROUP_NAME = "ROB Reviewed Admin Access"


def generate(finding: Finding, snap: Snapshot) -> FixPack | None:
    users = {u["sys_id"]: u for u in snap.t("sys_user")}
    direct = []
    for grant in snap.t("sys_user_has_role"):
        if grant.get("role") == "admin" and not grant.get("inherited"):
            u = users.get(grant.get("user"))
            if u and u.get("active"):
                direct.append(u)
    if not direct:
        return None

    blocks = []
    for u in sorted(direct, key=lambda x: -x.get("days_since_login", 0)):
        dormant = u.get("days_since_login", 0) >= 90
        blocks.append(
            "\n".join(
                [
                    f"// ---- {u['user_name']} (dormant {u.get('days_since_login')} days) ----" if dormant
                    else f"// ---- {u['user_name']} ----",
                    f"migrateAdmin('{u['sys_id']}'); // move grant into '{GROUP_NAME}'",
                ]
                + ([f"disableUser('{u['sys_id']}'); // dormant 90+ days: disable after owner confirmation"] if dormant else [])
            )
        )

    fix_artefact = "\n".join(
        [
            "// ROB fix-pack ROB-SEC-001: migrate direct admin grants into a reviewed group.",
            "// Each account block below is individually approvable: delete blocks you do not approve.",
            "// Apply in SUB-PRODUCTION first.",
            "",
            "var group = new GlideRecord('sys_user_group');",
            f"if (!group.get('name', '{GROUP_NAME}')) {{",
            "  group.initialize();",
            f"  group.name = '{GROUP_NAME}';",
            "  group.description = 'Access-reviewed admin group created by ROB fix-pack ROB-SEC-001';",
            "  group.insert();",
            "  var groupRole = new GlideRecord('sys_group_has_role');",
            "  groupRole.initialize();",
            "  groupRole.group = group.sys_id;",
            "  groupRole.role.setDisplayValue('admin');",
            "  groupRole.insert();",
            "}",
            "",
            "function migrateAdmin(userSysId) {",
            "  var m = new GlideRecord('sys_user_grmember');",
            "  m.initialize(); m.group = group.sys_id; m.user = userSysId; m.insert();",
            "  var r = new GlideRecord('sys_user_has_role');",
            "  r.addQuery('user', userSysId); r.addQuery('role.name', 'admin'); r.addQuery('inherited', false);",
            "  r.query();",
            "  while (r.next()) { r.deleteRecord(); }",
            "}",
            "function disableUser(userSysId) {",
            "  var u = new GlideRecord('sys_user');",
            "  if (u.get(userSysId)) { u.active = false; u.update(); }",
            "}",
            "",
        ]
        + blocks
    )

    dry_run = "\n".join(
        [
            "// Dry-run (read-only): lists every direct admin grant this fix-pack would migrate.",
            "var r = new GlideRecord('sys_user_has_role');",
            "r.addQuery('role.name', 'admin'); r.addQuery('inherited', false); r.addQuery('user.active', true);",
            "r.query();",
            "var n = 0;",
            "while (r.next()) { gs.info(r.user.user_name + ' | last login: ' + r.user.last_login_time); n++; }",
            f"gs.info('Direct active admin grants: ' + n + ' (expected {len(direct)})');",
        ]
    )

    backout_state = [
        {"sys_id": u["sys_id"], "user_name": u["user_name"], "was_active": True, "had_direct_admin": True}
        for u in direct
    ]
    backout = (
        "// Backout: restore previous state captured at generation time.\n"
        "// 1. Re-grant admin directly to each user below (sys_user_has_role insert).\n"
        "// 2. Re-enable any user this pack disabled.\n"
        f"// 3. Optionally remove the '{GROUP_NAME}' group if it was created by this pack.\n"
        "// Previous state (JSON):\n" + jexport(backout_state)
    )

    instructions = "\n".join(
        [
            "1. Environment: sub-production first. Required role: admin (user_admin for group changes).",
            "2. Change model: normal change; security approval chain (assumption from finding effort band).",
            f"3. Run the dry-run; confirm the count matches {len(direct)} and the account list matches this pack's blocks.",
            "4. Strike any account block you do not approve (keep break-glass/vendor accounts per your exclusion policy).",
            "5. Apply the fix artefact as a background script.",
            "6. Verify: re-run the dry-run; expected direct-grant count 0 (excluding struck blocks).",
            f"7. Record the change reference against finding {finding.fingerprint}.",
        ]
    )

    scope = (
        f"Touches ONLY: the '{GROUP_NAME}' group (create if absent), sys_user_grmember additions for listed users, "
        "deletion of DIRECT admin sys_user_has_role rows for listed users, and active=false on dormant listed users. "
        "Does not modify any other role, group or user attribute. Dependencies: none, but review your break-glass "
        "account policy before applying."
    )

    return FixPack(
        finding_fingerprint=finding.fingerprint,
        rule_id="ROB-SEC-001",
        name="fixpack-ROB-SEC-001-admin-grant-migration",
        fix_artefact=fix_artefact,
        fix_artefact_filename="fix_migrate_admin_grants.js",
        dry_run=dry_run,
        instructions=instructions,
        backout=backout,
        backout_filename="backout_admin_grants_export.json",
        scope_statement=scope,
    )
