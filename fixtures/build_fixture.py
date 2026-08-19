"""Builds a deterministic synthetic snapshot simulating a customised,
several-year-old instance (PDI-shaped data model, enterprise-shaped debt).
Every seed rule should trigger on this fixture. No randomness: fully seeded
by index arithmetic so the fixture is reproducible byte for byte."""
import json
import pathlib

SNAP = {
    "instance_id": "dev-fixture-001",
    "taken_at": "2026-08-13T09:00:00Z",
    "tables": {},
    "aggregates": {},
}
T = SNAP["tables"]


def sid(prefix, i):
    return (prefix + format(i, "x")).ljust(32, "0")[:32]


# --- TD-001: condition-less business rules on incident -----------------------
T["sys_script"] = [
    {
        "sys_id": sid("br", i),
        "name": f"Set assignment metadata {i}",
        "active": True,
        "collection": "incident",
        "when": "before" if i % 2 else "after",
        "condition": "",
        "filter_condition": "",
        "script": "if (current.assignment_group.nil()) { var gr = new GlideRecord('sys_user_group'); gr.query(); }",
        "oob": False,
    }
    for i in range(7)
] + [
    # OOB-shipped condition-less rule: must be excluded (false-positive control)
    {
        "sys_id": sid("broob", 0),
        "name": "SLA engine hook",
        "active": True,
        "collection": "incident",
        "when": "after",
        "condition": "",
        "filter_condition": "",
        "script": "var gr = new GlideRecord('task_sla'); gr.query();",
        "oob": True,
    },
    # TD-003 carrier: business rule with hard-coded sys_ids
    {
        "sys_id": sid("brhc", 0),
        "name": "Route to fallback group",
        "active": True,
        "collection": "sc_task",
        "when": "before",
        "condition": "current.active == true",
        "filter_condition": "",
        "script": "current.assignment_group = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'; // fallback\ncurrent.watch_list = 'deadbeefdeadbeefdeadbeefdeadbeef';",
        "oob": False,
    },
]

# --- TD-002: client scripts with sync server calls ---------------------------
T["sys_script_client"] = [
    {
        "sys_id": sid("cs", i),
        "name": f"Populate caller details {i}",
        "active": True,
        "table": "incident" if i < 9 else "u_asset_request",
        "script": (
            "var user = g_form.getReference('caller_id');\nvar gr = new GlideRecord('sys_user'); gr.get(user.sys_id);"
            if i % 3
            else "var resp = ga.getXMLWait();\ng_form.setValue('u_details', resp);"
        ),
    }
    for i in range(23)
] + [
    {
        "sys_id": sid("csok", 0),
        "name": "Async lookup (clean)",
        "active": True,
        "table": "incident",
        "script": "g_form.getReference('caller_id', function(user) { g_form.setValue('u_vip', user.vip); });",
    },
    {
        "sys_id": sid("cscmt", 0),
        "name": "Commented-out legacy (clean)",
        "active": True,
        "table": "incident",
        "script": "// var gr = new GlideRecord('sys_user'); old code kept for reference\ng_form.setVisible('u_x', true);",
    },
]

# --- TD-003: script includes with hard-coded sys_ids -------------------------
T["sys_script_include"] = [
    {
        "sys_id": sid("siau", 0),
        "name": "AssignmentUtils",
        "active": True,
        "oob": False,
        "script": "\n".join(f"var GROUP_{j} = '{sid('grp', j)}';" for j in range(9)),
    },
    {
        "sys_id": sid("sinet", 0),
        "name": "NetworkHelper",
        "active": True,
        "oob": False,
        "script": "var CI = 'cafebabecafebabecafebabecafebabe';",
    },
    {
        "sys_id": sid("siok", 0),
        "name": "CleanHelper",
        "active": True,
        "oob": False,
        "script": "var name = gs.getProperty('rob.fallback_group_name');",
    },
]

# --- SEC-001: direct admin ---------------------------------------------------
users = []
for i in range(17):
    dormant = i < 4
    users.append(
        {
            "sys_id": sid("usr", i),
            "user_name": ("svc.integration" if i == 16 else f"admin.user{i}"),
            "active": True,
            "days_since_login": 120 if dormant else 3,
        }
    )
users.append({"sys_id": sid("usrin", 0), "user_name": "left.company", "active": False, "days_since_login": 400})
T["sys_user"] = users
T["sys_user_has_role"] = [
    {"user": sid("usr", i), "role": "admin", "inherited": False} for i in range(17)
]
SNAP["aggregates"]["active_fulfiller_count"] = 210

# --- SEC-002: custom tables without ACLs / always-true ACL -------------------
T["sys_db_object"] = [
    {
        "sys_id": sid("tbl", 0),
        "name": "u_vendor_contracts",
        "row_count": 4120,
        "columns": ["u_vendor", "u_rate", "u_contact_email", "u_start_date"],
        "reference_data_only": False,
    },
    {
        "sys_id": sid("tbl", 1),
        "name": "u_legacy_data",
        "row_count": 900,
        "columns": ["u_code", "u_description"],
        "reference_data_only": False,
    },
    {
        "sys_id": sid("tbl", 2),
        "name": "u_country_codes",
        "row_count": 240,
        "columns": ["u_code", "u_name"],
        "reference_data_only": True,
    },
    {
        "sys_id": sid("tbl", 3),
        "name": "u_secured_table",
        "row_count": 100,
        "columns": ["u_data"],
        "reference_data_only": False,
    },
]
T["sys_security_acl"] = [
    # u_legacy_data has an always-true read ACL
    {"sys_id": sid("acl", 0), "name": "u_legacy_data", "operation": "read", "active": True, "script": "answer = true;", "roles": "", "condition": ""},
    # u_secured_table is properly protected (clean control)
    {"sys_id": sid("acl", 1), "name": "u_secured_table", "operation": "read", "active": True, "script": "", "roles": "u_secured_reader", "condition": ""},
    # u_country_codes reference table without ACL -> containment downgrade path
]

# --- SEC-003: hardening property deviations ----------------------------------
T["sys_properties"] = [
    {"name": "glide.ui.session_timeout", "value": "480"},
    {"name": "glide.security.strict.actions", "value": "false"},
    {"name": "glide.basicauth.required.scriptedprocessor", "value": "true"},  # compliant
    # rotate_sessions, x_frame_options, attachment.extensions missing entirely
]

# --- UPG-001: skipped records ------------------------------------------------
areas = [("Service Catalog", 860), ("Incident", 570), ("Change", 410), ("Knowledge", 300), ("CMDB", 200)]
T["sys_upgrade_history_log"] = [
    {"sys_id": sid("skip", i * 1000 + n), "upgrade": f"upgrade-{2024 + i}", "application": area, "disposition": "skipped", "resolved": False}
    for i, (area, count) in enumerate(areas)
    for n in range(count)
]

# --- UPG-002: modified baseline ratios (aggregate) ---------------------------
SNAP["aggregates"]["oob_modification_ratio_by_area"] = {
    "Incident": {"ratio": 0.31, "modified": 214, "total": 689},
    "Service Catalog": {"ratio": 0.24, "modified": 168, "total": 700},
    "Change": {"ratio": 0.11, "modified": 60, "total": 545},
}

# --- UPG-003: legacy workflows ----------------------------------------------
T["wf_workflow"] = [
    {"sys_id": sid("wf", 0), "name": "Change Approval - EU", "table": "change_request", "published": True, "oob": False},
    {"sys_id": sid("wf", 1), "name": "Hardware Request", "table": "sc_req_item", "published": True, "oob": False},
    {"sys_id": sid("wf", 2), "name": "Legacy HR Case", "table": "u_hr_case", "published": True, "oob": False},
    {"sys_id": sid("wf", 3), "name": "OOB Sample Flow", "table": "incident", "published": True, "oob": True},
]
SNAP["aggregates"]["wf_context_executions_90d"] = {
    sid("wf", 0): 1120,
    sid("wf", 1): 340,
    sid("wf", 2): 55,
    sid("wf", 3): 12,
}
SNAP["aggregates"]["transactions_per_day.incident"] = 3400

# --- CMDB population ---------------------------------------------------------
cmdb = []
# 120 windows servers: 40% unowned, discovery-populated, 50% stale
for i in range(120):
    cmdb.append(
        {
            "sys_id": sid("srv", i),
            "sys_class_name": "cmdb_ci_win_server",
            "name": f"WINSRV{i:03d}",
            "operational_status": "operational" if i < 110 else "retired",
            "owned_by": sid("usr", 5) if i % 5 < 3 else ("" if i % 5 == 3 else sid("usrin", 0)),
            "managed_by": "" if i % 5 >= 3 else sid("usr", 6),
            "support_group": "" if i % 5 >= 3 else "grp_wintel",
            "days_since_discovery": 60 if i % 2 else 10,
            "open_task_refs": 1 if i % 10 == 0 else 0,
        }
    )
# 80 applications: duplicates via repeated names, ownership fine
for i in range(80):
    cmdb.append(
        {
            "sys_id": sid("app", i),
            "sys_class_name": "cmdb_ci_appl",
            "name": f"APP-{i % 60:03d}",  # 20 duplicate pairs on name
            "operational_status": "operational",
            "owned_by": sid("usr", 7),
            "managed_by": sid("usr", 7),
            "support_group": "grp_apps",
            "days_since_update": 30,
            "created_by_source": "AppInventory import" if i >= 60 else "manual",
        }
    )
T["cmdb_ci"] = cmdb

# Relationships: link first 40 servers to apps; leave the rest orphaned.
rels = []
for i in range(40):
    rels.append({"sys_id": sid("rel", i), "parent": sid("app", i), "child": sid("srv", i), "type": "Runs on::Runs"})
# Dangling: 15 rels to retired servers, 10 rels to missing CIs
for i in range(15):
    rels.append({"sys_id": sid("reldr", i), "parent": sid("app", i), "child": sid("srv", 110 + (i % 10)), "type": "Runs on::Runs"})
for i in range(10):
    rels.append({"sys_id": sid("relmx", i), "parent": sid("app", i), "child": sid("gone", i), "type": "Runs on::Runs"})
T["cmdb_rel_ci"] = rels

# --- CSDM: business apps and services ---------------------------------------
T["cmdb_ci_business_app"] = [
    {
        "sys_id": sid("bap", i),
        "name": f"Business App {i:02d}",
        "lifecycle_stage": "operational" if i < 18 else "planning",
        "open_change_refs": 2 if i in (0, 1, 2) else 0,
    }
    for i in range(20)
]
T["cmdb_ci_service"] = [
    {
        "sys_id": sid("svc", i),
        "name": f"App Service {i:02d}",
        "operational_status": "operational",
        "service_classification": "Application Service" if i < 4 else "",
    }
    for i in range(12)
]
T["service_offering"] = [{"sys_id": sid("off", i), "name": f"Offering {i}"} for i in range(2)]
# Link 9 of 18 operational business apps to services; link 3 services to offerings
for i in range(9):
    T["cmdb_rel_ci"].append({"sys_id": sid("relba", i), "parent": sid("svc", i % 12), "child": sid("bap", i), "type": "Consumes::Consumed by"})
for i in range(3):
    T["cmdb_rel_ci"].append({"sys_id": sid("reloff", i), "parent": sid("off", i % 2), "child": sid("svc", i), "type": "Offers::Offered by"})

SNAP["aggregates"]["cmdb_instance_stale_rate"] = 0.41

# =============================================================================
# Wave 3: exposure and release governance
# =============================================================================
T["sys_report"] = [
    {"sys_id": sid("rep", i), "title": f"All {t} export", "table": t, "is_public": True, "roles": ""}
    for i, t in enumerate(["incident", "sys_user", "cmdb_ci", "change_request", "sc_req_item", "problem"])
]
T["sp_widget"] = [
    {"sys_id": sid("wid", i), "name": f"Public widget {i}", "public": True, "roles": ""}
    for i in range(4)
]
T["sys_ui_script"] = [
    # empty script + no function wrapper + a browser-storage offender
    {"sys_id": sid("uis", 0), "name": "legacy_helpers", "active": True, "script": "", "oob": False},
    {"sys_id": sid("uis", 1), "name": "global_tweaks", "active": True,
     "script": "var t = 1;\nwindow.robTweak = t;", "oob": False},
    {"sys_id": sid("uis", 2), "name": "supported_helper", "active": True,
     "script": "function robHelper() { return 1; }", "oob": False},
]
T["sys_update_set"] = (
    [{"sys_id": sid("ups", i), "name": f"REL-2026-0{i%9+1} Incident", "description": "",
      "state": "in progress", "days_since_update": 40 + i * 30} for i in range(6)]
    + [{"sys_id": sid("upsd", i), "name": "Interim fixes", "description": "Interim fixes",
        "state": "complete", "days_since_update": 10} for i in range(2)]
)

# =============================================================================
# Wave 4: scope, data model, operations, integrations, change governance
# =============================================================================

# --- SCOPE -------------------------------------------------------------------
T["sys_scope"] = [
    {"sys_id": sid("scp", 0), "name": "Global", "scope": "global", "version": "1.0", "active": True},
    {"sys_id": sid("scp", 1), "name": "Vendor Risk", "scope": "x_acme_vr", "version": "2.1", "active": True},
]
T["sys_app"] = [
    {"sys_id": sid("app_g", i), "name": f"Platform Extensions {i}", "scope": "global", "version": "1.0",
     "active": True, "is_global": True, "oob": False}
    for i in range(3)
] + [
    {"sys_id": sid("app_s", 0), "name": "Vendor Risk", "scope": "x_acme_vr", "version": "2.1",
     "active": True, "is_global": False, "oob": False},
]
T["sys_scope_privilege"] = (
    [{"sys_id": sid("prv_r", i), "source_scope": "x_acme_vr", "target_scope": "global",
      "target_name": tn, "target_type": "table", "operation": "read", "status": "requested"}
     for i, tn in enumerate(["incident", "cmdb_ci", "sys_user", "change_request"])]
    + [{"sys_id": sid("prv_w", i), "source_scope": "x_acme_vr", "target_scope": "global",
        "target_name": tn, "target_type": "table", "operation": op, "status": "allowed"}
       for i, (tn, op) in enumerate([("incident", "write"), ("cmdb_ci", "write"), ("task", "delete")])]
    + [{"sys_id": sid("prv_ok", 0), "source_scope": "x_acme_vr", "target_scope": "global",
        "target_name": "incident", "target_type": "table", "operation": "read", "status": "allowed"}]
)

# --- Data model: enrich the existing custom tables and add vendor tables ------
_dm_extra = {
    "u_vendor_contracts": {"scope": "global", "extension_depth": 1, "extension_root": "sys_metadata"},
    "u_legacy_data": {"scope": "global", "extension_depth": 5, "extension_root": "task"},
    "u_country_codes": {"scope": "global", "extension_depth": 0, "extension_root": "u_country_codes"},
}
for t in T["sys_db_object"]:
    t["is_custom"] = t["name"].startswith(("u_", "x_"))
    t.update(_dm_extra.get(t["name"], {"scope": "global", "extension_depth": 1, "extension_root": "task"}))
T["sys_db_object"] += [
    {"sys_id": sid("tbl_dead", i), "name": f"u_pilot_{i}", "row_count": 0, "columns": [],
     "reference_data_only": False, "is_custom": True, "scope": "global",
     "extension_depth": 1, "extension_root": "sys_metadata", "super_class": "sys_metadata"}
    for i in range(3)
] + [
    {"sys_id": sid("tbl_core", i), "name": n, "row_count": None, "columns": [],
     "reference_data_only": False, "is_custom": False, "scope": "global",
     "extension_depth": d, "extension_root": "task", "super_class": "task"}
    for i, (n, d) in enumerate([("incident", 1), ("change_request", 1), ("cmdb_ci", 0)])
]
T["sys_dictionary_custom_columns"] = [
    {"sys_id": sid("dic", i), "table": ["incident", "change_request", "cmdb_ci", "sys_user"][i % 4],
     "element": f"u_custom_{i}", "type": "string"}
    for i in range(46)
]

# --- Operational configuration -----------------------------------------------
# Two inactive users, so an orphaned run-as and orphaned authorship are real.
T["sys_user"] += [
    {"sys_id": sid("usr_gone", i), "user_name": f"former.dev{i}", "active": False, "days_since_login": 9999}
    for i in range(2)
]
T["sysauto_script"] = (
    [{"sys_id": sid("job_o", i), "name": f"Nightly reconciliation {i}", "active": True,
      "run_as": sid("usr_gone", 0), "run_as_inactive": True, "run_type": "daily",
      "condition": "", "oob": False} for i in range(2)]
    + [{"sys_id": sid("job_i", i), "name": f"Legacy sync {i}", "active": False,
        "run_as": sid("usr", 0), "run_as_inactive": False, "run_type": "weekly",
        "condition": "", "oob": False} for i in range(18)]
    + [{"sys_id": sid("job_ok", 0), "name": "Data archive", "active": True,
        "run_as": sid("usr", 0), "run_as_inactive": False, "run_type": "monthly",
        "condition": "", "oob": False}]
)
T["sysevent_email_action"] = (
    [{"sys_id": sid("not_x", i), "name": f"Escalation notice {i}", "active": True, "condition": "",
      "recipient_users": "", "recipient_fields": "", "event_name": "incident.escalated",
      "has_recipients": False, "oob": False} for i in range(5)]
    + [{"sys_id": sid("not_ok", 0), "name": "Assignment notice", "active": True, "condition": "",
        "recipient_users": "", "recipient_fields": "assigned_to", "event_name": "incident.assigned",
        "has_recipients": True, "oob": False}]
)
T["sysevent_in_email_action"] = [
    {"sys_id": sid("inm_x", 0), "name": "Create incident from mail", "active": True, "condition": "",
     "script": "current.short_description = email.subject;\ncurrent.insert();", "type": "new", "oob": False},
    {"sys_id": sid("inm_x", 1), "name": "Update from reply", "active": True, "condition": "",
     "script": "current.comments = email.body_text;\ncurrent.update();", "type": "reply", "oob": False},
    {"sys_id": sid("inm_ok", 0), "name": "Create request from mail", "active": True,
     "condition": "email.subject.startsWith('REQ')",
     "script": "current.short_description = email.subject;", "type": "new", "oob": False},
]

# --- Integrations -------------------------------------------------------------
T["sys_rest_message"] = [
    {"sys_id": sid("rm_x", 0), "name": "Vendor asset sync", "rest_endpoint": "http://assets.vendor.example/api",
     "authentication_type": "basic", "auth_profile": sid("auth", 0), "insecure_transport": True, "oob": False},
    {"sys_id": sid("rm_x", 1), "name": "Monitoring events", "rest_endpoint": "http://monitor.internal.example/events",
     "authentication_type": "", "auth_profile": "", "insecure_transport": True, "oob": False},
    {"sys_id": sid("rm_n", 0), "name": "Public status feed", "rest_endpoint": "https://status.vendor.example/feed",
     "authentication_type": "", "auth_profile": "", "insecure_transport": False, "oob": False},
    {"sys_id": sid("rm_ok", 0), "name": "HR sync", "rest_endpoint": "https://hr.vendor.example/api",
     "authentication_type": "oauth2", "auth_profile": sid("auth", 1), "insecure_transport": False, "oob": False},
]
T["sys_rest_message_fn"] = [
    {"sys_id": sid("rf_x", 0), "name": "getAssets", "rest_message": "Vendor asset sync",
     "rest_endpoint": "http://assets.vendor.example/api/assets", "authentication_type": "basic",
     "insecure_transport": True, "oob": False},
    {"sys_id": sid("rf_ok", 0), "name": "getEmployees", "rest_message": "HR sync",
     "rest_endpoint": "https://hr.vendor.example/api/employees", "authentication_type": "oauth2",
     "insecure_transport": False, "oob": False},
]

# --- Change governance (derived customisation ledger) -------------------------
_churn = []
# Work stranded in the Default update set
for i in range(9):
    _churn.append({
        "sys_id": f"sys_script_{sid('br', i)}", "name": f"sys_script_{sid('br', i)}",
        "target_name": f"Set assignment metadata {i}", "type": "Business Rule",
        "update_set": "Default", "update_count": 2 + i % 3, "author_count": 1,
        "authors": "admin.user0", "in_default_update_set": True,
        "author_inactive": False, "days_since_update": 15 + i,
    })
# High-churn artefacts
for i, (name, kind, n) in enumerate([("Assignment routing", "Business Rule", 61),
                                     ("Incident form logic", "Client Script", 38),
                                     ("SLA recalculation", "Script Include", 27)]):
    _churn.append({
        "sys_id": f"churn_hi_{i}", "name": f"churn_hi_{i}", "target_name": name, "type": kind,
        "update_set": "REL-2026-08 Incident", "update_count": n, "author_count": 4,
        "authors": "admin.user0, admin.user1, admin.user2, admin.user3",
        "in_default_update_set": False, "author_inactive": False, "days_since_update": 5 + i,
    })
# Orphaned authorship
for i in range(6):
    _churn.append({
        "sys_id": f"churn_orph_{i}", "name": f"churn_orph_{i}",
        "target_name": f"Legacy integration helper {i}", "type": "Script Include",
        "update_set": "REL-2023-11", "update_count": 3 + i, "author_count": 1,
        "authors": "former.dev0", "in_default_update_set": False,
        "author_inactive": True, "days_since_update": 700 + i * 10,
    })
# Healthy control: named set, active author, low churn
_churn.append({
    "sys_id": "churn_ok_0", "name": "churn_ok_0", "target_name": "Catalogue item variable",
    "type": "Variable", "update_set": "REL-2026-08 Incident", "update_count": 1,
    "author_count": 1, "authors": "admin.user0", "in_default_update_set": False,
    "author_inactive": False, "days_since_update": 3,
})
T["sys_update_xml_churn"] = _churn

# =============================================================================
# Wave 5: performance and code quality (script-pattern rules)
# Each script below is written to trigger exactly one new rule, so a failure to
# fire is a defect in the rule rather than an absence of test data.
# =============================================================================
_perf_server = [
    ("Sweep tasks nightly", "var gr = new GlideRecord('task');\ngr.addQuery('active', true);\ngr.query();\nwhile (gr.next()) { gr.state = 3; gr.update(); }"),
    ("Assign from manager", "while (task.next()) {\n  var u = new GlideRecord('sys_user');\n  u.addQuery('sys_id', task.assigned_to);\n  u.query();\n}"),
    ("Push to vendor", "var r = new sn_ws.RESTMessageV2('Vendor', 'post');\nvar resp = r.execute();\ngs.info(resp.getBody());"),
    ("Purge staging rows", "var gr = new GlideRecord('u_legacy_data');\ngr.addQuery('u_code', code);\ngr.deleteMultiple();"),
    ("Count open children", "var n = 0;\nwhile (kids.next()) { n++; }\nreturn n;"),
    ("Route incident", "gs.log('routing ' + current.number);\ncurrent.assignment_group = grp;"),
]
T["sys_script"] += [
    {"sys_id": sid("perf", i), "name": name, "active": True, "collection": "incident",
     "when": "before", "condition": "current.priority == 1", "filter_condition": "",
     "script": body, "oob": False}
    for i, (name, body) in enumerate(_perf_server)
]
# Display rule running a query (PERF-004)
T["sys_script"].append({
    "sys_id": sid("perfd", 0), "name": "Load approval count", "active": True,
    "collection": "change_request", "when": "display", "condition": "", "filter_condition": "",
    "script": "var a = new GlideRecord('sysapproval_approver');\na.addQuery('document_id', current.sys_id);\na.setLimit(50);\na.query();\ng_scratchpad.approvals = a.getRowCount();",
    "oob": False})
# current.update() in a business rule (CODE-001)
T["sys_script"].append({
    "sys_id": sid("code1", 0), "name": "Force priority", "active": True,
    "collection": "incident", "when": "before", "condition": "current.impact == 1", "filter_condition": "",
    "script": "current.priority = 1;\ncurrent.update();", "oob": False})
# Unguarded after-rule write (CODE-003)
T["sys_script"].append({
    "sys_id": sid("code3", 0), "name": "Roll up to parent", "active": True,
    "collection": "incident", "when": "after", "condition": "current.parent != ''", "filter_condition": "",
    "script": "var p = new GlideRecord('incident');\np.get(current.parent);\np.u_child_count = 1;\np.update();",
    "oob": False})
# Empty catch block (CODE-002)
T["sys_script_include"].append({
    "sys_id": sid("code2", 0), "name": "SyncUtil", "active": True,
    "script": "var SyncUtil = Class.create();\nSyncUtil.prototype = {\n  run: function() {\n    try { this.doSync(); } catch (e) {}\n  }\n};",
    "oob": False})
# Client-side role check (CODE-004)
T["sys_script_client"].append({
    "sys_id": sid("code4", 0), "name": "Hide cost from non-finance", "active": True,
    "table": "incident", "type": "onLoad",
    "script": "function onLoad() {\n  if (!g_user.hasRole('finance')) { g_form.setReadOnly('u_cost', true); }\n}",
    "oob": False})
# Declarative-only client script (CODE-005)
T["sys_script_client"].append({
    "sys_id": sid("code5", 0), "name": "Cause notes mandatory on close", "active": True,
    "table": "problem", "type": "onChange",
    "script": "function onChange(control, oldValue, newValue, isLoading) {\n  if (isLoading) return;\n  g_form.setMandatory('cause_notes', newValue == 'closed');\n}",
    "oob": False})




out = pathlib.Path(__file__).parent / "pdi_like_snapshot.json"
out.write_text(json.dumps(SNAP, indent=1))
print(f"Wrote {out} ({out.stat().st_size} bytes)")
print(f"Tables: {', '.join(sorted(T))}")
