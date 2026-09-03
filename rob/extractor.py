"""ROB extraction layer: read-only ServiceNow REST client + snapshot builder.

Posture (per service-now/required-permissions.md):
- Read-only. Only GET requests are ever issued; there is no code path that writes.
- Field-limited: every query names its fields (sysparm_fields). No full-record reads.
- PII-minimised: sys_user is identifiers + login recency only.
- sys_properties is read by baseline name only, never bulk.
- Aggregate-first on volume tables; record reads paginated and capped.

Auth: basic auth for PDI validation runs (documented deviation from the OAuth
product model; acceptable for a fixture test only). Password comes from the
ROB_SN_PASSWORD environment variable or an interactive prompt - never a CLI arg.

Stdlib only (urllib): the extractor must run on any machine with Python 3.10+.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "ROB-Remediation-Optimisation-Bot/0.1 (read-only scan)"
PAGE_SIZE = 1000
DEFAULT_CAP = 20000
RETRIES = 3

# Property names ROB is allowed to read: single-sourced from the SEC-003
# baseline so the extraction allowlist can never diverge from the rule.
from .rules.sec import SEC003HardeningProperties as _SEC003

PROPERTY_BASELINE_NAMES = sorted(_SEC003.BASELINE)

OOB_CREATORS = {"system", "glide.maint", "maint"}

# Population aggregates for custom columns (group 15b): one count per column,
# capped so a heavily customised instance cannot turn extraction into thousands
# of requests. Beyond the cap the gap is declared in the snapshot.
COLUMN_COUNT_CAP = 500


class SNClient:
    """Minimal read-only Table/Stats API client."""

    def __init__(self, instance_url: str, user: str, password: str, timeout: int = 60):
        self.base = instance_url.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        self.timeout = timeout
        self.access_errors: list[str] = []

    def _get(self, path: str, params: dict) -> dict:
        url = f"{self.base}{path}?{urllib.parse.urlencode(params)}"
        last_err: Exception | None = None
        for attempt in range(RETRIES):
            req = urllib.request.Request(url, headers=self.headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    raise PermissionError(
                        f"{e.code} on {path}: the account lacks read access to this table. "
                        "See service-now/required-permissions.md (profile R-A)."
                    ) from e
                if e.code == 429 or e.code >= 500:
                    last_err = e
                    time.sleep(2**attempt)
                    continue
                raise
            except urllib.error.URLError as e:
                last_err = e
                time.sleep(2**attempt)
        raise ConnectionError(f"Failed after {RETRIES} attempts: {url}") from last_err

    def rows(self, table: str, fields: list[str], query: str = "", cap: int = DEFAULT_CAP, display: bool = False) -> list[dict]:
        """Paginated read. On 403/permission errors the table is SKIPPED, the
        gap is recorded in access_errors, and extraction continues: a partial
        snapshot with a declared gap beats a dead run."""
        out: list[dict] = []
        offset = 0
        while len(out) < cap:
            params = {
                "sysparm_fields": ",".join(fields),
                "sysparm_limit": min(PAGE_SIZE, cap - len(out)),
                "sysparm_offset": offset,
                "sysparm_display_value": "all" if display else "false",
                "sysparm_exclude_reference_link": "true",
            }
            if query:
                params["sysparm_query"] = query
            try:
                batch = self._get(f"/api/now/table/{table}", params).get("result", [])
            except PermissionError as e:
                self.access_errors.append(f"{table}: {e}")
                return out
            out.extend(batch)
            if len(batch) < PAGE_SIZE:
                break
            offset += len(batch)
        return out

    def count(self, table: str, query: str = "") -> int:
        params = {"sysparm_count": "true"}
        if query:
            params["sysparm_query"] = query
        try:
            data = self._get(f"/api/now/stats/{table}", params)
        except PermissionError as e:
            self.access_errors.append(f"{table} (count): {e}")
            return 0
        return int(data["result"]["stats"]["count"])


def _ref(value) -> str:
    """Reference fields may arrive as dicts; normalise to the sys_id/value."""
    if isinstance(value, dict):
        return value.get("value", "")
    return value or ""


def _days_since(iso_ts: str, now: dt.datetime) -> int | None:
    if not iso_ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            then = dt.datetime.strptime(iso_ts, fmt).replace(tzinfo=dt.timezone.utc)
            return max(0, (now - then).days)
        except ValueError:
            continue
    return None


def _is_oob(record: dict, provision_cutoff: dt.datetime | None = None, customer_touched: set | None = None, table: str = "") -> bool:
    """OOB detection v3.

    Definitive signal when available: ServiceNow's customisation ledger.
    Human-made changes create sys_update_xml rows named '<table>_<sys_id>';
    vendor installs and upgrades do not (their rows are system-authored).
    A record absent from the customer-authored ledger is vendor code.
    Falls back to v2 heuristics when the ledger could not be extracted."""
    if customer_touched is not None and table:
        return f"{table}_{record.get('sys_id', '')}" not in customer_touched
    return _is_oob_heuristic(record, provision_cutoff)


def _is_oob_heuristic(record: dict, provision_cutoff: dt.datetime | None = None) -> bool:
    """OOB heuristic v2: creator marker OR created before the instance existed.

    Baseline records keep their original (often years-old) sys_created_on when
    an instance is provisioned; anything created before the instance's own
    admin user cannot be customer work. Validated against PDI dev395061 where
    creator-only detection missed OOB artefacts like 'incident query' and
    IncidentNotificationUtilSNC."""
    if (record.get("sys_created_by") or "").lower() in OOB_CREATORS:
        return True
    if provision_cutoff is not None:
        created = record.get("sys_created_on") or ""
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                when = dt.datetime.strptime(created, fmt).replace(tzinfo=dt.timezone.utc)
                return when < provision_cutoff
            except ValueError:
                continue
    return False


def build_snapshot(client: SNClient, instance_id: str, progress=print) -> dict:
    """Extract the MVP manifest and emit the snapshot format the engine reads.

    Approximations in this validation extractor (documented, revisit per release):
    - OOB detection uses sys_created_by heuristic, not baseline diffing.
    - UPG-002 baseline-divergence aggregates are NOT computed yet; the rule
      skips cleanly (reported in the scan manifest).
    - Upgrade-log 'application' grouping uses the record type as a proxy.
    """
    now = dt.datetime.now(dt.timezone.utc)
    snap: dict = {
        "instance_id": instance_id,
        "taken_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tables": {},
        "aggregates": {},
    }
    T = snap["tables"]

    progress("[0/18] Instance provision date (for OOB detection)")
    cutoff = None
    admin_rows = client.rows("sys_user", ["sys_created_on"], query="user_name=admin")
    if admin_rows:
        created = admin_rows[0].get("sys_created_on", "")
        try:
            cutoff = dt.datetime.strptime(created, "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc) - dt.timedelta(days=1)
        except ValueError:
            cutoff = None

    progress("[0b/18] Customisation ledger (sys_update_xml, customer-authored)")
    # One read, two uses. The ledger is the definitive OOB signal (below) and the
    # only record of what a human has actually changed on this instance, which is
    # what makes the churn analysis in group 18 possible without a second read of
    # a table that is routinely the largest in the instance.
    ledger = client.rows(
        "sys_update_xml",
        ["name", "type", "target_name", "update_set", "action",
         "sys_created_by", "sys_updated_on"],
        query="sys_created_by!=system^sys_created_by!=glide.maint",
        display=True,
        cap=100000,
    )
    customer_touched: set | None = {_disp(r.get("name")) for r in ledger} or None
    if customer_touched is None:
        progress("  ledger unavailable or empty: falling back to heuristic OOB detection")

    script_fields = ["sys_id", "name", "active", "script", "sys_created_by", "sys_created_on"]

    progress("[1/18] Business rules (sys_script)")
    T["sys_script"] = [
        {
            "sys_id": r["sys_id"], "name": r.get("name", ""), "active": r.get("active") in ("true", True),
            "collection": r.get("collection", ""), "when": r.get("when", ""),
            "condition": r.get("condition", ""), "filter_condition": r.get("filter_condition", ""),
            "script": r.get("script", ""), "oob": _is_oob(r, cutoff, customer_touched, "sys_script"),
        }
        for r in client.rows("sys_script", script_fields + ["collection", "when", "condition", "filter_condition"], query="active=true")
    ]

    progress("[2/18] Client scripts")
    T["sys_script_client"] = [
        {
            "sys_id": r["sys_id"], "name": r.get("name", ""), "active": r.get("active") in ("true", True),
            "table": r.get("table", ""), "script": r.get("script", ""), "oob": _is_oob(r, cutoff, customer_touched, "sys_script_client"),
            "type": (r.get("type", "") or "").lower(),
        }
        for r in client.rows("sys_script_client", script_fields + ["table", "type"], query="active=true")
    ]

    progress("[3/18] Script includes")
    T["sys_script_include"] = [
        {
            "sys_id": r["sys_id"], "name": r.get("name", ""), "active": r.get("active") in ("true", True),
            "script": r.get("script", ""), "oob": _is_oob(r, cutoff, customer_touched, "sys_script_include"),
        }
        for r in client.rows("sys_script_include", script_fields, query="active=true")
    ]

    progress("[4/18] Users (PII-minimised) and admin grants")
    T["sys_user"] = [
        {
            "sys_id": r["sys_id"], "user_name": r.get("user_name", ""),
            "active": r.get("active") in ("true", True),
            "days_since_login": _days_since(r.get("last_login_time", ""), now) or 9999,
        }
        for r in client.rows("sys_user", ["sys_id", "user_name", "active", "last_login_time"])
    ]
    T["sys_user_has_role"] = [
        {"user": _ref(r.get("user")), "role": "admin", "inherited": r.get("inherited") in ("true", True)}
        for r in client.rows("sys_user_has_role", ["user", "inherited"], query="role.name=admin")
    ]
    T["sys_user_grmember"] = []
    snap["aggregates"]["active_fulfiller_count"] = client.count("sys_user_has_role", "role.name=itil^user.active=true") or 1

    progress("[5/18] Custom tables and dictionary")
    custom_tables = client.rows("sys_db_object", ["sys_id", "name"], query="nameSTARTSWITHu_^ORnameSTARTSWITHx_")
    dictionary = client.rows("sys_dictionary", ["name", "element"], query="nameSTARTSWITHu_^ORnameSTARTSWITHx_^elementISNOTEMPTY")
    cols: dict[str, list[str]] = {}
    for d in dictionary:
        cols.setdefault(d.get("name", ""), []).append(d.get("element", ""))
    T["sys_db_object"] = []
    for t in custom_tables:
        name = t.get("name", "")
        try:
            row_count = client.count(name)
        except (PermissionError, ConnectionError, urllib.error.HTTPError):
            row_count = 0
        T["sys_db_object"].append(
            {"sys_id": t["sys_id"], "name": name, "row_count": row_count, "columns": cols.get(name, []), "reference_data_only": False}
        )

    progress("[6/18] ACLs")
    acl_roles = {(_ref(r.get("acl"))) for r in client.rows("sys_security_acl_role", ["acl"])}
    T["sys_security_acl"] = [
        {
            "sys_id": r["sys_id"], "name": r.get("name", ""), "operation": r.get("operation", ""),
            "active": r.get("active") in ("true", True), "script": r.get("script", ""),
            "condition": r.get("condition", ""), "roles": "granted" if r["sys_id"] in acl_roles else "",
        }
        for r in client.rows("sys_security_acl", ["sys_id", "name", "operation", "active", "script", "condition"], query="active=true^nameSTARTSWITHu_^ORnameSTARTSWITHx_")
    ]

    progress("[7/18] Hardening properties (baseline names only)")
    name_query = "nameIN" + ",".join(PROPERTY_BASELINE_NAMES)
    T["sys_properties"] = [
        {"name": r.get("name", ""), "value": r.get("value", "")}
        for r in client.rows("sys_properties", ["name", "value"], query=name_query)
    ]

    progress("[8/18] Upgrade history (skipped records)")
    upgrade_logs = client.rows(
        "sys_upgrade_history_log",
        ["sys_id", "upgrade_history", "type", "disposition", "resolution_status"],
        display=True,
        cap=50000,
    )
    T["sys_upgrade_history_log"] = [
        {
            "sys_id": _ref(r.get("sys_id")) or "",
            "upgrade": _ref(r.get("upgrade_history")),
            "application": _disp(r.get("type")) or "unknown",  # proxy grouping; see docstring
            "disposition": "skipped",
            "resolved": bool(_disp(r.get("resolution_status")) and _disp(r.get("resolution_status")).lower() not in ("not reviewed", "not_reviewed")),
        }
        for r in upgrade_logs
        if "skip" in _disp(r.get("disposition")).lower()
    ]

    progress("[9/18] Legacy workflows and 90-day execution counts")
    T["wf_workflow"] = [
        {"sys_id": r["sys_id"], "name": r.get("name", ""), "table": r.get("table", ""), "published": True, "oob": _is_oob(r, cutoff, customer_touched, "wf_workflow")}
        for r in client.rows("wf_workflow", ["sys_id", "name", "table", "sys_created_by", "sys_created_on"])
    ]
    contexts = client.rows(
        "wf_context", ["workflow_version.workflow"], query="sys_created_on>=javascript:gs.daysAgoStart(90)", cap=50000
    )
    execs: dict[str, int] = {}
    for c in contexts:
        wf = _ref(c.get("workflow_version.workflow"))
        if wf:
            execs[wf] = execs.get(wf, 0) + 1
    snap["aggregates"]["wf_context_executions_90d"] = execs

    progress("[10/18] Transaction volume signals")
    for table in ("incident", "sc_req_item", "change_request"):
        try:
            week = client.count(table, "sys_updated_on>=javascript:gs.daysAgoStart(7)")
            snap["aggregates"][f"transactions_per_day.{table}"] = round(week / 7)
        except (PermissionError, ConnectionError):
            pass

    progress("[11/18] CMDB (aggregate-first, capped record reads)")
    cis = client.rows(
        "cmdb_ci",
        ["sys_id", "sys_class_name", "name", "operational_status", "owned_by", "managed_by",
         "support_group", "sys_updated_on", "last_discovered", "serial_number", "correlation_id"],
        display=True,  # operational_status as display value
    )
    T["cmdb_ci"] = [
        {
            "sys_id": _ref(r.get("sys_id")) or r.get("sys_id", ""),
            # Technical class name, not display label: class-based severity
            # logic keys on cmdb_ci_* names (bug found on PDI dev395061).
            "sys_class_name": _ref(r.get("sys_class_name")) or _disp(r.get("sys_class_name")),
            "name": _disp(r.get("name")),
            "operational_status": _disp(r.get("operational_status")).lower(),
            "owned_by": _ref(r.get("owned_by")) or _disp(r.get("owned_by")),
            "managed_by": _ref(r.get("managed_by")) or _disp(r.get("managed_by")),
            "support_group": _ref(r.get("support_group")) or _disp(r.get("support_group")),
            "days_since_update": _days_since(_disp(r.get("sys_updated_on")), now),
            "days_since_discovery": _days_since(_disp(r.get("last_discovered")), now),
            "serial_number": _disp(r.get("serial_number")),
            "open_task_refs": 0,  # enrichment deferred; conservative default
            "created_by_source": "unknown",
        }
        for r in cis
    ]
    total_ci = len(T["cmdb_ci"]) or 1
    stale = sum(
        1
        for c in T["cmdb_ci"]
        if c["operational_status"] == "operational"
        and ((c["days_since_discovery"] or 0) > 45 if c["days_since_discovery"] is not None else (c["days_since_update"] or 0) > 180)
    )
    snap["aggregates"]["cmdb_instance_stale_rate"] = round(stale / total_ci, 2)

    T["cmdb_rel_ci"] = [
        {"sys_id": r["sys_id"], "parent": _ref(r.get("parent")), "child": _ref(r.get("child")), "type": _disp(r.get("type"))}
        for r in client.rows("cmdb_rel_ci", ["sys_id", "parent", "child", "type"])
    ]

    progress("[12/18] CSDM: business apps, services, offerings")
    T["cmdb_ci_business_app"] = [
        {
            "sys_id": _ref(r.get("sys_id")) or "", "name": _disp(r.get("name")),
            "lifecycle_stage": (_disp(r.get("life_cycle_stage")) or "operational").lower(),
            "open_change_refs": 0,
        }
        for r in client.rows("cmdb_ci_business_app", ["sys_id", "name", "life_cycle_stage"], display=True)
    ]
    T["cmdb_ci_service"] = [
        {
            "sys_id": _ref(r.get("sys_id")) or "", "name": _disp(r.get("name")),
            "operational_status": _disp(r.get("operational_status")).lower() or "operational",
            "service_classification": _disp(r.get("service_classification")),
        }
        for r in client.rows("cmdb_ci_service", ["sys_id", "name", "operational_status", "service_classification"], display=True)
    ]
    T["service_offering"] = [
        {"sys_id": r["sys_id"], "name": _disp(r.get("name"))}
        for r in client.rows("service_offering", ["sys_id", "name"])
    ]

    progress("[13/18] Exposure and release governance (reports, widgets, UI scripts, update sets)")
    # Filtered at source: only publicly-exposed reports and widgets are extracted, so
    # the extraction stays proportionate to the question being asked (D-002 posture).
    T["sys_report"] = [
        {"sys_id": r["sys_id"], "title": _disp(r.get("title")), "table": _disp(r.get("table")),
         "is_public": True, "roles": _disp(r.get("roles"))}
        for r in client.rows("sys_report", ["sys_id", "title", "table", "is_public", "roles"], query="is_public=true")
    ]
    T["sp_widget"] = [
        {"sys_id": r["sys_id"], "name": _disp(r.get("name")) or _disp(r.get("id")),
         "public": True, "roles": _disp(r.get("roles"))}
        for r in client.rows("sp_widget", ["sys_id", "id", "name", "public", "roles"], query="public=true")
    ]
    T["sys_ui_script"] = [
        {
            "sys_id": r["sys_id"], "name": _disp(r.get("name")), "active": r.get("active") in ("true", True),
            "script": r.get("script", ""), "oob": _is_oob(r, cutoff, customer_touched, "sys_ui_script"),
        }
        for r in client.rows("sys_ui_script", script_fields, query="active=true")
    ]
    T["sys_update_set"] = [
        {
            "sys_id": r["sys_id"], "name": _disp(r.get("name")), "description": _disp(r.get("description")),
            "state": (_disp(r.get("state")) or "").lower(),
            "days_since_update": _days_since(_disp(r.get("sys_updated_on")), now),
        }
        for r in client.rows("sys_update_set", ["sys_id", "name", "description", "state", "sys_updated_on"],
                             query="state!=ignore", cap=5000)
    ]

    progress("[14/18] Application scope and packaging")
    # Small tables, read whole. Scope is the boundary that makes an instance
    # maintainable, so this is cheap information about an expensive problem.
    T["sys_scope"] = [
        {"sys_id": r.get("sys_id", ""), "name": _disp(r.get("name")), "scope": _disp(r.get("scope")),
         "version": _disp(r.get("version")), "active": r.get("active") in ("true", True, None)}
        for r in client.rows("sys_scope", ["sys_id", "name", "scope", "version", "active"], cap=5000)
    ]
    T["sys_app"] = [
        {
            "sys_id": r.get("sys_id", ""), "name": _disp(r.get("name")), "scope": _disp(r.get("scope")),
            "version": _disp(r.get("version")), "active": r.get("active") in ("true", True, None),
            # A custom application whose scope is "global" bypasses scope
            # protections entirely, which is the whole point of the check.
            "is_global": (_disp(r.get("scope")) or "global").lower() in ("", "global"),
            "oob": _is_oob(r, cutoff, customer_touched, "sys_app"),
        }
        for r in client.rows("sys_app", ["sys_id", "name", "scope", "version", "active",
                                         "sys_created_by", "sys_created_on"], cap=5000)
    ]
    T["sys_scope_privilege"] = [
        {"sys_id": r.get("sys_id", ""), "source_scope": _disp(r.get("source_scope")),
         "target_scope": _disp(r.get("target_scope")), "target_name": _disp(r.get("target_name")),
         "target_type": (_disp(r.get("target_type")) or "").lower(),
         "status": (_disp(r.get("status")) or "").lower(),
         "operation": (_disp(r.get("operation")) or "").lower()}
        for r in client.rows("sys_scope_privilege",
                             ["sys_id", "source_scope", "target_scope", "target_name",
                              "target_type", "status", "operation"], display=True, cap=10000)
    ]

    progress("[15/18] Data model (table extension, custom columns on vendor tables)")
    all_tables = client.rows("sys_db_object", ["sys_id", "name", "super_class", "sys_scope", "sys_created_by"],
                             display=True, cap=20000)
    by_name = {_disp(t.get("name")): t for t in all_tables}

    def _depth(table_name: str, seen: set | None = None) -> int:
        """How many levels this table sits below its root.

        Depth is a maintenance cost: every level adds columns, business rules and
        ACLs that a record inherits, and a custom table five levels under task
        carries all of it whether or not it needs any.
        """
        seen = seen or set()
        node = by_name.get(table_name)
        if not node or table_name in seen:
            return 0
        seen.add(table_name)
        parent = _disp(node.get("super_class"))
        return 0 if not parent else 1 + _depth(parent, seen)

    def _root(table_name: str, seen: set | None = None) -> str:
        seen = seen or set()
        node = by_name.get(table_name)
        if not node or table_name in seen:
            return table_name
        seen.add(table_name)
        parent = _disp(node.get("super_class"))
        return table_name if not parent else _root(parent, seen)

    existing = {t["name"]: t for t in T["sys_db_object"]}
    T["sys_db_object"] = []
    for t in all_tables:
        name = _disp(t.get("name"))
        if not name:
            continue
        prior = existing.get(name, {})
        T["sys_db_object"].append({
            "sys_id": t.get("sys_id", ""), "name": name,
            "super_class": _disp(t.get("super_class")),
            "extension_depth": _depth(name),
            "extension_root": _root(name),
            "scope": (_disp(t.get("sys_scope")) or "global").lower(),
            "is_custom": name.startswith(("u_", "x_")),
            "row_count": prior.get("row_count", None),
            "columns": prior.get("columns", []),
            "reference_data_only": False,
        })

    # Custom columns on vendor tables: a u_ field on incident is a customisation
    # that upgrades must carry forever, and it is invisible in a scope review.
    custom_columns = client.rows(
        "sys_dictionary", ["sys_id", "name", "element", "internal_type"],
        query="elementSTARTSWITHu_^nameNOT LIKEu_^nameNOT LIKEx_", display=True, cap=20000)
    T["sys_dictionary_custom_columns"] = [
        {"sys_id": r.get("sys_id", ""), "table": _disp(r.get("name")), "element": _disp(r.get("element")),
         "type": _disp(r.get("internal_type"))}
        for r in custom_columns if _disp(r.get("name"))
    ]

    progress("[15b/18] Data model attributes (dictionary, choices, overrides, placement, numbering)")
    # Attribute-level customisation. Group 15 answers "what tables exist and how
    # deep"; this group answers what has been done to individual columns, which
    # is where most of the invisible upgrade and usability cost of a data model
    # sits. Every join is done here so the rules stay declarative (D-014).
    CORE_FAMILIES = {"task", "cmdb_ci"}
    PICKER_TARGETS = {"sys_user", "sys_user_group", "cmdb_ci", "task"}
    PLACEHOLDER_LABELS = ("field", "new field", "new", "test", "temp", "tmp", "copy", "string", "integer", "reference")
    LOG_LIKE_MARKERS = ("_log", "_staging", "_stage", "_import", "_hist", "_audit", "_archive", "_temp", "_tmp")

    def _truthy(v) -> bool:
        return v in ("true", True, "1", 1)

    def _to_int(v) -> int | None:
        try:
            return int(str(_disp(v)).strip())
        except (TypeError, ValueError):
            return None

    def _customer_modified(record: dict, table: str) -> bool:
        """Definitive via the ledger; falls back to the updater when the ledger is absent."""
        if customer_touched is not None:
            return f"{table}_{record.get('sys_id', '')}" in customer_touched
        return (_disp(record.get("sys_updated_by")) or "").lower() not in OOB_CREATORS

    dict_fields = ["sys_id", "name", "element", "internal_type", "max_length", "reference",
                   "reference_qual", "reference_qual_condition", "dynamic_ref_qual", "mandatory",
                   "read_only", "default_value", "column_label", "comments", "audit",
                   "sys_created_on", "sys_created_by", "sys_updated_by"]

    # (a) Every custom column, wherever it lives: u_ columns on vendor tables plus
    #     all columns on custom tables.
    custom_col_rows = client.rows(
        "sys_dictionary", dict_fields,
        query="elementSTARTSWITHu_^ORnameSTARTSWITHu_^ORnameSTARTSWITHx_^elementISNOTEMPTY^internal_type!=collection",
        display=True, cap=20000)
    # (b) Vendor columns a customer has touched. Vendor installs and upgrades
    #     leave sys_updated_by as system/maint; a human updater is the signal,
    #     confirmed against the ledger when the ledger was readable.
    modified_rows = client.rows(
        "sys_dictionary", dict_fields,
        query="nameNOT LIKEu_^nameNOT LIKEx_^elementISNOTEMPTY^elementNOT LIKEu_"
              "^sys_updated_byNOT INsystem,glide.maint,maint",
        display=True, cap=20000)
    # (c) Collection rows of custom tables: the table-level flags (audit) live here,
    #     and this is the record an audit fix writes to.
    collection_rows = client.rows(
        "sys_dictionary", ["sys_id", "name", "audit", "sys_created_on", "sys_created_by"],
        query="internal_type=collection^nameSTARTSWITHu_^ORnameSTARTSWITHx_", display=True, cap=20000)

    # Placement: only custom elements, so the read stays proportional to the
    # customisation rather than to the whole form catalogue.
    form_placed: set[tuple[str, str]] = set()
    for r in client.rows("sys_ui_element", ["element", "sys_ui_section.name"],
                         query="elementSTARTSWITHu_", display=True, cap=50000):
        form_placed.add((_disp(r.get("sys_ui_section.name")).lower(), _disp(r.get("element")).lower()))
    list_placed: set[tuple[str, str]] = set()
    for r in client.rows("sys_ui_list_element", ["element", "sys_ui_list.name"],
                         query="elementSTARTSWITHu_", display=True, cap=50000):
        list_placed.add((_disp(r.get("sys_ui_list.name")).lower(), _disp(r.get("element")).lower()))
    placed_elements = {e for _, e in form_placed} | {e for _, e in list_placed}

    numbered = {_disp(r.get("category")).lower()
                for r in client.rows("sys_number", ["sys_id", "category", "prefix"], display=True, cap=5000)}

    table_meta = {t["name"]: t for t in T["sys_db_object"]}
    descendants_of_core: dict[str, str] = {t["name"]: t.get("extension_root", t["name"]) for t in T["sys_db_object"]}

    def _family(table_name: str) -> str:
        return descendants_of_core.get(table_name, _root(table_name))

    # Population counts: one aggregate per column, capped. Beyond the cap the
    # count is None and the rule cannot fire, and the gap is declared rather
    # than the column silently reported as populated or empty.
    table_rows_cache: dict[str, int | None] = {}

    def _table_rows(table_name: str) -> int | None:
        if table_name not in table_rows_cache:
            prior = table_meta.get(table_name, {}).get("row_count")
            if prior is None:
                try:
                    prior = client.count(table_name)
                except (PermissionError, ConnectionError, urllib.error.HTTPError):
                    prior = None
            table_rows_cache[table_name] = prior
        return table_rows_cache[table_name]

    columns_out = []
    counted = 0
    for r in custom_col_rows:
        table_name, element = _disp(r.get("name")), _disp(r.get("element"))
        if not table_name or not element:
            continue
        itype = (_disp(r.get("internal_type")) or "").lower()
        label = _disp(r.get("column_label")).strip()
        # ServiceNow derives the element from the label, so "Backup approver" for
        # u_backup_approver is normal. A placeholder is an empty label, the raw
        # element name left as the label, or a vocabulary word ("string 3").
        norm_label = label.lower().strip()
        raw_element = element.lower().strip()
        family = _family(table_name)
        on_core = family in CORE_FAMILIES or table_name in CORE_FAMILIES
        max_len = _to_int(r.get("max_length"))
        ref_target = _disp(r.get("reference"))
        ref_root = _family(ref_target) if ref_target else ""
        has_qual = bool(_disp(r.get("reference_qual")) or _disp(r.get("reference_qual_condition"))
                        or _disp(r.get("dynamic_ref_qual")))
        placed = (table_name.lower(), element.lower()) in form_placed or \
                 (table_name.lower(), element.lower()) in list_placed or \
                 (element.lower() in placed_elements and not (form_placed or list_placed))
        total_rows = _table_rows(table_name)
        populated = None
        if counted < COLUMN_COUNT_CAP and total_rows:
            try:
                populated = client.count(table_name, f"{element}ISNOTEMPTY")
            except (PermissionError, ConnectionError, urllib.error.HTTPError):
                populated = None
            counted += 1
        placeholder = (not label) or norm_label == raw_element or norm_label in PLACEHOLDER_LABELS \
            or any(norm_label.startswith(p + " ") for p in PLACEHOLDER_LABELS)
        columns_out.append({
            "sys_id": r.get("sys_id", ""), "name": f"{table_name}.{element}",
            "table": table_name, "element": element, "type": itype,
            "on_vendor_table": not table_name.startswith(("u_", "x_")),
            "table_family": family, "on_core_family": on_core,
            "max_length": max_len,
            # >255 leaves the base row on task/cmdb families; >4000 does so anywhere.
            "oversized": itype == "string" and max_len is not None and (
                (on_core and max_len > 255) or max_len > 4000),
            "reference": ref_target, "reference_root": ref_root,
            "reference_to_picker_target": ref_root in PICKER_TARGETS or ref_target in PICKER_TARGETS,
            "has_reference_qualifier": has_qual,
            "column_label": label, "placeholder_label": placeholder,
            "comments_empty": not _disp(r.get("comments")).strip(),
            "undocumented": placeholder or (on_core and not _disp(r.get("comments")).strip()),
            "placed": placed,
            "table_row_count": total_rows,
            "populated_count": populated,
            "days_since_created": _days_since(_disp(r.get("sys_created_on")), now),
        })
    T["sys_dictionary_columns"] = sorted(columns_out, key=lambda c: c["name"])
    if len(custom_col_rows) > COLUMN_COUNT_CAP:
        snap["aggregates"]["column_population_gap"] = {
            "cap": COLUMN_COUNT_CAP, "columns": len(custom_col_rows),
            "note": "populated_count is None beyond the cap; ROB-DM-005 cannot fire on those columns",
        }

    T["sys_dictionary_modified_oob"] = sorted([
        {
            "sys_id": r.get("sys_id", ""), "name": f"{_disp(r.get('name'))}.{_disp(r.get('element'))}",
            "table": _disp(r.get("name")), "element": _disp(r.get("element")),
            "type": (_disp(r.get("internal_type")) or "").lower(),
            "table_family": _family(_disp(r.get("name"))),
            "on_core_family": _family(_disp(r.get("name"))) in CORE_FAMILIES or _disp(r.get("name")) in CORE_FAMILIES,
            "mandatory": _truthy(_disp(r.get("mandatory"))), "read_only": _truthy(_disp(r.get("read_only"))),
            "max_length": _to_int(r.get("max_length")),
            "has_reference_qualifier": bool(_disp(r.get("reference_qual")) or _disp(r.get("reference_qual_condition"))),
            "has_default": bool(_disp(r.get("default_value"))),
            "updated_by": _disp(r.get("sys_updated_by")),
            "customer_modified": True,
        }
        for r in modified_rows
        if _disp(r.get("name")) and _disp(r.get("element")) and _customer_modified(r, "sys_dictionary")
    ], key=lambda c: c["name"])

    # T["sys_dictionary"] holds collection rows for custom tables only. The name
    # is the real table because the audit fix (ROB-DM-012) writes to it.
    T["sys_dictionary"] = sorted([
        {
            "sys_id": r.get("sys_id", ""), "name": _disp(r.get("name")),
            "internal_type": "collection", "is_custom": True,
            "audit": _truthy(_disp(r.get("audit"))),
            "row_count": table_meta.get(_disp(r.get("name")), {}).get("row_count"),
            "extension_root": _family(_disp(r.get("name"))),
            "log_like": any(m in _disp(r.get("name")).lower() for m in LOG_LIKE_MARKERS)
                        or _family(_disp(r.get("name"))) in ("sys_import_set_row", "syslog"),
            "oob": _is_oob(r, cutoff, customer_touched, "sys_dictionary"),
        }
        for r in collection_rows if _disp(r.get("name"))
    ], key=lambda c: c["name"])
    for t in T["sys_db_object"]:
        t["has_number_prefix"] = t["name"].lower() in numbered
        t["extends_task"] = t.get("extension_root") == "task" and t["name"] != "task"

    BRANCHING_ELEMENTS = {"state", "priority", "impact", "urgency", "approval", "type", "stage",
                          "escalation", "close_code", "risk", "phase", "hold_reason"}
    EXTENSIBLE_ELEMENTS = {"category", "subcategory", "u_category", "contact_type"}
    T["sys_choice"] = sorted([
        {
            "sys_id": r.get("sys_id", ""), "name": f"{_disp(r.get('name'))}.{_disp(r.get('element'))}={_disp(r.get('value'))}",
            "table": _disp(r.get("name")), "element": _disp(r.get("element")),
            "value": _disp(r.get("value")), "choice_label": _disp(r.get("label")),
            "inactive": _truthy(_disp(r.get("inactive"))),
            "table_family": _family(_disp(r.get("name"))),
            "branching_field": _disp(r.get("element")).lower() in BRANCHING_ELEMENTS,
            "designed_for_extension": _disp(r.get("element")).lower() in EXTENSIBLE_ELEMENTS,
            "oob": _is_oob(r, cutoff, customer_touched, "sys_choice"),
        }
        for r in client.rows(
            "sys_choice",
            ["sys_id", "name", "element", "value", "label", "inactive", "language", "sys_created_by", "sys_created_on"],
            query="nameNOT LIKEu_^nameNOT LIKEx_^elementNOT LIKEu_^language=en"
                  "^sys_created_byNOT INsystem,glide.maint,maint",
            display=True, cap=20000)
        if _disp(r.get("name")) and _disp(r.get("element"))
    ], key=lambda c: c["name"])

    OVERRIDE_FLAGS = ("mandatory_override", "read_only_override", "default_value_override",
                      "reference_qual_override", "calculation_override")
    T["sys_dictionary_override"] = sorted([
        {
            "sys_id": r.get("sys_id", ""), "name": f"{_disp(r.get('name'))}.{_disp(r.get('element'))}",
            "table": _disp(r.get("name")), "base_table": _disp(r.get("base_table")),
            "element": _disp(r.get("element")),
            "behaviour_overrides": [f for f in OVERRIDE_FLAGS if _truthy(_disp(r.get(f)))],
            "overrides_behaviour": any(_truthy(_disp(r.get(f))) for f in OVERRIDE_FLAGS),
            "oob": _is_oob(r, cutoff, customer_touched, "sys_dictionary_override"),
        }
        for r in client.rows(
            "sys_dictionary_override",
            ["sys_id", "name", "base_table", "element", *OVERRIDE_FLAGS, "sys_created_by", "sys_created_on"],
            query="sys_created_byNOT INsystem,glide.maint,maint", display=True, cap=20000)
        if _disp(r.get("name")) and _disp(r.get("element"))
    ], key=lambda c: c["name"])

    progress("[16/18] Scheduled jobs and notifications")
    inactive_users = {u["sys_id"] for u in T.get("sys_user", []) if not u.get("active")}
    T["sysauto_script"] = [
        {
            "sys_id": r.get("sys_id", ""), "name": _disp(r.get("name")),
            "active": r.get("active") in ("true", True),
            "run_as": _ref(r.get("run_as")),
            # Derived rather than left to the rule: a rule that had to join two
            # tables could not stay declarative.
            "run_as_inactive": _ref(r.get("run_as")) in inactive_users if _ref(r.get("run_as")) else False,
            "run_type": _disp(r.get("run_type")),
            "condition": _disp(r.get("condition")),
            "oob": _is_oob(r, cutoff, customer_touched, "sysauto_script"),
        }
        for r in client.rows("sysauto_script",
                             ["sys_id", "name", "active", "run_as", "run_type", "condition",
                              "sys_created_by", "sys_created_on"], cap=10000)
    ]
    T["sysevent_email_action"] = [
        {
            "sys_id": r.get("sys_id", ""), "name": _disp(r.get("name")),
            "active": r.get("active") in ("true", True),
            "condition": _disp(r.get("condition")),
            "recipient_users": _disp(r.get("recipient_users")),
            "recipient_fields": _disp(r.get("recipient_fields")),
            "event_name": _disp(r.get("event_name")),
            "has_recipients": bool(_disp(r.get("recipient_users")) or _disp(r.get("recipient_fields"))),
            "oob": _is_oob(r, cutoff, customer_touched, "sysevent_email_action"),
        }
        for r in client.rows("sysevent_email_action",
                             ["sys_id", "name", "active", "condition", "recipient_users",
                              "recipient_fields", "event_name", "sys_created_by", "sys_created_on"], cap=10000)
    ]
    T["sysevent_in_email_action"] = [
        {
            "sys_id": r.get("sys_id", ""), "name": _disp(r.get("name")),
            "active": r.get("active") in ("true", True),
            "condition": _disp(r.get("condition")),
            "script": r.get("script", ""),
            "type": _disp(r.get("type")),
            "oob": _is_oob(r, cutoff, customer_touched, "sysevent_in_email_action"),
        }
        for r in client.rows("sysevent_in_email_action",
                             ["sys_id", "name", "active", "condition", "script", "type",
                              "sys_created_by", "sys_created_on"], cap=5000)
    ]

    progress("[17/18] Outbound integrations")
    T["sys_rest_message"] = [
        {
            "sys_id": r.get("sys_id", ""), "name": _disp(r.get("name")),
            "rest_endpoint": _disp(r.get("rest_endpoint")),
            "authentication_type": (_disp(r.get("authentication_type")) or "").lower(),
            "auth_profile": _ref(r.get("authentication_profile")),
            # Cleartext transport is a property of the endpoint, so it is derived
            # here rather than left to a regex in a rule.
            "insecure_transport": _disp(r.get("rest_endpoint")).lower().startswith("http://"),
            "oob": _is_oob(r, cutoff, customer_touched, "sys_rest_message"),
        }
        for r in client.rows("sys_rest_message",
                             ["sys_id", "name", "rest_endpoint", "authentication_type",
                              "authentication_profile", "sys_created_by", "sys_created_on"], cap=10000)
    ]
    T["sys_rest_message_fn"] = [
        {
            "sys_id": r.get("sys_id", ""), "name": _disp(r.get("function_name")),
            "rest_message": _disp(r.get("rest_message")),
            "rest_endpoint": _disp(r.get("rest_endpoint")),
            "authentication_type": (_disp(r.get("authentication_type")) or "").lower(),
            "insecure_transport": _disp(r.get("rest_endpoint")).lower().startswith("http://"),
            "oob": _is_oob(r, cutoff, customer_touched, "sys_rest_message_fn"),
        }
        for r in client.rows("sys_rest_message_fn",
                             ["sys_id", "function_name", "rest_message", "rest_endpoint",
                              "authentication_type", "sys_created_by", "sys_created_on"], cap=20000)
    ]

    progress("[18/18] Customisation churn (what has actually been changed, and by whom)")
    # Derived from the group 0b ledger, one row per changed artefact rather than
    # one row per update record: the question a platform team asks is "what has
    # been touched, how often, by whom, and was it captured for release", and
    # that is an aggregate over sys_update_xml, not a record listing.
    inactive_usernames = {u["user_name"] for u in T.get("sys_user", []) if not u.get("active") and u.get("user_name")}
    churn: dict[str, dict] = {}
    for r in ledger:
        key = _disp(r.get("name"))
        if not key:
            continue
        entry = churn.get(key)
        if entry is None:
            entry = churn[key] = {
                "name": key,
                "target_name": _disp(r.get("target_name")),
                "type": _disp(r.get("type")),
                "update_set": _disp(r.get("update_set")),
                "authors": set(),
                "update_count": 0,
                "days_since_update": None,
                "action": _disp(r.get("action")),
            }
        entry["update_count"] += 1
        author = _disp(r.get("sys_created_by"))
        if author:
            entry["authors"].add(author)
        age = _days_since(_disp(r.get("sys_updated_on")), now)
        if age is not None and (entry["days_since_update"] is None or age < entry["days_since_update"]):
            entry["days_since_update"] = age
        # Latest update set wins: an artefact moved into a named set later is
        # captured for release even if an earlier change was not.
        if _disp(r.get("update_set")):
            entry["update_set"] = _disp(r.get("update_set"))
    T["sys_update_xml_churn"] = [
        {
            "sys_id": e["name"],
            "name": e["name"],
            "target_name": e["target_name"] or e["name"],
            "type": e["type"],
            "update_set": e["update_set"],
            "update_count": e["update_count"],
            "author_count": len(e["authors"]),
            "authors": ", ".join(sorted(e["authors"])),
            # "Default" is the per-scope set that cannot be moved between
            # instances (Default update set, ServiceNow product documentation),
            # so work sitting in it is work that was never captured for release.
            "in_default_update_set": e["update_set"].strip().lower().startswith("default"),
            "author_inactive": bool(e["authors"]) and e["authors"] <= inactive_usernames,
            "days_since_update": e["days_since_update"],
        }
        for e in sorted(churn.values(), key=lambda x: (-x["update_count"], x["name"]))
    ]

    errors = list(getattr(client, "access_errors", []))
    snap["aggregates"]["extraction_errors"] = errors
    if errors:
        progress(f"Extraction complete with {len(errors)} access gap(s) (declared in the snapshot; affected rules will not trigger):")
        for e in errors:
            progress(f"  - {e.splitlines()[0]}")
    else:
        progress("Extraction complete.")
    return snap


def _disp(value) -> str:
    if isinstance(value, dict):
        return value.get("display_value") or value.get("value") or ""
    return value or ""
