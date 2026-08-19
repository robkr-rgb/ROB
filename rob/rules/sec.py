"""Security rules: ROB-SEC-001..003."""
from __future__ import annotations

import re

from ..models import Evidence, Snapshot
from .base import Rule, s

SENSITIVE_COLUMN_HINTS = ("password", "token", "ssn", "salary", "dob", "rate", "email", "iban")


class SEC001DirectAdminAssignment(Rule):
    ID = "ROB-SEC-001"
    CATEGORY = "Security"
    TITLE = "Direct admin role assignment to users"
    TIER = "T2"
    OWNER = "Security team (with Platform owner)"
    DOC_TOPICS = ("admin role", "role assignment", "elevated privilege group")
    REFERENCES = ("ServiceNow Instance Security Hardening Settings (privileged access)", "Least-privilege access review practice (ISO 27001 A.9 alignment)")

    def detect(self, snap: Snapshot, params: dict) -> list:
        exclusions = set(params.get("admin_exclusion_list", []))
        users = {u["sys_id"]: u for u in snap.t("sys_user")}
        direct = []
        for grant in snap.t("sys_user_has_role"):
            if grant.get("role") != "admin" or grant.get("inherited"):
                continue
            user = users.get(grant.get("user"))
            if not user or not user.get("active") or user.get("user_name") in exclusions:
                continue
            direct.append(user)
        if not direct:
            return []
        dormant = [u for u in direct if u.get("days_since_login", 0) >= 90]
        shared = [u for u in direct if u.get("user_name", "").startswith(("svc", "shared", "int."))]
        likelihood = "Likely" if (dormant or shared) else "Possible"
        fulfillers = snap.agg("active_fulfiller_count", 0) or 1
        pct = round(100 * len(direct) / fulfillers, 1)
        evidence = [
            Evidence(
                summary=(
                    f"User '{u['user_name']}' holds admin directly"
                    + (f"; no login for {u.get('days_since_login')} days" if u.get("days_since_login", 0) >= 90 else "")
                ),
                record_ref=f"sys_user/{u['sys_id']}",
            )
            for u in direct
        ]
        return [
            self.finding(
                affected_area="sys_user_has_role (admin)",
                evidence=evidence,
                evidence_total=len(direct),
                why=(
                    f"{len(direct)} active users hold admin directly rather than via a reviewed group "
                    f"({pct}% of {fulfillers} fulfillers); {len(dormant)} are dormant 90+ days. Standing "
                    "privileged access without group mediation defeats access review and widens breach impact."
                ),
                remediation=(
                    "Create or reuse an access-reviewed admin group, migrate direct grants into it, disable or "
                    "de-privilege dormant admin accounts, and record justification for each remaining grant. "
                    "ROB generates the migration payload itemised per account."
                ),
                optimisation="Schedule a quarterly privileged-access review sourced from this rule's output.",
                trace=s(
                    "Severe",
                    likelihood,
                    effort="Medium",
                    assumptions="Normal change; security approval chain; per-account verification",
                ),
            )
        ]


class SEC002MissingOrOpenACLs(Rule):
    ID = "ROB-SEC-002"
    VERSION = "0.3"  # v0.3: platform-generated table exclusion + empty-table containment (PDI tuning round 1)
    CATEGORY = "Security"
    TITLE = "Tables without ACLs or with always-true ACLs"
    TIER = "T2"
    OWNER = "Security team"
    DOC_TOPICS = ("access control list", "ACL row level", "table read access")
    REFERENCES = ("ServiceNow contextual security / ACL model documentation",)

    # Platform-generated scratch tables, not customer-built (e.g. CMDB Query
    # Builder result tables observed on PDI dev395061).
    PLATFORM_GENERATED = re.compile(r"^u_cmdb_qb_result_")

    def detect(self, snap: Snapshot, params: dict) -> list:
        findings = []
        acls_by_table: dict[str, list[dict]] = {}
        for acl in snap.t("sys_security_acl"):
            if acl.get("active"):
                acls_by_table.setdefault(acl.get("name", ""), []).append(acl)

        for table in snap.t("sys_db_object"):
            name = table.get("name", "")
            if not (name.startswith("u_") or name.startswith("x_")):
                continue
            if self.PLATFORM_GENERATED.match(name):
                continue
            table_acls = [a for a in acls_by_table.get(name, []) if a.get("operation") == "read"]
            always_true = [
                a
                for a in acls_by_table.get(name, [])
                if _is_always_true(a)
            ]
            if table_acls and not always_true:
                continue
            sensitive = [c for c in table.get("columns", []) if any(h in c for h in SENSITIVE_COLUMN_HINTS)]
            reference_only = table.get("reference_data_only", False)
            empty = not table.get("row_count", 0)
            modifiers = []
            if sensitive:
                modifiers.append("blast_radius")
            if reference_only or (empty and not sensitive):
                modifiers.append("containment")  # empty table: exposure is structural, nothing to read today
            issue = "no active read ACL" if not table_acls else f"{len(always_true)} always-true ACL(s)"
            evidence = [
                Evidence(
                    summary=f"Custom table {name} ({table.get('row_count', '?')} rows): {issue}",
                    record_ref=f"sys_db_object/{table.get('sys_id')}",
                    data={"sensitive_columns": sensitive},
                )
            ]
            findings.append(
                self.finding(
                    affected_area=name,
                    evidence=evidence,
                    evidence_total=1,
                    why=(
                        f"Table {name} is readable beyond its intended audience ({issue})"
                        + (f"; columns {', '.join(sensitive)} suggest sensitive content" if sensitive else "")
                        + ". Any authenticated user with a list view can query it."
                    ),
                    remediation=(
                        f"Create explicit read/write ACLs on {name} scoped to its actual consumer roles; delete or "
                        "implement always-true ACLs. ROB generates ACL skeletons from observed list/module access "
                        "as a fix-pack requiring sub-production testing."
                    ),
                    optimisation="Add ACL presence to the table-creation standard so new custom tables cannot ship open.",
                    trace=s(
                        "Severe",
                        "Possible",
                        modifiers,
                        effort="Medium",
                        assumptions="Normal change; one sub-production test pass; security review",
                    ),
                )
            )
        return findings


class SEC003HardeningProperties(Rule):
    ID = "ROB-SEC-003"
    VERSION = "0.3"  # v0.3: baseline expanded from 6-property subset to full v1 list
    CATEGORY = "Security"
    TITLE = "Security hardening properties deviating from baseline"
    TIER = "T1"
    OWNER = "Security team (with Platform team)"
    DOC_TOPICS = ("instance security hardening", "security properties", "hardening baseline")
    REFERENCES = ("ServiceNow Instance Security Hardening Settings (property baseline v1; validate per release before company-instance use)",)

    # Baseline v1. Versioned artefact: any change bumps the rule VERSION.
    # compare: eq = must equal | max = must not exceed | set = must be non-empty.
    # Property names and hardened values must be validated against the official
    # Instance Security Hardening Settings for the target release.
    BASELINE = {
        # Session and cookies
        "glide.ui.session_timeout": {"value": "30", "impact": "Severe", "compare": "max"},
        "glide.ui.rotate_sessions": {"value": "true", "impact": "Severe", "compare": "eq"},
        "glide.ui.secure_cookies": {"value": "true", "impact": "Severe", "compare": "eq"},
        "glide.cookies.http_only": {"value": "true", "impact": "Severe", "compare": "eq"},
        # UI / request hardening
        "glide.set_x_frame_options": {"value": "true", "impact": "Major", "compare": "eq"},
        "glide.security.use_csrf_token": {"value": "true", "impact": "Severe", "compare": "eq"},
        "glide.security.strict.actions": {"value": "true", "impact": "Major", "compare": "eq"},
        "glide.security.strict.updates": {"value": "true", "impact": "Major", "compare": "eq"},
        # Unauthenticated surface
        "glide.basicauth.required.scriptedprocessor": {"value": "true", "impact": "Severe", "compare": "eq"},
        "glide.basicauth.required.wsdl": {"value": "true", "impact": "Major", "compare": "eq"},
        "glide.basicauth.required.csv": {"value": "true", "impact": "Major", "compare": "eq"},
        "glide.basicauth.required.xml": {"value": "true", "impact": "Major", "compare": "eq"},
        # Attachments and files
        "glide.attachment.extensions": {"value": "<restricted list set>", "impact": "Major", "compare": "set"},
        "glide.security.file.mime_type.validation": {"value": "true", "impact": "Major", "compare": "eq"},
        # Authentication
        "glide.login.no_blank_password": {"value": "true", "impact": "Severe", "compare": "eq"},
        # Scripting surface
        "glide.script.use.sandbox": {"value": "true", "impact": "Major", "compare": "eq"},
    }

    def detect(self, snap: Snapshot, params: dict) -> list:
        props = {p["name"]: p.get("value") for p in snap.t("sys_properties")}
        deviations = []
        worst_impact = "Major"
        for name, spec in sorted(self.BASELINE.items()):
            current = props.get(name)
            deviating = False
            if spec["compare"] == "eq":
                deviating = current != spec["value"]
            elif spec["compare"] == "max":
                try:
                    deviating = current is None or int(current) > int(spec["value"])
                except (TypeError, ValueError):
                    deviating = True
            elif spec["compare"] == "set":
                deviating = not current
            if deviating:
                deviations.append((name, current, spec))
                if spec["impact"] == "Severe":
                    worst_impact = "Severe"
        if not deviations:
            return []
        evidence = [
            Evidence(
                summary=f"{name} = {current if current is not None else '<not set, insecure default>'} (baseline: {spec['value']})",
                record_ref=f"sys_properties/{name}",
                data={"impact": spec["impact"]},
            )
            for name, current, spec in deviations
        ]
        return [
            self.finding(
                affected_area="sys_properties (hardening baseline)",
                evidence=evidence,
                evidence_total=len(deviations),
                why=(
                    f"{len(deviations)} of {len(self.BASELINE)} baseline hardening properties deviate from the "
                    "hardened value. These settings are live configuration: session, auth and UI protections are "
                    "weaker than baseline right now."
                ),
                remediation=(
                    "Set each deviating property to its baseline value, or record a justification where the "
                    "deviation is intentional (e.g. SSO design). ROB generates the property-set fix-pack with "
                    "previous values captured for backout; each property is individually approvable."
                ),
                optimisation="Monitor baseline drift each scan cycle; alert on regressions after upgrades.",
                trace=s(
                    worst_impact,
                    "Certain",
                    effort="Low",
                    assumptions="Standard change per property; intentional deviations need documented justification",
                ),
            )
        ]


def _is_always_true(acl: dict) -> bool:
    script = (acl.get("script") or "").replace(" ", "").lower()
    unconditional = script in ("answer=true;", "answer=true", "returntrue;", "true;")
    return unconditional and not acl.get("roles") and not acl.get("condition")


RULES = [SEC001DirectAdminAssignment(), SEC002MissingOrOpenACLs(), SEC003HardeningProperties()]
