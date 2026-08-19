"""Technical debt rules: ROB-TD-001..003."""
from __future__ import annotations

from ..models import Evidence, Snapshot
from .base import HIGH_VOLUME_TABLES, SYS_ID_RE, Rule, s


class TD001ConditionlessBusinessRules(Rule):
    ID = "ROB-TD-001"
    VERSION = "0.3"  # v0.3: low-volume containment (PDI tuning round 1)
    CATEGORY = "Technical Debt"
    TITLE = "Condition-less business rules on high-volume tables"
    TIER = "T2"
    OWNER = "Platform team"
    DOC_TOPICS = ("business rule", "business rule condition", "GlideRecord query performance")
    REFERENCES = ("ServiceNow business rule best practice (conditions on high-volume tables)", "Native Instance Scan performance checks (overlapping intent)")

    LOW_VOLUME_FLOOR = 50  # transactions/day below which the debt is latent, not active

    def detect(self, snap: Snapshot, params: dict) -> list:
        findings = []
        by_table: dict[str, list[dict]] = {}
        for br in snap.t("sys_script"):
            if not br.get("active"):
                continue
            if br.get("collection") not in HIGH_VOLUME_TABLES:
                continue
            if br.get("condition") or br.get("filter_condition"):
                continue
            if br.get("when") not in ("before", "after"):
                continue
            script = br.get("script", "")
            if len(script) < 80 and "GlideRecord" not in script and "GlideAggregate" not in script:
                continue
            if br.get("oob"):
                continue  # OOB-shipped rules reported separately (false-positive control)
            by_table.setdefault(br["collection"], []).append(br)

        for table, rules in sorted(by_table.items()):
            tpd = snap.agg(f"transactions_per_day.{table}", 0)
            modifiers = ["blast_radius"] if (tpd > 1000 or len(rules) > 5) else []
            if tpd < self.LOW_VOLUME_FLOOR and not modifiers:
                modifiers = ["containment"]  # latent debt on a quiet table: real, not urgent
            volume_phrase = f" (~{tpd}/day)" if tpd >= self.LOW_VOLUME_FLOOR else " (currently low-volume: latent debt)"
            evidence = [
                Evidence(
                    summary=f"Business rule '{r['name']}' ({r['when']}) runs on every {table} transaction",
                    record_ref=f"sys_script/{r['sys_id']}",
                    data={"queries_in_script": "GlideRecord" in r.get("script", "")},
                )
                for r in rules
            ]
            findings.append(
                self.finding(
                    affected_area=table,
                    evidence=evidence,
                    evidence_total=len(rules),
                    why=(
                        f"{len(rules)} active condition-less business rules execute on every insert/update of "
                        f"{table}{volume_phrase}, adding avoidable server work to each transaction and slowing "
                        "the process for every user."
                    ),
                    remediation=(
                        "Add a condition or filter matching each rule's actual intent. Where the script opens "
                        "with an if-guard, move that guard into the rule condition (ROB generates this as a "
                        "fix-pack candidate for review)."
                    ),
                    optimisation=(
                        "Adopt a development standard requiring conditions on all business rules for task and "
                        "cmdb_ci hierarchies, enforced at peer review."
                    ),
                    trace=s(
                        "Moderate",
                        "Certain",
                        modifiers,
                        effort="Low",
                        assumptions="Standard change; per-rule edit, no UI testing needed",
                    ),
                )
            )
        return findings


class TD002ClientScriptRoundTrips(Rule):
    ID = "ROB-TD-002"
    VERSION = "0.3"  # v0.3: OOB scripts excluded per rule spec (PDI tuning round 1: 92 OOB flags)
    CATEGORY = "Technical Debt"
    TITLE = "Server round-trips in client scripts"
    TIER = "T2"
    OWNER = "Platform team"
    DOC_TOPICS = ("client script", "GlideAjax asynchronous", "client script performance")
    REFERENCES = ("ServiceNow client scripting best practice (async GlideAjax/getReference; no client-side GlideRecord)",)

    PATTERNS = ("getXMLWait", "new GlideRecord(", "GlideRecord(")

    def detect(self, snap: Snapshot, params: dict) -> list:
        offenders = []
        for cs in snap.t("sys_script_client"):
            if not cs.get("active") or cs.get("oob"):
                continue
            script = _strip_comments(cs.get("script", ""))
            sync_ref = "getReference(" in script and "function" not in script.split("getReference(", 1)[1][:80]
            if any(p in script for p in self.PATTERNS) or sync_ref:
                offenders.append(cs)
        if not offenders:
            return []
        hv = [c for c in offenders if c.get("table") in HIGH_VOLUME_TABLES]
        modifiers = ["blast_radius"] if (hv or len(offenders) > 10) else []
        evidence = [
            Evidence(
                summary=f"Client script '{c['name']}' on {c.get('table')} performs a synchronous server call",
                record_ref=f"sys_script_client/{c['sys_id']}",
            )
            for c in offenders
        ]
        return [
            self.finding(
                affected_area="sys_script_client (instance-wide)",
                evidence=evidence,
                evidence_total=len(offenders),
                why=(
                    f"{len(offenders)} active client scripts perform synchronous server calls "
                    f"({len(hv)} on high-volume forms), blocking the browser for every user of those forms."
                ),
                remediation=(
                    "Replace with GlideAjax with callback, g_scratchpad populated by a display business rule, "
                    "or async getReference. ROB generates refactored versions as a fix-pack for review and testing."
                ),
                optimisation="Add a Livecheck-style peer-review rule banning client-side GlideRecord and getXMLWait.",
                trace=s(
                    "Moderate",
                    "Certain",
                    modifiers,
                    effort="Low",
                    assumptions="Standard change; per-script refactor with one sub-production form test",
                ),
            )
        ]


class TD003HardcodedSysIds(Rule):
    ID = "ROB-TD-003"
    CATEGORY = "Technical Debt"
    TITLE = "Hard-coded sys_ids in server scripts"
    TIER = "T2"
    OWNER = "Platform team"
    DOC_TOPICS = ("script include", "system property", "instance clone sys_id")
    REFERENCES = ("ServiceNow instance cloning/migration guidance (environment-independent references)",)

    TABLES = ("sys_script", "sys_script_include", "sys_script_client")

    def detect(self, snap: Snapshot, params: dict) -> list:
        offenders = []
        total_literals = 0
        for table in self.TABLES:
            for rec in snap.t(table):
                if not rec.get("active") or rec.get("oob"):
                    continue
                literals = SYS_ID_RE.findall(_strip_comments(rec.get("script", "")))
                if literals:
                    offenders.append((table, rec, len(literals)))
                    total_literals += len(literals)
        if not offenders:
            return []
        modifiers = ["aggregation"] if len(offenders) > 50 else []
        offenders.sort(key=lambda x: -x[2])
        evidence = [
            Evidence(
                summary=f"{table}/{rec['name']}: {n} hard-coded sys_id literal(s)",
                record_ref=f"{table}/{rec['sys_id']}",
            )
            for table, rec, n in offenders
        ]
        return [
            self.finding(
                affected_area="Server scripts (custom)",
                evidence=evidence,
                evidence_total=len(offenders),
                why=(
                    f"{len(offenders)} custom artefacts contain {total_literals} hard-coded sys_ids. These break "
                    "silently on clone, rebuild and migration, and hide record dependencies from impact analysis."
                ),
                remediation=(
                    "Replace literals with system properties, name/reference lookups or a constants module. "
                    "ROB generates the property definitions and edited scripts as a fix-pack for review."
                ),
                optimisation="Introduce a shared constants pattern and block new sys_id literals at peer review.",
                trace=s(
                    "Moderate",
                    "Likely",
                    modifiers,
                    effort="Low" if len(offenders) <= 20 else "Medium",
                    assumptions="Standard change; treat >20 artefacts as one clean-up work package",
                ),
            )
        ]


def _strip_comments(script: str) -> str:
    out_lines = []
    for line in script.splitlines():
        if "//" in line:
            line = line.split("//", 1)[0]
        out_lines.append(line)
    return "\n".join(out_lines)


RULES = [TD001ConditionlessBusinessRules(), TD002ClientScriptRoundTrips(), TD003HardcodedSysIds()]
