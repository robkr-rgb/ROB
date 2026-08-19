"""Upgrade readiness rules: ROB-UPG-001..003."""
from __future__ import annotations

from ..models import Evidence, Snapshot
from .base import Rule, s


class UPG001SkippedRecords(Rule):
    ID = "ROB-UPG-001"
    CATEGORY = "Upgrade Readiness"
    TITLE = "Unresolved skipped records from previous upgrades"
    TIER = "T3"
    OWNER = "Platform team"
    DOC_TOPICS = ("skipped records upgrade", "upgrade history", "upgrade review")
    REFERENCES = ("ServiceNow upgrade process documentation (skipped records review)",)

    def detect(self, snap: Snapshot, params: dict) -> list:
        skipped = [r for r in snap.t("sys_upgrade_history_log") if r.get("disposition") == "skipped" and not r.get("resolved")]
        if not skipped:
            return []
        by_area: dict[str, int] = {}
        for r in skipped:
            by_area[r.get("application", "unknown")] = by_area.get(r.get("application", "unknown"), 0) + 1
        top = sorted(by_area.items(), key=lambda x: -x[1])
        modifiers = ["aggregation"] if len(skipped) > 1000 else []
        adjustments = ["upgrade_window_proximity"] if params.get("upgrade_planned_within_quarter") else []
        evidence = [
            Evidence(summary=f"{area}: {count} unreviewed skipped records", record_ref=f"sys_upgrade_history_log?application={area}")
            for area, count in top
        ]
        upgrades = {r.get("upgrade") for r in skipped}
        return [
            self.finding(
                affected_area="sys_upgrade_history (skip backlog)",
                evidence=evidence,
                evidence_total=len(skipped),
                why=(
                    f"{len(skipped)} skipped records remain unreviewed across {len(upgrades)} upgrade(s), "
                    f"concentrated in {top[0][0]}. Each unreviewed skip is an unresolved conflict between "
                    "customisation and baseline that compounds risk and effort at the next family release."
                ),
                remediation=(
                    "Triage skipped records by application area using ROB's grouped worksheet: resolve or "
                    "explicitly accept each area; institute per-upgrade skip review as standard practice. "
                    "Whole inactive plugin areas can be accepted in one decision."
                ),
                optimisation="Add skip-review completion as an exit criterion to the upgrade runbook.",
                trace=s(
                    "Major",
                    "Likely",
                    modifiers,
                    effort="High" if len(skipped) > 500 else "Medium",
                    assumptions="Project-level triage above 500 records; architect involvement",
                    adjustments=adjustments,
                ),
            )
        ]


class UPG002ModifiedBaseline(Rule):
    ID = "ROB-UPG-002"
    CATEGORY = "Upgrade Readiness"
    TITLE = "Modified out-of-box records concentration"
    TIER = "T3"
    OWNER = "Architect"
    DOC_TOPICS = ("customer update baseline", "modified out-of-box", "upgrade skipped changes")
    REFERENCES = ("ServiceNow upgradability guidance (baseline divergence; HealthScan upgradability dimension overlap)",)

    CORE_AREAS = {"Incident", "Change", "Service Catalog", "Problem", "CMDB"}

    def detect(self, snap: Snapshot, params: dict) -> list:
        areas = snap.agg("oob_modification_ratio_by_area", {})
        if not areas:
            return []
        flagged = {a: v for a, v in areas.items() if v.get("ratio", 0) > 0.0}
        if not flagged:
            return []
        core_over = [a for a, v in flagged.items() if a in self.CORE_AREAS and v["ratio"] >= 0.20]
        impact_likelihood = ("Major", "Likely") if core_over else ("Moderate", "Likely")
        top = sorted(flagged.items(), key=lambda x: -x[1]["ratio"])
        evidence = [
            Evidence(
                summary=f"{area}: {round(v['ratio'] * 100)}% of OOB records modified ({v['modified']} of {v['total']})",
                record_ref=f"sys_update_xml?application={area}",
            )
            for area, v in top
        ]
        return [
            self.finding(
                affected_area="Baseline divergence (instance-wide)",
                evidence=evidence,
                evidence_total=sum(v["modified"] for v in flagged.values()),
                why=(
                    f"Baseline divergence is concentrated in {top[0][0]} ({round(top[0][1]['ratio']*100)}%). "
                    "Every modified OOB record is a future skip, a regression-test obligation and a blocker to "
                    "adopting new platform capability."
                ),
                remediation=(
                    "Run a divergence review on the top 3 areas using ROB's ranked inventory: identify "
                    "modifications now redundant with current OOB capability and revert those specifically. "
                    "No blanket reverts."
                ),
                optimisation="Track the divergence ratio per release cycle as a platform governance KPI.",
                trace=s(
                    impact_likelihood[0],
                    impact_likelihood[1],
                    effort="High",
                    assumptions="Design decisions per area; architect-led; regression testing",
                ),
            )
        ]


class UPG003LegacyWorkflowUsage(Rule):
    ID = "ROB-UPG-003"
    CATEGORY = "Upgrade Readiness"
    TITLE = "Active legacy Workflow usage"
    TIER = "T3"
    OWNER = "Architect (with Process owners)"
    DOC_TOPICS = ("legacy workflow", "Flow Designer migration", "workflow editor")
    REFERENCES = ("ServiceNow Workflow-to-Flow Designer migration guidance (legacy engine deprecation)",)

    def detect(self, snap: Snapshot, params: dict) -> list:
        active = []
        contexts = snap.agg("wf_context_executions_90d", {})
        for wf in snap.t("wf_workflow"):
            if not wf.get("published"):
                continue
            runs = contexts.get(wf["sys_id"], 0)
            if runs > 0:
                active.append((wf, runs))
        custom = [(wf, runs) for wf, runs in active if not wf.get("oob")]
        if not custom:
            return []
        custom.sort(key=lambda x: -x[1])
        core = [(wf, r) for wf, r in custom if wf.get("table") in {"incident", "change_request", "sc_req_item"}]
        impact_likelihood = ("Major", "Likely") if core else ("Moderate", "Likely")
        evidence = [
            Evidence(
                summary=f"Workflow '{wf['name']}' on {wf.get('table')}: {runs} executions in 90 days",
                record_ref=f"wf_workflow/{wf['sys_id']}",
            )
            for wf, runs in custom
        ]
        return [
            self.finding(
                affected_area="wf_workflow (legacy engine)",
                evidence=evidence,
                evidence_total=len(custom),
                why=(
                    f"{len(custom)} custom legacy workflows executed in the last 90 days "
                    f"({len(core)} on core ITSM tables). The legacy engine is deprecated technology: "
                    "every release increases migration cost and skilled-maintainer risk."
                ),
                remediation=(
                    "Use ROB's ranked migration inventory: migrate simple approval-pattern workflows to Flow "
                    "Designer first; schedule designed migrations for integration-heavy workflows; leave OOB "
                    "workflows untouched."
                ),
                optimisation="Freeze new legacy Workflow creation via development standard and peer review.",
                trace=s(
                    impact_likelihood[0],
                    impact_likelihood[1],
                    effort="High",
                    assumptions="Per-workflow migration effort itemised in evidence; project-level overall",
                ),
            )
        ]


RULES = [UPG001SkippedRecords(), UPG002ModifiedBaseline(), UPG003LegacyWorkflowUsage()]
