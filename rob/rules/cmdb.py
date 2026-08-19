"""CMDB quality and CSDM alignment rules: ROB-CMDB-001..006."""
from __future__ import annotations

from collections import defaultdict

from ..models import Evidence, Snapshot
from .base import Rule, s

ITSM_CLASSES = {"cmdb_ci_server", "cmdb_ci_win_server", "cmdb_ci_linux_server", "cmdb_ci_appl", "cmdb_ci_database"}
REL_EXPECTED_CLASSES = ITSM_CLASSES | {"cmdb_ci_service"}


def _cis_by_class(snap: Snapshot) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = defaultdict(list)
    for ci in snap.t("cmdb_ci"):
        out[ci.get("sys_class_name", "cmdb_ci")].append(ci)
    return out


class CMDB001OwnershipCoverage(Rule):
    ID = "ROB-CMDB-001"
    CATEGORY = "CMDB"
    TITLE = "CI ownership coverage below threshold"
    TIER = "T2"
    OWNER = "CMDB owner"
    DOC_TOPICS = ("CMDB health completeness", "CI ownership assignment", "owned by managed by")
    REFERENCES = ("ServiceNow CMDB Health (completeness KPIs: ownership)",)

    THRESHOLD = 0.20
    MIN_CLASS_SIZE = 50

    def detect(self, snap: Snapshot, params: dict) -> list:
        inactive_users = {u["sys_id"] for u in snap.t("sys_user") if not u.get("active")}
        findings = []
        for cls, cis in sorted(_cis_by_class(snap).items()):
            operational = [c for c in cis if c.get("operational_status") == "operational"]
            if len(operational) < self.MIN_CLASS_SIZE:
                continue
            unowned = [c for c in operational if not (c.get("owned_by") or c.get("managed_by") or c.get("support_group"))]
            dead_owner = [c for c in operational if c.get("owned_by") in inactive_users]
            rate = len(unowned) / len(operational)
            if rate < self.THRESHOLD:
                continue
            il = ("Major", "Likely") if cls in ITSM_CLASSES else ("Moderate", "Likely")
            evidence = [
                Evidence(summary=f"{cls}: {len(unowned)} of {len(operational)} operational CIs fully unowned ({round(rate*100)}%)"),
                Evidence(summary=f"{cls}: {len(dead_owner)} CIs owned by inactive users"),
            ]
            findings.append(
                self.finding(
                    affected_area=cls,
                    evidence=evidence,
                    evidence_total=len(unowned) + len(dead_owner),
                    why=(
                        f"{round(rate*100)}% of operational {cls} CIs have no owner, manager or support group. "
                        "Unowned CIs break incident routing and change risk assessment for every process that "
                        "references them."
                    ),
                    remediation=(
                        f"Backfill ownership on {cls} using ROB's mapping-driven batch payload (CMDB owner "
                        "completes the class/name-pattern → owner mapping; ROB fills and validates), then make "
                        "ownership mandatory on the class's identification path."
                    ),
                    optimisation="Add ownership assignment to provisioning flows so coverage cannot regress; track as monthly KPI.",
                    trace=s(il[0], il[1], effort="Medium", assumptions="Normal change; mapping input required from CMDB owner"),
                )
            )
        return findings


class CMDB002StaleCIs(Rule):
    ID = "ROB-CMDB-002"
    CATEGORY = "CMDB"
    TITLE = "Stale operational CIs"
    TIER = "T2"
    OWNER = "CMDB owner"
    DOC_TOPICS = ("CMDB health staleness", "CI lifecycle operational status", "last discovered")
    REFERENCES = ("ServiceNow CMDB Health (staleness/correctness KPIs); CMDB lifecycle practice",)

    THRESHOLD = 0.25
    STALE_DAYS = 180
    STALE_DISCOVERY_DAYS = 45

    def detect(self, snap: Snapshot, params: dict) -> list:
        findings = []
        excluded = set(params.get("static_ci_classes", []))
        for cls, cis in sorted(_cis_by_class(snap).items()):
            if cls in excluded:
                continue
            operational = [c for c in cis if c.get("operational_status") == "operational"]
            if len(operational) < 50:
                continue
            discovered_class = any(c.get("days_since_discovery") is not None for c in operational)
            if discovered_class:
                stale = [c for c in operational if (c.get("days_since_discovery") or 0) > self.STALE_DISCOVERY_DAYS]
            else:
                stale = [c for c in operational if (c.get("days_since_update") or 0) > self.STALE_DAYS]
            rate = len(stale) / len(operational)
            if rate < self.THRESHOLD:
                continue
            referenced = [c for c in stale if c.get("open_task_refs", 0) > 0]
            il = ("Major", "Likely") if referenced else ("Moderate", "Likely")
            instance_stale_rate = snap.agg("cmdb_instance_stale_rate", 0)
            modifiers = ["aggregation"] if instance_stale_rate > 0.40 else []
            basis = f"no discovery in {self.STALE_DISCOVERY_DAYS}+ days" if discovered_class else f"no update in {self.STALE_DAYS}+ days"
            findings.append(
                self.finding(
                    affected_area=cls,
                    evidence=[
                        Evidence(summary=f"{cls}: {len(stale)} of {len(operational)} operational CIs stale ({basis}, {round(rate*100)}%)"),
                        Evidence(summary=f"{cls}: {len(referenced)} stale CIs referenced by open tasks or recent changes"),
                    ],
                    evidence_total=len(stale),
                    why=(
                        f"{round(rate*100)}% of operational {cls} CIs show no activity ({basis}). A decaying class "
                        "means impact analysis and change collision detection run on wrong data."
                    ),
                    remediation=(
                        "Confirm the CI lifecycle policy, then apply ROB's batch retirement payload for CIs "
                        "meeting the policy's retirement criteria (itemised for approval). For discovery-populated "
                        "classes, close the discovery schedule coverage gaps first."
                    ),
                    optimisation="Expose per-class staleness as a monthly CMDB KPI with a defined ceiling.",
                    trace=s(il[0], il[1], modifiers, effort="Medium", assumptions="Lifecycle policy confirmed by CMDB owner first"),
                )
            )
        return findings


class CMDB003DuplicateCIs(Rule):
    ID = "ROB-CMDB-003"
    VERSION = "0.3"  # v0.3: software classes need hard-identity match, name alone is noise (PDI tuning round 1)
    CATEGORY = "CMDB"
    TITLE = "Duplicate CIs by identity attributes"
    TIER = "T2"
    OWNER = "CMDB owner (with Integration team)"
    DOC_TOPICS = ("duplicate CI", "identification reconciliation engine", "CMDB deduplication")
    REFERENCES = ("ServiceNow CMDB identification & reconciliation documentation",)

    # Classes where identical names are legitimate (many installs/versions of
    # one product): duplicates only count on serial/correlation match.
    NAME_MATCH_UNSAFE = {"cmdb_ci_spkg", "cmdb_sam_sw_install", "cmdb_ci_software", "cmdb_software_instance"}

    def detect(self, snap: Snapshot, params: dict) -> list:
        findings = []
        for cls, cis in sorted(_cis_by_class(snap).items()):
            operational = [c for c in cis if c.get("operational_status") == "operational"]
            if len(operational) < 50:
                continue
            name_unsafe = cls in self.NAME_MATCH_UNSAFE or "software" in cls.lower() or "spkg" in cls.lower()
            groups: dict[tuple, list[dict]] = defaultdict(list)
            for c in operational:
                if name_unsafe:
                    hard_id = c.get("serial_number") or c.get("correlation_id")
                    if not hard_id:
                        continue  # no hard identity: name collisions are expected, skip
                    key = (cls, hard_id)
                else:
                    key = (c.get("normalised_name") or c.get("name", "").lower().strip(),)
                    if c.get("serial_number"):
                        key = key + (c["serial_number"],)
                groups[key].append(c)
            dup_groups = {k: v for k, v in groups.items() if len(v) > 1}
            if not dup_groups:
                continue
            dup_cis = sum(len(v) for v in dup_groups.values())
            rate = dup_cis / len(operational)
            il = ("Major", "Likely") if (cls in ITSM_CLASSES and rate > 0.05) else ("Moderate", "Likely")
            sources = defaultdict(int)
            for v in dup_groups.values():
                for c in v:
                    sources[c.get("created_by_source", "unknown")] += 1
            top_source = max(sources.items(), key=lambda x: x[1])
            findings.append(
                self.finding(
                    affected_area=cls,
                    evidence=[
                        Evidence(summary=f"{cls}: {len(dup_groups)} duplicate groups ({dup_cis} CIs, {round(rate*100)}% of class)"),
                        Evidence(summary=f"Top duplicate source: '{top_source[0]}' ({top_source[1]} CIs)"),
                    ],
                    evidence_total=dup_cis,
                    why=(
                        f"{len(dup_groups)} duplicate groups in {cls} fragment relationships and task history "
                        "across copies, so no single CI shows the true picture."
                    ),
                    remediation=(
                        "Apply ROB's per-group merge/retire payload (survivor proposed by relationship count and "
                        "discovery recency; each group individually approvable), then fix the ingestion source "
                        f"('{top_source[0]}') by adding identification rules."
                    ),
                    optimisation="Enforce identification rules on all import sets and integrations touching CMDB classes.",
                    trace=s(il[0], il[1], effort="Medium" if dup_cis < 200 else "High", assumptions="Per-group review; integration fix is separate work"),
                )
            )
        return findings


class CMDB004OrphanCIsAndDanglingRels(Rule):
    ID = "ROB-CMDB-004"
    CATEGORY = "CMDB"
    TITLE = "Orphan CIs and dangling relationships"
    TIER = "T1/T3"
    OWNER = "CMDB owner"
    DOC_TOPICS = ("CI relationship", "orphan CI", "CMDB health correctness")
    REFERENCES = ("ServiceNow CMDB Health (relationship/orphan KPIs); service mapping practice",)

    def detect(self, snap: Snapshot, params: dict) -> list:
        cis = {c["sys_id"]: c for c in snap.t("cmdb_ci")}
        related_ids = set()
        dangling = []
        for rel in snap.t("cmdb_rel_ci"):
            parent, child = cis.get(rel.get("parent")), cis.get(rel.get("child"))
            if parent is None or child is None or parent.get("operational_status") == "retired" or child.get("operational_status") == "retired":
                dangling.append(rel)
            else:
                related_ids.add(rel["parent"])
                related_ids.add(rel["child"])
        orphans = [
            c
            for c in cis.values()
            if c.get("sys_class_name") in REL_EXPECTED_CLASSES
            and c.get("operational_status") == "operational"
            and c["sys_id"] not in related_ids
        ]
        if not orphans and not dangling:
            return []
        expected = [c for c in cis.values() if c.get("sys_class_name") in REL_EXPECTED_CLASSES and c.get("operational_status") == "operational"]
        rate = len(orphans) / len(expected) if expected else 0
        service_mapped_over = rate > 0.30
        modifiers = ["blast_radius"] if service_mapped_over else []
        return [
            self.finding(
                affected_area="cmdb_rel_ci / relationship-expected classes",
                evidence=[
                    Evidence(summary=f"{len(orphans)} operational CIs ({round(rate*100)}% of relationship-expected classes) have no relationships"),
                    Evidence(summary=f"{len(dangling)} dangling cmdb_rel_ci records reference missing or retired CIs"),
                ],
                evidence_total=len(orphans) + len(dangling),
                why=(
                    "Orphan CIs are invisible to impact analysis; dangling relationships corrupt it. "
                    f"At {round(rate*100)}% orphan rate, service maps over these classes cannot be trusted."
                ),
                remediation=(
                    "T1: apply ROB's deletion payload for dangling cmdb_rel_ci records (full record export "
                    "captured as backout). T3: build relationships top-down from the business services actually "
                    "referenced in incident and change, using ROB's orphan inventory."
                ),
                optimisation="Make relationship creation part of CI onboarding for relationship-expected classes.",
                trace=s(
                    "Moderate",
                    "Likely",
                    modifiers,
                    effort="Medium",
                    assumptions="Dangling repair is Low effort standalone; orphan build is per-service work",
                ),
            )
        ]


class CMDB005BusinessAppsWithoutServices(Rule):
    ID = "ROB-CMDB-005"
    CATEGORY = "CMDB (CSDM)"
    TITLE = "Business applications without linked application services"
    TIER = "T2"
    OWNER = "CMDB owner (with Application owners)"
    DOC_TOPICS = ("CSDM application service", "business application", "service mapping")
    REFERENCES = ("ServiceNow CSDM white paper (business application to application service chain)",)

    def detect(self, snap: Snapshot, params: dict) -> list:
        apps = [a for a in snap.t("cmdb_ci_business_app") if a.get("lifecycle_stage", "operational") == "operational"]
        if not apps:
            return []
        service_ids = {sv["sys_id"] for sv in snap.t("cmdb_ci_service")}
        linked_app_ids = set()
        for rel in snap.t("cmdb_rel_ci"):
            if rel.get("parent") in service_ids:
                linked_app_ids.add(rel.get("child"))
            if rel.get("child") in service_ids:
                linked_app_ids.add(rel.get("parent"))
        unlinked = [a for a in apps if a["sys_id"] not in linked_app_ids]
        if not unlinked:
            return []
        # CSDM maturity reframe: if the org has no application services at all,
        # emit one informational observation, not per-app findings (false-positive control, D-006).
        if not service_ids:
            return [
                self.finding(
                    affected_area="CSDM adoption",
                    evidence=[Evidence(summary=f"{len(apps)} operational business applications; 0 application services exist")],
                    evidence_total=len(apps),
                    why="The instance has not adopted application services; the CSDM design-to-manage chain does not exist yet.",
                    remediation="Treat as a CSDM maturity decision, not a defect: plan application service adoption starting with the most consumed applications.",
                    optimisation="Adopt CSDM staging: crawl (foundation data) before walk (application services).",
                    trace=s("Minor", "Certain", effort="High", assumptions="Programme-level decision"),
                    tier="T3",
                    title="CSDM maturity observation: no application services",
                )
            ]
        rate = len(unlinked) / len(apps)
        in_flight = [a for a in unlinked if a.get("open_change_refs", 0) > 0]
        modifiers = ["aggregation"] if (rate > 0.40 or in_flight) else []
        evidence = [
            Evidence(
                summary=f"Business application '{a['name']}' has no linked application service"
                + (f" ({a.get('open_change_refs')} open changes reference it)" if a.get("open_change_refs") else ""),
                record_ref=f"cmdb_ci_business_app/{a['sys_id']}",
            )
            for a in sorted(unlinked, key=lambda x: -x.get("open_change_refs", 0))
        ]
        return [
            self.finding(
                affected_area="cmdb_ci_business_app (CSDM chain)",
                evidence=evidence,
                evidence_total=len(unlinked),
                why=(
                    f"{len(unlinked)} of {len(apps)} operational business applications ({round(rate*100)}%) have "
                    f"no linked application service; {len(in_flight)} are referenced by open changes where impact "
                    "analysis currently dead-ends at the design layer."
                ),
                remediation=(
                    "Create application services for the highest-consumption unlinked applications first. ROB "
                    "generates proposed application service records (named per the instance's observed convention) "
                    "plus the relationship payload for CMDB owner review before creation."
                ),
                optimisation="Make application service creation part of the new-business-application intake flow.",
                trace=s("Moderate", "Likely", modifiers, effort="Medium", assumptions="Naming convention confirmed; app owner validation per service"),
            )
        ]


class CMDB006ServicesWithoutClassification(Rule):
    ID = "ROB-CMDB-006"
    CATEGORY = "CMDB (CSDM)"
    TITLE = "Application services without classification or offering linkage"
    TIER = "T2"
    OWNER = "CMDB owner"
    DOC_TOPICS = ("service offering", "service classification", "CSDM service model")
    REFERENCES = ("ServiceNow CSDM white paper (service classification; consume-side chain)",)

    def detect(self, snap: Snapshot, params: dict) -> list:
        services = [sv for sv in snap.t("cmdb_ci_service") if sv.get("operational_status") == "operational"]
        if not services:
            return []
        offerings = {o["sys_id"] for o in snap.t("service_offering")}
        if not offerings and all(not sv.get("service_classification") for sv in services):
            return [
                self.finding(
                    affected_area="CSDM adoption",
                    evidence=[Evidence(summary=f"{len(services)} services; no classifications and no offerings exist")],
                    evidence_total=len(services),
                    why="Service portfolio structures are not adopted; classification findings would be noise.",
                    remediation="Treat as a CSDM maturity decision: introduce service classification and offerings when portfolio reporting is needed.",
                    optimisation="Stage adoption per CSDM guidance rather than backfilling piecemeal.",
                    trace=s("Minor", "Certain", effort="High", assumptions="Programme-level decision"),
                    tier="T3",
                    title="CSDM maturity observation: no service portfolio structures",
                )
            ]
        unclassified = [sv for sv in services if not sv.get("service_classification") or sv.get("service_classification") == "unspecified"]
        linked_service_ids = set()
        for rel in snap.t("cmdb_rel_ci"):
            if rel.get("parent") in offerings:
                linked_service_ids.add(rel.get("child"))
            if rel.get("child") in offerings:
                linked_service_ids.add(rel.get("parent"))
        unlinked = [sv for sv in services if sv["sys_id"] not in linked_service_ids]
        if not unclassified and not unlinked:
            return []
        rate = len(unclassified) / len(services)
        modifiers = ["aggregation"] if rate > 0.50 else []
        return [
            self.finding(
                affected_area="cmdb_ci_service (classification and offerings)",
                evidence=[
                    Evidence(summary=f"{len(unclassified)} of {len(services)} operational services ({round(rate*100)}%) carry no service classification"),
                    Evidence(summary=f"{len(unlinked)} application services have no offering or business service linkage"),
                ],
                evidence_total=len(unclassified) + len(unlinked),
                why=(
                    f"With {round(rate*100)}% of services unclassified, portfolio and catalog reporting is "
                    "structurally unreliable; unlinked services break the CSDM consume-side chain."
                ),
                remediation=(
                    "Apply ROB's batch classification payload where classification is derivable from class and "
                    "naming (each line approvable); link services to the offerings actually consumed in catalog "
                    "and ITSM records using the ranked linkage proposals."
                ),
                optimisation="Make classification mandatory on service creation forms.",
                trace=s("Moderate", "Likely", modifiers, effort="Medium", assumptions="Derivable classifications reviewed by CMDB owner"),
            )
        ]


RULES = [
    CMDB001OwnershipCoverage(),
    CMDB002StaleCIs(),
    CMDB003DuplicateCIs(),
    CMDB004OrphanCIsAndDanglingRels(),
    CMDB005BusinessAppsWithoutServices(),
    CMDB006ServicesWithoutClassification(),
]
