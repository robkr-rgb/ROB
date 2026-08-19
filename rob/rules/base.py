"""Rule base class. Each rule mirrors its specification in scanner/scan-rules.md."""
from __future__ import annotations

import re

from ..models import Evidence, Finding, ScoreTrace, Snapshot
from ..scoring import score

EVIDENCE_CAP = 10  # evidence lines are a capped sample; totals always reported

SYS_ID_RE = re.compile(r"[0-9a-f]{32}")

HIGH_VOLUME_TABLES = {"incident", "change_request", "sc_req_item", "sc_task", "task", "problem", "cmdb_ci", "sys_user"}


class Rule:
    ID = "ROB-XXX-000"
    VERSION = "0.2"
    CATEGORY = ""
    TITLE = ""
    TIER = "T3"
    OWNER = ""
    # Authoritative basis for the rule's practice claim. Labels, not URLs:
    # customers verify against the named source for their release.
    REFERENCES: tuple = ()
    # Staged activation (D-014). The hand-written seed library is pilot-measured
    # (39% -> 0% FP over two tuning rounds), so it ships validated. Imported rules
    # start unvalidated and earn their way up.
    CONFIDENCE = "validated"
    # Standing-approval class (D-013). A3 is a strict subset of T1 and is never
    # assigned by default.
    AUTONOMY = "A1"
    # ServiceNow concepts this rule is about, for finding reference material.
    # Empty is allowed: ROB then falls back to the title, and cites less well.
    DOC_TOPICS: tuple = ()

    def detect(self, snap: Snapshot, params: dict) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError

    def finding(
        self,
        *,
        affected_area: str,
        evidence: list[Evidence],
        evidence_total: int,
        why: str,
        remediation: str,
        optimisation: str,
        trace: ScoreTrace,
        dependencies: list[str] | None = None,
        title: str | None = None,
        tier: str | None = None,
        owner: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.ID,
            rule_version=self.VERSION,
            title=title or self.TITLE,
            category=self.CATEGORY,
            affected_area=affected_area,
            tier=tier or self.TIER,
            evidence=evidence[:EVIDENCE_CAP],
            evidence_total=evidence_total,
            why_it_matters=why,
            remediation=remediation,
            optimisation=optimisation,
            owner=owner or self.OWNER,
            dependencies=dependencies or [],
            score=trace,
            confidence=self.CONFIDENCE,
            autonomy=self.AUTONOMY,
            doc_topics=list(self.DOC_TOPICS),
        )


def s(impact, likelihood, modifiers=None, effort="Medium", assumptions="", adjustments=None) -> ScoreTrace:
    return score(impact, likelihood, modifiers, effort, assumptions, adjustments)
