"""ROB core data models.

Snapshot: point-in-time extract of instance data (table -> records, plus aggregates).
Finding: evidence-backed result of a rule, with reproducible scoring inputs.
FixPack: executable fix per the fix-pack contract (remediation-framework.md).
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


SEVERITIES = ["Informational", "Low", "Medium", "High", "Critical"]
PRIORITIES = ["P4", "P3", "P2", "P1"]
EFFORTS = ["Low", "Medium", "High"]
TIERS = ["T1", "T2", "T3"]
# Staged activation ladder (scanner/rule-catalogue-triage.md, D-014).
CONFIDENCES = ["unvalidated", "provisional", "validated"]
# Autonomy classes (recommendations/autonomy-model.md, D-013). A4 does not exist.
AUTONOMY_CLASSES = ["A0", "A1", "A2", "A3"]

# Tables no executor operation may ever target, regardless of approval
# (W-C design decision 2). Defined here, not in the executor, so the rule-pack
# governance gate can refuse a remediation block at authoring time instead of
# the executor refusing it at apply time. Same list, one definition.
EXECUTOR_FORBIDDEN_TABLES = frozenset({
    "sys_security_acl", "sys_security_acl_role", "sys_user", "sys_user_role",
    "sys_user_has_role", "sys_user_grmember", "sys_group_has_role",
    "sys_user_group", "sys_authentication_profile", "oauth_credential",
})


@dataclass
class Snapshot:
    """Point-in-time extract. tables: table name -> list of record dicts.
    aggregates: precomputed aggregate signals (e.g. transactions/day per table).
    """

    instance_id: str
    taken_at: str  # ISO timestamp, supplied by the extractor
    tables: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    aggregates: dict[str, Any] = field(default_factory=dict)

    def t(self, name: str) -> list[dict[str, Any]]:
        return self.tables.get(name, [])

    def agg(self, key: str, default: Any = None) -> Any:
        return self.aggregates.get(key, default)


@dataclass
class Evidence:
    """One evidence line. record_ref is a table/sys_id style pointer."""

    summary: str
    record_ref: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoreTrace:
    """Reproducibility record: every input that produced severity and priority."""

    impact: str  # Severe / Major / Moderate / Minor
    likelihood: str  # Certain / Likely / Possible / Unlikely
    matrix_severity: str
    modifiers_applied: list[str] = field(default_factory=list)
    final_severity: str = ""
    effort: str = ""
    effort_assumptions: str = ""
    base_priority: str = ""
    adjustments_applied: list[str] = field(default_factory=list)
    final_priority: str = ""


@dataclass
class Finding:
    rule_id: str
    rule_version: str
    title: str
    category: str
    affected_area: str
    tier: str  # T1 / T2 / T3 (may be composite e.g. "T1/T3")
    evidence: list[Evidence]
    evidence_total: int  # total matches (evidence list is a capped sample)
    why_it_matters: str
    remediation: str
    optimisation: str
    owner: str
    dependencies: list[str] = field(default_factory=list)
    score: ScoreTrace | None = None
    fixpack_ref: str | None = None
    accepted: bool = False
    accepted_reason: str = ""
    # Staged activation (D-014): validated findings report normally; provisional
    # and unvalidated findings run in shadow mode so a false-positive rate can be
    # measured before the rule is allowed to speak.
    confidence: str = "validated"
    # Standing-approval class (D-013). Declared per rule, never inferred.
    autonomy: str = "A1"
    # ServiceNow vocabulary for this finding, declared by the rule. Used to find
    # reference material. A rule title is written for a human reading a report
    # ("Tables without ACLs or with always-true ACLs"), and searching with it
    # matched documentation on the words "always" and "true".
    doc_topics: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return f"{self.rule_id}:{self.affected_area}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FixPack:
    """Per the fix-pack contract: all five elements mandatory."""

    finding_fingerprint: str
    rule_id: str
    name: str
    fix_artefact: str  # the executable fix (script / payload / update set XML)
    fix_artefact_filename: str
    dry_run: str  # read-only verification showing exactly what will change
    instructions: str  # ordered application steps incl. environment + change model
    backout: str  # captured previous state sufficient to reverse
    backout_filename: str
    scope_statement: str  # what this fix does NOT touch + ordering dependencies
    # Machine-applicable form of the same change (D-019 / W-C). Every entry is a
    # typed record operation an executor can apply, inspect and reverse one at a
    # time. A pack with no operations is human-apply only, which is the honest
    # default: most fixes are scripts, and a script is a black box an executor
    # cannot bound or back out per record.
    operations: list[dict] = field(default_factory=list)

    @property
    def is_executable(self) -> bool:
        return bool(self.operations)

    def is_complete(self) -> bool:
        return all(
            [
                self.fix_artefact.strip(),
                self.dry_run.strip(),
                self.instructions.strip(),
                self.backout.strip(),
                self.scope_statement.strip(),
            ]
        )
