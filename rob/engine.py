"""ROB rule engine.

Runs the registered rule library against a Snapshot deterministically:
same snapshot in, same findings out, ordered by rule ID. Rules never touch
a live instance; they only read the snapshot (MVP posture: read-only).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, FixPack, Snapshot
from .rules import RULE_REGISTRY
from .rules.declarative import DeclarativeRule, MissingSnapshotData
from .fixpacks import FIXPACK_GENERATORS


@dataclass
class ScanResult:
    snapshot: Snapshot
    rule_versions: dict[str, str]
    findings: list[Finding] = field(default_factory=list)
    fixpacks: list[FixPack] = field(default_factory=list)
    skipped_rules: list[str] = field(default_factory=list)
    # Findings from rules below 'validated' confidence (D-014 staged activation).
    # Held separately so an imported, unmeasured rule cannot add noise to a
    # customer report before its false-positive rate is known.
    shadow_findings: list[Finding] = field(default_factory=list)

    @property
    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            sev = f.score.final_severity if f.score else "Informational"
            out[sev] = out.get(sev, 0) + 1
        return out

    @property
    def by_priority(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            pri = f.score.final_priority if f.score else "P4"
            out[pri] = out.get(pri, 0) + 1
        return out


def run_scan(
    snapshot: Snapshot,
    scan_params: dict | None = None,
    accepted_risks: dict | None = None,
    include_shadow: bool = False,
) -> ScanResult:
    """Execute all registered rules, then generate fix-packs for T1/T2 findings
    that have a registered generator. Deterministic ordering by rule ID.

    accepted_risks: fingerprint -> register entry (already expiry-filtered).
    Accepted findings get the accepted_risk priority adjustment, are labelled
    (never hidden) and have fix-pack generation suppressed."""
    scan_params = scan_params or {}
    accepted_risks = accepted_risks or {}
    result = ScanResult(
        snapshot=snapshot,
        rule_versions={rid: rule.VERSION for rid, rule in sorted(RULE_REGISTRY.items())},
    )

    for rule_id in sorted(RULE_REGISTRY):
        rule = RULE_REGISTRY[rule_id]
        try:
            findings = rule.detect(snapshot, scan_params)
        except MissingSnapshotData as exc:
            # Declared data gap: skip the rule and say so, never guess.
            result.skipped_rules.append(f"{rule_id}: missing snapshot data ({exc})")
            continue
        except KeyError as exc:
            # Legacy path for the hand-written seed library, which signals a data
            # gap with a plain KeyError. Declarative rules must raise
            # MissingSnapshotData explicitly, so a coding defect inside a
            # primitive fails loudly instead of masquerading as a permission gap.
            if isinstance(rule, DeclarativeRule):
                raise
            result.skipped_rules.append(f"{rule_id}: missing snapshot data ({exc})")
            continue
        for f in sorted(findings, key=lambda x: x.fingerprint):
            if f.confidence != "validated" and not include_shadow:
                result.shadow_findings.append(f)
                continue
            entry = accepted_risks.get(f.fingerprint)
            if entry and f.score:
                f.accepted = True
                f.accepted_reason = entry.get("reason", "")
                from .scoring import score as _score

                f.score = _score(
                    f.score.impact,
                    f.score.likelihood,
                    f.score.modifiers_applied,
                    f.score.effort,
                    f.score.effort_assumptions,
                    list(f.score.adjustments_applied) + ["accepted_risk"],
                )
            result.findings.append(f)

    seen_names: set[str] = set()
    for f in result.findings:
        gen = FIXPACK_GENERATORS.get(f.rule_id)
        if gen is None or f.tier.startswith("T3") or f.accepted:
            continue
        pack = gen(f, snapshot)
        if pack is not None and pack.is_complete():
            if pack.name in seen_names:  # uniqueness guard for per-area packs
                pack.name = f"{pack.name}-{len(seen_names)}"
            seen_names.add(pack.name)
            f.fixpack_ref = pack.name
            result.fixpacks.append(pack)

    return result
