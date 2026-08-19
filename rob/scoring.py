"""ROB scoring engine.

Implements scanner/rule-severity-model.md and scanner/rule-prioritisation.md
exactly: Impact x Likelihood matrix, bounded modifiers, severity x effort
priority matrix, exposure adjustments. Every input is recorded on the
ScoreTrace so scores are re-derivable from evidence.
"""
from __future__ import annotations

from .models import SEVERITIES, ScoreTrace

# Severity matrix: impact -> likelihood -> severity
SEVERITY_MATRIX = {
    "Severe": {"Certain": "Critical", "Likely": "Critical", "Possible": "High", "Unlikely": "Medium"},
    "Major": {"Certain": "High", "Likely": "High", "Possible": "Medium", "Unlikely": "Low"},
    "Moderate": {"Certain": "Medium", "Likely": "Medium", "Possible": "Low", "Unlikely": "Low"},
    "Minor": {"Certain": "Low", "Likely": "Low", "Possible": "Informational", "Unlikely": "Informational"},
}

# Modifier direction: +1 step up, -1 step down. Max one step each, bounded.
MODIFIER_DIRECTIONS = {"blast_radius": +1, "containment": -1, "aggregation": +1}

# Priority matrix: severity -> effort -> priority
PRIORITY_MATRIX = {
    "Critical": {"Low": "P1", "Medium": "P1", "High": "P1"},
    "High": {"Low": "P1", "Medium": "P2", "High": "P2"},
    "Medium": {"Low": "P2", "Medium": "P3", "High": "P3"},
    "Low": {"Low": "P3", "Medium": "P4", "High": "P4"},
    "Informational": {"Low": "P4", "Medium": "P4", "High": "P4"},
}

# Exposure adjustments: name -> (direction, cap). Applied after matrix, one step.
ADJUSTMENT_RULES = {
    "upgrade_window_proximity": (+1, "P1"),
    "quick_win_promotion": (+1, "P2"),
    "accepted_risk": (-1, None),
}

_PRIORITY_ORDER = ["P4", "P3", "P2", "P1"]  # ascending urgency


def _shift_severity(severity: str, steps: int) -> str:
    idx = SEVERITIES.index(severity) + steps
    idx = max(0, min(len(SEVERITIES) - 1, idx))
    return SEVERITIES[idx]


def _shift_priority(priority: str, steps: int, cap: str | None) -> str:
    idx = _PRIORITY_ORDER.index(priority) + steps
    idx = max(0, min(len(_PRIORITY_ORDER) - 1, idx))
    result = _PRIORITY_ORDER[idx]
    if cap is not None and _PRIORITY_ORDER.index(result) > _PRIORITY_ORDER.index(cap):
        result = cap
    return result


def score(
    impact: str,
    likelihood: str,
    modifiers: list[str] | None = None,
    effort: str = "Medium",
    effort_assumptions: str = "",
    adjustments: list[str] | None = None,
) -> ScoreTrace:
    """Compute severity and priority with a full reproducibility trace."""
    modifiers = modifiers or []
    adjustments = adjustments or []

    matrix_severity = SEVERITY_MATRIX[impact][likelihood]
    final_severity = matrix_severity
    for m in modifiers:
        if m not in MODIFIER_DIRECTIONS:
            raise ValueError(f"Unknown severity modifier: {m}")
        final_severity = _shift_severity(final_severity, MODIFIER_DIRECTIONS[m])

    # Rule: Critical requires the Severe impact row (severity-model rule 1).
    if final_severity == "Critical" and impact != "Severe":
        final_severity = "High"

    base_priority = PRIORITY_MATRIX[final_severity][effort]
    final_priority = base_priority
    for a in adjustments:
        if a not in ADJUSTMENT_RULES:
            raise ValueError(f"Unknown priority adjustment: {a}")
        direction, cap = ADJUSTMENT_RULES[a]
        final_priority = _shift_priority(final_priority, direction, cap)

    return ScoreTrace(
        impact=impact,
        likelihood=likelihood,
        matrix_severity=matrix_severity,
        modifiers_applied=list(modifiers),
        final_severity=final_severity,
        effort=effort,
        effort_assumptions=effort_assumptions,
        base_priority=base_priority,
        adjustments_applied=list(adjustments),
        final_priority=final_priority,
    )
