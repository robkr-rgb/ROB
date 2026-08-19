"""Trend diff between two scans, keyed on finding fingerprints
(architecture/data-model.md trend semantics): new / resolved / persisting,
with severity and priority drift on persisting findings.
"""
from __future__ import annotations

import json
import pathlib


def load_findings(path: str) -> dict[str, dict]:
    data = json.loads(pathlib.Path(path).read_text())
    out = {}
    for f in data:
        fp = f"{f['rule_id']}:{f['affected_area']}"
        out[fp] = f
    return out


def diff_runs(db_path: str, old_run: int, new_run: int) -> str:
    """Diff two stored runs by id (scan history, D-007)."""
    from .store import connect, run_findings

    con = connect(db_path)
    old, new = run_findings(con, old_run), run_findings(con, new_run)
    return _render(old, new, f"run {old_run}", f"run {new_run}")


def diff_scans(old_path: str, new_path: str) -> str:
    old, new = load_findings(old_path), load_findings(new_path)
    return _render(old, new, old_path, new_path)


def _render(old: dict[str, dict], new: dict[str, dict], old_label: str, new_label: str) -> str:
    new_fps = sorted(set(new) - set(old))
    resolved_fps = sorted(set(old) - set(new))
    persisting_fps = sorted(set(old) & set(new))

    lines = [
        "# ROB Scan Diff",
        "",
        f"Baseline: {old_label} ({len(old)} findings) -> Current: {new_label} ({len(new)} findings)",
        "",
        f"## New ({len(new_fps)})",
        "",
    ]
    for fp in new_fps:
        f = new[fp]
        lines.append(f"- {fp} [{f['score']['final_severity']}/{f['score']['final_priority']}] {f['title']}")
    lines += ["", f"## Resolved ({len(resolved_fps)})", ""]
    for fp in resolved_fps:
        f = old[fp]
        lines.append(f"- {fp} (was {f['score']['final_severity']}/{f['score']['final_priority']}) {f['title']}")
    lines += ["", f"## Persisting ({len(persisting_fps)})", ""]
    for fp in persisting_fps:
        o, n = old[fp], new[fp]
        drift = ""
        if o["score"]["final_severity"] != n["score"]["final_severity"] or o["score"]["final_priority"] != n["score"]["final_priority"]:
            drift = f" | drift: {o['score']['final_severity']}/{o['score']['final_priority']} -> {n['score']['final_severity']}/{n['score']['final_priority']}"
        evid = ""
        if o.get("evidence_total") != n.get("evidence_total"):
            evid = f" | volume: {o.get('evidence_total')} -> {n.get('evidence_total')}"
        lines.append(f"- {fp} [{n['score']['final_severity']}/{n['score']['final_priority']}]{drift}{evid}")
    lines += [
        "",
        "## Reading This Diff",
        "",
        "Resolved means the condition no longer triggers on the current snapshot: verify a remediation caused it "
        "(check change references) rather than a data or permission gap. Volume changes on persisting findings "
        "show whether remediation is making progress even where the finding has not fully cleared.",
    ]
    return "\n".join(lines)
