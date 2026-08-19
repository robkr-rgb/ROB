"""Rule pack loader and validator.

A pack is a JSON file of rule specs. The loader is deliberately strict: it is
where RULE_AUTHORING.md's governance rules are enforced mechanically, because
at library scale they cannot be enforced by review alone.

Enforced here:
  - immutable rule IDs and ID format
  - VERSION bump required on any detection/severity/tier/autonomy change
    (logic hash recorded in pack.lock.json; a silent logic edit fails the load)
  - no rule without a written false-positive analysis
  - no rule without at least one triggering AND one non-triggering fixture case
  - no rule without a declared basis (D-015: primary source, never the catalogue)
  - A3 autonomy only on T1 tier and validated confidence (D-013)
  - detection primitive and condition operators must exist

Stdlib only, JSON not YAML: the skeleton's zero-dependency posture is a feature,
not an accident (see architecture/high-level-architecture.md).
"""
from __future__ import annotations

import hashlib
import json
import pathlib

from ..models import AUTONOMY_CLASSES, CONFIDENCES, EFFORTS, TIERS
from ..scoring import MODIFIER_DIRECTIONS, SEVERITY_MATRIX
from .declarative import CONDITION_OPS, DETECTORS, DeclarativeRule

PACK_DIR = pathlib.Path(__file__).parent / "packs"
LOCK_FILE = PACK_DIR / "pack.lock.json"

ID_PARTS = ("ROB", "")  # ROB-<CATEGORY>-<NNN>

REQUIRED = (
    "id", "version", "category", "title", "tier", "owner", "basis",
    "confidence", "autonomy", "detect", "severity", "why", "remediation",
    "false_positives", "fixture_cases",
)

# Logic-bearing keys: a change to any of these must be accompanied by a
# VERSION bump, because findings are stamped with the rule version and stale
# logic under an unchanged version is exactly the failure the pilot hit.
LOGIC_KEYS = ("detect", "severity", "tier", "autonomy")


class PackError(ValueError):
    """A rule pack failed validation. Never soft-fails: a bad pack is a build break."""


def _fail(rule_id: str, msg: str):
    raise PackError(f"{rule_id or '<no id>'}: {msg}")


def _valid_id(rid: str) -> bool:
    parts = rid.split("-")
    return (
        len(parts) == 3
        and parts[0] == "ROB"
        and parts[1].isalpha() and parts[1].isupper() and 2 <= len(parts[1]) <= 6
        and parts[2].isdigit() and len(parts[2]) == 3
    )


def logic_hash(spec: dict) -> str:
    payload = {k: spec.get(k) for k in LOGIC_KEYS}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


def _validate_conditions(rid: str, conditions, where_name: str):
    if conditions is None:
        return
    if not isinstance(conditions, list):
        _fail(rid, f"{where_name} must be a list of conditions")
    for c in conditions:
        if "field" not in c:
            _fail(rid, f"{where_name} condition missing 'field': {c}")
        ops = set(c) - {"field"}
        if len(ops) != 1 or not ops <= CONDITION_OPS:
            _fail(rid, f"{where_name} condition must use exactly one known operator {sorted(CONDITION_OPS)}: {c}")


def validate(spec: dict, seen: dict[str, str] | None = None) -> None:
    """Validate one spec. Raises PackError on the first problem found."""
    rid = spec.get("id", "")
    for key in REQUIRED:
        if key not in spec or spec[key] in (None, "", [], {}):
            _fail(rid, f"missing required field '{key}'")
    if not _valid_id(rid):
        _fail(rid, "rule ID must match ROB-<CATEGORY>-<NNN> (e.g. ROB-TD-004)")
    if seen is not None and rid in seen:
        _fail(rid, f"duplicate rule ID (already defined in {seen[rid]})")
    if spec["tier"] not in TIERS:
        _fail(rid, f"tier must be one of {TIERS}")
    if spec["confidence"] not in CONFIDENCES:
        _fail(rid, f"confidence must be one of {CONFIDENCES}")
    if spec["autonomy"] not in AUTONOMY_CLASSES:
        _fail(rid, f"autonomy must be one of {AUTONOMY_CLASSES} (A4 does not exist by design)")
    # D-013: A3 is a strict subset of T1, and never on unmeasured rules.
    if spec["autonomy"] == "A3":
        if spec["tier"] != "T1":
            _fail(rid, "autonomy A3 requires tier T1 (autonomy-model.md eligibility test)")
        if spec["confidence"] != "validated":
            _fail(rid, "autonomy A3 requires confidence 'validated'")
    if not isinstance(spec["basis"], list) or not all(isinstance(b, str) and b.strip() for b in spec["basis"]):
        _fail(rid, "basis must be a non-empty list of primary-source labels (D-015)")
    if not isinstance(spec["false_positives"], list) or not spec["false_positives"]:
        _fail(rid, "false-positive analysis is mandatory before a rule may load")

    sev = spec["severity"]
    if sev.get("impact") not in SEVERITY_MATRIX:
        _fail(rid, f"severity.impact must be one of {sorted(SEVERITY_MATRIX)}")
    if sev.get("likelihood") not in SEVERITY_MATRIX[sev["impact"]]:
        _fail(rid, "severity.likelihood invalid for the severity matrix")
    for m in sev.get("modifiers", []):
        if m not in MODIFIER_DIRECTIONS:
            _fail(rid, f"unknown severity modifier '{m}'")
    for cm in sev.get("conditional_modifiers", []):
        if cm.get("modifier") not in MODIFIER_DIRECTIONS:
            _fail(rid, f"unknown conditional modifier '{cm.get('modifier')}'")
        if "when_total_at_least" not in cm:
            _fail(rid, "conditional_modifiers entries need 'when_total_at_least'")
    if sev.get("effort", "Medium") not in EFFORTS:
        _fail(rid, f"severity.effort must be one of {EFFORTS}")
    for esc in sev.get("effort_escalation", []):
        if esc.get("effort") not in EFFORTS or "when_total_at_least" not in esc:
            _fail(rid, "effort_escalation entries need 'effort' and 'when_total_at_least'")

    det = spec["detect"]
    if det.get("type") not in DETECTORS:
        _fail(rid, f"unknown detection primitive '{det.get('type')}'. Known: {sorted(DETECTORS)}")
    if "affected_area" not in det:
        _fail(rid, "detect.affected_area is required (identity field: technical names, never display labels)")
    if not (det.get("tables") or det.get("table")):
        _fail(rid, "detect must name a table or tables")
    if det["type"] == "pattern_match":
        if det.get("match", "any") not in ("any", "none"):
            _fail(rid, "detect.match must be 'any' or 'none'")
        if det.get("match") == "none" and not any(
            c.get("field") == det.get("field", "script") and c.get("empty") is False for c in det.get("where", [])
        ):
            _fail(
                rid,
                "an absence check (match: none) must exclude empty fields with a "
                "{\"field\": \"<field>\", \"empty\": false} condition, or every empty record is flagged",
            )
    _validate_conditions(rid, det.get("where"), "detect.where")
    _validate_conditions(rid, det.get("join_where"), "detect.join_where")

    cases = spec["fixture_cases"]
    if not any(c.get("triggers") for c in cases):
        _fail(rid, "at least one fixture case must trigger the rule")
    if not any(not c.get("triggers") for c in cases):
        _fail(rid, "at least one fixture case must NOT trigger the rule (the false-positive control)")
    for c in cases:
        if "tables" not in c or "name" not in c:
            _fail(rid, "each fixture case needs 'name' and 'tables'")


def read_lock() -> dict:
    if not LOCK_FILE.exists():
        return {}
    return json.loads(LOCK_FILE.read_text())


def check_lock(specs: list[dict], lock: dict) -> list[str]:
    """Return violations where logic changed without a version bump."""
    problems = []
    for spec in specs:
        prior = lock.get(spec["id"])
        if not prior:
            continue
        if prior["logic_hash"] != logic_hash(spec) and prior["version"] == spec["version"]:
            problems.append(
                f"{spec['id']}: detection/severity logic changed but VERSION is still "
                f"{spec['version']}. Bump the version (RULE_AUTHORING.md governance)."
            )
    return problems


def write_lock(specs: list[dict]) -> None:
    lock = {s["id"]: {"version": s["version"], "logic_hash": logic_hash(s)} for s in sorted(specs, key=lambda x: x["id"])}
    LOCK_FILE.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")


def load_specs(pack_dir: pathlib.Path | None = None) -> list[dict]:
    """Read and validate every spec in the pack directory. Deterministic order."""
    pack_dir = pack_dir or PACK_DIR
    if not pack_dir.exists():
        return []
    specs: list[dict] = []
    seen: dict[str, str] = {}
    for path in sorted(pack_dir.glob("*.json")):
        if path.name == LOCK_FILE.name:
            continue
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise PackError(f"{path.name}: invalid JSON ({exc})") from exc
        entries = data.get("rules", data if isinstance(data, list) else [])
        if not entries:
            raise PackError(f"{path.name}: pack contains no rules")
        for spec in entries:
            validate(spec, seen)
            seen[spec["id"]] = path.name
            spec["_pack"] = path.name
            specs.append(spec)
    problems = check_lock(specs, read_lock())
    if problems:
        raise PackError("; ".join(problems))
    return sorted(specs, key=lambda s: s["id"])


def load_rules(pack_dir: pathlib.Path | None = None) -> list[DeclarativeRule]:
    return [DeclarativeRule(s) for s in load_specs(pack_dir)]


def library_manifest(registry: dict) -> str:
    """Stable hash over the whole loaded library.

    Replaces the seed library's hardcoded count assertion: a count says nothing
    about whether the right rules loaded at the right versions.
    """
    payload = sorted(f"{rid}@{r.VERSION}#{r.CONFIDENCE}" for rid, r in registry.items())
    return hashlib.sha256("|".join(payload).encode()).hexdigest()[:12]
