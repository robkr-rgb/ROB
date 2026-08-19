"""Rule registry. Rules are registered by immutable rule ID.

Two sources, one registry:
  - hand-written Rule subclasses (the pilot-validated seed library)
  - declarative specs loaded from rob/rules/packs/*.json (D-014)

A rule's origin changes nothing downstream: the engine, scoring, reports, CSV,
dashboard, diff and store all see the same Rule interface.
"""
from .td import RULES as TD_RULES
from .sec import RULES as SEC_RULES
from .upg import RULES as UPG_RULES
from .cmdb import RULES as CMDB_RULES
from .pack import library_manifest, load_rules

HANDWRITTEN_RULES = [*TD_RULES, *SEC_RULES, *UPG_RULES, *CMDB_RULES]
DECLARATIVE_RULES = load_rules()

SEED_RULE_COUNT = 15
assert len(HANDWRITTEN_RULES) == SEED_RULE_COUNT, (
    f"Expected {SEED_RULE_COUNT} hand-written seed rules, got {len(HANDWRITTEN_RULES)}"
)

_ALL_RULES = [*HANDWRITTEN_RULES, *DECLARATIVE_RULES]
RULE_REGISTRY = {rule.ID: rule for rule in _ALL_RULES}
if len(RULE_REGISTRY) != len(_ALL_RULES):
    _ids = [r.ID for r in _ALL_RULES]
    _dupes = sorted({i for i in _ids if _ids.count(i) > 1})
    raise ValueError(f"Duplicate rule IDs across the library: {_dupes}. Rule IDs are immutable and unique.")

# Replaces the seed library's hardcoded count assertion: a count cannot tell you
# whether the right rules loaded at the right versions and confidences.
LIBRARY_MANIFEST = library_manifest(RULE_REGISTRY)

ACTIVE_RULES = {rid: r for rid, r in RULE_REGISTRY.items() if r.CONFIDENCE == "validated"}
SHADOW_RULES = {rid: r for rid, r in RULE_REGISTRY.items() if r.CONFIDENCE != "validated"}
