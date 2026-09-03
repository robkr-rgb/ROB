# ROB - Rule Authoring Guide

## What the rules are based on

ROB's rules codify widely documented ServiceNow platform practice: the Instance
Security Hardening Settings, business rule / client scripting guidance,
upgrade mechanics (skipped records, baseline divergence), CMDB Health KPI
concepts and the CSDM white paper. Each rule declares its basis in a
`REFERENCES` attribute — run `python3 -m rob rules` to see the full library
with sources. The severity matrix, priority model and remediability tiers are
ROB's own design (see the project's scanner/ documents).

They are NOT: an official ServiceNow ruleset, scraped internet content, or
unreviewable AI output. Every rule has a written specification a human can
audit.

## How validity is assured (three mechanisms)

1. **Reviewable specification** - each rule documents objective, data sources,
   detection logic, severity logic and known false-positive cases in
   `scanner/scan-rules.md` before it is code.
2. **Empirical measurement** - rules are validated against real instances with
   per-finding verdicts (correct / false positive). The pilot took the library
   from 39% to 0% false positives in two tuning rounds; the false-positive
   feedback channel in every report keeps this loop running permanently.
3. **Scoring transparency** - every finding carries its full derivation and is
   re-derivable (regression-tested), so any severity or priority can be
   challenged with evidence.

Before scanning a company instance, cross-check `SEC-003`'s property baseline
against the Instance Security Hardening Settings for your release: the
skeleton ships a 6-property subset.

## Two ways to author a rule

| Path | Use when | Governance |
|---|---|---|
| **Rule pack** (`rob/rules/packs/*.json`) - the default | The detection fits one of the nine primitives | Enforced mechanically by the loader |
| **Python class** - the exception | Detection needs logic no primitive expresses | Enforced by review plus a hand-written test |

The pack path exists because the triaged catalogue puts a realistic library at
roughly 150 rules, and most reduce to a handful of shapes. Writing 150 classes
to express nine shapes is the wrong trade. The pack path is not a lighter
governance path: it is a stricter one, because the loader refuses specs that a
reviewer might wave through.

### Detection primitives

| Primitive | Detects |
|---|---|
| `value_match` | A key/value record deviates from a declared expected value |
| `presence` | Records exist that should not |
| `count_threshold` | Cardinality of a filtered set above or below a threshold |
| `field_empty_rate` | Share of records with an empty field, per group, above a threshold |
| `staleness` | A precomputed age field beyond a window |
| `pattern_match` | Regex match over a script-bearing field. `match: "none"` inverts it to flag a **missing** required construct (no function wrapper, no isLoading guard); an absence check must exclude empty fields or the validator rejects it |
| `duplicate_key` | Records sharing a declared identity key |
| `dangling_reference` | Reference field pointing at a record that does not exist |
| `cross_table_join` | Records in A with no matching record in B |

### What the loader enforces (and will not let you skip)

- Rule ID format `ROB-<CATEGORY>-<NNN>`, unique across the whole library
- A `basis` list naming a **primary source**. Never a competitor's documentation (D-015)
- A non-empty `false_positives` analysis
- At least one fixture case that triggers **and** at least one that must not
- `autonomy: A3` only on `tier: T1` with `confidence: validated` (D-013)
- A `VERSION` bump whenever detection, severity, tier or autonomy changes.
  The logic hash lives in `packs/pack.lock.json`; a silent logic edit fails the
  load. After a deliberate, version-bumped change run `python3 -m rob rules --relock`
- Every table a rule reads must be populated by the extractor, so a rule cannot
  ship and then silently never fire

### Declared remediation: the fix ships inside the rule (D-028)

A pack rule may carry a `remediation_pack` block. The engine compiles it into
a full five-element fix-pack with typed executor operations at scan time, so
**a new rule with a block is executable on day one, with no Python written**.
A rule without a block still gets its finding and its written remediation
text; the block is what upgrades advice into a gated, reversible action.

| Kind | Fix shape | Pairs with detection |
|---|---|---|
| `update_fields` | Set declared field values on every matched record | `presence` |
| `transform_field` | Compute the new value from the current one via a named transform (e.g. `http_to_https`) | `presence` |
| `set_expected_properties` | The detection's own `expect` map IS the fix | `value_match` |

Worked example - the shipped ROB-INT-001 block:

```json
"remediation_pack": {
  "kind": "transform_field",
  "field": "rest_endpoint",
  "transform": "http_to_https",
  "scope_statement": "Rewrites the rest_endpoint scheme from http to https ...",
  "instructions_extra": "Re-test each integration end to end ..."
}
```

A value the snapshot cannot supply is a **declared question, never a guess**:

```json
"set": {"run_as": {"$input": "service_account_sys_id"}},
"inputs": {"service_account_sys_id": "sys_id of the service account that ..."}
```

The executor refuses to run a plan with unbound inputs; the approver supplies
values at approval time (`bind_inputs`). A rule with inputs can never be A3,
because standing approval cannot answer a question.

What the loader enforces on a block (in addition to everything below):

- `kind` known, `scope_statement` present (the fix-pack contract's "what this
  does NOT touch" is mandatory, not boilerplate)
- The target table is not on the executor's forbidden list - a block that
  touches ACLs, roles, users or credentials fails the **load**, not the apply
- Every `$input` is declared with a prompt; `A3` + inputs is refused
- **Proof at load time**: the block must produce at least one complete,
  executable operation on the rule's own triggering fixture. A fix that
  compiles to nothing on the case the rule was proven against is a promise
  the product cannot keep, and it fails the build instead of a customer
- `remediation_pack` is logic: changing it without a `VERSION` bump fails the
  load, because a changed fix under an unchanged version would detach a
  standing approval from what the rule now does

Operations cover the **full offender set** re-selected from the snapshot, not
the capped evidence sample, and records already at the target value are
skipped (idempotence). Fixes that need per-record judgement (logic rewrites,
CMDB merges, recipient decisions) do not belong in a block - write the
remediation text for a human, or a hand-written generator if it is partially
mechanical.

### Confidence: the staged activation ladder

| Confidence | Behaviour |
|---|---|
| `unvalidated` | Loads, runs, findings withheld. Not yet reviewed against a real instance |
| `provisional` | Loads, runs, findings withheld. Under false-positive measurement |
| `validated` | Findings reported normally |

Shadow findings never reach a customer report, never generate fix-packs and
never count toward severity totals. Measure them with `rob scan --include-shadow`,
record the false-positive rate, then promote. Imported rules always start below
`validated`: the pilot's 39% to 0% improvement came from measurement, not
confidence.

### Autonomy class

Declared per rule (`A0` observe, `A1` propose, `A2` approve per fix, `A3`
standing approval under a signed baseline). `A4` does not exist. Assigning `A3`
requires the seven-point eligibility test in `recommendations/autonomy-model.md`
and is a recorded decision, not a code change made in passing.

## Adding your own rule (worked example, Python path)

Goal: flag active scheduled jobs owned by departed (inactive) users.

### Step 1 - Write the specification first

Use the rule template (project instructions): Rule ID `ROB-GOV-001`, category
Governance, objective, data sources (`sysauto_script`, `sys_user`), detection
logic, severity logic, recommendation logic, false-positive considerations
(e.g. jobs deliberately owned by service accounts), example finding. No spec,
no rule - this is what makes the library auditable.

### Step 2 - Extend the extraction manifest (if needed)

If the rule needs a table ROB does not extract yet, add it to
`rob/extractor.py` (field-limited, PII-minimised) and to the permission
document so access stays declared.

### Step 3 - Implement the rule class

```python
# rob/rules/gov.py
from ..models import Evidence, Snapshot
from .base import Rule, s

class GOV001JobsOwnedByInactiveUsers(Rule):
    ID = "ROB-GOV-001"
    VERSION = "0.1"
    CATEGORY = "Governance"
    TITLE = "Scheduled jobs owned by inactive users"
    TIER = "T2"
    OWNER = "Platform team"
    REFERENCES = ("Your organisation's leaver process standard",)

    def detect(self, snap: Snapshot, params: dict) -> list:
        inactive = {u["sys_id"] for u in snap.t("sys_user") if not u.get("active")}
        offenders = [j for j in snap.t("sysauto_script")
                     if j.get("active") and j.get("run_as") in inactive]
        if not offenders:
            return []
        evidence = [Evidence(summary=f"Job '{j['name']}' runs as an inactive user",
                             record_ref=f"sysauto_script/{j['sys_id']}")
                    for j in offenders]
        return [self.finding(
            affected_area="sysauto_script",
            evidence=evidence, evidence_total=len(offenders),
            why="Jobs running as departed users fail silently on the next credential or ACL change.",
            remediation="Reassign each job to an owned service account; verify next execution.",
            optimisation="Add job ownership transfer to the leaver checklist.",
            trace=s("Moderate", "Likely", effort="Low",
                    assumptions="Standard change; per-job reassignment"),
        )]

RULES = [GOV001JobsOwnedByInactiveUsers()]
```

### Step 4 - Register it

Add to `rob/rules/__init__.py` (and bump the expected count in the assertion
and tests). New categories also need an entry in the project's
`scanner/scan-categories.md` per the expansion rules there.

### Step 5 - Prove it

Add a fixture case that triggers the rule and (important) one that must NOT
trigger it - the false-positive control from your spec, as a test. Run
`python3 -m pytest tests/ -q`.

The engine, scoring, reports, CSV, dashboard and diff all pick the rule up
automatically - a rule is one spec plus one `detect()` method, nothing else.

## Governance rules (non-negotiable)

- Every rule declares a **primary source** basis. A competitor's rule catalogue
  is a coverage map and a backlog input, never a basis (D-015).
- Rule IDs are immutable; retired rules keep their ID.
- Any change to detection/severity/remediability logic bumps `VERSION`
  (versions are stamped on findings - this caught a stale-code run in the pilot).
- No rule activates without its false-positive analysis written and tested.
- Thresholds belong in class constants (data), not buried in logic.
- Identity fields (affected_area) use technical names, never display labels.
