# ROB - MVP Walking Skeleton

Executable skeleton of ROB - Remediation & Optimisation Bot. Implements the
engine layers specified in the project documentation: snapshot model, rule
engine (15 validated seed rules + declarative rule packs), scoring engine
(severity + priority matrices),
fix-pack generation (2 generators) and report generation.

## Run

```bash
python3 fixtures/build_fixture.py
python3 -m rob scan --snapshot fixtures/pdi_like_snapshot.json --out out/
python3 -m pytest tests/ -q
python3 -m rob rules
python3 -m rob serve
python3 -m rob scan --snapshot fixtures/pdi_like_snapshot.json --out out/ --include-shadow
```

## Layout

| Path | Layer |
|---|---|
| `rob/models.py` | Snapshot, Finding, FixPack, ScoreTrace |
| `rob/scoring.py` | Severity matrix + modifiers, priority matrix + adjustments (per scanner/rule-severity-model.md and rule-prioritisation.md) |
| `rob/engine.py` | Deterministic rule runner + fix-pack dispatch |
| `rob/doctor.py` | `rob doctor`: proves the installation is sound and says what optional pieces are missing |
| `rob/knowledge.py` | Reference indexes: ServiceNow docs (D-015 primary sources) and the Best Practices Library. Links only, never content |
| `rob/executor.py` | W-C executor (D-019): applies typed record operations through NowAIKit inside a named update set. Never runs a script, never touches ACLs or identity |
| `rob/mcp_server.py` | ROB as an MCP server: the five contracts for Claude Desktop (D-020) |
| `rob/ui.py` | Console design system: tokens, shell and components, ported from the ROB Instance Health design. No external requests |
| `rob/pages.py` | The five report sections (overview, findings, remediation, coverage, estate) plus Settings, rendered from stored runs |
| `rob/settings.py` | Every workspace setting, with a validator per group and the safety properties that are deliberately not settings |
| `rob/health.py` | Instance health score 0-100 and the arithmetic that produced it |
| `rob/schedule.py` | Scheduled scan, fingerprint-level diff, notification. No model on this path |
| `bin/rob`, `ROB.command` | Launcher that works from any directory, and a double-clickable starter |
| `rob/nowaikit.py` | NowAIKit MCP read path (D-018): read-tool allowlist, capped-read gap declaration, stdio and HTTP transports |
| `rob/agent.py` | Agent orchestrator (D-012): five enumerated tool contracts, HMAC approval tokens, autonomy ceiling, append-only audit log |
| `rob/rules/` | 15 validated seed rules: TD 3, SEC 3, UPG 3, CMDB 6 (per scanner/scan-rules.md) |
| `rob/rules/declarative.py` | Nine detection primitives; a rule as a spec record rather than a method (D-014) |
| `rob/rules/pack.py` | Rule pack loader: validates governance, enforces version bumps via `packs/pack.lock.json` |
| `rob/rules/packs/` | Declarative rule packs (JSON), 58 rules across 10 categories (73 rules, 12 categories with the seed library). Pack rules start in shadow until their false-positive rate is measured |
| `rob/fixpacks/` | Generators for ROB-SEC-003 (T1) and ROB-CMDB-004 dangling rels (T1); five-element contract enforced |
| `rob/report.py` | Executive summary (no sys_ids) + technical report (full traces) |
| `fixtures/` | Deterministic synthetic snapshot simulating a customised instance |
| `tests/` | Determinism (S5), score re-derivation, fix-pack contract, false-positive controls |

## Posture

Read-only: the engine only ever reads snapshots. Fix-packs are artefacts a
human applies (MVP policy, decision D-004). No extraction layer yet - that
follows the A2 security review (decision D-005). To scan a real PDI, the next
component is a Table/Aggregate API extractor that writes this snapshot format.

## Status

Skeleton, not product: thresholds are defaults, the SEC-003 baseline list is
a 6-property subset, and rule logic simplifies the specs where instance
release differences matter. Purpose: make assumption tests A3 (rule noise)
and A6 (fix-pack trust) executable against a real instance.
