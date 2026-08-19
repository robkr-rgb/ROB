"""Scan history store (decision D-007: embedded relational now, Postgres later).

SQLite via stdlib: zero dependencies, single file, correct relational shape for
the two queries that matter - fingerprint joins across runs (trend) and run
listings per instance (tenancy-neutral: instance_id everywhere). The schema
deliberately mirrors architecture/data-model.md so a Postgres migration is a
dialect change, not a redesign.
"""
from __future__ import annotations

import json
import pathlib
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
  run_id INTEGER PRIMARY KEY AUTOINCREMENT,
  instance_id TEXT NOT NULL,
  taken_at TEXT NOT NULL,
  rule_versions TEXT NOT NULL,
  findings_count INTEGER NOT NULL,
  fixpack_names TEXT NOT NULL,
  skipped_rules TEXT NOT NULL,
  extraction_gaps TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  run_id INTEGER NOT NULL REFERENCES scan_runs(run_id),
  fingerprint TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  priority TEXT NOT NULL,
  tier TEXT NOT NULL,
  evidence_total INTEGER NOT NULL,
  accepted INTEGER NOT NULL,
  data TEXT NOT NULL,
  PRIMARY KEY (run_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
"""


def connect(path: str | pathlib.Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(path))
    con.executescript(SCHEMA)
    return con


def store_run(con: sqlite3.Connection, result) -> int:
    """Persist a ScanResult; returns the run_id."""
    cur = con.execute(
        "INSERT INTO scan_runs (instance_id, taken_at, rule_versions, findings_count, fixpack_names, skipped_rules, extraction_gaps)"
        " VALUES (?,?,?,?,?,?,?)",
        (
            result.snapshot.instance_id,
            result.snapshot.taken_at,
            json.dumps(result.rule_versions),
            len(result.findings),
            json.dumps([p.name for p in result.fixpacks]),
            json.dumps(result.skipped_rules),
            json.dumps(result.snapshot.agg("extraction_errors", [])),
        ),
    )
    run_id = cur.lastrowid
    con.executemany(
        "INSERT INTO findings (run_id, fingerprint, rule_id, severity, priority, tier, evidence_total, accepted, data)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        [
            (
                run_id,
                f.fingerprint,
                f.rule_id,
                f.score.final_severity,
                f.score.final_priority,
                f.tier,
                f.evidence_total,
                1 if f.accepted else 0,
                json.dumps(f.to_dict()),
            )
            for f in result.findings
        ],
    )
    con.commit()
    return run_id


def list_runs(con: sqlite3.Connection, instance_id: str | None = None) -> list[dict]:
    q = "SELECT run_id, instance_id, taken_at, findings_count, fixpack_names FROM scan_runs"
    params: tuple = ()
    if instance_id:
        q += " WHERE instance_id = ?"
        params = (instance_id,)
    q += " ORDER BY run_id"
    return [
        {"run_id": r[0], "instance_id": r[1], "taken_at": r[2], "findings": r[3], "fixpacks": len(json.loads(r[4]))}
        for r in con.execute(q, params)
    ]


def run_findings(con: sqlite3.Connection, run_id: int) -> dict[str, dict]:
    rows = con.execute("SELECT fingerprint, data FROM findings WHERE run_id = ?", (run_id,)).fetchall()
    return {fp: json.loads(data) for fp, data in rows}


def previous_run_id(con: sqlite3.Connection, instance_id: str, before_run_id: int) -> int | None:
    row = con.execute(
        "SELECT MAX(run_id) FROM scan_runs WHERE instance_id = ? AND run_id < ?",
        (instance_id, before_run_id),
    ).fetchone()
    return row[0] if row and row[0] is not None else None


def trend_meta(con: sqlite3.Connection, instance_id: str, run_id: int, max_history: int = 10) -> dict | None:
    """Trend payload for the dashboard: run history + changes vs previous run."""
    history = [r for r in list_runs(con, instance_id) if r["run_id"] <= run_id][-max_history:]
    prev = previous_run_id(con, instance_id, run_id)
    if prev is None:
        return {"history": history, "prev_run_id": None, "new": [], "resolved": [], "persisting_count": 0}
    old, new = run_findings(con, prev), run_findings(con, run_id)

    def brief(f):
        return {"fingerprint": f"{f['rule_id']}:{f['affected_area']}", "title": f["title"], "severity": f["score"]["final_severity"]}

    return {
        "history": history,
        "prev_run_id": prev,
        "new": [brief(new[fp]) for fp in sorted(set(new) - set(old))],
        "resolved": [brief(old[fp]) for fp in sorted(set(old) - set(new))],
        "persisting_count": len(set(old) & set(new)),
    }


def trend_summary(con: sqlite3.Connection, instance_id: str, run_id: int) -> str | None:
    """One-line trend vs the previous run of the same instance, or None if first run."""
    prev = previous_run_id(con, instance_id, run_id)
    if prev is None:
        return None
    old = set(run_findings(con, prev))
    new = set(run_findings(con, run_id))
    return (
        f"Trend vs run {prev}: +{len(new - old)} new, -{len(old - new)} resolved, "
        f"{len(old & new)} persisting. Full diff: rob diff --runs {prev} {run_id}"
    )
