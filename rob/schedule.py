"""Scheduled scanning and notification: the proactive half, with no model in it.

Detection, scoring and fix-pack generation are deterministic code. A nightly
scan that reports "2 new High, 1 resolved" needs no language model at all, so
this module has none. That decoupling is deliberate: the expensive, uncertain
part of the product (conversation) does not gate the part that delivers value
every night whether or not anyone is watching.

Run it from cron or a systemd timer:
    python3 -m rob scheduled-scan --home /opt/rob --instance dev12345
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import smtplib
import urllib.error
import urllib.request
from email.message import EmailMessage

from .dashboard import render_dashboard
from .engine import run_scan
from .models import Snapshot
from .report import backlog_csv, executive_summary, technical_report
from .risks import active_acceptances, load_register
from .store import connect, list_runs, run_findings, store_run, trend_meta

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")


class ScheduleError(RuntimeError):
    """A scheduled run could not complete. Always reported, never swallowed."""


# --------------------------------------------------------------------------- diffing


def diff_findings(previous: dict, current: dict) -> dict:
    """Fingerprint-level diff between two stored runs.

    Fingerprints, not counts: "17 findings again" tells an operator nothing,
    whereas "the ACL one is gone and two admin grants are new" is actionable.
    """
    prev_fps, cur_fps = set(previous), set(current)
    new = sorted(cur_fps - prev_fps)
    resolved = sorted(prev_fps - cur_fps)
    changed = sorted(
        fp for fp in (cur_fps & prev_fps)
        if (current[fp].get("evidence_total") != previous[fp].get("evidence_total")
            or (current[fp].get("score") or {}).get("final_severity")
            != (previous[fp].get("score") or {}).get("final_severity"))
    )
    return {"new": new, "resolved": resolved, "changed": changed}


def severity_counts(findings: dict) -> dict:
    out = {}
    for f in findings.values():
        sev = (f.get("score") or {}).get("final_severity", "Informational")
        out[sev] = out.get(sev, 0) + 1
    return {s: out.get(s, 0) for s in SEVERITY_ORDER if out.get(s)}


def is_noteworthy(delta: dict, current: dict, always: bool = False) -> bool:
    """Whether this run deserves a notification.

    An unchanged instance still gets a report when `always` is set, because
    silence is ambiguous: it reads the same as a broken scheduler.
    """
    if always:
        return True
    return bool(delta["new"] or delta["resolved"] or delta["changed"])


# --------------------------------------------------------------------------- rendering


def render_summary(instance_id: str, run_id: int, findings: dict, delta: dict | None,
                   gaps: list, skipped: list) -> str:
    """Plain text, readable in an email client and in a terminal.

    Written for the ServiceNow team who receive it: product owner, platform
    owner, developers, configuration and asset manager. No sys_ids, because
    this leaves ROB and lands in mailboxes.
    """
    counts = severity_counts(findings)
    lines = [
        f"ROB scan of {instance_id} - run {run_id}",
        "",
        "Findings by severity: " + (", ".join(f"{k} {v}" for k, v in counts.items()) or "none"),
    ]
    solvable = [f for f in findings.values() if f.get("fixpack_ref")]
    lines.append(f"Fix-packs ready to review: {len(solvable)} of {len(findings)} findings")

    if delta is None:
        lines += ["", "First run for this instance, so there is nothing to compare against yet."]
    elif not (delta["new"] or delta["resolved"] or delta["changed"]):
        lines += ["", "No change since the previous run."]
    else:
        lines.append("")
        if delta["new"]:
            lines.append(f"New ({len(delta['new'])}):")
            lines += [f"  + {_label(findings, fp)}" for fp in delta["new"][:10]]
            if len(delta["new"]) > 10:
                lines.append(f"  ... and {len(delta['new']) - 10} more")
        if delta["resolved"]:
            lines.append(f"Resolved ({len(delta['resolved'])}):")
            lines += [f"  - {fp}" for fp in delta["resolved"][:10]]
        if delta["changed"]:
            lines.append(f"Changed ({len(delta['changed'])}):")
            lines += [f"  ~ {_label(findings, fp)}" for fp in delta["changed"][:10]]

    top = sorted(
        (f for f in findings.values() if (f.get("score") or {}).get("final_priority") == "P1"),
        key=lambda f: f.get("title", ""),
    )
    if top:
        lines += ["", f"P1 items ({len(top)}):"]
        lines += [f"  {f.get('title')} - {f.get('affected_area')} (owner: {f.get('owner')})" for f in top[:10]]

    if gaps:
        lines += ["", "Extraction gaps declared (affected rules stayed silent):"]
        lines += [f"  {str(g).splitlines()[0]}" for g in gaps[:5]]
    if skipped:
        lines += ["", f"Rules skipped for missing data: {len(skipped)}"]

    lines += ["", "Full reports and fix-packs are in the ROB console.",
              "ROB proposes; it changes nothing without an approval."]
    return "\n".join(lines)


def _label(findings: dict, fp: str) -> str:
    f = findings.get(fp, {})
    sev = (f.get("score") or {}).get("final_severity", "?")
    return f"[{sev}] {f.get('title', fp)} - {f.get('affected_area', '')}"


# --------------------------------------------------------------------------- delivery


def notify(config: dict, subject: str, body: str) -> list[str]:
    """Send to whatever channels are configured. Returns what was delivered.

    Best-effort per channel: a broken webhook must not suppress the email.
    """
    delivered = []
    email = config.get("email") or {}
    if email.get("to"):
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = email.get("from", "rob@localhost")
            msg["To"] = ", ".join(email["to"]) if isinstance(email["to"], list) else email["to"]
            msg.set_content(body)
            host, port = email.get("host", "localhost"), int(email.get("port", 25))
            with smtplib.SMTP(host, port, timeout=30) as s:
                if email.get("starttls"):
                    s.starttls()
                if email.get("user"):
                    s.login(email["user"], email.get("password", ""))
                s.send_message(msg)
            delivered.append(f"email:{msg['To']}")
        except Exception as exc:
            delivered.append(f"email:FAILED {exc}")

    webhook = config.get("webhook") or {}
    if webhook.get("url"):
        try:
            payload = json.dumps({"text": f"*{subject}*\n```{body}```"}).encode()
            req = urllib.request.Request(
                webhook["url"], data=payload,
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=30):
                pass
            delivered.append("webhook")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            delivered.append(f"webhook:FAILED {exc}")

    return delivered


# --------------------------------------------------------------------------- the run


def run_scheduled_scan(home: str | pathlib.Path, snapshot: Snapshot, notify_config: dict | None = None,
                       always_notify: bool = False, progress=print) -> dict:
    """Scan, store, diff against the previous run, write outputs, notify.

    Returns a result dict so a caller (cron wrapper, test, future queue worker)
    can act on it without parsing text.
    """
    home = pathlib.Path(home)
    home.mkdir(parents=True, exist_ok=True)
    runs_dir = home / "webruns"
    runs_dir.mkdir(exist_ok=True)

    accepted = active_acceptances(load_register(home / "accepted_risks.json"),
                                  dt.datetime.now(dt.timezone.utc))
    result = run_scan(snapshot, {}, accepted)
    con = connect(home / "rob_history.db")

    previous_runs = list_runs(con, snapshot.instance_id)
    previous = run_findings(con, previous_runs[-1]["run_id"]) if previous_runs else None

    run_id = store_run(con, result)
    current = run_findings(con, run_id)
    delta = diff_findings(previous, current) if previous is not None else None

    out = runs_dir / f"run_{run_id}"
    out.mkdir(exist_ok=True)
    meta = {
        "instance_id": snapshot.instance_id,
        "taken_at": snapshot.taken_at,
        "rule_count": len(result.rule_versions),
        "fixpacks": [{"name": p.name, "rule_id": p.rule_id, "finding_fingerprint": p.finding_fingerprint}
                     for p in result.fixpacks],
        "skipped_rules": result.skipped_rules,
        "extraction_gaps": snapshot.agg("extraction_errors", []),
        "trend": trend_meta(con, snapshot.instance_id, run_id),
    }
    # Kept so an approved fix-pack can be regenerated for execution later.
    (out / "snapshot.json").write_text(json.dumps({
        "instance_id": snapshot.instance_id, "taken_at": snapshot.taken_at,
        "tables": snapshot.tables, "aggregates": snapshot.aggregates}))
    (out / "dashboard.html").write_text(render_dashboard([f.to_dict() for f in result.findings], meta))
    (out / "executive_summary.md").write_text(executive_summary(result))
    (out / "technical_report.md").write_text(technical_report(result))
    (out / "backlog.csv").write_text(backlog_csv(result))
    packs_dir = out / "fixpacks"
    packs_dir.mkdir(exist_ok=True)
    for p in result.fixpacks:
        d = packs_dir / p.name
        d.mkdir(exist_ok=True)
        (d / p.fix_artefact_filename).write_text(p.fix_artefact)
        (d / p.backout_filename).write_text(p.backout)
        (d / "dry_run.txt").write_text(p.dry_run)
        (d / "instructions.md").write_text(p.instructions)
        (d / "scope.md").write_text(p.scope_statement)

    summary = render_summary(snapshot.instance_id, run_id, current, delta,
                             snapshot.agg("extraction_errors", []), result.skipped_rules)
    progress(summary)

    delivered = []
    if notify_config and is_noteworthy(delta or {"new": [], "resolved": [], "changed": []},
                                       current, always=always_notify or delta is None):
        counts = severity_counts(current)
        headline = ", ".join(f"{v} {k}" for k, v in counts.items()) or "no findings"
        subject = f"ROB: {snapshot.instance_id} run {run_id} - {headline}"
        if delta and delta["new"]:
            subject = f"ROB: {snapshot.instance_id} - {len(delta['new'])} new finding(s)"
        delivered = notify(notify_config, subject, summary)
        progress(f"Notified: {delivered}")

    return {
        "run_id": run_id,
        "instance_id": snapshot.instance_id,
        "counts": severity_counts(current),
        "delta": delta,
        "summary": summary,
        "notified": delivered,
        "out_dir": str(out),
        "shadow_withheld": len(result.shadow_findings),
    }
