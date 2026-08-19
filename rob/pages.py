"""Console sections, rendered from stored runs.

One module per concern: `ui.py` owns how things look, this owns what is said.
The five report sections mirror the questions a platform team actually asks in
order — how bad is it, what exactly, what do I do, what did you not check, how
does this instance compare — and Settings makes the workspace configurable
without hand-editing JSON.

Nothing here talks to an instance. Every page reads the stored run, so opening
the console never triggers an extraction (D-012: scan is discovery, not a verb
the UI performs by accident).
"""
from __future__ import annotations

import html
import json

from . import ui
from .health import (
    domain_breakdown,
    health_score,
    priority_buckets,
    severity_breakdown,
    verdict,
)
from .settings import LOCKED_FACTS, merged
from .store import connect, list_runs, previous_run_id, run_findings

e = ui.e
q = ui.q

SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
EFFORT_HOURS = {"Low": "20 min - 2 h", "Medium": "3 - 8 h", "High": "1 - 3 d"}


# --------------------------------------------------------------------------- context

class View:
    """Everything a section needs, resolved once per request."""

    def __init__(self, state, run_id: int | None = None):
        self.state = state
        self.config = merged(state.config)
        self.ui_cfg = self.config["ui"]
        self.role = self.ui_cfg.get("role", "platform_admin")
        self.redact = bool(self.ui_cfg.get("redact_identifiers"))
        self.show_sla = bool(self.ui_cfg.get("show_sla_dates", True))
        self.con = connect(state.db_path)
        self.runs = list_runs(self.con)
        self.run = None
        if self.runs:
            self.run = next((r for r in self.runs if r["run_id"] == run_id), self.runs[-1])
        self.findings: list[dict] = []
        if self.run:
            stored = run_findings(self.con, self.run["run_id"])
            # Finding.fingerprint is a property, so asdict() drops it and the
            # stored record carries no fingerprint field. The store keys by it,
            # so put it back on the record: every link that identifies a finding
            # depends on it, and its absence fails silently as an empty href.
            for fp, rec in stored.items():
                rec.setdefault("fingerprint", fp)
            self.findings = sorted(
                stored.values(),
                key=lambda f: (SEV_RANK.get((f.get("score") or {}).get("final_severity"), 9),
                               f.get("rule_id", ""), f.get("affected_area", "")),
            )
        self.score = health_score(self.findings, domains_scanned=len(domain_breakdown(self.findings)))

    # -- derived --------------------------------------------------------------
    @property
    def instance_id(self) -> str:
        return self.run["instance_id"] if self.run else ""

    def instance_record(self) -> dict | None:
        for inst in self.config.get("instances", []):
            if inst.get("name") == self.instance_id or self.instance_id in (inst.get("url") or ""):
                return inst
        return None

    def sidebar_instance(self) -> dict | None:
        if not self.run:
            insts = self.config.get("instances", [])
            if not insts:
                return None
            i = insts[0]
            return {"label": i.get("name") or i.get("url", ""),
                    "environment": i.get("environment", "dev"),
                    "meta": "No scan yet"}
        rec = self.instance_record() or {}
        return {
            "label": self.instance_id,
            "environment": rec.get("environment", "dev"),
            "meta": f"Snapshot {self.run['taken_at'][:10]} · run {self.run['run_id']} · "
                    f"{len(self.rule_ids())} rules",
        }

    def rule_ids(self) -> list[str]:
        row = self.con.execute("SELECT rule_versions FROM scan_runs WHERE run_id=?",
                               (self.run["run_id"],)).fetchone() if self.run else None
        return sorted(json.loads(row[0])) if row else []

    def counts(self) -> dict:
        if not self.run:
            return {}
        fixable = sum(1 for f in self.findings if f.get("fixpack_ref"))
        return {
            "findings": len(self.findings),
            "remediation": fixable,
            "coverage": len(self.rule_ids()),
            "estate": len({r["instance_id"] for r in self.runs}),
        }

    def redacted(self, text: str) -> str:
        """Identifier redaction for executive-safe sharing (report-output-model)."""
        if not self.redact:
            return text
        import re
        return re.sub(r"[0-9a-f]{32}", "·" * 8, text or "")

    def trend_scores(self) -> list[int]:
        """Health score for each of the last five runs of this instance."""
        if not self.run:
            return []
        same = [r for r in self.runs if r["instance_id"] == self.instance_id
                and r["run_id"] <= self.run["run_id"]][-5:]
        out = []
        for r in same:
            fs = list(run_findings(self.con, r["run_id"]).values())
            out.append(health_score(fs)["score"])
        return out

    def previous_score(self) -> int | None:
        if not self.run:
            return None
        prev = previous_run_id(self.con, self.instance_id, self.run["run_id"])
        if prev is None:
            return None
        return health_score(list(run_findings(self.con, prev).values()))["score"]

    def footer(self) -> tuple[str, str]:
        if not self.run:
            return ("", "")
        fixpacks = sum(1 for f in self.findings if f.get("fixpack_ref"))
        left = ("Generated by ROB — Remediation &amp; Optimisation Bot. Every finding carries its "
                "detection logic, evidence sample and scoring basis."
                + (" Identifiers are redacted in this view." if self.redact else ""))
        right = (f"{e(self.instance_id)} · run {self.run['run_id']}<br>"
                 f"{e(self.run['taken_at'][:10])} · {len(self.findings)} findings · {fixpacks} fix-packs")
        return left, right


def render(v: View, *, active: str, crumb: str, heading: str, body: str, actions: str = "") -> str:
    fl, fr = v.footer()
    status = ""
    if v.run:
        gaps = v.con.execute("SELECT extraction_gaps FROM scan_runs WHERE run_id=?",
                             (v.run["run_id"],)).fetchone()
        n_gaps = len(json.loads(gaps[0])) if gaps else 0
        status = f"Scan complete · {len(v.rule_ids())} rules · {n_gaps} gaps"
    return ui.shell(
        title=heading, crumb=crumb, heading=heading, body=body, active=active,
        instance=v.sidebar_instance(), counts=v.counts(), role=v.role,
        actions=actions, status=status, footer_left=fl, footer_right=fr,
    )


TOP_ACTIONS = ('<a class="btn" href="/exports">Export</a>'
               '<form method="post" action="/scan" style="display:inline">'
               '<button class="btn dark" type="submit">Re-scan</button></form>')


def empty_state(v: View, active: str, heading: str) -> str:
    body = ('<div class="card"><h2>No scan runs yet</h2>'
            '<p class="note">ROB works from a stored run, so there is nothing to show until the '
            'first scan completes. Connect an instance in Settings, then run a scan. Nothing here '
            'reaches an instance on its own.</p>'
            '<div class="formfoot"><a class="btn dark" href="/settings">Open settings</a>'
            '<a class="btn" href="/settings#scan">Run a scan</a></div></div>')
    return render(v, active=active, crumb=heading.upper(), heading=heading, body=body)


# --------------------------------------------------------------------------- overview

def overview(v: View) -> str:
    if not v.run:
        return empty_state(v, "overview", "Instance health")

    s = v.score
    prev = v.previous_score()
    delta = "" if prev is None else f"{s['score'] - prev:+d} vs run {previous_run_id(v.con, v.instance_id, v.run['run_id'])}"
    counts = s["counts"]
    fixable = [f for f in v.findings if f.get("fixpack_ref")]
    unassigned = [f for f in v.findings if not f.get("owner")]
    p1 = priority_buckets(v.findings)["P1"]

    chips = []
    if counts.get("Critical"):
        chips.append(ui.pill(f"{counts['Critical']} critical", "Critical"))
    if fixable:
        chips.append(ui.pill(f"{len(fixable)} fix-pack{'s' if len(fixable) > 1 else ''} ready to apply"))
    if unassigned:
        chips.append(ui.pill(f"{len(unassigned)} findings unassigned", "Medium"))

    trend = v.trend_scores()
    hero = f"""
    <div class="card" style="padding:0">
      <div class="hero">
        <div style="padding:26px 30px;display:grid;place-items:center;gap:8px">
          {ui.donut(s['score'])}
          <div style="font-size:12.5px"><b>Grade {e(s['grade'])}</b>
            <span style="color:var(--muted)">&nbsp;{e(delta)}</span></div>
        </div>
        <div style="padding:26px 28px;border-left:1px solid var(--line);border-right:1px solid var(--line)">
          <div class="lbl">Verdict</div>
          <div class="verdict">{e(verdict(v.findings, s))}</div>
          <div style="display:flex;flex-wrap:wrap;gap:7px">{''.join(chips)}</div>
        </div>
        <div style="padding:26px 28px">
          <div class="lbl">Score trend</div>
          {ui.spark_bars(trend)}
          <div class="note" style="margin-top:10px">
            {e(_trend_note(trend, v.instance_id))}</div>
        </div>
      </div>
    </div>"""

    kpis = "".join([
        ui.kpi("Health score", s["score"], f"{s['grade']}"
               + (f" · {delta}" if delta else " · first run"), "#0B6E6E"),
        ui.kpi("Findings", len(v.findings),
               f"across {len(v.rule_ids())} rules, {len(s['domains'])} domains", "#0B6E6E"),
        ui.kpi("Urgent (P1)", len(p1),
               "immediate remediation" if p1 else "nothing urgent", "#C0362C" if p1 else "#A8B6BA"),
        ui.kpi("Fixes ready", f"{len(fixable)}/{len(v.findings)}",
               "ROB-generated, reversible", "#0B6247"),
        ui.kpi("Unassigned", len(unassigned),
               "no owner accepted yet" if unassigned else "all owned", "#C08A16" if unassigned else "#A8B6BA"),
    ])

    sev = severity_breakdown(v.findings)
    sev_max = max([n for _, n in sev] or [1]) or 1
    sev_rows = "".join(
        ui.bar_row(name, n, 100 * n / sev_max, ui.SEVERITY_BAR[name],
                   ui.SEVERITY_COLOURS[name][0] if n else "#A8B6BA")
        for name, n in sev)

    dom = domain_breakdown(v.findings)
    dom_max = max([n for _, n in dom] or [1]) or 1
    dom_rows = "".join(
        ui.bar_row(name, n, 100 * n / dom_max, ui.DOMAIN_BAR[i % len(ui.DOMAIN_BAR)])
        for i, (name, n) in enumerate(dom))

    breakdowns = f"""
    <div class="grid g2">
      <div class="card"><div class="cardhead"><div><div class="sec-h">By severity</div></div>
        <span class="sub">{len(v.findings)} findings</span></div>{sev_rows}</div>
      <div class="card"><div class="cardhead"><div><div class="sec-h">By domain</div></div>
        <span class="sub">{len(dom)} domains in scope</span></div>{dom_rows}
        <div class="note" style="margin-top:12px">{e(_domain_note(dom, counts))}</div></div>
    </div>"""

    queue = _queue(v)
    return render(v, active="overview", crumb="Overview", heading="Instance health",
                  actions=TOP_ACTIONS,
                  body=f'<div class="stack">{hero}<div class="grid g5">{kpis}</div>{breakdowns}{queue}</div>')


def _trend_note(trend: list[int], instance: str) -> str:
    if len(trend) < 2:
        return ("One snapshot so far. A second scan draws the trend, and the score is recomputed "
                "from each run's findings rather than carried forward.")
    return (f"{len(trend)} snapshots of {instance}. Scores are recomputed from each run's findings, "
            "so history rebases when the ruleset changes.")


def _domain_note(dom, counts) -> str:
    if not dom:
        return ""
    top = dom[0][0]
    if counts.get("Critical"):
        return f"{top} carries the most findings, and every critical in this run sits inside it."
    return f"{top} carries the most findings in this run."


def _queue(v: View) -> str:
    """Role-ordered work list. The lens changes the ordering, never the facts."""
    items = list(v.findings)
    if v.role == "platform_admin":
        items.sort(key=lambda f: (0 if f.get("fixpack_ref") else 1,
                                  SEV_RANK.get((f.get("score") or {}).get("final_severity"), 9)))
        note = "Platform admin lens · ordered by what unblocks most"
    elif v.role == "security":
        items.sort(key=lambda f: (0 if "Security" in (f.get("category") or "") else 1,
                                  SEV_RANK.get((f.get("score") or {}).get("final_severity"), 9)))
        note = "Security lens · exposure first"
    elif v.role == "executive":
        items.sort(key=lambda f: SEV_RANK.get((f.get("score") or {}).get("final_severity"), 9))
        note = "Executive lens · severity order, no record identifiers"
    else:
        items.sort(key=lambda f: (f.get("category") or "", f.get("rule_id") or ""))
        note = "Architect lens · grouped by domain"

    rows = ""
    for i, f in enumerate(items[:6], 1):
        sev = (f.get("score") or {}).get("final_severity", "")
        colour = ui.SEVERITY_BAR.get(sev, "#A8B6BA")
        badge = ui.pill("Fix ready") if f.get("fixpack_ref") else ui.pill(sev, sev)
        effort = EFFORT_HOURS.get((f.get("score") or {}).get("effort", ""), "")
        sub = f"{f.get('rule_id','')} · {f.get('affected_area','')}"
        if v.role == "executive":
            sub = f"{f.get('rule_id','')} · {f.get('category','')}"
        href = (f'/fix?f={q(f.get("fingerprint",""))}' if f.get("fixpack_ref")
                else f'/findings?f={q(f.get("fingerprint",""))}')
        rows += (f'<div class="queue" style="border-left-color:{colour}">'
                 f'<span class="i">{i:02d}</span><div class="t">'
                 f'<a href="{href}"><b>{e(f.get("title",""))}</b></a>'
                 f'<span class="meta">{e(v.redacted(sub))}</span></div>'
                 f'{badge}<span class="e">{e(effort)}</span></div>')
    if not rows:
        rows = '<div class="note">Nothing in this run needs attention.</div>'
    return (f'<div class="card"><div class="cardhead"><div class="sec-h">Your queue today</div>'
            f'<span class="sub">{e(note)}</span></div>{rows}'
            f'<div class="note" style="margin-top:12px">Ordering follows the reading-as lens in the '
            f'sidebar. Change it in Settings to make it the default.</div></div>')


# --------------------------------------------------------------------------- findings

def findings(v: View, selected: str = "") -> str:
    if not v.run:
        return empty_state(v, "findings", "Findings")

    chosen = next((f for f in v.findings if f.get("fingerprint") == selected), None) or (
        v.findings[0] if v.findings else None)

    rows = ""
    for f in v.findings:
        sev = (f.get("score") or {}).get("final_severity", "")
        fp = f.get("fingerprint", "")
        on = chosen is not None and fp == chosen.get("fingerprint")
        ready = (f'<a class="btn sm teal" href="/fix?f={q(fp)}">Fix</a>'
                 if f.get("fixpack_ref") else '<span class="sub">guidance</span>')
        rows += (
            f'<tr style="{"background:var(--surface-3)" if on else ""}">'
            f'<td style="border-left:3px solid {ui.SEVERITY_BAR.get(sev, "#A8B6BA")}">'
            f'<a href="/findings?f={q(fp)}"><b>{e(f.get("title",""))}</b></a><br>'
            f'<span class="meta">{e(f.get("rule_id",""))} · {e(v.redacted(f.get("affected_area","")))}</span></td>'
            f'<td>{ui.pill(sev, sev)}</td>'
            f'<td class="sub">{e((f.get("score") or {}).get("final_priority",""))}</td>'
            f'<td class="num">{e(f.get("evidence_total", 0))}</td>'
            f'<td>{ready}</td></tr>')

    table = (f'<div class="card flush"><table><thead><tr><th>Finding</th><th>Severity</th>'
             f'<th>Priority</th><th class="num">Evidence</th><th>Fix</th></tr></thead>'
             f'<tbody>{rows}</tbody></table></div>')

    return render(v, active="findings", crumb="Findings", heading="Findings",
                  actions=TOP_ACTIONS,
                  body=f'<div class="grid" style="grid-template-columns:1.35fr 1fr;'
                       f'align-items:start">{table}'
                       f'<div style="position:sticky;top:16px">{_detail(v, chosen)}</div></div>')


def _detail(v: View, f: dict | None) -> str:
    if not f:
        return '<div class="card"><div class="note">No findings in this run.</div></div>'
    trace = f.get("score") or {}
    sev = trace.get("final_severity", "")
    ev_rows = "".join(
        f'<div style="padding:8px 0;border-bottom:1px solid var(--line-2)">'
        f'<div class="mono" style="font-size:11.5px">{e(v.redacted(str(x.get("record_ref") or "")))}</div>'
        f'<div class="note">{e(v.redacted(str(x.get("summary") or "")))}</div></div>'
        for x in (f.get("evidence") or [])[:5])

    why_sev = "".join(
        f'<div class="kv"><span class="k">{e(k)}</span>'
        f'<span class="v" style="color:{colour}">{e(val)}</span></div>'
        for k, val, colour in [
            ("Impact", trace.get("impact", ""), "var(--ink)"),
            ("Likelihood", trace.get("likelihood", ""), "var(--ink)"),
            ("Matrix severity", trace.get("matrix_severity", ""), "var(--ink)"),
            ("Modifiers", ", ".join(trace.get("modifiers_applied") or []) or "none", "var(--ink-3)"),
            ("Effort", trace.get("effort", ""), "var(--ink)"),
            ("Final", f"{sev} · {trace.get('final_priority','')}",
             ui.SEVERITY_COLOURS.get(sev, ("var(--ink)", ""))[0]),
        ])

    sla = ""
    if v.show_sla:
        sla = ('<div class="kv"><span class="k">Target fix window</span>'
               f'<span class="v">{e(EFFORT_HOURS.get(trace.get("effort",""), "—"))}</span></div>')

    refs = "".join(f'<div class="note">· {e(r)}</div>' for r in (f.get("references") or [])[:4])
    fix = (f'<div class="lbl">Fix</div><div class="quote">{e(f["fixpack_ref"])}</div>'
           f'<div style="margin-top:10px"><a class="btn teal" href="/fix?f={q(f.get("fingerprint",""))}">'
           f'Open the fix</a></div>'
           f'<div class="hint">Shows what changes, what is captured before the first write, and which '
           f'gate is currently stopping it.</div>'
           if f.get("fixpack_ref") else
           '<div class="lbl">Fix</div><div class="note">No fix-pack generator for this rule yet, so the '
           'remediation above is the whole of it.</div>')

    return f"""<div class="card">
      <div class="lbl">{e(f.get('rule_id',''))} · {e(v.redacted(f.get('affected_area','')))}</div>
      <div class="grid g3" style="gap:0;margin:2px 0 14px">
        <div><div class="lbl">Evidence</div><div style="font-size:21px;font-weight:600">{e(f.get('evidence_total',0))}</div></div>
        <div><div class="lbl">Effort</div><div style="font-size:21px;font-weight:600">{e(trace.get('effort','—'))}</div></div>
        <div><div class="lbl">Impact</div><div style="font-size:21px;font-weight:600;color:{ui.SEVERITY_COLOURS.get(sev,('var(--ink)',''))[0]}">{e(sev)}</div></div>
      </div>
      {sla}
      <div class="lbl">Why this matters</div>
      <div style="font-size:12.5px;line-height:1.6">{e(f.get('why_it_matters',''))}</div>
      <div class="lbl">Recommended remediation</div>
      <div class="quote">{e(f.get('remediation',''))}</div>
      <div class="lbl">Why this severity <span style="float:right;text-transform:none;letter-spacing:0;font-weight:400">scoring is deterministic</span></div>
      {why_sev}
      <div class="lbl">Evidence sample <span style="float:right;text-transform:none;letter-spacing:0;font-weight:400">{min(5, len(f.get('evidence') or []))} of {e(f.get('evidence_total',0))}</span></div>
      {ev_rows or '<div class="note">No evidence lines recorded.</div>'}
      {f'<div class="lbl">Basis</div>{refs}' if refs else ''}
      {fix}
    </div>"""


# --------------------------------------------------------------------------- remediation

def remediation(v: View) -> str:
    if not v.run:
        return empty_state(v, "remediation", "Remediation")

    ready = [f for f in v.findings if f.get("fixpack_ref")]
    head = ""
    if ready:
        f = ready[0]
        head = f"""<div class="card">
          <div class="cardhead"><div class="sec-h">
            <span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--good-l);margin-right:7px"></span>
            Fix-pack ready to apply</div>
            <span class="sub">{len(ready)} of {len(v.findings)} findings is ROB-remediable today</span></div>
          <div class="grid" style="grid-template-columns:1fr auto;gap:24px;align-items:start">
            <div><div class="mono" style="font-size:13px;font-weight:600">{e(f['fixpack_ref'])}</div>
              <div class="note" style="margin:8px 0 12px">{e(f.get('remediation','')[:340])}</div>
              <div style="display:flex;gap:7px;flex-wrap:wrap">
                <span class="tag">Reversible</span><span class="tag">Dry-run included</span>
                <span class="tag">Backout captured before first write</span>
                <span class="tag">{e(EFFORT_HOURS.get((f.get('score') or {}).get('effort',''),''))}</span></div></div>
            <div style="display:flex;flex-direction:column;gap:8px;min-width:190px">
              <a class="btn teal" style="width:100%;text-align:center" href="/fix?f={q(f.get('fingerprint',''))}">Open the fix</a>
              <a class="btn" style="text-align:center" href="/runs/{v.run['run_id']}/dashboard">Open run dashboard</a>
              <div class="note">Generated {e(v.run['taken_at'][:10])} · run {v.run['run_id']}
                {'· global dry run is ON' if v.config.get('global_dry_run', True) else '· dry run is OFF'}</div>
            </div></div></div>"""
    else:
        head = ('<div class="card"><div class="sec-h">No fix-pack in this run</div>'
                '<div class="note" style="margin-top:6px">Every finding here is guidance or needs a '
                'generator. A rule under measurement never gets one: nothing unvalidated is applied '
                'to an instance.</div></div>')

    buckets = priority_buckets(v.findings)
    cols = ""
    for pkey, window, accent in (("P1", "within 5 days", "#C0362C"),
                                 ("P2", "within 30 days", "#8A3B0B"),
                                 ("P3", "within 90 days", "#C08A16")):
        items = buckets.get(pkey, [])
        rows = "".join(
            f'<div style="display:flex;justify-content:space-between;gap:12px;padding:7px 0;'
            f'border-bottom:1px solid var(--line-2);font-size:12.5px">'
            f'<span>{e(x.get("title",""))}</span>'
            f'<span class="sub" style="white-space:nowrap">{e(EFFORT_HOURS.get((x.get("score") or {}).get("effort",""),""))}</span></div>'
            for x in items[:7]) or '<div class="note">Nothing in this bucket.</div>'
        cols += (f'<div class="card" style="border-top:3px solid {accent}">'
                 f'<div class="cardhead"><div class="sec-h">{pkey} — {window}</div>'
                 f'<span class="sub">{len(items)} findings</span></div>{rows}</div>')

    owners: dict[str, dict] = {}
    for f in v.findings:
        o = f.get("owner") or "Unassigned"
        rec = owners.setdefault(o, {"assigned": 0, "unassigned": 0, "blocking": ""})
        if f.get("owner"):
            rec["assigned"] += 1
        else:
            rec["unassigned"] += 1
        if not rec["blocking"] and (f.get("score") or {}).get("final_priority") == "P1":
            rec["blocking"] = f.get("title", "")
    own_rows = "".join(
        f'<tr><td><b>{e(name)}</b></td><td class="num">{d["assigned"]}</td>'
        f'<td class="num" style="color:{"var(--crit)" if d["unassigned"] else "var(--muted)"}">{d["unassigned"]}</td>'
        f'<td class="sub">{e(d["blocking"] or "—")}</td></tr>'
        for name, d in sorted(owners.items(), key=lambda kv: -kv[1]["assigned"] - kv[1]["unassigned"]))

    ownership = (f'<div class="card flush"><div style="padding:16px 20px 0"><div class="cardhead">'
                 f'<div class="sec-h">Ownership</div><span class="sub">suggested owners, from the rule library</span>'
                 f'</div></div><table><thead><tr><th>Owner group</th><th class="num">Assigned</th>'
                 f'<th class="num">Unassigned</th><th>Blocking</th></tr></thead><tbody>{own_rows}</tbody></table></div>')

    return render(v, active="remediation", crumb="Remediation", heading="Remediation plan",
                  actions=TOP_ACTIONS,
                  body=f'<div class="stack">{head}<div class="grid g3">{cols}</div>{ownership}</div>')


# --------------------------------------------------------------------------- coverage

def coverage(v: View) -> str:
    if not v.run:
        return empty_state(v, "coverage", "Coverage")

    from .fixpacks import FIXPACK_GENERATORS
    from .rules import RULE_REGISTRY, SHADOW_RULES

    executed = v.rule_ids()
    by_rule: dict[str, list[dict]] = {}
    for f in v.findings:
        by_rule.setdefault(f.get("rule_id", ""), []).append(f)

    cats: dict[str, list[str]] = {}
    for rid in executed:
        rule = RULE_REGISTRY.get(rid)
        cats.setdefault(getattr(rule, "CATEGORY", "Uncategorised"), []).append(rid)

    sections = ""
    for cat in sorted(cats):
        rows = ""
        for rid in sorted(cats[cat]):
            rule = RULE_REGISTRY.get(rid)
            hits = by_rule.get(rid, [])
            objects = sum(x.get("evidence_total", 0) for x in hits)
            worst = min((SEV_RANK.get((h.get("score") or {}).get("final_severity"), 9) for h in hits),
                        default=9)
            worst_name = {0: "Critical", 1: "High", 2: "Medium", 3: "Low"}.get(worst, "")
            # Stated, not colour-coded: "clean" and "3 findings" are different
            # facts and a bar length cannot tell you which one you are looking at.
            if hits:
                result = (f'{ui.pill(str(len(hits)) + " finding" + ("s" if len(hits) != 1 else ""), worst_name)}')
            else:
                result = '<span class="sub">clean</span>'
            solve = ("fix-pack" if rid in FIXPACK_GENERATORS
                     else ("guidance" if str(getattr(rule, "TIER", "")).startswith("T3") else "manual"))
            rows += (
                f'<tr><td><a class="rid" href="/rule?id={q(rid)}">{e(rid)}</a></td>'
                f'<td><a href="/rule?id={q(rid)}">{e(getattr(rule, "TITLE", ""))}</a><br>'
                f'<span class="sub">{e(getattr(rule, "OWNER", ""))}</span></td>'
                f'<td class="num">{objects:,}</td>'
                f'<td>{result}</td>'
                f'<td class="sub">{e(getattr(rule, "TIER", ""))} · {e(solve)}</td>'
                f'<td class="sub">{e(getattr(rule, "CONFIDENCE", ""))}</td></tr>')
        sections += (
            f'<div class="card flush" style="margin-bottom:12px"><div style="padding:15px 20px 0">'
            f'<div class="cardhead"><div class="sec-h">{e(cat)}</div>'
            f'<span class="sub">{len(cats[cat])} rule(s)</span></div></div>'
            f'<table><thead><tr><th>Rule</th><th>What it checks</th><th class="num">Objects</th>'
            f'<th>Result</th><th>Tier &amp; solve</th><th>Confidence</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>')

    gaps_row = v.con.execute("SELECT skipped_rules, extraction_gaps FROM scan_runs WHERE run_id=?",
                             (v.run["run_id"],)).fetchone()
    skipped = json.loads(gaps_row[0]) if gaps_row else []
    gaps = json.loads(gaps_row[1]) if gaps_row else []

    not_looked = "".join(f'<span class="tag">{e(x)}</span>' for x in [
        "Instance health from logs", "Flow Designer structure", "Licence position",
        "Front-end library CVEs", "Data privacy",
    ])
    shadow_note = (f'<div class="note" style="margin-top:10px">{len(SHADOW_RULES)} rule(s) are under '
                   f'measurement and were withheld from this run. They are not gaps: they ran, and their '
                   f'findings are held back until a false-positive rate exists.</div>') if SHADOW_RULES else ""

    build = "".join(
        f'<div class="kv"><span class="k">{e(b["label"])}</span>'
        f'<span class="v">{("+" if b["value"] > 0 else "")}{b["value"]:g}</span></div>'
        for b in v.score["build"])
    build += (f'<div class="kv" style="border-top:1px solid var(--line);margin-top:4px;padding-top:10px">'
              f'<span class="k"><b>Instance health score</b></span>'
              f'<span class="v">{v.score["score"]} · {e(v.score["grade"])}</span></div>')

    body = f"""<div class="stack">
      <div class="card"><div class="cardhead"><div class="sec-h">What ran</div>
        <span class="sub">{len(executed)} executed · {len(skipped)} skipped · {len(gaps)} extraction gaps</span></div>
        <div class="note">Every rule below is a named check with a written specification. Open one to read
        what it looks for, how it decides, what it deliberately does not flag, and the source the practice
        comes from. Nothing here is a heuristic ROB cannot explain.</div></div>
      {sections}
      <div class="grid g2">
        <div class="card"><div class="sec-h">What this scan did not look at</div>
          <div class="note" style="margin:8px 0 12px">The rules above are the whole of what ran. These areas
          have no rule in the library yet, so a finding count is a statement about those rules and not about
          the instance as a whole.</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">{not_looked}</div>
          {shadow_note}
          {('<div class="note" style="margin-top:12px"><b>Extraction gaps:</b> ' + e('; '.join(gaps)) + '</div>') if gaps else ''}
        </div>
        <div class="card"><div class="sec-h">How the score is built</div>
          <div class="note" style="margin:8px 0 10px">Every line is reproducible from the findings above.
          No weighting is applied that is not shown here.</div>{build}</div>
      </div></div>"""
    return render(v, active="coverage", crumb="Coverage", heading="Coverage and scoring",
                  actions=TOP_ACTIONS, body=body)


# --------------------------------------------------------------------------- rule detail

def rule_page(v: View, rule_id: str) -> str:
    """One rule, explained from its own specification."""
    from .explain import explain
    from .fixpacks import FIXPACK_GENERATORS
    from .rules import RULE_REGISTRY
    from .rules.pack import load_specs

    rule = RULE_REGISTRY.get(rule_id)
    if rule is None:
        return render(v, active="coverage", crumb="Rule", heading="Unknown rule",
                      body='<div class="card"><div class="note">No rule with that ID is installed. '
                           '<a href="/coverage">Back to coverage</a>.</div></div>')
    spec = next((s for s in load_specs() if s["id"] == rule_id), None)
    x = explain(rule, spec)
    hits = [f for f in v.findings if f.get("rule_id") == rule_id]

    def block(label, items, empty=""):
        if not items:
            return f'<div class="lbl">{label}</div><div class="note">{empty}</div>' if empty else ""
        li = "".join(f'<div class="note" style="margin:5px 0">· {e(i)}</div>' for i in items)
        return f'<div class="lbl">{label}</div>{li}'

    def _fix_cell(f):
        fp = e(f.get("fingerprint", ""))
        if f.get("fixpack_ref"):
            return f'<a href="/fix?f={fp}">open fix</a>'
        return '<span class="sub">no fix-pack</span>'

    findings_rows = "".join(
        f'<tr><td><a href="/findings?f={q(f.get("fingerprint",""))}">'
        f'{e(v.redacted(f.get("affected_area","")))}</a></td>'
        f'<td>{ui.pill((f.get("score") or {}).get("final_severity",""), (f.get("score") or {}).get("final_severity",""))}</td>'
        f'<td class="num">{e(f.get("evidence_total",0))}</td>'
        f'<td>{_fix_cell(f)}</td></tr>'
        for f in hits)
    findings_card = (
        f'<div class="card flush"><div style="padding:15px 20px 0"><div class="cardhead">'
        f'<div class="sec-h">Findings in this run</div><span class="sub">run {v.run["run_id"] if v.run else "-"}</span>'
        f'</div></div><table><thead><tr><th>Affected area</th><th>Severity</th>'
        f'<th class="num">Evidence</th><th>Fix</th></tr></thead><tbody>{findings_rows}</tbody></table></div>'
        if hits else
        f'<div class="card"><div class="sec-h">Findings in this run</div>'
        f'<div class="note" style="margin-top:6px">{e(_no_hits_reason(rule))}</div></div>')

    solve = ("ROB generates an executable fix-pack for this rule."
             if rule_id in FIXPACK_GENERATORS else
             "No fix-pack generator exists for this rule yet, so findings come with written remediation "
             "rather than an artefact to apply.")

    # The `why` text is a finding template. On a rule page there is no count to
    # fill it with, so the placeholders are shown as N rather than leaked raw.
    why_text = x['why'] or getattr(rule, 'TITLE', '')
    if hits:
        why_text = why_text.replace("{count}", str(len(hits))).replace("{total}", str(len(hits)))
    for ph, sub in (("{count}", "N"), ("{total}", "N"), ("{area}", "the affected area"),
                    ("{threshold}", "the threshold"), ("{days}", "the window"),
                    ("{rate}", "the measured rate"), ("{group_total}", "the group"),
                    ("{hits}", "N")):
        why_text = why_text.replace(ph, sub)

    body = f"""<div class="grid" style="grid-template-columns:1.4fr 1fr;align-items:start">
      <div class="stack">
        <div class="card">
          <div class="lbl" style="margin-top:0">What it checks</div>
          <div style="font-size:13px;line-height:1.6">{e(why_text)}</div>
          {block("How ROB decides", x['detection'])}
          {block("What it deliberately does not flag", x['false_positives'],
                 "This rule is hand-written; its false-positive analysis is in scanner/scan-rules.md.")}
        </div>
        <div class="card">
          <div class="lbl" style="margin-top:0">Recommended remediation</div>
          <div class="quote">{e(x['remediation'] or 'See the finding detail for this rule.')}</div>
          {f'<div class="lbl">Beyond the fix</div><div class="note">{e(x["optimisation"])}</div>' if x['optimisation'] else ''}
          <div class="lbl">Can ROB apply it</div><div class="note">{e(solve)}</div>
        </div>
        {findings_card}
      </div>
      <div class="stack">
        <div class="card">
          <div class="lbl" style="margin-top:0">Classification</div>
          <div class="kv"><span class="k">Category</span><span class="v">{e(x['category'])}</span></div>
          <div class="kv"><span class="k">Version</span><span class="v">v{e(x['version'])}</span></div>
          <div class="kv"><span class="k">Suggested owner</span><span class="v">{e(x['owner'])}</span></div>
          <div class="kv"><span class="k">Detection</span><span class="v">{e(x['primitive'])}</span></div>
          <div class="lbl">Remediability {e(x['tier'])}</div>
          <div class="note">{e(x['tier_meaning'])}</div>
          <div class="lbl">Autonomy {e(x['autonomy'])}</div>
          <div class="note">{e(x['autonomy_meaning'])}</div>
          <div class="lbl">Confidence {e(x['confidence'])}</div>
          <div class="note">{e(x['confidence_meaning'])}</div>
        </div>
        <div class="card">
          {block("How severity is decided", x['severity'],
                 "Severity for this rule is computed in its Python implementation.")}
          {block("Data it reads", [", ".join(x['tables'])] if x['tables'] else [],
                 "See the rule source.")}
        </div>
        <div class="card">
          {block("Basis", x['basis'], "No basis recorded.")}
          <div class="note" style="margin-top:10px">Every rule states the source its practice claim comes
          from. ROB re-derives from primary sources rather than copying a third-party catalogue.</div>
        </div>
      </div>
    </div>
    <div style="margin-top:14px"><a class="btn" href="/coverage">Back to coverage</a></div>"""
    return render(v, active="coverage", crumb="Rule", heading=f"{rule_id} — {x['title']}", body=body)


# --------------------------------------------------------------------------- estate

def estate(v: View) -> str:
    if not v.run:
        return empty_state(v, "estate", "Estate")

    latest_per_instance: dict[str, dict] = {}
    for r in v.runs:
        latest_per_instance[r["instance_id"]] = r

    cards, rows = "", ""
    for name, r in sorted(latest_per_instance.items()):
        fs = list(run_findings(v.con, r["run_id"]).values())
        info = health_score(fs)
        rec = next((i for i in v.config.get("instances", []) if i.get("name") == name), {})
        env = (rec.get("environment") or ("dev" if name == v.instance_id else "dev")).lower()
        this = name == v.instance_id
        crit = info["counts"].get("Critical", 0)
        fixes = sum(1 for f in fs if f.get("fixpack_ref"))
        cards += f"""<div class="card {'dark-card' if this else ''}">
          <div class="cardhead"><div><div class="sec-h mono">{e(name)}</div>
            <span class="sub">Last scan {e(r['taken_at'][:10])} · run {r['run_id']}</span></div>
            <span class="env {e(env) if env in ('prod','test') else ''}">{e('THIS SCAN' if this else env.upper())}</span></div>
          <div style="display:flex;align-items:baseline;gap:10px;margin:4px 0 10px">
            <span class="score-n">{info['score']}</span>
            <span style="font-size:12.5px"><b>Grade {e(info['grade'])}</b></span></div>
          {ui.bar(info['score'], '#6FD3C6' if this else '#0B6E6E')}
          <div class="grid g3" style="margin-top:14px;gap:0">
            <div><div style="font-size:17px;font-weight:600">{len(fs)}</div><div class="sub">findings</div></div>
            <div><div style="font-size:17px;font-weight:600;color:{'#FF9A8F' if this and crit else ('var(--crit)' if crit else 'inherit')}">{crit}</div><div class="sub">critical</div></div>
            <div><div style="font-size:17px;font-weight:600">{fixes}</div><div class="sub">fix-packs</div></div>
          </div></div>"""

        dom = dict(domain_breakdown(fs))
        rows += (f'<tr><td class="mono">{e(name)}</td>'
                 + "".join(f'<td class="num">{dom.get(d, 0)}</td>' for d in _estate_domains(v))
                 + f'<td class="num"><b>{len(fs)}</b></td>'
                 f'<td class="num sub">{e(r["taken_at"][:10])}</td></tr>')

    heads = "".join(f'<th class="num">{e(d)}</th>' for d in _estate_domains(v))
    table = (f'<div class="card flush"><div style="padding:16px 20px 0"><div class="cardhead">'
             f'<div class="sec-h">Findings by domain across the estate</div>'
             f'<span class="sub">last completed scan per instance</span></div></div>'
             f'<table><thead><tr><th>Instance</th>{heads}<th class="num">Total</th>'
             f'<th class="num">Scanned</th></tr></thead><tbody>{rows}</tbody></table>'
             f'<div style="padding:12px 20px 16px" class="note">Only {e(v.instance_id)} was scanned in '
             f'run {v.run["run_id"]}. Other rows come from their own last completed runs and are shown '
             f'for comparison, not as part of this snapshot.</div></div>')

    return render(v, active="estate", crumb="Estate", heading="Estate comparison",
                  actions=TOP_ACTIONS,
                  body=f'<div class="stack"><div class="grid g3">{cards}</div>{table}</div>')


def _estate_domains(v: View) -> list[str]:
    seen: set[str] = set()
    for r in {r["instance_id"]: r for r in v.runs}.values():
        for f in run_findings(v.con, r["run_id"]).values():
            if f.get("category"):
                seen.add(f["category"])
    return sorted(seen)[:5]


def _no_hits_reason(rule) -> str:
    """No findings and withheld findings are different facts.

    A shadow rule may well have matched: its findings are held back until a
    false-positive rate exists. Reporting that as "found nothing" would be the
    console telling a comfortable lie about its own coverage.
    """
    if getattr(rule, "CONFIDENCE", "validated") != "validated":
        return ("This rule is under measurement, so any findings it produced were withheld from this "
                "run rather than reported. Turn on 'include shadow rules' in Settings to see them and "
                "measure its false-positive rate.")
    return ("This rule ran and found nothing. That is a result, not an absence: the check was executed "
            "against this instance.")


# --------------------------------------------------------------------------- fix

def fix_page(v: View, fingerprint: str, message: str = "", kind: str = "ok") -> str:
    """One finding, and everything that stands between it and being fixed.

    The approve button used to sit in a table row, which said nothing about what
    would happen when it was pressed. Applying a change to an instance deserves
    a page: what changes, what does not, what is captured before the first
    write, and which gate is currently stopping it.
    """
    if not v.run:
        return empty_state(v, "remediation", "Fix")
    f = next((x for x in v.findings if x.get("fingerprint") == fingerprint), None)
    if f is None:
        return render(v, active="remediation", crumb="Fix", heading="Finding not found",
                      body='<div class="card"><div class="note">That finding is not in this run. '
                           '<a href="/remediation">Back to remediation</a>.</div></div>')

    orch = v.state.orchestrator
    cfg = v.config
    ex_kind = (cfg.get("executor") or {}).get("kind", "none")
    ceiling = orch.autonomy_ceiling(v.instance_id)
    dry = bool(cfg.get("global_dry_run", True))
    inst = v.instance_record() or {}
    env = (inst.get("environment") or "dev").lower()

    pack = orch.fixpack(v.run["run_id"], fingerprint, actor="console-operator")
    pack_data = pack.data if pack.ok else {}

    # Every gate, in the order apply() checks them. Shown whether or not it passes,
    # because "why can't I apply this" is the question this page exists to answer.
    gates = [
        ("Environment is sub-production", env != "prod",
         "Marked prod. ROB never applies here; use the fix-pack through your own change process."
         if env == "prod" else f"This instance is marked {env}."),
        ("Rule is validated", f.get("confidence") == "validated",
         "This rule is still under measurement. Nothing unvalidated is applied to an instance."
         if f.get("confidence") != "validated" else "Measured, so its findings are reported and applyable."),
        ("Autonomy ceiling is A2 or higher", ceiling in ("A2", "A3"),
         f"Ceiling is {ceiling}. Raise it in Settings, which is a recorded decision."
         if ceiling not in ("A2", "A3") else f"Ceiling is {ceiling}."),
        ("An executor is configured", ex_kind == "nowaikit",
         "No executor. An approved fix is delivered as a fix-pack you apply by hand."
         if ex_kind != "nowaikit" else "W-C via NowAIKit."),
        ("Global dry run is off", not dry,
         "Dry run is ON, so approving runs the preview against the live instance and writes nothing."
         if dry else "Dry run is off: an approved fix will be written."),
        ("Fix-pack has machine-applicable operations", bool(pack_data.get("elements")) and f.get("fixpack_ref"),
         "This pack is human-apply only, which is the honest default: most fixes are scripts, and a script "
         "cannot be bounded or reversed per record."),
    ]
    gate_rows = "".join(
        f'<div class="kv"><span class="k">'
        f'<span style="display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:8px;'
        f'background:{"var(--good-l)" if ok else "var(--muted-2)"}"></span>{e(label)}</span>'
        f'<span class="v" style="font-weight:400;color:var(--muted);max-width:52%">{e(note)}</span></div>'
        for label, ok, note in gates)

    blocked = [(label, note) for label, ok, note in gates[:3] if not ok]
    if blocked:
        label, note = blocked[0]
        cta = (f'<div class="locked"><b>Refused: {e(label.lower())} is not satisfied.</b><br>{e(note)}'
               f'<br><br>Approving is refused while this holds, and the refusal is written to the audit '
               f'log like any other tool call.</div>')
    elif dry or ex_kind != "nowaikit":
        cta = ('<form method="post" action="/agent/approve">'
               f'<input type="hidden" name="run_id" value="{v.run["run_id"]}">'
               f'<input type="hidden" name="fingerprint" value="{e(fingerprint)}">'
               '<button class="btn teal" type="submit">Run the dry-run</button></form>'
               '<div class="hint">Reads the live instance and reports exactly what would change. '
               'Writes nothing.</div>')
    else:
        cta = ('<form method="post" action="/agent/approve">'
               f'<input type="hidden" name="run_id" value="{v.run["run_id"]}">'
               f'<input type="hidden" name="fingerprint" value="{e(fingerprint)}">'
               '<button class="btn teal" type="submit">Approve and apply</button></form>'
               '<div class="hint">Mints an approval token bound to this finding, this run and you, '
               'valid for a few minutes. Captures the before-state, writes inside a named update set, '
               'then reads back to verify.</div>')

    elements = "".join(
        f'<li><a href="/runs/{v.run["run_id"]}/fixpacks/{e(pack_data.get("name",""))}/{e(el)}">{e(el)}</a></li>'
        for el in pack_data.get("elements", []))
    pack_card = (
        f'<div class="card"><div class="cardhead"><div class="sec-h">Fix-pack</div>'
        f'<span class="mono sub">{e(pack_data.get("name",""))}</span></div>'
        f'<div class="note">Five elements, all mandatory: the fix, a dry-run that shows what will change, '
        f'ordered instructions, a backout artefact, and a scope statement saying what it does not touch.</div>'
        f'<ul style="margin:10px 0 0;padding-left:18px;font-size:12.5px">{elements}</ul></div>'
        if pack_data.get("elements") else
        '<div class="card"><div class="sec-h">No fix-pack</div><div class="note" style="margin-top:6px">'
        'No generator exists for this rule yet, so the remediation below is written guidance. '
        'That is deliberate: a rule gets a generator once its fix is provably reversible.</div></div>')

    flash = f'<div class="flash {e(kind)}">{e(message)}</div>' if message else ""
    trace = f.get("score") or {}
    body = f"""{flash}<div class="grid" style="grid-template-columns:1.35fr 1fr;align-items:start">
      <div class="stack">
        <div class="card">
          <div class="cardhead"><div><div class="sec-h">{e(f.get('title',''))}</div>
            <span class="meta">{e(f.get('rule_id',''))} · {e(v.redacted(f.get('affected_area','')))}</span></div>
            {ui.pill(trace.get('final_severity',''), trace.get('final_severity',''))}</div>
          <div class="lbl">Why this matters</div>
          <div style="font-size:12.5px;line-height:1.6">{e(f.get('why_it_matters',''))}</div>
          <div class="lbl">What to do</div>
          <div class="quote">{e(f.get('remediation',''))}</div>
          <div class="lbl">Affects</div>
          <div class="note">{e(f.get('evidence_total',0))} record(s). Suggested owner: {e(f.get('owner','') or 'unassigned')}.
          <a href="/rule?id={q(f.get('rule_id',''))}">Read how this rule decides</a>.</div>
        </div>
        {pack_card}
      </div>
      <div class="stack">
        <div class="card"><div class="sec-h">Before anything runs</div>
          <div class="note" style="margin:6px 0 10px">These are the gates <code>apply()</code> checks, in
          order. They are shown whether or not they pass.</div>
          {gate_rows}
          <div style="margin-top:16px">{cta}</div>
        </div>
        <div class="card"><div class="sec-h">If it goes wrong</div>
          <div class="note" style="margin-top:6px">The before-state is read from the live instance
          immediately before the first write, never taken from what the scan recorded, because the
          instance may have moved. Every write lands in a named update set that is exported on
          completion, so the change is a reviewable artefact in your own release process. A failure
          part-way rolls back what landed and reports anything it could not revert.</div></div>
      </div>
    </div>
    <div style="margin-top:14px"><a class="btn" href="/remediation">Back to remediation</a>
      <a class="btn" href="/findings?f={q(fingerprint)}">See the evidence</a></div>"""
    return render(v, active="remediation", crumb="Fix", heading="Apply a fix", body=body)


# --------------------------------------------------------------------------- settings

def settings(v: View, flash: str = "", flash_kind: str = "ok") -> str:
    c = v.config
    ex = c["executor"]
    email = c["email"]
    scanning = c["scanning"]
    uicfg = c["ui"]
    flash_html = f'<div class="flash {e(flash_kind)}">{e(flash)}</div>' if flash else ""

    # -- instances
    inst_rows = ""
    for i, inst in enumerate(c.get("instances", [])):
        env = (inst.get("environment") or "dev").lower()
        name = inst.get("name") or inst.get("url", "")
        ceiling = c.get("autonomy_ceilings", {}).get(name, "A1")
        opts = "".join(f'<option value="{x}"{" selected" if x == env else ""}>{x}</option>'
                       for x in ("dev", "test", "prod"))
        inst_rows += f"""<form method="post" action="/settings/instance" class="card" style="margin-bottom:10px">
          <input type="hidden" name="index" value="{i}">
          <div class="cardhead"><div><div class="sec-h mono">{e(inst.get('url',''))}</div>
            <span class="sub">autonomy ceiling {e(ceiling)} · credentials stored in this workspace</span></div>
            <span class="env {e(env) if env in ('prod','test') else ''}">{e(env.upper())}</span></div>
          <div class="grid g3">
            <div><label>Display name</label><input type="text" name="name" value="{e(inst.get('name',''))}"></div>
            <div><label>Service account user</label><input type="text" name="user" value="{e(inst.get('user',''))}"></div>
            <div><label>Environment</label><select name="environment">{opts}</select></div>
          </div>
          <label>New password <span class="sub">(leave blank to keep the stored one)</span></label>
          <input type="password" name="password" autocomplete="new-password">
          <label>Notes</label><input type="text" name="notes" value="{e(inst.get('notes',''))}">
          <div class="formfoot"><button class="btn dark" type="submit">Save</button>
            <label class="inline"><input type="checkbox" name="delete"> Remove this instance</label></div>
          {'<div class="hint" style="color:var(--crit)">Marked prod: ROB will never apply a fix here. Production changes go through your own change process using the fix-pack.</div>' if env == 'prod' else ''}
        </form>"""

    add_form = """<form method="post" action="/settings/instance/add" class="card">
      <div class="sec-h">Connect an instance</div>
      <div class="grid g2">
        <div><label>Instance URL</label><input type="url" name="url" placeholder="https://dev12345.service-now.com" required></div>
        <div><label>Display name</label><input type="text" name="name" placeholder="dev12345"></div>
        <div><label>Service account user</label><input type="text" name="user" required></div>
        <div><label>Password</label><input type="password" name="password" autocomplete="new-password"></div>
        <div><label>Environment</label><select name="environment">
          <option value="dev">dev</option><option value="test">test</option><option value="prod">prod</option>
        </select></div>
        <div><label>Notes</label><input type="text" name="notes" placeholder="PDI, read-only profile R-A"></div>
      </div>
      <div class="hint">Read-only extraction (profile R-A). Credentials live in this workspace's config
        file at mode 0600. The web product replaces this with a secret store; until then, this is a
        single-operator workspace and is documented as such.</div>
      <div class="formfoot"><button class="btn dark" type="submit">Connect</button></div>
    </form>"""

    # -- policy
    ceil_rows = ""
    for inst in c.get("instances", []) or [{"name": v.instance_id}]:
        name = inst.get("name") or inst.get("url", "") or v.instance_id
        if not name:
            continue
        current = c.get("autonomy_ceilings", {}).get(name, "A1")
        opts = "".join(
            f'<option value="{x}"{" selected" if x == current else ""}>{x} — {label}</option>'
            for x, label in (("A0", "observe only"), ("A1", "propose"),
                             ("A2", "approve each fix"), ("A3", "standing approval")))
        ceil_rows += (f'<div><label>{e(name)}</label>'
                      f'<select name="ceiling:{e(name)}">{opts}</select></div>')

    policy = f"""<form method="post" action="/settings/policy" class="card">
      <input type="hidden" name="form" value="policy">
      <div class="sec-h">Policy</div>
      <div class="note" style="margin:6px 0 4px">These are recorded decisions: changing them writes to
      the agent audit log, with the previous value.</div>
      <div class="grid g2">{ceil_rows or '<div class="note">Connect an instance to set a ceiling.</div>'}</div>
      <label class="inline"><input type="checkbox" name="global_dry_run"
        {'checked' if c.get('global_dry_run', True) else ''}> Global dry run — nothing executes, on any instance</label>
      <div class="hint">With dry run on, an approved fix still runs its preview against the live
      instance and reports what would change. That preview is worth having, which is why it is not
      simply refused.</div>
      <div class="formfoot"><button class="btn dark" type="submit">Save policy</button></div>
    </form>"""

    # -- executor
    kind_opts = "".join(f'<option value="{k}"{" selected" if k == ex.get("kind") else ""}>{label}</option>'
                        for k, label in (("none", "None — fix-packs are applied by hand"),
                                         ("nowaikit", "W-C — NowAIKit MCP (sub-production only)")))
    executor = f"""<form method="post" action="/settings/executor" class="card">
      <div class="sec-h">Executor</div>
      <div class="note" style="margin:6px 0 4px">How an approved fix reaches an instance. W-B, the
      in-instance scoped app, is the intended production mechanism and is not built (D-019).</div>
      <label>Mechanism</label><select name="kind">{kind_opts}</select>
      <div class="grid g2">
        <div><label>NowAIKit URL</label><input type="url" name="url" value="{e(ex.get('url',''))}"
          placeholder="https://127.0.0.1:8931/mcp"></div>
        <div><label>Or local command</label><input type="text" name="command" value="{e(ex.get('command',''))}"
          placeholder="npx -y nowaikit-mcp"></div>
        <div><label>Token <span class="sub">(blank keeps the stored one)</span></label>
          <input type="password" name="token" autocomplete="new-password"></div>
        <div><label>Update set prefix</label><input type="text" name="update_set_prefix"
          value="{e(ex.get('update_set_prefix','ROB'))}"></div>
      </div>
      <div class="formfoot"><button class="btn dark" type="submit">Save executor</button></div>
    </form>"""

    locked = "".join(
        f'<div class="locked" style="margin-bottom:8px"><b>{e(title)}</b><br>{e(why)}</div>'
        for title, why in LOCKED_FACTS)
    locked_card = (f'<div class="card"><div class="sec-h">Not configurable, by design</div>'
                   f'<div class="note" style="margin:6px 0 12px">These are enforced in code, not by a '
                   f'setting. They are listed so you can see they exist and that no checkbox turns '
                   f'them off.</div>{locked}</div>')

    # -- scanning + presentation
    scan_card = f"""<form method="post" action="/settings/scanning" class="card">
      <div class="sec-h">Scan defaults</div>
      <label class="inline"><input type="checkbox" name="include_shadow"
        {'checked' if scanning.get('include_shadow') else ''}> Include shadow rules in scans</label>
      <div class="hint">Rules below <code>validated</code> confidence are withheld from reports. Turn
      this on to measure their false-positive rate against a real instance — never for a customer report.</div>
      <label class="inline"><input type="checkbox" name="upgrade_planned"
        {'checked' if scanning.get('upgrade_planned') else ''}> A family upgrade is planned within a quarter</label>
      <div class="hint">Applies the upgrade-window exposure adjustment when prioritising.</div>
      <div class="formfoot"><button class="btn dark" type="submit">Save defaults</button></div>
    </form>"""

    role_opts = "".join(
        f'<option value="{k}"{" selected" if k == uicfg.get("role") else ""}>{label}</option>'
        for k, label, _ in ui.ROLES)
    present_card = f"""<form method="post" action="/settings/ui" class="card">
      <div class="sec-h">Presentation</div>
      <label>Default reading-as lens</label><select name="role">{role_opts}</select>
      <div class="hint">Changes ordering and emphasis. It never changes a finding, a score or a count.</div>
      <label class="inline"><input type="checkbox" name="redact_identifiers"
        {'checked' if uicfg.get('redact_identifiers') else ''}> Redact record identifiers</label>
      <div class="hint">Replaces sys_ids in evidence and affected areas, so a screen can be shared
      outside the platform team. The executive layer contains no identifiers either way.</div>
      <label class="inline"><input type="checkbox" name="show_sla_dates"
        {'checked' if uicfg.get('show_sla_dates', True) else ''}> Show target fix windows</label>
      <div class="formfoot"><button class="btn dark" type="submit">Save presentation</button></div>
    </form>"""

    # -- notifications
    to = email.get("to")
    to_str = ", ".join(to) if isinstance(to, list) else (to or "")
    notif = f"""<form method="post" action="/settings/notifications" class="card">
      <div class="sec-h">Scheduled scan notifications</div>
      <div class="note" style="margin:6px 0 4px">Used by <code>rob scheduled-scan</code>. A scan with
      no channel configured still runs and still stores its run; it just tells nobody.</div>
      <label>Recipients</label><input type="text" name="to" value="{e(to_str)}"
        placeholder="platform.owner@example.com, cmdb.owner@example.com">
      <div class="grid g3">
        <div><label>From</label><input type="text" name="from" value="{e(email.get('from',''))}"></div>
        <div><label>SMTP host</label><input type="text" name="host" value="{e(email.get('host',''))}"></div>
        <div><label>Port</label><input type="number" name="port" value="{e(email.get('port',25))}"></div>
      </div>
      <div class="grid g2">
        <div><label>SMTP user</label><input type="text" name="user" value="{e(email.get('user',''))}"></div>
        <div><label>SMTP password <span class="sub">(blank keeps stored)</span></label>
          <input type="password" name="password" autocomplete="new-password"></div>
      </div>
      <label class="inline"><input type="checkbox" name="starttls"
        {'checked' if email.get('starttls') else ''}> Use STARTTLS</label>
      <label>Webhook URL</label><input type="url" name="webhook_url" value="{e((c.get('webhook') or {}).get('url',''))}">
      <label class="inline"><input type="checkbox" name="always"
        {'checked' if (c.get('notify') or {}).get('always') else ''}> Notify on every run, not only on change</label>
      <div class="formfoot"><button class="btn dark" type="submit">Save notifications</button></div>
    </form>"""

    # -- reference sources + workspace
    from .knowledge import KnowledgeBase
    kb = KnowledgeBase(v.state.home)
    sources = {ix.source for ix in kb.indexes}
    docs_ok = any("doc" in s.lower() or "servicenow" in s.lower() for s in sources)
    bpl_ok = any("bpl" in s.lower() or "practice" in s.lower() for s in sources)
    refs_card = f"""<div class="card"><div class="sec-h">Reference sources</div>
      <div class="note" style="margin:6px 0 12px">Findings cite official documentation when an index
      is present. With none, ROB works unchanged and simply says less.</div>
      <div class="kv"><span class="k">ServiceNow product documentation</span>
        <span class="v" style="color:{'var(--good)' if docs_ok else 'var(--muted)'}">{'indexed' if docs_ok else 'not built'}</span></div>
      <div class="kv"><span class="k">Best Practices Library</span>
        <span class="v" style="color:{'var(--good)' if bpl_ok else 'var(--muted)'}">{'indexed' if bpl_ok else 'not built'}</span></div>
      <div class="hint" style="margin-top:10px">Build or refresh them from the CLI:
        <code>rob knowledge index-docs</code> and <code>rob knowledge index-bpl</code>. Indexes store
        titles and links only; they never copy document content.</div></div>"""

    pw_card = """<form method="post" action="/settings/password" class="card">
      <div class="sec-h">Administrator password</div>
      <div class="grid g3">
        <div><label>Current</label><input type="password" name="current" required></div>
        <div><label>New</label><input type="password" name="new" required></div>
        <div><label>Confirm</label><input type="password" name="confirm" required></div>
      </div>
      <div class="hint">PBKDF2-SHA256, 200,000 iterations, stored in this workspace only. Changing it
      signs out every other session.</div>
      <div class="formfoot"><button class="btn dark" type="submit">Change password</button></div>
    </form>"""

    ws_card = f"""<div class="card"><div class="sec-h">Workspace</div>
      <div class="kv"><span class="k">Home</span><span class="v mono">{e(v.state.home)}</span></div>
      <div class="kv"><span class="k">Config</span><span class="v mono">web_config.json</span></div>
      <div class="kv"><span class="k">Scan history</span><span class="v mono">rob_history.db</span></div>
      <div class="kv"><span class="k">Stored runs</span><span class="v">{len(v.runs)}</span></div>
      <div class="hint" style="margin-top:10px">The console binds to 127.0.0.1 by default. It has one
      shared password and no TLS, which is fine on loopback and is not fine on a public interface.</div></div>"""

    body = f"""{flash_html}<div class="stack">
      <div class="lbl" style="margin-top:0">Instances</div>{inst_rows}{add_form}
      <div class="lbl">Execution</div>
      <div class="grid g2" style="align-items:start">{policy}{executor}</div>
      {locked_card}
      <div class="lbl">Scanning &amp; presentation</div>
      <div class="grid g2" style="align-items:start">{scan_card}{present_card}</div>
      <div class="lbl">Delivery</div>{notif}
      <div class="lbl">Workspace</div>
      <div class="grid g2" style="align-items:start">{refs_card}{ws_card}</div>
      {pw_card}
    </div>"""
    return render(v, active="settings", crumb="Settings", heading="Settings", body=body)
