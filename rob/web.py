"""ROB web application (decision D-009): browser front-end served by ROB itself.

Zero dependencies (stdlib http.server): `python3 -m rob serve` and open the
printed URL. Journeys covered: first-run setup, login, connect instance, run
scans with live progress, browse runs, open per-run dashboards, download
reports, audit the rule library.

Security posture (single-operator MVP):
- Binds 127.0.0.1 by default; exposing it wider is an explicit --host choice.
- First run forces an admin password (PBKDF2-hashed in the config file).
- Session cookie is an HMAC-signed random token, HttpOnly + SameSite=Strict.
- Instance credentials are stored in the local config file (0600). The web
  product replaces this with a proper secret store; stated in the UI.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import pathlib
import secrets
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import pages, ui
from .dashboard import render_dashboard
from .engine import run_scan
from .models import Snapshot
from .report import backlog_csv, executive_summary, technical_report
from .risks import active_acceptances, load_register
from .settings import (
    SettingsError,
    apply_executor,
    apply_instance_add,
    apply_instance_update,
    apply_notifications,
    apply_policy,
    apply_scanning,
    apply_ui,
)
from .store import connect, list_runs, run_findings, store_run, trend_meta, trend_summary

PBKDF_ITERS = 200_000


class AppState:
    def __init__(self, home: str | pathlib.Path):
        self.home = pathlib.Path(home)
        self.home.mkdir(parents=True, exist_ok=True)
        self.config_path = self.home / "web_config.json"
        self.db_path = self.home / "rob_history.db"
        self.risks_path = self.home / "accepted_risks.json"
        self.runs_dir = self.home / "webruns"
        self.runs_dir.mkdir(exist_ok=True)
        self.sessions: set[str] = set()
        self.job: dict = {"state": "idle", "log": [], "run_id": None, "error": None}
        self.job_lock = threading.Lock()
        self.config = json.loads(self.config_path.read_text()) if self.config_path.exists() else {}
        self._orchestrator = None

    @property
    def orchestrator(self):
        """The agent's policy gate. One per workspace; key persisted with the config."""
        from .agent import Orchestrator

        if self._orchestrator is None:
            key_hex = self.config.get("agent_signing_key")
            if not key_hex:
                key_hex = secrets.token_hex(32)
                self.config["agent_signing_key"] = key_hex
                self.save_config()
            (self.home / "baselines").mkdir(exist_ok=True)
            self._orchestrator = Orchestrator(self.home, bytes.fromhex(key_hex), self.config)
        self._orchestrator.config = self.config
        return self._orchestrator

    # -- config ---------------------------------------------------------------
    def save_config(self):
        self.config_path.write_text(json.dumps(self.config, indent=2))
        try:
            os.chmod(self.config_path, 0o600)
        except OSError:
            pass

    @property
    def is_set_up(self) -> bool:
        return bool(self.config.get("password_hash"))

    def set_password(self, password: str):
        salt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF_ITERS).hex()
        self.config.update({"salt": salt, "password_hash": h, "secret": secrets.token_hex(32)})
        self.config.setdefault("instances", [])
        self.save_config()

    def check_password(self, password: str) -> bool:
        if not self.is_set_up:
            return False
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(self.config["salt"]), PBKDF_ITERS).hex()
        return hmac.compare_digest(h, self.config["password_hash"])

    # -- sessions ---------------------------------------------------------------
    def new_session(self) -> str:
        raw = secrets.token_hex(16)
        sig = hmac.new(self.config["secret"].encode(), raw.encode(), hashlib.sha256).hexdigest()[:24]
        token = f"{raw}.{sig}"
        self.sessions.add(token)
        return token

    def valid_session(self, token: str | None) -> bool:
        if not token or token not in self.sessions or "." not in token:
            return False
        raw, sig = token.rsplit(".", 1)
        want = hmac.new(self.config["secret"].encode(), raw.encode(), hashlib.sha256).hexdigest()[:24]
        return hmac.compare_digest(sig, want)

    # -- scanning ----------------------------------------------------------------
    def start_scan(self, instance: dict | None, snapshot_path: str | None) -> bool:
        with self.job_lock:
            if self.job["state"] == "running":
                return False
            self.job = {"state": "running", "log": [], "run_id": None, "error": None}
        threading.Thread(target=self._scan_worker, args=(instance, snapshot_path), daemon=True).start()
        return True

    def _log(self, msg: str):
        self.job["log"].append(msg)

    def _scan_worker(self, instance: dict | None, snapshot_path: str | None):
        import datetime as dt

        try:
            if snapshot_path:
                self._log(f"Loading snapshot file: {snapshot_path}")
                data = json.loads(pathlib.Path(snapshot_path).read_text())
                snap = Snapshot(data["instance_id"], data["taken_at"], data.get("tables", {}), data.get("aggregates", {}))
            else:
                from .extractor import SNClient, build_snapshot

                self._log(f"Extracting from {instance['url']} (read-only)...")
                client = SNClient(instance["url"], instance["user"], instance["password"])
                instance_id = instance["url"].split("//")[-1].split(".")[0]
                raw = build_snapshot(client, instance_id, progress=self._log)
                snap = Snapshot(raw["instance_id"], raw["taken_at"], raw["tables"], raw["aggregates"])

            self._log("Running rule library...")
            accepted = active_acceptances(load_register(self.risks_path), dt.datetime.now(dt.timezone.utc))
            result = run_scan(snap, {}, accepted)

            con = connect(self.db_path)
            run_id = store_run(con, result)
            trend = trend_meta(con, snap.instance_id, run_id)
            out = self.runs_dir / f"run_{run_id}"
            out.mkdir(exist_ok=True)
            meta = {
                "instance_id": snap.instance_id,
                "taken_at": snap.taken_at,
                "rule_count": len(result.rule_versions),
                "fixpacks": [{"name": p.name, "rule_id": p.rule_id, "finding_fingerprint": p.finding_fingerprint} for p in result.fixpacks],
                "skipped_rules": result.skipped_rules,
                "extraction_gaps": snap.agg("extraction_errors", []),
                "trend": trend,
            }
            # Kept so an approved fix-pack can be regenerated for execution later.
            (out / "snapshot.json").write_text(json.dumps({
                "instance_id": snap.instance_id, "taken_at": snap.taken_at,
                "tables": snap.tables, "aggregates": snap.aggregates}))
            (out / "dashboard.html").write_text(render_dashboard([f.to_dict() for f in result.findings], meta))
            (out / "executive_summary.md").write_text(executive_summary(result))
            (out / "technical_report.md").write_text(technical_report(result))
            (out / "backlog.csv").write_text(backlog_csv(result))
            packs_dir = out / "fixpacks"
            packs_dir.mkdir(exist_ok=True)
            for p in result.fixpacks:
                pdir = packs_dir / p.name
                pdir.mkdir(exist_ok=True)
                (pdir / p.fix_artefact_filename).write_text(p.fix_artefact)
                (pdir / "dry_run.js").write_text(p.dry_run)
                (pdir / p.backout_filename).write_text(p.backout)
                (pdir / "INSTRUCTIONS.md").write_text(f"# {p.name}\n\n{p.instructions}\n\n## Scope\n\n{p.scope_statement}\n")
            t_line = trend_summary(con, snap.instance_id, run_id)
            self._log(f"Scan complete: {len(result.findings)} findings, {len(result.fixpacks)} fix-packs." + (f" {t_line}" if t_line else ""))
            self.job.update({"state": "done", "run_id": run_id})
        except Exception as exc:  # surfaced to the UI, never swallowed
            self._log(f"FAILED: {exc}")
            self.job.update({"state": "error", "error": str(exc)})


# ---------------------------------------------------------------------------- UI

STYLE = ui.STYLE


def page(title: str, body: str, nav: bool = True, state=None, active: str = "") -> str:
    """Legacy shell for the pages not yet ported to the section layout.

    Kept deliberately: the agent console, rule library and approval receipt are
    correct as they stand, and rewriting them alongside the new sections would
    have mixed a visual change with a behavioural one in the same commit.
    """
    if not nav:
        return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} - ROB</title><style>{ui.STYLE}</style></head>
<body><main class="wrap">{body}</main></body></html>"""
    try:
        view = pages.View(state) if state is not None else None
    except Exception:  # a broken workspace must still render a page
        view = None
    inst = view.sidebar_instance() if view else None
    counts = view.counts() if view else {}
    role = view.role if view else "platform_admin"
    heading = title
    return ui.shell(title=title, crumb=title, heading=heading, body=body,
                    active=active, instance=inst, counts=counts, role=role)


def login_page(error: str = "", setup: bool = False) -> str:
    err = f'<div class="flash err">{html.escape(error)}</div>' if error else ""
    if setup:
        head, sub, action, extra = (
            "Welcome to ROB",
            "First run: choose the administrator password for this workspace.",
            "/setup",
            '<label>Confirm password</label><input type="password" name="password2" required>',
        )
        cta = "Set password and continue"
    else:
        head, sub, action, extra = (
            "Sign in", "Instance health, remediation and optimisation.", "/login", "")
        cta = "Log in"
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ROB - Sign in</title><style>{ui.STYLE}</style></head>
<body><div class="login-wrap"><div class="login"><div class="card">
<div class="brand"><div class="mark">R</div><div><b>ROB</b><span>Instance health</span></div></div>
<h1>{head}</h1><div class="sub">{sub}</div>{err}
<form method="post" action="{action}">
<label>Password</label><input type="password" name="password" autofocus required>
{extra}
<div class="formfoot"><button class="btn dark" type="submit" style="width:100%">{cta}</button></div>
</form>
<div class="hint" style="margin-top:16px">Read-only scanning. ROB changes nothing on an instance
without a fix-pack you approved here.</div>
</div></div></div></body></html>"""


# --------------------------------------------------------------------------- app


def make_handler(state: AppState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ROB/0.1"

        # -- plumbing ---------------------------------------------------------
        def log_message(self, *args):  # quiet
            pass

        def _send(self, code: int, body: str, ctype="text/html; charset=utf-8", headers: dict | None = None):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _redirect(self, to: str, cookie: str | None = None):
            self.send_response(303)
            self.send_header("Location", to)
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _form(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode()
            return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

        def _token(self) -> str | None:
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                if part.strip().startswith("rob_session="):
                    return part.strip().split("=", 1)[1]
            return None

        def _authed(self) -> bool:
            return state.valid_session(self._token())

        # -- routing -----------------------------------------------------------
        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if not state.is_set_up:
                return self._send(200, login_page(setup=True))
            if path == "/login":
                return self._send(200, login_page())
            if path == "/logout":
                token = self._token()
                state.sessions.discard(token)
                return self._redirect("/login", cookie="rob_session=; Max-Age=0; Path=/")
            if not self._authed():
                return self._redirect("/login")
            if path == "/":
                return self._send(200, pages.overview(pages.View(state)))
            if path == "/findings":
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                return self._send(200, pages.findings(pages.View(state), (q.get("f") or [""])[0]))
            if path == "/remediation":
                return self._send(200, pages.remediation(pages.View(state)))
            if path == "/coverage":
                return self._send(200, pages.coverage(pages.View(state)))
            if path == "/estate":
                return self._send(200, pages.estate(pages.View(state)))
            if path == "/rule":
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                return self._send(200, pages.rule_page(pages.View(state), (q.get("id") or [""])[0]))
            if path == "/fix":
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                return self._send(200, pages.fix_page(
                    pages.View(state), (q.get("f") or [""])[0],
                    (q.get("m") or [""])[0], (q.get("k") or ["ok"])[0]))
            if path == "/settings":
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                return self._send(200, pages.settings(
                    pages.View(state), (q.get("m") or [""])[0], (q.get("k") or ["ok"])[0]))
            if path == "/role":
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                role = (q.get("to") or ["platform_admin"])[0]
                if role in dict((k, l) for k, l, _ in ui.ROLES):
                    state.config.setdefault("ui", {})["role"] = role
                    state.save_config()
                # Referer is attacker-influenceable, so it is matched against the
                # known section paths rather than followed. An unknown value goes home.
                back = urllib.parse.urlparse(self.headers.get("Referer") or "").path
                known = {href for href, _, _ in ui.SECTIONS}
                return self._redirect(back if back in known else "/")
            if path == "/exports":
                return self._send(200, self.exports())
            if path == "/rules":
                return self._send(200, self.rules_page())
            if path == "/agent":
                return self._send(200, self.agent_page())
            if path == "/agent/tools":
                from .agent import tool_schemas

                return self._send(200, json.dumps(tool_schemas(), indent=2), "application/json")
            if path == "/agent/audit":
                return self._send(200, json.dumps(state.orchestrator.audit_tail(200), indent=2), "application/json")
            if path == "/scan/status":
                return self._send(200, json.dumps({"state": state.job["state"], "log": state.job["log"], "run_id": state.job["run_id"]}), "application/json")
            if path == "/scan":
                return self._send(200, self.scan_page())
            if path.startswith("/runs/"):
                return self.run_asset(path)
            return self._send(404, page("Not found", "<h1>Not found</h1>"))

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path
            if path == "/setup" and not state.is_set_up:
                form = self._form()
                if form.get("password") and form["password"] == form.get("password2"):
                    state.set_password(form["password"])
                    token = state.new_session()
                    return self._redirect("/", cookie=f"rob_session={token}; HttpOnly; SameSite=Strict; Path=/")
                return self._send(200, login_page("Passwords did not match.", setup=True))
            if path == "/login":
                form = self._form()
                if state.check_password(form.get("password", "")):
                    token = state.new_session()
                    return self._redirect("/", cookie=f"rob_session={token}; HttpOnly; SameSite=Strict; Path=/")
                return self._send(200, login_page("Wrong password."))
            if not self._authed():
                return self._redirect("/login")
            if path == "/instances":
                # Legacy endpoint kept so an old bookmark or test still works.
                return self._settings_post(apply_instance_add, self._form())
            if path.startswith("/settings/"):
                form = self._form()
                action = path.split("/", 2)[2]
                if action == "instance/add":
                    return self._settings_post(apply_instance_add, form)
                if action == "instance":
                    return self._settings_post(apply_instance_update, form)
                if action == "policy":
                    return self._settings_post(apply_policy, form, audited="policy")
                if action == "executor":
                    return self._settings_post(apply_executor, form, audited="executor")
                if action == "scanning":
                    return self._settings_post(apply_scanning, form)
                if action == "notifications":
                    return self._settings_post(apply_notifications, form)
                if action == "ui":
                    return self._settings_post(apply_ui, form)
                if action == "password":
                    return self._change_password(form)
                return self._send(404, page("Not found", "<h1>Not found</h1>", state=state))
            if path == "/agent/approve":
                return self._send(200, self.agent_approve(self._form()))
            if path == "/agent/tool":
                return self._send(200, self.agent_tool(self._form()))
            if path == "/agent/policy":
                form = self._form()
                state.config["global_dry_run"] = form.get("dry_run") == "on"
                ceilings = state.config.setdefault("autonomy_ceilings", {})
                if form.get("instance_id"):
                    ceilings[form["instance_id"]] = form.get("ceiling", "A1")
                state.save_config()
                return self._redirect("/agent")
            if path == "/scan":
                form = self._form()
                snapshot_path = form.get("snapshot_path") or None
                instance = None
                if not snapshot_path:
                    idx = int(form.get("instance", "0"))
                    instances = state.config.get("instances", [])
                    if not instances:
                        return self._redirect("/")
                    instance = instances[min(idx, len(instances) - 1)]
                state.start_scan(instance, snapshot_path)
                return self._redirect("/scan")
            return self._send(404, page("Not found", "<h1>Not found</h1>"))

        # -- settings ------------------------------------------------------------
        def _settings_post(self, fn, form: dict, audited: str = ""):
            """Apply one settings group. Refuses loudly; never half-saves.

            The validator runs against a copy, so a rejected form leaves the
            stored config untouched rather than partially written.
            """
            import copy

            draft = copy.deepcopy(state.config)
            try:
                result = fn(draft, form)
            except SettingsError as exc:
                return self._redirect(
                    "/settings?k=err&m=" + urllib.parse.quote(str(exc)))
            decisions: list[str] = []
            if isinstance(result, tuple):
                message, decisions = result
            else:
                message = result
            state.config = draft
            state.save_config()
            state._orchestrator = None  # rebuilt with the new config on next use
            for decision in decisions:
                # A change to what may reach an instance is a recorded decision,
                # not a silent save (D-013).
                from .agent import ToolResult

                state.orchestrator._audit(
                    f"settings.{audited or 'change'}", "console-operator",
                    {"change": decision}, ToolResult(True, "settings", data={"summary": decision}), "")
            return self._redirect("/settings?k=ok&m=" + urllib.parse.quote(message))

        def _change_password(self, form: dict):
            if not state.check_password(form.get("current", "")):
                return self._redirect("/settings?k=err&m=" + urllib.parse.quote(
                    "Current password is wrong. Nothing was changed."))
            new = form.get("new", "")
            if len(new) < 8:
                return self._redirect("/settings?k=err&m=" + urllib.parse.quote(
                    "Choose a password of at least 8 characters."))
            if new != form.get("confirm", ""):
                return self._redirect("/settings?k=err&m=" + urllib.parse.quote(
                    "The two new passwords do not match."))
            state.set_password(new)
            state.sessions.clear()  # every other session is now invalid
            return self._redirect("/login")

        # -- pages ---------------------------------------------------------------
        def exports(self) -> str:
            """Every artefact this workspace can hand to someone else."""
            v = pages.View(state)
            if not v.run:
                return pages.empty_state(v, "overview", "Exports")
            rows = ""
            for r in reversed(v.runs):
                rows += (
                    f"<tr><td><b>#{r['run_id']}</b><br><span class='meta'>{html.escape(r['instance_id'])}</span></td>"
                    f"<td class='sub'>{html.escape(r['taken_at'][:16].replace('T', ' '))}</td>"
                    f"<td class='num'>{r['findings']}</td><td class='num'>{r['fixpacks']}</td>"
                    f"<td><a href='/runs/{r['run_id']}/dashboard'>dashboard</a> &middot; "
                    f"<a href='/runs/{r['run_id']}/executive_summary.md'>executive</a> &middot; "
                    f"<a href='/runs/{r['run_id']}/technical_report.md'>technical</a> &middot; "
                    f"<a href='/runs/{r['run_id']}/backlog.csv'>csv</a></td></tr>")
            body = f"""<div class="stack">
              <div class="card"><div class="sec-h">Two layers, deliberately separate</div>
              <div class="note" style="margin-top:6px">The executive summary carries no record
              identifiers and is safe to forward. The technical report carries evidence, traces and
              sys_ids and is for the platform team. That separation is the reporting model, not a
              formatting preference.</div></div>
              <div class="card flush"><table><thead><tr><th>Run</th><th>Snapshot</th>
              <th class="num">Findings</th><th class="num">Fix-packs</th><th>Artefacts</th></tr></thead>
              <tbody>{rows}</tbody></table></div></div>"""
            return pages.render(v, active="overview", crumb="Exports", heading="Exports", body=body)

        def scan_page(self) -> str:
            return page(
                "Scan",
                """
                <h1>Scan in progress</h1>
                <div class="card"><pre class="log" id="log">starting...</pre>
                <div id="done" style="display:none;margin-top:10px"></div></div>
                <script>
                async function poll() {
                  const r = await fetch('/scan/status'); const j = await r.json();
                  document.getElementById('log').textContent = j.log.join('\\n') || 'starting...';
                  if (j.state === 'done') {
                    document.getElementById('done').style.display = '';
                    document.getElementById('done').innerHTML =
                      `<a class="btn" href="/runs/${j.run_id}/dashboard">Open dashboard for run #${j.run_id}</a> <a class="btn ghost" href="/">Back to overview</a>`;
                  } else if (j.state === 'error') {
                    document.getElementById('done').style.display = '';
                    document.getElementById('done').innerHTML = '<a class="btn ghost" href="/">Back to overview</a>';
                  } else { setTimeout(poll, 1000); }
                }
                poll();
                </script>""",
            )

        def rules_page(self) -> str:
            from .fixpacks import FIXPACK_GENERATORS
            from .rules import RULE_REGISTRY

            rows = ""
            for rid in sorted(RULE_REGISTRY):
                r = RULE_REGISTRY[rid]
                solve = "fix-pack" if rid in FIXPACK_GENERATORS else ("guidance (T3)" if r.TIER.startswith("T3") else "-")
                refs = "<br>".join(html.escape(x) for x in r.REFERENCES)
                rows += (
                    f"<tr><td><strong>{rid}</strong><br><span class='muted'>v{r.VERSION} | {r.TIER}</span></td>"
                    f"<td>{html.escape(r.TITLE)}<br><span class='muted'>{html.escape(r.CATEGORY)} | owner: {html.escape(r.OWNER)}</span></td>"
                    f"<td>{solve}</td><td class='muted'>{refs}</td></tr>"
                )
            return page(
                "Rules",
                f"""<h1>Rule library</h1>
                <div class="muted">Every rule has a reviewable specification with false-positive analysis; scores are re-derivable from finding traces. See RULE_AUTHORING.md to add rules.</div>
                <div class="card" style="padding:0 6px"><table>
                <tr><th>Rule</th><th>Detects</th><th>Solve</th><th>Basis</th></tr>{rows}</table></div>""",
            )


        # -- agent console -------------------------------------------------------
        def agent_page(self) -> str:
            from .agent import CATEGORY_FILTERS, TOOL_NAMES
            from .rules import ACTIVE_RULES, SHADOW_RULES

            orch = state.orchestrator
            con = connect(state.db_path)
            runs = list_runs(con)
            latest = runs[-1] if runs else None

            if not latest:
                return page("Agent", """<h1>Agent console</h1>
                <div class="card muted">No scan runs yet. The agent works from a stored run, so start a scan
                on the Overview page first. Nothing here reaches an instance directly.</div>""")

            instance_id = latest["instance_id"]
            ceiling = orch.autonomy_ceiling(instance_id)
            dry = orch.global_dry_run
            res = orch.findings(latest["run_id"], solvable_only=True, actor="console")
            solvable = res.data.get("findings", []) if res.ok else []
            all_res = orch.findings(latest["run_id"], actor="console")
            all_findings = all_res.data.get("findings", []) if all_res.ok else []
            sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
            solvable.sort(key=lambda f: (sev_rank.get(f["severity"], 9), f["fingerprint"]))

            rows = ""
            for f in solvable:
                badge = f"<span class=\'pill sev-{html.escape(str(f['severity']).lower())}\'>{html.escape(str(f['severity']))}</span>"
                accepted = " &middot; <span class='muted'>accepted risk</span>" if f["accepted"] else ""
                rows += f"""<tr>
                  <td>{badge}<br><span class="muted">{html.escape(f['priority'] or '')}</span></td>
                  <td><strong>{html.escape(f['title'] or '')}</strong><br>
                      <span class="muted">{html.escape(f['rule_id'])} v{html.escape(f['rule_version'] or '')} &middot;
                      {html.escape(f['affected_area'] or '')} &middot; {f['evidence_total']} item(s){accepted}</span></td>
                  <td>{html.escape(f['tier'] or '')} / {html.escape(f['autonomy'])}</td>
                  <td>{html.escape(f['owner'] or '')}</td>
                  <td>
                    <form method="post" action="/agent/approve" style="margin:0">
                      <input type="hidden" name="run_id" value="{latest['run_id']}">
                      <input type="hidden" name="fingerprint" value="{html.escape(f['fingerprint'])}">
                      <button type="submit" class="ghost">Approve &amp; apply</button>
                    </form>
                  </td></tr>"""
            if not rows:
                rows = "<tr><td colspan='5' class='muted'>Nothing in this run has a generated fix-pack.</td></tr>"

            shadow_note = ""
            withheld = [f for f in all_findings if f["confidence"] != "validated"]
            if SHADOW_RULES:
                shadow_note = (f"<div class='muted' style='margin-top:8px'>{len(SHADOW_RULES)} rule(s) are under "
                               f"measurement and withheld from this view. {len(ACTIVE_RULES)} active.</div>")

            audit_rows = "".join(
                f"<tr><td class='muted'>{html.escape(e['at'][11:19])}</td><td><code>{html.escape(e['tool'])}</code></td>"
                f"<td>{html.escape(e['actor'])}</td>"
                f"<td>{'ok' if e['ok'] else 'refused'}</td>"
                f"<td class='muted'>{html.escape(str(e['outcome'])[:160])}</td></tr>"
                for e in orch.audit_tail(15)
            ) or "<tr><td colspan='5' class='muted'>No agent activity yet.</td></tr>"

            ex_cfg = (state.config.get("executor") or {})
            executor_state = (
                f"NowAIKit (W-C){' via ' + ex_cfg['url'] if ex_cfg.get('url') else ' via local process'}"
                if ex_cfg.get("kind") == "nowaikit" else "none configured - fix-packs are applied by hand"
            )
            ceil_opts = "".join(
                f"<option value='{c}'{' selected' if c == ceiling else ''}>{c}</option>"
                for c in ("A0", "A1", "A2", "A3")
            )
            tool_opts = "".join(f"<option value='{t}'>{t}</option>" for t in TOOL_NAMES)

            return page("Agent", f"""
            <h1>Agent console</h1>
            <div class="muted">This is where the agent lives. It reaches ROB through five enumerated tool
            contracts and nothing else: no free-text query, no table name, no script. Approval is minted here,
            by you, and is bound to one finding in one run for {int(__import__('rob.agent', fromlist=['x']).APPROVAL_TTL_SECONDS/60)} minutes.</div>

            <div class="cards" style="margin-top:16px">
              <div class="card kpi"><div class="k">Working from</div><div class="v">#{latest['run_id']}</div>
                   <div class="muted">{html.escape(instance_id)}</div></div>
              <div class="card kpi"><div class="k">Fixable now</div><div class="v">{len(solvable)}</div>
                   <div class="muted">of {len(all_findings)} findings</div></div>
              <div class="card kpi"><div class="k">Autonomy ceiling</div><div class="v">{html.escape(ceiling)}</div>
                   <div class="muted">{'A2+ permits apply' if ceiling in ('A2','A3') else 'propose only'}</div></div>
              <div class="card kpi"><div class="k">Dry run</div><div class="v">{'ON' if dry else 'off'}</div>
                   <div class="muted">{'nothing executes' if dry else 'execution permitted'}</div></div>
              <div class="card kpi"><div class="k">Executor</div><div class="v">{'W-C' if ex_cfg.get('kind') == 'nowaikit' else 'none'}</div>
                   <div class="muted">{'NowAIKit, sub-production' if ex_cfg.get('kind') == 'nowaikit' else 'fix-packs applied by hand'}</div></div>
            </div>

            <h2>What ROB can fix on {html.escape(instance_id)}</h2>
            <div class="card" style="padding:0 6px"><table>
              <tr><th>Severity</th><th>Finding</th><th>Tier / autonomy</th><th>Suggested owner</th><th>Action</th></tr>
              {rows}</table></div>
            {shadow_note}

            <div class="cards" style="grid-template-columns:1fr 1fr; align-items:start; margin-top:20px">
              <form method="post" action="/agent/tool" class="card">
                <h2 style="margin-top:0">Call a tool contract</h2>
                <div class="muted">Exactly what the agent sees. Use it to check a contract before wiring a model to it.</div>
                <label>Tool</label><select name="tool">{tool_opts}</select>
                <label>Arguments (JSON)</label>
                <input name="args" value='{{"run_id": {latest['run_id']}, "solvable_only": true}}'>
                <div style="margin-top:12px"><button type="submit" class="ghost">Call</button></div>
              </form>
              <form method="post" action="/agent/policy" class="card">
                <h2 style="margin-top:0">Policy</h2>
                <label>Instance</label><input name="instance_id" value="{html.escape(instance_id)}">
                <label>Autonomy ceiling</label><select name="ceiling">{ceil_opts}</select>
                <label style="margin-top:10px"><input type="checkbox" name="dry_run" {'checked' if dry else ''}> Global dry run</label>
                <div class="muted" style="margin-top:6px">Executor: <strong>{html.escape(executor_state)}</strong></div>
                <div class="muted" style="margin-top:8px">A3 standing approval additionally requires a signed
                baseline in this workspace. Raising a ceiling is a recorded decision. With no executor
                configured, an approved fix is delivered as a fix-pack for you to apply.</div>
                <div style="margin-top:12px"><button type="submit" class="ghost">Save policy</button></div>
              </form>
            </div>

            <h2>Audit trail</h2>
            <div class="muted">Every tool call, independent of any conversation transcript.
            Full log: <a href="/agent/audit">/agent/audit</a> &middot; contracts: <a href="/agent/tools">/agent/tools</a></div>
            <div class="card" style="padding:0 6px"><table>
              <tr><th>Time</th><th>Tool</th><th>Actor</th><th>Result</th><th>Outcome</th></tr>
              {audit_rows}</table></div>
            """)

        def agent_approve(self, form: dict) -> str:
            orch = state.orchestrator
            run_id = int(form.get("run_id", "0"))
            fingerprint = form.get("fingerprint", "")
            # The token is minted HERE, by a human form POST, and nowhere else.
            token = orch.mint_approval(run_id, fingerprint, actor="console-operator")
            result = orch.apply(run_id, fingerprint, token, "sub-production", actor="console-operator")
            pack = orch.fixpack(run_id, fingerprint, actor="console-operator")
            body = f"<h1>Approval recorded</h1><div class='muted'>{html.escape(fingerprint)}</div>"

            if not result.ok:
                body += ("<div class='card' style='margin-top:14px'><h2 style='margin-top:0'>Not applied</h2>"
                         f"<p>{html.escape(result.refusal)}</p></div>")
            elif result.data.get("applied") is False:
                rows = "".join(
                    f"<tr><td><code>{html.escape(str(p.get('key','')))}</code></td>"
                    f"<td>{html.escape(str(p.get('label','')))}</td>"
                    f"<td class='muted'>{html.escape(json.dumps(p.get('live_before', {})))}</td>"
                    f"<td>{'already correct' if p.get('already_correct') else 'would change'}</td></tr>"
                    for p in result.data.get("preview", []))
                body += ("<div class='card' style='margin-top:14px'><h2 style='margin-top:0'>Dry run - nothing was changed</h2>"
                         f"<p>{html.escape(result.data.get('note',''))}</p>"
                         "<table><tr><th>Record</th><th>Change</th><th>Live value now</th><th>Effect</th></tr>"
                         f"{rows}</table></div>")
            else:
                d = result.data
                verified = d.get("verified")
                rows = "".join(f"<li><code>{html.escape(str(k))}</code></li>" for k in d.get("operations_applied", []))
                skipped = "".join(f"<li><code>{html.escape(str(k))}</code> already correct</li>"
                                  for k in d.get("operations_already_correct", []))
                body += (f"<div class='card' style='margin-top:14px'><h2 style='margin-top:0'>"
                         f"{'Applied and verified' if verified else 'Applied, VERIFICATION FAILED'}</h2>"
                         f"<p>Change reference: <code>{html.escape(str(d.get('change_reference')))}</code> "
                         "(the update set every write landed in)</p>"
                         f"<ul>{rows}{skipped}</ul>")
                if not verified:
                    body += ("<div class='err'>Read-back did not match for: "
                             + html.escape(", ".join(d.get("verification_failures", [])))
                             + ". Investigate before trusting this change.</div>")
                body += ("<details><summary>Backout state captured before the first write</summary>"
                         f"<pre style='white-space:pre-wrap'>{html.escape(str(d.get('backout_state','')))}</pre>"
                         "</details></div>")
            if pack.ok:
                links = "".join(
                    f"<li><a href='/runs/{run_id}/fixpacks/{html.escape(pack.data['name'])}/{html.escape(e)}'>{html.escape(e)}</a></li>"
                    for e in pack.data["elements"])
                body += (f"<div class='card'><h2 style='margin-top:0'>Fix-pack {html.escape(pack.data['name'])}</h2>"
                         f"<ul>{links}</ul><div class='muted'>Five-element contract: fix, dry-run, instructions, "
                         "backout, scope. Run the dry-run before applying and again afterwards to verify.</div></div>")
            body += "<p><a href='/agent'>Back to the agent console</a></p>"
            return page("Approval", body)

        def agent_tool(self, form: dict) -> str:
            orch = state.orchestrator
            tool = form.get("tool", "findings")
            try:
                args = json.loads(form.get("args") or "{}")
                if not isinstance(args, dict):
                    raise ValueError("arguments must be a JSON object")
            except ValueError as exc:
                return page("Tool call", f"<h1>Tool call</h1><div class='err'>{html.escape(str(exc))}</div>"
                                         "<p><a href='/agent'>Back</a></p>")
            result = orch.call(tool, args, actor="console-operator")
            rendered = json.dumps(result.to_dict(), indent=2)[:60000]
            return page("Tool call", f"""<h1>{html.escape(tool)}()</h1>
            <div class="muted">This is the exact envelope the agent receives.</div>
            <div class="card"><pre style="white-space:pre-wrap; overflow-x:auto">{html.escape(rendered)}</pre></div>
            <p><a href="/agent">Back to the agent console</a></p>""")

        def run_asset(self, path: str):
            parts = path.strip("/").split("/")
            if len(parts) < 3 or not parts[1].isdigit():
                return self._send(404, page("Not found", "<h1>Not found</h1>"))
            run_id, asset = parts[1], "/".join(parts[2:])
            if asset == "dashboard":
                asset = "dashboard.html"
            base = (state.runs_dir / f"run_{run_id}").resolve()
            target = (base / asset).resolve()
            if not str(target).startswith(str(base)):
                return self._send(404, page("Not found", "<h1>Not found</h1>"))
            if not target.is_file():
                # CLI-stored runs have no webrun dir: render the dashboard from the DB on the fly
                if asset == "dashboard.html":
                    return self.db_dashboard(int(run_id))
                return self._send(404, page("Not found", "<h1>Not found</h1>"))
            ctype = "text/html; charset=utf-8" if target.suffix == ".html" else "text/plain; charset=utf-8"
            if target.suffix == ".csv":
                ctype = "text/csv; charset=utf-8"
            return self._send(200, target.read_text(), ctype)

        def db_dashboard(self, run_id: int):
            con = connect(state.db_path)
            findings = list(run_findings(con, run_id).values())
            if not findings:
                return self._send(404, page("Not found", "<h1>Run not found</h1>"))
            row = con.execute("SELECT instance_id, taken_at, rule_versions, fixpack_names, skipped_rules, extraction_gaps FROM scan_runs WHERE run_id=?", (run_id,)).fetchone()
            meta = {
                "instance_id": row[0],
                "taken_at": row[1],
                "rule_count": len(json.loads(row[2])),
                "fixpacks": [{"name": n, "rule_id": "", "finding_fingerprint": ""} for n in json.loads(row[3])],
                "skipped_rules": json.loads(row[4]),
                "extraction_gaps": json.loads(row[5]),
                "trend": trend_meta(con, row[0], run_id),
            }
            return self._send(200, render_dashboard(findings, meta))

    return Handler


def serve(home: str, host: str = "127.0.0.1", port: int = 8422):
    state = AppState(home)
    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    print(f"ROB web interface: http://{host}:{port}")
    if not state.is_set_up:
        print("First run: the browser will ask you to set the administrator password.")
    httpd.serve_forever()
