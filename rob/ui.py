"""ROB design system: tokens and components for the console.

Ported from the 'ROB Instance Health' design (Claude Design project
400bf911). The design declares its own font stacks and palette; both are
reproduced here literally rather than approximated, so the console and the
design stay comparable.

Deliberately free of external requests. The console is tested for making
none, so fonts are declared and allowed to fall back to the system stack
rather than fetched from a CDN. That is exactly what the design declares.

Everything here returns a string. No template engine, no dependencies:
the whole product's posture is that it runs from a checkout with nothing
installed (architecture/high-level-architecture.md).
"""
from __future__ import annotations

import html
import urllib.parse

# --------------------------------------------------------------------------- tokens

SANS = "'IBM Plex Sans', ui-sans-serif, system-ui, -apple-system, sans-serif"
SERIF = "'IBM Plex Serif', ui-serif, Georgia, serif"
MONO = "'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace"

# Severity and state colours. Ink-on-tint pairs, so a pill reads at any size
# and never depends on colour alone: every pill carries its own word.
SEVERITY_COLOURS = {
    "Critical": ("#8F1D14", "#FBEAE8"),
    "High": ("#8A3B0B", "#FDEFE4"),
    "Medium": ("#7A5209", "#FBF3DF"),
    "Low": ("#4C6068", "#EDF1F1"),
    "Informational": ("#5E7178", "#F2F5F5"),
}
SEVERITY_BAR = {
    "Critical": "#C0362C",
    "High": "#D4641F",
    "Medium": "#C08A16",
    "Low": "#A8B6BA",
    "Informational": "#C9D4D6",
}
DOMAIN_BAR = ("#0B6E6E", "#12868A", "#2A9D9D", "#4FB3AE", "#6FD3C6", "#96DDD3")

STYLE = f"""
:root {{
  --page:#F1F4F4; --surface:#FFFFFF; --surface-2:#FAFCFC; --surface-3:#F7FAFA;
  --tint:#F2F7F7; --ink:#16262E; --ink-2:#24404A; --ink-3:#4C6068;
  --muted:#7A8E94; --muted-2:#8497A0;
  --line:#E1E8E8; --line-2:#EDF1F1; --line-3:#F2F5F5;
  --teal:#0B6E6E; --teal-d:#0D2A2A; --teal-l:#6FD3C6;
  --dark:#12262E; --dark-2:#0D1F26;
  --good:#0B6247; --good-l:#0F7A55; --good-t:#E6F5EE;
  --crit:#8F1D14; --crit-b:#C0362C; --warn:#7A5209; --high:#8A3B0B;
  --radius:10px;
}}
* {{ box-sizing:border-box; }}
html, body {{ height:100%; }}
body {{ margin:0; background:var(--page); color:var(--ink);
  font:400 13.5px/1.55 {SANS}; -webkit-font-smoothing:antialiased; }}
a {{ color:var(--teal); text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
code, .mono {{ font-family:{MONO}; font-size:.92em; }}

/* ---- shell ---- */
.shell {{ display:flex; min-height:100vh; align-items:stretch; }}
.side {{ width:196px; flex:0 0 196px; background:var(--surface-2);
  border-right:1px solid var(--line); padding:18px 14px 22px; display:flex;
  flex-direction:column; gap:20px; }}
.brand {{ display:flex; align-items:center; gap:9px; }}
.mark {{ width:30px; height:30px; border-radius:8px; background:var(--teal);
  color:#fff; font-weight:700; font-size:15px; display:grid; place-items:center; }}
.brand b {{ font-size:15px; font-weight:700; letter-spacing:.01em; display:block; line-height:1.1; }}
.brand span {{ font-size:9px; letter-spacing:.1em; text-transform:uppercase; color:var(--muted); }}
.side h3 {{ font-size:9px; letter-spacing:.1em; text-transform:uppercase;
  color:var(--muted); margin:0 0 8px 2px; font-weight:600; }}
.inst-card {{ background:var(--tint); border:1px solid var(--line); border-radius:8px;
  padding:10px 11px; }}
.inst-card .n {{ display:flex; align-items:center; justify-content:space-between; gap:6px; }}
.inst-card .n b {{ font-family:{MONO}; font-size:12.5px; font-weight:600; }}
.inst-card .m {{ font-size:10.5px; color:var(--muted); margin-top:5px; line-height:1.45; }}
.env {{ font-size:8.5px; letter-spacing:.09em; text-transform:uppercase; font-weight:700;
  padding:2px 5px; border-radius:4px; background:#DCEAEA; color:var(--teal); }}
.env.prod {{ background:#FBEAE8; color:var(--crit); }}
.env.test {{ background:#FBF3DF; color:var(--warn); }}
nav.sections {{ display:flex; flex-direction:column; gap:1px; }}
nav.sections a {{ display:flex; align-items:center; justify-content:space-between;
  padding:7px 11px; border-radius:6px; color:var(--ink-2); font-size:13px;
  border-left:2px solid transparent; }}
nav.sections a:hover {{ background:var(--line-3); text-decoration:none; }}
nav.sections a.on {{ background:var(--line-2); color:var(--ink); font-weight:600;
  border-left-color:var(--teal); }}
nav.sections a .c {{ font-size:11.5px; color:var(--muted); font-weight:400; }}
.side .foot {{ margin-top:auto; }}
.roles {{ display:flex; flex-wrap:wrap; gap:5px; }}
.roles a {{ font-size:11.5px; padding:4px 9px; border-radius:999px; border:1px solid var(--line);
  color:var(--ink-3); background:var(--surface); }}
.roles a:hover {{ text-decoration:none; border-color:var(--muted-2); }}
.roles a.on {{ background:var(--teal-d); border-color:var(--teal-d); color:#fff; }}
.role-note {{ font-size:10.5px; color:var(--muted); margin-top:9px; line-height:1.45; }}

.main {{ flex:1; min-width:0; background:var(--page); }}
.topbar {{ display:flex; align-items:flex-start; gap:16px; padding:22px 30px 0; }}
.crumb {{ font-size:9.5px; letter-spacing:.1em; text-transform:uppercase; color:var(--muted); }}
.crumb b {{ color:var(--ink-2); font-weight:600; }}
.topbar h1 {{ font-size:25px; font-weight:500; margin:6px 0 0; letter-spacing:-.01em; }}
.topbar .grow {{ flex:1; }}
.topacts {{ display:flex; align-items:center; gap:8px; padding-top:14px; }}
.wrap {{ padding:20px 30px 44px; max-width:1180px; }}

/* ---- primitives ---- */
.chip {{ display:inline-flex; align-items:center; gap:6px; font-size:11.5px;
  border:1px solid var(--line); background:var(--surface); color:var(--ink-3);
  border-radius:999px; padding:5px 11px; }}
.chip .dot {{ width:6px; height:6px; border-radius:50%; background:var(--good-l); }}
.chip.bad .dot {{ background:var(--crit-b); }}
.btn {{ font:600 12.5px/1 {SANS}; border:1px solid var(--line); background:var(--surface);
  color:var(--ink); border-radius:8px; padding:9px 14px; cursor:pointer; display:inline-block; }}
.btn:hover {{ text-decoration:none; border-color:var(--muted-2); }}
.btn.dark {{ background:var(--dark); border-color:var(--dark); color:#fff; }}
.btn.dark:hover {{ background:#0A1A20; }}
.btn.teal {{ background:var(--good); border-color:var(--good); color:#fff; }}
.btn.teal:hover {{ background:var(--good-l); }}
.btn.danger {{ color:var(--crit); border-color:#F0D5D2; background:#FDF6F5; }}
.btn.sm {{ padding:6px 10px; font-size:11.5px; }}

.card {{ background:var(--surface); border:1px solid var(--line); border-radius:var(--radius);
  padding:18px 20px; }}
.card.flush {{ padding:0; overflow:hidden; }}
.card > h2, .sec-h {{ font-size:14.5px; font-weight:600; margin:0 0 2px; }}
.card .sub {{ font-size:11.5px; color:var(--muted); }}
.cardhead {{ display:flex; align-items:baseline; justify-content:space-between; gap:12px;
  margin-bottom:14px; }}
.grid {{ display:grid; gap:12px; }}
.g2 {{ grid-template-columns:1fr 1fr; }}
.g3 {{ grid-template-columns:repeat(3,1fr); }}
.g5 {{ grid-template-columns:repeat(5,1fr); }}
@media (max-width:960px) {{ .g2,.g3,.g5 {{ grid-template-columns:1fr; }} }}
.stack {{ display:flex; flex-direction:column; gap:12px; }}

.kpi {{ background:var(--surface); border:1px solid var(--line); border-radius:var(--radius);
  border-top:3px solid var(--teal); padding:13px 15px 15px; }}
.kpi .k {{ font-size:11.5px; color:var(--ink-3); }}
.kpi .v {{ font-size:27px; font-weight:600; line-height:1.15; margin:3px 0 2px;
  letter-spacing:-.02em; }}
.kpi .c {{ font-size:10.5px; color:var(--muted); }}

.pill {{ display:inline-block; font-size:11px; font-weight:600; padding:3px 9px;
  border-radius:999px; white-space:nowrap; }}
.tag {{ display:inline-block; font-size:11px; color:var(--ink-3); background:var(--line-3);
  border:1px solid var(--line); border-radius:999px; padding:3px 9px; }}

table {{ width:100%; border-collapse:collapse; }}
thead th {{ text-align:left; font-size:9.5px; letter-spacing:.09em; text-transform:uppercase;
  color:var(--muted); font-weight:600; padding:11px 14px; border-bottom:1px solid var(--line); }}
tbody td {{ padding:11px 14px; border-bottom:1px solid var(--line-2); vertical-align:top; }}
tbody tr:last-child td {{ border-bottom:none; }}
tbody tr:hover td {{ background:var(--surface-3); }}
td.num, th.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
.rid {{ font-family:{MONO}; font-size:11px; color:var(--teal); }}
.meta {{ font-size:11px; color:var(--muted); font-family:{MONO}; }}

.bar {{ height:6px; border-radius:3px; background:var(--line-2); overflow:hidden; }}
.bar > i {{ display:block; height:100%; border-radius:3px; }}
.barrow {{ display:grid; grid-template-columns:96px 1fr 34px; align-items:center; gap:12px;
  padding:5px 0; font-size:12.5px; }}
.barrow .n {{ text-align:right; font-variant-numeric:tabular-nums; color:var(--ink-2); }}

.note {{ font-size:11.5px; color:var(--muted); line-height:1.5; }}
.quote {{ border-left:2px solid var(--line); padding:2px 0 2px 13px; color:var(--ink-3);
  font-size:12.5px; line-height:1.55; }}
.kv {{ display:flex; align-items:baseline; justify-content:space-between; gap:12px;
  padding:7px 0; border-bottom:1px solid var(--line-2); font-size:12.5px; }}
.kv:last-child {{ border-bottom:none; }}
.kv .k {{ color:var(--ink-3); }}
.kv .v {{ font-weight:600; text-align:right; }}
.lbl {{ font-size:9.5px; letter-spacing:.09em; text-transform:uppercase; color:var(--muted);
  font-weight:600; margin:16px 0 7px; }}
.lbl:first-child {{ margin-top:0; }}

.queue {{ display:flex; align-items:center; gap:14px; padding:11px 0 11px 14px;
  border-left:3px solid var(--line); }}
.queue .i {{ font-family:{MONO}; font-size:11px; color:var(--muted-2); width:18px; }}
.queue .t {{ flex:1; min-width:0; }}
.queue .t b {{ font-size:13px; font-weight:600; display:block; }}
.queue .e {{ font-size:11.5px; color:var(--muted); font-variant-numeric:tabular-nums; }}

.dark-card {{ background:var(--teal-d); border-color:var(--teal-d); color:#EAF2F2; }}
.dark-card .sub, .dark-card .note {{ color:#8FA9A9; }}
.dark-card .bar {{ background:#1D3D3D; }}

/* ---- forms ---- */
form.set {{ display:block; }}
label {{ display:block; font-size:11.5px; color:var(--ink-3); margin:12px 0 5px; font-weight:500; }}
label.inline {{ display:flex; align-items:center; gap:8px; margin:10px 0 0; font-size:12.5px;
  color:var(--ink); }}
input[type=text], input[type=password], input[type=url], input[type=number], select, textarea {{
  font:400 13px/1.4 {SANS}; color:var(--ink); background:var(--surface); width:100%;
  border:1px solid var(--line); border-radius:8px; padding:9px 11px; }}
input:focus, select:focus, textarea:focus {{ outline:2px solid #BFDDDD; outline-offset:-1px;
  border-color:var(--teal); }}
input[type=checkbox] {{ width:15px; height:15px; accent-color:var(--teal); }}
.hint {{ font-size:11px; color:var(--muted); margin-top:5px; line-height:1.5; }}
.formfoot {{ margin-top:18px; display:flex; align-items:center; gap:10px; }}
.locked {{ background:var(--surface-3); border:1px dashed var(--line); border-radius:8px;
  padding:12px 14px; font-size:12px; color:var(--ink-3); line-height:1.55; }}
.locked b {{ color:var(--ink); }}
.flash {{ border-radius:8px; padding:10px 13px; font-size:12.5px; margin-bottom:14px; }}
.flash.ok {{ background:var(--good-t); color:var(--good); }}
.flash.err {{ background:#FBEAE8; color:var(--crit); }}
.footer {{ display:flex; justify-content:space-between; gap:24px; padding:20px 30px 34px;
  border-top:1px solid var(--line); margin-top:26px; font-size:11px; color:var(--muted);
  line-height:1.6; }}
.footer .r {{ text-align:right; font-family:{MONO}; white-space:nowrap; }}
pre.log {{ background:var(--dark-2); color:#CBD9DB; border-radius:var(--radius);
  padding:14px 16px; font:12px/1.6 {MONO}; overflow:auto; max-height:340px; }}

/* ---- login ---- */
.login-wrap {{ min-height:100vh; display:grid; place-items:center; padding:24px; }}
.login {{ width:390px; }}
.login .card {{ padding:28px 30px; }}
.login h1 {{ font:500 23px/1.2 {SERIF}; margin:14px 0 4px; }}
.login .sub {{ font-size:13px; color:var(--ink-3); margin-bottom:6px; }}

.verdict {{ font:400 21px/1.38 {SERIF}; letter-spacing:-.005em; margin:8px 0 14px; }}
.hero {{ display:grid; grid-template-columns:210px minmax(340px,1fr) 300px; align-items:stretch; }}
@media (max-width:1000px) {{ .hero {{ grid-template-columns:1fr; }}
  .hero > div {{ border-left:none !important; border-right:none !important;
    border-top:1px solid var(--line); }} }}
.inst-card .n b {{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.score-n {{ font:600 34px/1 {SANS}; letter-spacing:-.02em; }}
"""


# --------------------------------------------------------------------------- helpers

def e(x) -> str:
    return html.escape("" if x is None else str(x))


def q(x) -> str:
    """A value going into a URL query string.

    Fingerprints are `rule_id:affected_area`, and an affected area is a
    technical name that legitimately contains spaces and parentheses
    ("sys_user_has_role (admin)"). html.escape does not encode those, so the
    href was malformed and strict clients refused it. Percent-encode first,
    then escape for HTML.
    """
    return html.escape(urllib.parse.quote(str(x or ""), safe=""))


def pill(text: str, severity: str = "") -> str:
    fg, bg = SEVERITY_COLOURS.get(severity, ("#0B6247", "#E6F5EE"))
    return f'<span class="pill" style="color:{fg};background:{bg}">{e(text)}</span>'


def bar(pct: float, colour: str) -> str:
    w = max(0.0, min(100.0, pct))
    return f'<div class="bar"><i style="width:{w:.1f}%;background:{colour}"></i></div>'


def bar_row(label: str, value, pct: float, colour: str, label_colour: str = "") -> str:
    style = f' style="color:{label_colour}"' if label_colour else ""
    return (f'<div class="barrow"><span{style}>{e(label)}</span>{bar(pct, colour)}'
            f'<span class="n">{e(value)}</span></div>')


def kpi(label: str, value, caption: str = "", accent: str = "#0B6E6E") -> str:
    return (f'<div class="kpi" style="border-top-color:{accent}"><div class="k">{e(label)}</div>'
            f'<div class="v">{e(value)}</div><div class="c">{e(caption)}</div></div>')


def donut(score: int, size: int = 118, stroke: int = 11) -> str:
    """Score ring. SVG, no library, no external request."""
    r = (size - stroke) / 2
    c = 2 * 3.14159265 * r
    on = c * max(0, min(100, score)) / 100
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img" '
        f'aria-label="Health score {score} of 100">'
        f'<circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none" stroke="#E1E8E8" stroke-width="{stroke}"/>'
        f'<circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none" stroke="#0B6E6E" stroke-width="{stroke}" '
        f'stroke-linecap="round" stroke-dasharray="{on:.2f} {c - on:.2f}" '
        f'transform="rotate(-90 {size/2} {size/2})"/>'
        f'<text x="50%" y="49%" text-anchor="middle" font-size="30" font-weight="600" '
        f'fill="#16262E" font-family="{SANS}">{score}</text>'
        f'<text x="50%" y="64%" text-anchor="middle" font-size="8.5" letter-spacing="1.4" '
        f'fill="#7A8E94" font-family="{SANS}">OF 100</text></svg>'
    )


def spark_bars(values: list[int], labels: list[str] | None = None, height: int = 62) -> str:
    """Score trend. Last bar is the current run and is emphasised."""
    if not values:
        return '<div class="note">No trend yet: a second scan draws this.</div>'
    top = max(values) or 1
    cells = []
    for i, v in enumerate(values):
        h = max(6, int(height * v / top))
        shade = "#0B6E6E" if i == len(values) - 1 else ["#CFE3E3", "#BBD9D9", "#A3CDCD", "#8BC1C1"][min(i, 3)]
        cells.append(
            f'<div style="display:flex;flex-direction:column;align-items:center;gap:6px">'
            f'<div style="width:26px;height:{h}px;border-radius:4px 4px 2px 2px;background:{shade}"></div>'
            f'<span style="font-size:10px;color:{"#16262E" if i == len(values)-1 else "#7A8E94"};'
            f'font-variant-numeric:tabular-nums">{e(v)}</span></div>'
        )
    return (f'<div style="display:flex;align-items:flex-end;gap:9px;height:{height + 20}px">'
            + "".join(cells) + "</div>")


SECTIONS = (
    ("/", "Overview", "overview"),
    ("/findings", "Findings", "findings"),
    ("/remediation", "Remediation", "remediation"),
    ("/coverage", "Coverage", "coverage"),
    ("/estate", "Estate", "estate"),
    ("/settings", "Settings", "settings"),
)

ROLES = (
    ("executive", "Executive", "Headline, trend and what leadership must decide. No record identifiers."),
    ("architect", "Architect", "Structure: scope, data model, coverage and what the ruleset did not look at."),
    ("platform_admin", "Platform admin", "Today's queue: what is urgent, what ROB can fix, and how long each takes."),
    ("security", "Security", "Exposure first: access, ACLs, transport and standing privilege."),
)
ROLE_LABELS = {k: label for k, label, _ in ROLES}
ROLE_NOTES = {k: note for k, _, note in ROLES}


def sidebar(*, active: str, instance: dict | None, counts: dict, role: str) -> str:
    if instance:
        env = (instance.get("environment") or "dev").lower()
        card = (
            f'<div class="inst-card"><div class="n"><b>{e(instance.get("label", ""))}</b>'
            f'<span class="env {e(env) if env in ("prod", "test") else ""}">{e(env.upper())}</span></div>'
            f'<div class="m">{e(instance.get("meta", ""))}</div></div>'
        )
    else:
        card = '<div class="inst-card"><div class="m">No instance connected yet.</div></div>'
    nav = "".join(
        f'<a href="{href}" class="{"on" if key == active else ""}">{e(label)}'
        + (f'<span class="c">{e(counts[key])}</span>' if counts.get(key) not in (None, "") else "")
        + "</a>"
        for href, label, key in SECTIONS
    )
    role_pills = "".join(
        f'<a href="/role?to={k}" class="{"on" if k == role else ""}">{e(label)}</a>'
        for k, label, _ in ROLES
    )
    return f"""<aside class="side">
  <div class="brand"><div class="mark">R</div><div><b>ROB</b><span>Instance health</span></div></div>
  <div><h3>Scanned instance</h3>{card}</div>
  <div><h3>Sections</h3><nav class="sections">{nav}</nav></div>
  <div class="foot"><h3>Reading as</h3><div class="roles">{role_pills}</div>
    <div class="role-note">{e(ROLE_NOTES.get(role, ""))}</div></div>
</aside>"""


def shell(*, title: str, crumb: str, heading: str, body: str, active: str,
          instance: dict | None = None, counts: dict | None = None,
          role: str = "platform_admin", actions: str = "", status: str = "",
          footer_left: str = "", footer_right: str = "") -> str:
    status_html = f'<span class="chip"><span class="dot"></span>{e(status)}</span>' if status else ""
    foot = ""
    if footer_left or footer_right:
        foot = (f'<div class="footer"><div>{footer_left}</div>'
                f'<div class="r">{footer_right}</div></div>')
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} - ROB</title><style>{STYLE}</style></head>
<body><div class="shell">
{sidebar(active=active, instance=instance, counts=counts or {}, role=role)}
<div class="main">
  <div class="topbar">
    <div><div class="crumb">Remediation &amp; Optimisation Bot &nbsp;/&nbsp; <b>{e(crumb)}</b></div>
      <h1>{e(heading)}</h1></div>
    <div class="grow"></div>
    <div class="topacts">{status_html}{actions}</div>
  </div>
  <div class="wrap">{body}</div>
  {foot}
</div></div></body></html>"""
