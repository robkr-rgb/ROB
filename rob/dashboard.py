"""Self-contained interactive HTML dashboard (decision D-009 interim front-end).

One file, no server, no CDN, no browser storage: open in any browser. Rendered
from the same findings data as every other output (report-output-model.md data
contract). Executive rule holds: KPI layer contains no sys_ids; record refs
appear only inside expandable finding detail (the technical layer).
"""
from __future__ import annotations

import json

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
PRIORITY_ORDER = ["P1", "P2", "P3", "P4"]


def render_dashboard(findings: list[dict], meta: dict) -> str:
    payload = {"findings": findings, "meta": meta}
    data_json = json.dumps(payload).replace("</", "<\\/")
    return _TEMPLATE.replace("__DATA__", data_json)


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ROB - Instance Health Dashboard</title>
<style>
  .viz-root {
    color-scheme: light;
    --surface-1:#fcfcfb; --page:#f9f9f7;
    --ink-1:#0b0b0b; --ink-2:#52514e; --muted:#898781;
    --grid:#e1e0d9; --baseline:#c3c2b7; --ring:rgba(11,11,11,0.10);
    --series-1:#2a78d6; --seq-250:#86b6ef; --seq-450:#2a78d6; --seq-600:#184f95;
    --st-critical:#d03b3b; --st-serious:#ec835a; --st-warning:#fab219; --st-good:#0ca30c;
  }
  @media (prefers-color-scheme: dark) {
    :root:where(:not([data-theme="light"])) .viz-root {
      color-scheme: dark;
      --surface-1:#1a1a19; --page:#0d0d0d;
      --ink-1:#ffffff; --ink-2:#c3c2b7; --muted:#898781;
      --grid:#2c2c2a; --baseline:#383835; --ring:rgba(255,255,255,0.10);
      --series-1:#3987e5; --seq-250:#86b6ef; --seq-450:#3987e5; --seq-600:#184f95;
    }
  }
  :root[data-theme="dark"] .viz-root {
    color-scheme: dark;
    --surface-1:#1a1a19; --page:#0d0d0d;
    --ink-1:#ffffff; --ink-2:#c3c2b7; --muted:#898781;
    --grid:#2c2c2a; --baseline:#383835; --ring:rgba(255,255,255,0.10);
    --series-1:#3987e5;
  }
  * { box-sizing:border-box; }
  body.viz-root { margin:0; background:var(--page); color:var(--ink-1);
    font-family:system-ui,-apple-system,"Segoe UI",sans-serif; font-size:14px; line-height:1.45; }
  header { padding:20px 28px 8px; display:flex; align-items:baseline; gap:14px; flex-wrap:wrap; }
  header h1 { font-size:19px; margin:0; }
  header .sub { color:var(--ink-2); font-size:12.5px; }
  header .spacer { flex:1; }
  .theme-btn { border:1px solid var(--ring); background:var(--surface-1); color:var(--ink-2);
    border-radius:8px; padding:4px 10px; cursor:pointer; font:inherit; font-size:12px; }
  main { padding:8px 28px 40px; max-width:1200px; margin:0 auto; }
  section { margin-top:18px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; }
  .card { background:var(--surface-1); border:1px solid var(--ring); border-radius:12px; padding:12px 14px; }
  .card .k { font-size:12px; color:var(--ink-2); }
  .card .v { font-size:26px; font-weight:650; margin-top:2px; }
  .card .d { font-size:11.5px; color:var(--muted); margin-top:2px; }
  .charts { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
  @media (max-width:820px){ .charts{ grid-template-columns:1fr; } }
  .panel { background:var(--surface-1); border:1px solid var(--ring); border-radius:12px; padding:14px 16px; }
  .panel h2 { font-size:13px; margin:0 0 10px; color:var(--ink-2); font-weight:600; }
  .hrow { display:flex; align-items:center; gap:8px; margin:6px 0; }
  .hlab { width:110px; font-size:12.5px; color:var(--ink-2); text-align:right; flex:none; }
  .htrack { flex:1; display:flex; align-items:center; gap:6px; }
  .hbar { height:14px; border-radius:0 4px 4px 0; min-width:2px; }
  .hval { font-size:12px; color:var(--ink-2); }
  .filters { display:flex; gap:8px; flex-wrap:wrap; margin:14px 0 10px; align-items:center; }
  .filters select, .filters input[type=search] { font:inherit; font-size:12.5px; color:var(--ink-1);
    background:var(--surface-1); border:1px solid var(--ring); border-radius:8px; padding:5px 8px; }
  .filters input[type=search]{ min-width:200px; }
  .filters label.chk { font-size:12.5px; color:var(--ink-2); display:flex; gap:5px; align-items:center; }
  .count { font-size:12px; color:var(--muted); margin-left:auto; }
  table { width:100%; border-collapse:collapse; background:var(--surface-1);
    border:1px solid var(--ring); border-radius:12px; overflow:hidden; }
  thead th { text-align:left; font-size:11.5px; text-transform:uppercase; letter-spacing:.04em;
    color:var(--muted); padding:9px 10px; border-bottom:1px solid var(--grid); }
  tbody td { padding:9px 10px; border-bottom:1px solid var(--grid); vertical-align:top; }
  tbody tr.frow { cursor:pointer; }
  tbody tr.frow:hover { background:color-mix(in srgb, var(--series-1) 6%, var(--surface-1)); }
  tbody tr:last-child td { border-bottom:none; }
  .chip { display:inline-block; border-radius:999px; padding:1px 9px; font-size:11.5px; font-weight:600;
    border:1px solid var(--ring); white-space:nowrap; }
  .chip.sev { color:#fff; border:none; }
  .chip.sev.Low { color:var(--ink-1); background:var(--seq-250); }
  .chip.sev.Informational { color:#fff; background:var(--muted); }
  .chip.pri { color:var(--ink-2); background:transparent; }
  .chip.tier { color:var(--ink-2); }
  .fix-yes { color:var(--st-good); font-weight:600; font-size:12.5px; }
  .fix-no { color:var(--muted); font-size:12.5px; }
  .detail { display:none; background:color-mix(in srgb, var(--series-1) 4%, var(--surface-1)); }
  .detail.open { display:table-row; }
  .detail-inner { padding:6px 12px 14px; font-size:13px; color:var(--ink-1); }
  .detail-inner h4 { margin:10px 0 3px; font-size:11.5px; text-transform:uppercase;
    letter-spacing:.04em; color:var(--muted); }
  .detail-inner ul { margin:4px 0; padding-left:18px; }
  .detail-inner code { font-size:11.5px; background:var(--page); border:1px solid var(--ring);
    border-radius:5px; padding:0 4px; color:var(--ink-2); }
  .trace { font-size:12px; color:var(--ink-2); }
  .accepted-band { border-left:3px solid var(--st-warning); padding-left:8px; color:var(--ink-2); font-size:12.5px; }
  .packs { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:10px; }
  .pack { border:1px solid var(--ring); border-radius:10px; padding:10px 12px; background:var(--surface-1); }
  .pack .n { font-weight:600; font-size:13px; }
  .pack .m { font-size:12px; color:var(--ink-2); margin-top:4px; }
  footer { color:var(--muted); font-size:11.5px; padding:18px 28px; max-width:1200px; margin:0 auto; }
  .tooltip { position:fixed; pointer-events:none; background:var(--ink-1); color:var(--page);
    font-size:12px; padding:4px 8px; border-radius:6px; opacity:0; transition:opacity .08s; z-index:10; }
</style>
</head>
<body class="viz-root">
<header>
  <h1>ROB - Instance Health</h1>
  <div class="sub" id="meta-line"></div>
  <div class="spacer"></div>
  <button class="theme-btn" id="theme-toggle" type="button">Theme</button>
</header>
<main>
  <section class="cards" id="kpis"></section>

  <section class="charts">
    <div class="panel">
      <h2>Findings by severity</h2>
      <div id="chart-severity"></div>
    </div>
    <div class="panel">
      <h2>Findings by domain</h2>
      <div id="chart-category"></div>
    </div>
  </section>

  <section class="panel" id="trend-panel" style="display:none">
    <h2 id="trend-title">Trend</h2>
    <div class="charts" style="gap:16px">
      <div>
        <h2 style="font-weight:500">Findings per scan</h2>
        <div id="trend-history"></div>
      </div>
      <div>
        <div id="trend-changes"></div>
      </div>
    </div>
  </section>

  <section>
    <div class="filters">
      <select id="f-severity"><option value="">Severity: all</option></select>
      <select id="f-priority"><option value="">Priority: all</option></select>
      <select id="f-category"><option value="">Domain: all</option></select>
      <select id="f-tier"><option value="">Remediability: all</option></select>
      <label class="chk"><input type="checkbox" id="f-fix"> Fix ready</label>
      <input type="search" id="f-search" placeholder="Search findings...">
      <span class="count" id="f-count"></span>
    </div>
    <table id="findings-table" aria-label="Findings">
      <thead><tr>
        <th>Finding</th><th>Severity</th><th>Priority</th><th>Domain</th>
        <th>Tier</th><th>Evidence</th><th>Fix</th><th>Owner</th>
      </tr></thead>
      <tbody id="findings-body"></tbody>
    </table>
  </section>

  <section class="panel" id="packs-panel">
    <h2>Fix-packs ready to apply</h2>
    <div class="packs" id="packs"></div>
  </section>

  <section class="panel" id="manifest-panel">
    <h2>Scan manifest</h2>
    <div class="trace" id="manifest"></div>
  </section>
</main>
<footer>Generated by ROB - Remediation &amp; Optimisation Bot. Click a finding row for evidence,
scoring transparency and remediation. This file is self-contained and safe to share
(executive layer contains no record identifiers).</footer>
<div class="tooltip" id="tip"></div>
<script>
const DATA = __DATA__;
const F = DATA.findings, META = DATA.meta;
const SEV = ["Critical","High","Medium","Low","Informational"];
const PRI = ["P1","P2","P3","P4"];
const SEVC = {Critical:"var(--st-critical)", High:"var(--st-serious)", Medium:"var(--st-warning)",
              Low:"var(--seq-250)", Informational:"var(--muted)"};

const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const by = (arr, fn) => arr.reduce((m, x) => { const k = fn(x); m[k] = (m[k]||0)+1; return m; }, {});

// Header + KPIs -------------------------------------------------------------
document.getElementById("meta-line").textContent =
  `${META.instance_id} | snapshot ${META.taken_at} | ${META.rule_count} rules`;
const sevCounts = by(F, f => f.score.final_severity);
const priCounts = by(F, f => f.score.final_priority);
const fixReady = F.filter(f => f.fixpack_ref).length;
const accepted = F.filter(f => f.accepted).length;
const kpis = [
  ["Findings", F.length, "total this scan"],
  ["Urgent (P1)", priCounts.P1 || 0, "start within days"],
  ["Critical", sevCounts.Critical || 0, "highest severity"],
  ["Fixes ready", `${fixReady}/${F.length}`, "ROB-generated fix-packs"],
  ["Accepted risks", accepted, "formally accepted, reported"],
];
document.getElementById("kpis").innerHTML = kpis.map(([k,v,d]) =>
  `<div class="card"><div class="k">${k}</div><div class="v">${v}</div><div class="d">${d}</div></div>`).join("");

// Bar charts (HTML bars: rounded data-end, 2px gaps via row spacing) --------
const tip = document.getElementById("tip");
function bars(el, order, counts, colorFn, tipFn) {
  const max = Math.max(1, ...order.map(k => counts[k] || 0));
  el.innerHTML = order.filter(k => counts[k]).map(k => {
    const v = counts[k] || 0;
    return `<div class="hrow" data-k="${esc(k)}" data-v="${v}">
      <div class="hlab">${esc(k)}</div>
      <div class="htrack"><div class="hbar" style="width:${(v/max)*100}%;background:${colorFn(k)}"></div>
      <span class="hval">${v}</span></div></div>`;
  }).join("");
  el.querySelectorAll(".hrow").forEach(r => {
    r.addEventListener("mousemove", e => {
      tip.textContent = tipFn(r.dataset.k, r.dataset.v);
      tip.style.left = (e.clientX + 12) + "px"; tip.style.top = (e.clientY + 12) + "px";
      tip.style.opacity = 1;
    });
    r.addEventListener("mouseleave", () => tip.style.opacity = 0);
  });
}
bars(document.getElementById("chart-severity"), SEV, sevCounts,
     k => SEVC[k], (k,v) => `${k}: ${v} finding(s)`);
const catCounts = by(F, f => f.category);
bars(document.getElementById("chart-category"), Object.keys(catCounts).sort(), catCounts,
     () => "var(--series-1)", (k,v) => `${k}: ${v} finding(s)`);

// Filters -------------------------------------------------------------------
const sel = id => document.getElementById(id);
function fill(id, values, prefix) {
  values.forEach(v => { const o = document.createElement("option"); o.value = v; o.textContent = `${prefix}: ${v}`; sel(id).appendChild(o); });
}
fill("f-severity", SEV.filter(s => sevCounts[s]), "Severity");
fill("f-priority", PRI.filter(p => priCounts[p]), "Priority");
fill("f-category", Object.keys(catCounts).sort(), "Domain");
fill("f-tier", [...new Set(F.map(f => f.tier))].sort(), "Tier");

function matches(f) {
  const s = sel("f-severity").value, p = sel("f-priority").value, c = sel("f-category").value,
        t = sel("f-tier").value, fx = sel("f-fix").checked,
        q = sel("f-search").value.trim().toLowerCase();
  if (s && f.score.final_severity !== s) return false;
  if (p && f.score.final_priority !== p) return false;
  if (c && f.category !== c) return false;
  if (t && f.tier !== t) return false;
  if (fx && !f.fixpack_ref) return false;
  if (q) {
    const hay = (f.title + " " + f.affected_area + " " + f.why_it_matters + " " + f.rule_id).toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

// Findings table ------------------------------------------------------------
const sevRank = Object.fromEntries(SEV.map((s,i)=>[s,i]));
const priRank = Object.fromEntries(PRI.map((p,i)=>[p,i]));
const sorted = [...F].sort((a,b) =>
  priRank[a.score.final_priority]-priRank[b.score.final_priority] ||
  sevRank[a.score.final_severity]-sevRank[b.score.final_severity] ||
  a.rule_id.localeCompare(b.rule_id));

function detailHtml(f) {
  const t = f.score;
  const ev = f.evidence.map(e =>
    `<li>${esc(e.summary)}${e.record_ref ? ` <code>${esc(e.record_ref)}</code>` : ""}</li>`).join("");
  const more = f.evidence_total > f.evidence.length
    ? `<li class="trace">... showing ${f.evidence.length} of ${f.evidence_total} matches</li>` : "";
  return `<div class="detail-inner">
    ${f.accepted ? `<div class="accepted-band">Accepted risk: ${esc(f.accepted_reason)} (reported, not hidden; acceptance expires)</div>` : ""}
    <h4>Why it matters</h4><div>${esc(f.why_it_matters)}</div>
    <h4>Evidence (${f.evidence_total})</h4><ul>${ev}${more}</ul>
    <h4>Recommended remediation</h4><div>${esc(f.remediation)}</div>
    <h4>Optimisation opportunity</h4><div>${esc(f.optimisation)}</div>
    <h4>Scoring transparency</h4>
    <div class="trace">Impact ${esc(t.impact)} x Likelihood ${esc(t.likelihood)} -> ${esc(t.matrix_severity)}${t.modifiers_applied.length ? "; modifiers: " + esc(t.modifiers_applied.join(", ")) : ""} -> ${esc(t.final_severity)}.
    Effort ${esc(t.effort)} (${esc(t.effort_assumptions)}) -> ${esc(t.base_priority)}${t.adjustments_applied.length ? "; adjustments: " + esc(t.adjustments_applied.join(", ")) : ""} -> ${esc(t.final_priority)}.</div>
    <h4>Fix-pack</h4><div>${f.fixpack_ref ? `<span class="fix-yes">Ready:</span> <code>${esc(f.fixpack_ref)}</code> (in the scan output's fixpacks folder)` : (f.tier.startsWith("T3") ? "Design work (T3): ROB provides the inventory/worksheet, not an automated fix." : "Not generated in this run.")}</div>
  </div>`;
}

function renderTable() {
  const body = document.getElementById("findings-body");
  const rows = sorted.filter(matches);
  document.getElementById("f-count").textContent = `${rows.length} of ${F.length} findings`;
  body.innerHTML = rows.map((f,i) => `
    <tr class="frow" data-i="${i}">
      <td><strong>${esc(f.title)}</strong><br><span class="trace">${esc(f.rule_id)} | ${esc(f.affected_area)}</span></td>
      <td><span class="chip sev ${esc(f.score.final_severity)}" style="background:${f.score.final_severity==="Low"||f.score.final_severity==="Informational" ? "" : SEVC[f.score.final_severity]}">${esc(f.score.final_severity)}</span></td>
      <td><span class="chip pri">${esc(f.score.final_priority)}</span></td>
      <td>${esc(f.category)}</td>
      <td><span class="chip tier">${esc(f.tier)}</span></td>
      <td>${f.evidence_total}</td>
      <td>${f.fixpack_ref ? '<span class="fix-yes">Ready</span>' : (f.tier.startsWith("T3") ? '<span class="fix-no">design</span>' : '<span class="fix-no">-</span>')}</td>
      <td class="trace">${esc(f.owner)}</td>
    </tr>
    <tr class="detail"><td colspan="8">${detailHtml(f)}</td></tr>`).join("");
  body.querySelectorAll("tr.frow").forEach(r => r.addEventListener("click", () => {
    r.nextElementSibling.classList.toggle("open");
  }));
}
["f-severity","f-priority","f-category","f-tier","f-fix","f-search"].forEach(id =>
  sel(id).addEventListener(id === "f-search" ? "input" : "change", renderTable));
renderTable();

// Fix-packs -----------------------------------------------------------------
const packs = META.fixpacks || [];
document.getElementById("packs-panel").style.display = packs.length ? "" : "none";
document.getElementById("packs").innerHTML = packs.map(p => `
  <div class="pack"><div class="n">${esc(p.name)}</div>
  <div class="m">${esc(p.rule_id)} | finding <code>${esc(p.finding_fingerprint)}</code><br>
  Dry-run, itemised fix, backout and instructions in the pack folder.</div></div>`).join("");

// Manifest ------------------------------------------------------------------
document.getElementById("manifest").innerHTML = [
  `Rules executed: ${META.rule_count}`,
  `Skipped rules: ${esc((META.skipped_rules || []).join("; ") || "none")}`,
  `Extraction gaps: ${esc((META.extraction_gaps || []).map(g => g.split("\n")[0]).join("; ") || "none")}`,
  `Findings: ${F.length} | Fix-packs: ${packs.length}`,
].join("<br>");

// Trend (scan history) --------------------------------------------------------
const TREND = META.trend;
if (TREND && TREND.history && TREND.history.length > 1) {
  document.getElementById("trend-panel").style.display = "";
  document.getElementById("trend-title").textContent =
    `Trend (${TREND.history.length} scans stored)`;
  const hist = TREND.history;
  const max = Math.max(1, ...hist.map(h => h.findings));
  document.getElementById("trend-history").innerHTML = hist.map(h => `
    <div class="hrow" data-k="run ${h.run_id} (${esc(h.taken_at)})" data-v="${h.findings}">
      <div class="hlab">run ${h.run_id}</div>
      <div class="htrack"><div class="hbar" style="width:${(h.findings/max)*100}%;background:var(--series-1)"></div>
      <span class="hval">${h.findings}</span></div></div>`).join("");
  document.getElementById("trend-history").querySelectorAll(".hrow").forEach(r => {
    r.addEventListener("mousemove", e => {
      tip.textContent = `${r.dataset.k}: ${r.dataset.v} finding(s)`;
      tip.style.left = (e.clientX + 12) + "px"; tip.style.top = (e.clientY + 12) + "px";
      tip.style.opacity = 1;
    });
    r.addEventListener("mouseleave", () => tip.style.opacity = 0);
  });
  const chg = [];
  const chip = f => `<li><span class="chip sev ${esc(f.severity)}" style="background:${f.severity==="Low"||f.severity==="Informational" ? "" : SEVC[f.severity]}">${esc(f.severity)}</span> ${esc(f.title)}</li>`;
  chg.push(`<h2 style="font-weight:500">Since run ${TREND.prev_run_id}</h2>`);
  chg.push(`<div class="trace" style="margin-bottom:6px">${TREND.new.length} new, ${TREND.resolved.length} resolved, ${TREND.persisting_count} persisting</div>`);
  if (TREND.new.length) chg.push(`<h4 class="trace">New</h4><ul style="margin:4px 0;padding-left:18px">${TREND.new.map(chip).join("")}</ul>`);
  if (TREND.resolved.length) chg.push(`<h4 class="trace" style="color:var(--st-good)">Resolved</h4><ul style="margin:4px 0;padding-left:18px">${TREND.resolved.map(chip).join("")}</ul>`);
  if (!TREND.new.length && !TREND.resolved.length) chg.push(`<div class="trace">No change in findings since the previous scan.</div>`);
  document.getElementById("trend-changes").innerHTML = chg.join("");
}

// Theme toggle --------------------------------------------------------------
document.getElementById("theme-toggle").addEventListener("click", () => {
  const r = document.documentElement;
  const cur = r.getAttribute("data-theme");
  const dark = matchMedia("(prefers-color-scheme: dark)").matches;
  r.setAttribute("data-theme", cur ? (cur === "dark" ? "light" : "dark") : (dark ? "light" : "dark"));
});
</script>
</body>
</html>
"""
