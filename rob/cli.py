"""ROB CLI: run a scan against a snapshot file.

Usage:
    python -m rob scan --snapshot fixtures/pdi_like_snapshot.json --out out/
"""
from __future__ import annotations

import argparse
import json
import pathlib

from .engine import run_scan
from .models import Snapshot
from .report import executive_summary, technical_report


def load_snapshot(path: str) -> Snapshot:
    data = json.loads(pathlib.Path(path).read_text())
    return Snapshot(
        instance_id=data["instance_id"],
        taken_at=data["taken_at"],
        tables=data.get("tables", {}),
        aggregates=data.get("aggregates", {}),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rob", description="ROB - Remediation & Optimisation Bot (MVP skeleton)")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run all rules against a snapshot")
    scan.add_argument("--snapshot", required=True, help="Path to snapshot JSON")
    scan.add_argument("--out", default="out", help="Output directory")
    scan.add_argument("--upgrade-planned", action="store_true", help="Family upgrade planned within a quarter (exposure adjustment)")
    scan.add_argument("--risks", default="accepted_risks.json", help="Accepted-risk register file")
    scan.add_argument("--db", default="rob_history.db", help="Scan history database (empty string disables)")
    scan.add_argument("--include-shadow", action="store_true",
                      help="Promote shadow rules (confidence below 'validated') into this run's findings. "
                           "Use for false-positive measurement, never for a customer report.")

    hist = sub.add_parser("history", help="List stored scan runs")
    hist.add_argument("--db", default="rob_history.db")
    hist.add_argument("--instance", default=None)

    accept_cmd = sub.add_parser("accept", help="Formally accept a finding by fingerprint")
    accept_cmd.add_argument("--fingerprint", required=True, help='e.g. "ROB-SEC-001:sys_user_has_role (admin)"')
    accept_cmd.add_argument("--reason", required=True)
    accept_cmd.add_argument("--by", default="", help="Who accepted (defaults to OS user)")
    accept_cmd.add_argument("--risks", default="accepted_risks.json")

    rules_cmd = sub.add_parser("rules", help="List the installed rule library with basis references")
    rules_cmd.add_argument("--relock", action="store_true",
                           help="Rewrite rob/rules/packs/pack.lock.json after a deliberate, version-bumped "
                                "rule pack change. Refuses if any rule changed logic without a version bump.")

    serve_cmd = sub.add_parser("serve", help="Start the ROB web interface")
    serve_cmd.add_argument("--home", default="rob_home", help="ROB workspace directory (config, history, runs)")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=8422)

    dash = sub.add_parser("dashboard", help="Render the interactive HTML dashboard from a findings.json")
    dash.add_argument("--findings", required=True, help="Path to findings.json")
    dash.add_argument("--instance", default="unknown-instance")
    dash.add_argument("--taken-at", default="", help="Snapshot timestamp label")
    dash.add_argument("--out", default="dashboard.html")

    diff_cmd = sub.add_parser("diff", help="Trend diff between two findings.json files or stored runs")
    diff_cmd.add_argument("baseline", nargs="?", help="Older findings.json")
    diff_cmd.add_argument("current", nargs="?", help="Newer findings.json")
    diff_cmd.add_argument("--runs", nargs=2, type=int, metavar=("OLD", "NEW"), help="Diff two stored run ids")
    diff_cmd.add_argument("--db", default="rob_history.db")
    diff_cmd.add_argument("--out", default="", help="Optional output file (default: print)")

    mcp_cmd = sub.add_parser("mcp", help="Run ROB as an MCP server over stdio (point Claude Desktop at this)")
    mcp_cmd.add_argument("--home", default="rob_home", help="ROB workspace to serve (share it with 'rob serve')")

    sched = sub.add_parser("scheduled-scan", help="Extract, scan, diff against the previous run and notify")
    sched.add_argument("--home", default="rob_home", help="ROB workspace")
    sched.add_argument("--instance", default="", help="Instance URL for the native read path")
    sched.add_argument("--user", default="", help="Service account user name")
    sched.add_argument("--snapshot", default="", help="Use an existing snapshot file instead of extracting")
    sched.add_argument("--via", choices=("native", "nowaikit"), default="native")
    sched.add_argument("--nowaikit-url", default="")
    sched.add_argument("--nowaikit-token", default="")
    sched.add_argument("--nowaikit-command", default="npx -y nowaikit-mcp")
    sched.add_argument("--always-notify", action="store_true",
                       help="Notify even when nothing changed. Silence reads the same as a broken scheduler.")

    doc = sub.add_parser("doctor", help="Check this installation and say what is missing")
    doc.add_argument("--home", default="rob_home", help="Workspace to inspect")

    know = sub.add_parser("knowledge", help="Index and search reference sources (ServiceNow docs, Best Practices Library)")
    know.add_argument("action", choices=("index-docs", "index-bpl", "search", "status"))
    # nargs="*" after an optional is ambiguous to argparse, so
    #   rob knowledge search --home X some terms
    # would fail while
    #   rob knowledge search some terms --home X
    # worked. Neither order should be wrong for a search box.
    know.add_argument("query", nargs="*", default=[], help="Search terms for 'search'")
    know.add_argument("--q", dest="q", default="", help="Search terms, if you prefer a flag")
    know.add_argument("--home", default="rob_home", help="Workspace the index is written to and read from")
    know.add_argument("--repo", default="", help="Path to a ServiceNowDocs clone (index-docs)")
    know.add_argument("--branch", default="australia", help="Release family branch the clone is on")
    know.add_argument("--catalog", default="", help="Path to a BPL-Scraper library/catalog.json (index-bpl)")
    know.add_argument("--files", default="", help="Path to BPL-Scraper library/files, to link local copies")
    know.add_argument("--files-as", default="",
                      help="Record local paths under this root instead of --files. Use when the index "
                           "is built where the library is mounted and read where it is not.")

    probe = sub.add_parser("nowaikit-probe", help="Report what a NowAIKit MCP server can do for ROB (inventory plan, Part A)")
    # NOT --command: the subparsers dest is "command", so that flag would overwrite
    # the subcommand name itself and route every probe call to the scan branch.
    probe.add_argument("--server-command", default="npx -y nowaikit-mcp", help="Command to start the stdio server")
    probe.add_argument("--url", default="", help="HTTP transport URL instead of stdio")
    probe.add_argument("--token", default="", help="Bearer token for the HTTP transport")

    extract = sub.add_parser("extract", help="Read-only extraction from a ServiceNow instance to snapshot JSON")
    extract.add_argument("--instance", default="", help="Instance URL, e.g. https://dev12345.service-now.com (native path)")
    extract.add_argument("--user", default="", help="Service account user name (profile R-A, native path)")
    extract.add_argument("--snapshot-out", default="snapshot.json", help="Output snapshot path")
    extract.add_argument("--via", choices=("native", "nowaikit"), default="native",
                         help="Read path. 'native' uses ROB's own GET-only REST client. 'nowaikit' reads "
                              "through a NowAIKit MCP server, which holds its own instance credentials.")
    extract.add_argument("--nowaikit-url", default="", help="NowAIKit HTTP transport URL (omit to spawn stdio)")
    extract.add_argument("--nowaikit-token", default="", help="Bearer token for the NowAIKit HTTP transport")
    extract.add_argument("--nowaikit-command", default="npx -y nowaikit-mcp",
                         help="Command to start the NowAIKit stdio server")
    args = parser.parse_args(argv)

    if args.command == "serve":
        from .web import serve

        serve(args.home, args.host, args.port)
        return 0

    if args.command == "rules":
        if getattr(args, "relock", False):
            from .rules.pack import load_specs, write_lock

            specs = load_specs()  # raises if logic changed without a version bump
            write_lock(specs)
            print(f"pack.lock.json rewritten for {len(specs)} rule(s).")
            return 0

        from .rules import ACTIVE_RULES, DECLARATIVE_RULES, LIBRARY_MANIFEST, RULE_REGISTRY, SHADOW_RULES

        from .fixpacks import FIXPACK_GENERATORS

        declarative_ids = {r.ID for r in DECLARATIVE_RULES}
        for rid in sorted(RULE_REGISTRY):
            r = RULE_REGISTRY[rid]
            pack = "fix-pack" if rid in FIXPACK_GENERATORS else ("guidance (T3)" if r.TIER.startswith("T3") else "no pack yet")
            state = "active" if r.CONFIDENCE == "validated" else f"SHADOW ({r.CONFIDENCE})"
            origin = "pack" if rid in declarative_ids else "core"
            print(f"{rid} v{r.VERSION} [{r.TIER}/{r.AUTONOMY}] {r.TITLE}")
            print(f"    category: {r.CATEGORY} | owner: {r.OWNER} | solve: {pack} | {state} | source: {origin}")
            for ref in r.REFERENCES:
                print(f"    basis: {ref}")
        print(
            f"\n{len(RULE_REGISTRY)} rules ({len(ACTIVE_RULES)} active, {len(SHADOW_RULES)} shadow). "
            f"Library manifest: {LIBRARY_MANIFEST}"
        )
        print("Shadow rules are measured, not reported: run 'scan --include-shadow' to see their findings.")
        print("Specifications: scanner/scan-rules.md and rob/rules/packs/. Authoring guide: RULE_AUTHORING.md")
        return 0

    if args.command == "mcp":
        from .mcp_server import serve_stdio

        return serve_stdio(args.home)

    if args.command == "scheduled-scan":
        import os

        from .schedule import run_scheduled_scan

        home = pathlib.Path(args.home)
        if args.snapshot:
            snapshot = load_snapshot(args.snapshot)
        elif args.via == "nowaikit":
            from .extractor import build_snapshot
            from .nowaikit import NowAIKitClient

            client = (NowAIKitClient.http(args.nowaikit_url, args.nowaikit_token) if args.nowaikit_url
                      else NowAIKitClient.stdio(args.nowaikit_command.split()))
            iid = args.instance.split("//")[-1].split(".")[0] if args.instance else "nowaikit-instance"
            try:
                raw = build_snapshot(client, iid, progress=lambda *_: None)
            finally:
                client.close()
            snapshot = Snapshot(raw["instance_id"], raw["taken_at"], raw["tables"], raw["aggregates"])
        else:
            from .extractor import SNClient, build_snapshot

            password = os.environ.get("ROB_SN_PASSWORD", "")
            if not (args.instance and args.user and password):
                print("scheduled-scan needs --instance, --user and ROB_SN_PASSWORD in the environment,")
                print("or --snapshot to scan a file. A scheduled job must never prompt.")
                return 2
            iid = args.instance.split("//")[-1].split(".")[0]
            raw = build_snapshot(SNClient(args.instance, args.user, password), iid, progress=lambda *_: None)
            snapshot = Snapshot(raw["instance_id"], raw["taken_at"], raw["tables"], raw["aggregates"])

        cfg_path = home / "web_config.json"
        cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
        outcome = run_scheduled_scan(home, snapshot, cfg.get("notify"), always_notify=args.always_notify)
        print(f"\nRun {outcome['run_id']} stored. Outputs: {outcome['out_dir']}")
        return 0

    if args.command == "doctor":
        from .doctor import report

        return report(args.home)

    if args.command == "knowledge":
        from .knowledge import BPL_INDEX_NAME, DOCS_INDEX_NAME, KnowledgeBase, build_bpl_index, build_docs_index

        home = pathlib.Path(args.home)
        home.mkdir(parents=True, exist_ok=True)

        if args.action == "index-docs":
            if not args.repo:
                print("Need --repo pointing at a ServiceNowDocs clone. Get one with:")
                print("  git clone --depth 1 https://github.com/ServiceNow/ServiceNowDocs")
                return 2
            print(json.dumps(build_docs_index(args.repo, home / DOCS_INDEX_NAME, args.branch), indent=2))
            print("\nIndexed titles, areas and canonical links only. No document content is copied.")
            return 0

        if args.action == "index-bpl":
            if not args.catalog:
                print("Need --catalog pointing at your BPL-Scraper library/catalog.json.")
                return 2
            print(json.dumps(build_bpl_index(args.catalog, home / BPL_INDEX_NAME,
                                             args.files or None, args.files_as), indent=2))
            print("\nIndexed metadata and links only. Best Practices Library assets are ServiceNow")
            print("copyright behind a login: ROB points at them, it never reproduces their content.")
            return 0

        kb = KnowledgeBase(home)
        if args.action == "status":
            if not kb.available:
                print("No reference indexes in this workspace.")
                print("  rob knowledge index-docs --repo /path/to/ServiceNowDocs")
                print("  rob knowledge index-bpl  --catalog /path/to/BPL-Scraper/library/catalog.json")
                return 0
            for index in kb.indexes:
                print(f"{index.source}: {len(index.entries)} entries")
            return 0

        query = args.q or " ".join(args.query)
        if not query.strip():
            print("Give me something to search for, e.g.")
            print('  rob knowledge search admin role assignment')
            return 2
        refs = kb.search(query, limit_per_source=5)
        if not refs:
            print("No matches. Try broader terms, or check 'rob knowledge status'.")
            return 0
        for r in refs:
            print(f"[{r.score:4.0f}] {r.title}")
            print(f"       {r.source} | {r.area[:70]}")
            if r.url:
                print(f"       {r.url}")
            if r.local_path:
                print(f"       local: {r.local_path}")
        return 0

    if args.command == "nowaikit-probe":
        from .nowaikit import NowAIKitClient

        client = (NowAIKitClient.http(args.url, args.token) if args.url
                  else NowAIKitClient.stdio(args.server_command.split()))
        try:
            report = client.capability_report()
        finally:
            client.close()
        print(json.dumps(report, indent=2))
        print("\nROB reads through NowAIKit and never writes through it (D-011). Write tools listed above")
        print("are reported for the security review, not used.")
        return 0

    if args.command == "accept":
        import datetime as dt
        import getpass as gp

        from .risks import accept, load_register, save_register

        register = load_register(args.risks)
        accept(register, args.fingerprint, args.reason, args.by or gp.getuser(), dt.datetime.now(dt.timezone.utc))
        save_register(args.risks, register)
        print(f"Accepted: {args.fingerprint} (expires in 365 days). Register: {args.risks}")
        return 0

    if args.command == "dashboard":
        from .dashboard import render_dashboard

        findings = json.loads(pathlib.Path(args.findings).read_text())
        meta = {
            "instance_id": args.instance,
            "taken_at": args.taken_at or "(from findings file)",
            "rule_count": len({f["rule_id"] for f in findings}),
            "fixpacks": [
                {"name": f["fixpack_ref"], "rule_id": f["rule_id"], "finding_fingerprint": f"{f['rule_id']}:{f['affected_area']}"}
                for f in findings
                if f.get("fixpack_ref")
            ],
            "skipped_rules": [],
            "extraction_gaps": [],
        }
        pathlib.Path(args.out).write_text(render_dashboard(findings, meta))
        print(f"Dashboard written to {args.out} - open it in a browser.")
        return 0

    if args.command == "history":
        from .store import connect, list_runs

        runs = list_runs(connect(args.db), args.instance)
        if not runs:
            print("No stored runs." + (f" (instance {args.instance})" if args.instance else ""))
            return 0
        for r in runs:
            print(f"run {r['run_id']:>3} | {r['instance_id']} | {r['taken_at']} | {r['findings']} findings | {r['fixpacks']} fix-packs")
        return 0

    if args.command == "diff":
        from .diff import diff_runs, diff_scans

        if args.runs:
            text = diff_runs(args.db, args.runs[0], args.runs[1])
        elif args.baseline and args.current:
            text = diff_scans(args.baseline, args.current)
        else:
            print("Provide two findings.json paths or --runs OLD NEW")
            return 2
        text = text
        if args.out:
            pathlib.Path(args.out).write_text(text)
            print(f"Diff written to {args.out}")
        else:
            print(text)
        return 0

    if args.command == "extract":
        import getpass
        import os

        from .extractor import SNClient, build_snapshot

        if args.via == "nowaikit":
            from .nowaikit import NowAIKitClient

            client = (NowAIKitClient.http(args.nowaikit_url, args.nowaikit_token) if args.nowaikit_url
                      else NowAIKitClient.stdio(args.nowaikit_command.split()))
            instance_id = args.instance.split("//")[-1].split(".")[0] if args.instance else "nowaikit-instance"
            print("Reading through NowAIKit (read allowlist enforced; ROB never writes through it).")
            report = client.capability_report()
            if not report["supports_offset"]:
                print(f"  Note: {report['verdict']}")
            try:
                snap = build_snapshot(client, instance_id)
            finally:
                client.close()
        else:
            if not args.instance or not args.user:
                print("--instance and --user are required for the native read path.")
                return 2
            password = os.environ.get("ROB_SN_PASSWORD") or getpass.getpass(f"Password for {args.user}: ")
            instance_id = args.instance.split("//")[-1].split(".")[0]
            client = SNClient(args.instance, args.user, password)
            snap = build_snapshot(client, instance_id)
        pathlib.Path(args.snapshot_out).write_text(json.dumps(snap, indent=1))
        sizes = {t: len(rows) for t, rows in snap["tables"].items()}
        print(f"Snapshot written to {args.snapshot_out}")
        print(f"Record counts: {sizes}")
        print("Next: python3 -m rob scan --snapshot " + args.snapshot_out + " --out out/")
        return 0

    import datetime as dt

    from .report import backlog_csv
    from .risks import active_acceptances, load_register

    snapshot = load_snapshot(args.snapshot)
    params = {"upgrade_planned_within_quarter": args.upgrade_planned}
    accepted = active_acceptances(load_register(args.risks), dt.datetime.now(dt.timezone.utc))
    result = run_scan(snapshot, params, accepted, include_shadow=getattr(args, "include_shadow", False))

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "executive_summary.md").write_text(executive_summary(result))
    from .knowledge import KnowledgeBase

    _kb = KnowledgeBase(pathlib.Path(getattr(args, "home", "rob_home")))
    (out / "technical_report.md").write_text(technical_report(result, _kb if _kb.available else None))
    (out / "findings.json").write_text(json.dumps([f.to_dict() for f in result.findings], indent=2))
    (out / "backlog.csv").write_text(backlog_csv(result))

    stored_line = None
    trend = None
    if getattr(args, "db", ""):
        from .store import connect, store_run, trend_meta, trend_summary

        con = connect(args.db)
        run_id = store_run(con, result)
        trend = trend_meta(con, snapshot.instance_id, run_id)
        t_line = trend_summary(con, snapshot.instance_id, run_id)
        stored_line = f"Stored as run {run_id} in {args.db}" + (f"  |  {t_line}" if t_line else "  |  first stored run for this instance")

    from .dashboard import render_dashboard

    dash_meta = {
        "instance_id": snapshot.instance_id,
        "taken_at": snapshot.taken_at,
        "rule_count": len(result.rule_versions),
        "fixpacks": [
            {"name": p.name, "rule_id": p.rule_id, "finding_fingerprint": p.finding_fingerprint}
            for p in result.fixpacks
        ],
        "skipped_rules": result.skipped_rules,
        "extraction_gaps": snapshot.agg("extraction_errors", []),
        "trend": trend,
    }
    (out / "dashboard.html").write_text(render_dashboard([f.to_dict() for f in result.findings], dash_meta))

    packs_dir = out / "fixpacks"
    packs_dir.mkdir(exist_ok=True)
    for p in result.fixpacks:
        pdir = packs_dir / p.name
        pdir.mkdir(exist_ok=True)
        (pdir / p.fix_artefact_filename).write_text(p.fix_artefact)
        (pdir / "dry_run.js").write_text(p.dry_run)
        (pdir / p.backout_filename).write_text(p.backout)
        (pdir / "INSTRUCTIONS.md").write_text(
            f"# {p.name}\n\nFinding: `{p.finding_fingerprint}`\n\n## Scope\n\n{p.scope_statement}\n\n## Steps\n\n{p.instructions}\n"
        )

    if stored_line:
        print(stored_line)

    print(f"Findings: {len(result.findings)}  |  by priority: {result.by_priority}  |  by severity: {result.by_severity}")
    print(f"Fix-packs: {[p.name for p in result.fixpacks]}")
    if result.shadow_findings:
        _shadow_rules = sorted({f.rule_id for f in result.shadow_findings})
        print(
            f"Shadow: {len(result.shadow_findings)} finding(s) withheld from {len(_shadow_rules)} unvalidated "
            f"rule(s) {_shadow_rules}. Re-run with --include-shadow to measure them."
        )
    if result.skipped_rules:
        print(f"Skipped rules: {result.skipped_rules}")
    print(f"Reports written to {out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
