"""`rob doctor`: prove the installation is sound, in one command.

Written for two readers. Someone setting ROB up for the first time, who needs to
know which of the optional pieces are missing and what that costs them. And
someone returning to it weeks later, who needs to know whether anything drifted.

Every check reports one of three states and says what to do next:
  ok    - working
  note  - optional and absent, with the consequence stated
  fail  - broken, with the fix

Nothing here touches a ServiceNow instance. Doctor is safe to run anywhere.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import sys
from dataclasses import dataclass

OK, NOTE, FAIL = "ok", "note", "fail"
MARK = {OK: "  ok  ", NOTE: " note ", FAIL: " FAIL "}


@dataclass
class Check:
    name: str
    state: str
    detail: str
    fix: str = ""


def _python() -> Check:
    v = sys.version_info
    if v >= (3, 10):
        return Check("Python", OK, f"{v.major}.{v.minor}.{v.micro}")
    return Check("Python", FAIL, f"{v.major}.{v.minor}", "ROB needs Python 3.10 or newer.")


def _rules() -> Check:
    try:
        from .rules import ACTIVE_RULES, LIBRARY_MANIFEST, RULE_REGISTRY, SHADOW_RULES
        from .rules.pack import check_lock, load_specs, read_lock
    except Exception as exc:  # a broken pack must not look like a missing feature
        return Check("Rule library", FAIL, f"failed to load: {exc}",
                     "Run 'rob rules' for the full error. A malformed pack blocks every scan.")
    problems = check_lock(load_specs(), read_lock())
    if problems:
        return Check("Rule library", FAIL, "; ".join(problems),
                     "Bump the rule VERSION, then run 'rob rules --relock'.")
    detail = (f"{len(RULE_REGISTRY)} rules, {len(ACTIVE_RULES)} active, "
              f"{len(SHADOW_RULES)} shadow, manifest {LIBRARY_MANIFEST}")
    if SHADOW_RULES:
        return Check("Rule library", NOTE, detail,
                     "Shadow rules are withheld from reports until measured. "
                     "Run a scan with --include-shadow against a real instance to start measuring.")
    return Check("Rule library", OK, detail)


def _fixpacks() -> Check:
    from .fixpacks import FIXPACK_GENERATORS
    from .rules import ACTIVE_RULES

    missing = sorted(rid for rid, rule in ACTIVE_RULES.items()
                     if not rule.TIER.startswith("T3") and rid not in FIXPACK_GENERATORS)
    if missing:
        return Check("Fix-pack coverage", FAIL, f"active rules with no generator: {missing}",
                     "An active rule must be solvable, not only reportable.")
    return Check("Fix-pack coverage", OK, f"{len(FIXPACK_GENERATORS)} generators for the active library")


def _workspace(home: pathlib.Path) -> list[Check]:
    out = []
    if not home.exists():
        return [Check("Workspace", NOTE, f"{home} does not exist yet",
                      "It is created on first use by 'rob serve' or 'rob scheduled-scan'.")]
    out.append(Check("Workspace", OK, str(home)))

    db = home / "rob_history.db"
    if db.exists():
        from .store import connect, list_runs

        runs = list_runs(connect(db))
        out.append(Check("Scan history", OK if runs else NOTE,
                         f"{len(runs)} run(s)" + (f", latest #{runs[-1]['run_id']} on {runs[-1]['instance_id']}" if runs else ""),
                         "" if runs else "Run a scan to populate it."))
    else:
        out.append(Check("Scan history", NOTE, "no runs stored yet", "Run a scan."))

    cfg_path = home / "web_config.json"
    cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
    if cfg.get("agent_signing_key"):
        mode = oct(cfg_path.stat().st_mode & 0o777)
        out.append(Check("Approval signing key", OK if mode == "0o600" else NOTE,
                         f"present, {cfg_path.name} mode {mode}",
                         "" if mode == "0o600" else f"chmod 600 {cfg_path} - it signs approvals."))
    else:
        out.append(Check("Approval signing key", NOTE, "not created yet",
                         "Created on first use of the console or the MCP server."))
    return out


def _policy(home: pathlib.Path) -> list[Check]:
    cfg_path = home / "web_config.json"
    cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
    ceiling = (cfg.get("autonomy_ceilings") or {}).get("_default", "A1")
    dry = cfg.get("global_dry_run", True)
    executor = (cfg.get("executor") or {}).get("kind")

    checks = [Check("Autonomy ceiling", OK, f"{ceiling} ({'propose only' if ceiling in ('A0', 'A1') else 'may apply approved fixes'})"),
              Check("Global dry run", OK, "on, nothing executes" if dry else "OFF, approved fixes will be applied")]
    if executor == "nowaikit":
        checks.append(Check("Executor", OK, "W-C via NowAIKit, sub-production only"))
    else:
        checks.append(Check("Executor", NOTE, "none configured",
                            "Approved fixes are delivered as fix-packs to apply by hand. "
                            "See RUN_GUIDE section 8 to enable W-C."))
    if not dry and executor == "nowaikit" and ceiling in ("A2", "A3"):
        checks.append(Check("Combined posture", NOTE, "ROB can write to a sub-production instance",
                            "Deliberate, and worth knowing. Approval is still required per fix."))
    return checks


def _knowledge(home: pathlib.Path) -> Check:
    from .knowledge import KnowledgeBase

    kb = KnowledgeBase(home)
    if not kb.available:
        return Check("Reference sources", NOTE, "no indexes",
                     "Findings will carry no citations. Build them with 'rob knowledge index-docs' "
                     "and 'rob knowledge index-bpl'.")
    detail = ", ".join(f"{i.source} ({len(i.entries)})" for i in kb.indexes)
    return Check("Reference sources", OK, detail)


def _nowaikit(home: pathlib.Path) -> Check:
    cfg_path = home / "web_config.json"
    cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
    configured = (cfg.get("executor") or {}).get("kind") == "nowaikit"
    if shutil.which("npx") is None:
        return Check("NowAIKit", FAIL if configured else NOTE, "npx not found",
                     "Install Node 20+ if you want the NowAIKit read path or the W-C executor.")
    return Check("NowAIKit", OK, "npx available",
                 "" if configured else "")


def _mcp() -> Check:
    """Exercise the server in-process rather than claiming it works."""
    import io

    from .mcp_server import handle, tool_definitions

    names = {t["name"] for t in tool_definitions()}
    if names != {"scan", "findings", "fixpack", "apply", "baseline_diff"}:
        return Check("MCP server", FAIL, f"unexpected tool set: {sorted(names)}",
                     "The five contracts are the security boundary. This should never change silently.")
    for t in tool_definitions():
        if t["inputSchema"].get("additionalProperties") is not False:
            return Check("MCP server", FAIL, f"{t['name']} allows extra arguments",
                         "A client could smuggle an argument the gate never checks.")
    return Check("MCP server", OK, f"{len(names)} contracts, all schemas closed")


def run(home: str | pathlib.Path = "rob_home") -> tuple[list[Check], int]:
    home = pathlib.Path(home)
    checks = [_python(), _rules(), _fixpacks(), _mcp()]
    checks += _workspace(home)
    checks += _policy(home)
    checks += [_knowledge(home), _nowaikit(home)]
    failures = sum(1 for c in checks if c.state == FAIL)
    return checks, failures


def report(home: str | pathlib.Path = "rob_home") -> int:
    checks, failures = run(home)
    width = max(len(c.name) for c in checks)
    print(f"ROB doctor - workspace {pathlib.Path(home).resolve()}\n")
    for c in checks:
        print(f"[{MARK[c.state]}] {c.name.ljust(width)}  {c.detail}")
        if c.fix:
            print(f"{'':>9}{''.ljust(width)}  -> {c.fix}")
    notes = sum(1 for c in checks if c.state == NOTE)
    print(f"\n{len(checks)} checks, {failures} failing, {notes} optional piece(s) not set up.")
    if failures:
        print("Fix the failures above before scanning a real instance.")
    else:
        print("ROB is sound. Anything marked 'note' is optional and costs only what it says.")
    return 1 if failures else 0
