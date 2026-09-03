"""W-C executor: apply an approved fix-pack through NowAIKit (D-019).

Why this exists: D-005 chose W-B, a ROB scoped app installed inside the
instance, which has the better attribution story. W-B does not exist. NowAIKit
does, and it has update sets, guardrails and an audit log. This is the interim
executor for sub-production, behind every gate the orchestrator already applies.

Three design decisions worth stating, because each rejects an easier option.

1. TYPED OPERATIONS, NOT BACKGROUND SCRIPTS. NowAIKit exposes
   execute_background_script and run_fix_script, and ROB's fix artefacts are
   JavaScript, so running them would have been the quick path. It is refused
   here. A background script is a black box: it cannot be diffed before it runs,
   cannot be bounded, cannot be reversed per record, and NowAIKit's own table and
   field guardrails cannot see inside it. Every write this executor makes is a
   declared operation on a named record, so it can be previewed, guarded,
   verified and reversed individually.

2. SECURITY RECORDS ARE NEVER WRITTEN HERE, even with a human approval. ACLs,
   roles, group membership and user records go through W-B or a human. A wrong
   ACL is an outage or a breach, and this executor's attribution story is a
   service account rather than in-instance governance. That is good enough for a
   system property, not for access control.

3. BACKOUT IS CAPTURED BEFORE THE FIRST WRITE, by reading current state from the
   instance rather than trusting what the fix-pack recorded at generation time.
   The instance may have moved since the scan.
"""
from __future__ import annotations

import datetime as dt
import json
import re

from .models import EXECUTOR_FORBIDDEN_TABLES as FORBIDDEN_TABLES
from .nowaikit import NowAIKitError, NowAIKitClient

# Operation kinds this executor understands. Anything else is refused, so a
# future fix-pack generator cannot widen the executor's reach by accident.
OPERATION_KINDS = ("set_property", "update_record", "delete_record")

WRITE_TOOLS = {
    "set_property": "set_system_property",
    "update_record": "update_record",
    "delete_record": "delete_record",
}
UPDATE_SET_TOOLS = ("create_update_set", "switch_update_set", "complete_update_set", "export_update_set")
READ_TOOLS = ("query_records", "get_record")


class ExecutionRefused(RuntimeError):
    """A precondition failed. Nothing was written. The message is safe to show."""


class ExecutionFailed(RuntimeError):
    """A write failed partway. Carries what was rolled back and what was not."""

    def __init__(self, message: str, applied: list, rolled_back: list, residual: list):
        super().__init__(message)
        self.applied, self.rolled_back, self.residual = applied, rolled_back, residual


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")[:40]


class WriteClient(NowAIKitClient):
    """A NowAIKit client permitted to write, used ONLY by this executor.

    Deliberately a separate class from NowAIKitClient: the read path's allowlist
    is a safety property that extraction depends on, and widening it in place
    would have removed that property everywhere to serve one caller.
    """

    PERMITTED = frozenset(READ_TOOLS) | frozenset(WRITE_TOOLS.values()) | frozenset(UPDATE_SET_TOOLS)
    PERMISSION_HINT = (
        "Background script execution is deliberately excluded: a script cannot be "
        "previewed, bounded or reversed per record."
    )


class NowAIKitExecutor:
    """Applies a fix-pack's declared operations inside a named update set."""

    def __init__(self, client: WriteClient, instance_id: str = ""):
        self.client = client
        self.instance_id = instance_id

    # -- preconditions --------------------------------------------------------

    def preflight(self, pack) -> dict:
        """Everything checked before a single write. Raises, or returns a plan."""
        if not pack.operations:
            raise ExecutionRefused(
                f"Fix-pack '{pack.name}' has no machine-applicable operations. Its fix is a script, "
                "which this executor will not run: a script cannot be previewed, bounded or reversed "
                "per record. Apply it by hand using the pack's instructions."
            )
        missing_write = [t for t in WRITE_TOOLS.values() if self.client.tool_names and t not in self.client.tool_names]
        missing_us = [t for t in UPDATE_SET_TOOLS if self.client.tool_names and t not in self.client.tool_names]
        if missing_write or missing_us:
            raise ExecutionRefused(
                "NowAIKit is not configured for execution. Missing tools: "
                f"{missing_write + missing_us}. Start it with WRITE_ENABLED=true, "
                "or apply the fix-pack by hand."
            )
        for op in pack.operations:
            if op.get("kind") not in OPERATION_KINDS:
                raise ExecutionRefused(f"Unknown operation kind '{op.get('kind')}'. Known: {list(OPERATION_KINDS)}")
            table = (op.get("table") or "").lower()
            if table in FORBIDDEN_TABLES:
                raise ExecutionRefused(
                    f"Operation targets '{table}', which W-C never writes even with an approval. "
                    "Access control and identity changes go through the in-instance executor (W-B) "
                    "or a human. Apply this fix-pack by hand."
                )
            if not op.get("key"):
                raise ExecutionRefused("Every operation needs a 'key' identifying the record it touches.")
            unbound = sorted(
                v["$input"] for v in (op.get("after") or {}).values()
                if isinstance(v, dict) and "$input" in v
            )
            if unbound:
                raise ExecutionRefused(
                    f"Operation on {op.get('table')}/{op.get('key')} has unbound inputs {unbound}. "
                    "A declared input is a question only the approver can answer: bind values with "
                    "rob.fixpacks.declarative.bind_inputs before execution. Nothing was written."
                )
        return {"operations": len(pack.operations),
                "update_set": f"ROB {_slug(pack.name)}",
                "kinds": sorted({op["kind"] for op in pack.operations})}

    # -- state ---------------------------------------------------------------

    def read_current(self, op: dict) -> dict:
        """Read live state for one operation. This is the backout, not the pack's copy."""
        if op["kind"] == "set_property":
            rows = self.client.call("query_records", {
                "table": "sys_properties", "query": f"name={op['key']}", "fields": "sys_id,name,value", "limit": 2})
            records = rows if isinstance(rows, list) else (rows.get("records") or rows.get("result") or [])
            if not records:
                return {"exists": False}
            return {"exists": True, "sys_id": records[0].get("sys_id"), "value": records[0].get("value")}
        data = self.client.call("get_record", {"table": op["table"], "sys_id": op["key"]})
        record = data.get("record") if isinstance(data, dict) and "record" in data else data
        return {"exists": bool(record), "record": record}

    # -- application ----------------------------------------------------------

    def _apply_one(self, op: dict) -> dict:
        if op["kind"] == "set_property":
            return self.client.call("set_system_property", {"name": op["key"], "value": op["after"]["value"]})
        if op["kind"] == "update_record":
            return self.client.call("update_record", {"table": op["table"], "sys_id": op["key"], "fields": op["after"]})
        if op["kind"] == "delete_record":
            return self.client.call("delete_record", {"table": op["table"], "sys_id": op["key"]})
        raise ExecutionRefused(f"Unhandled kind '{op['kind']}'")

    def _revert_one(self, op: dict, before: dict) -> None:
        if op["kind"] == "set_property":
            if before.get("exists"):
                self.client.call("set_system_property", {"name": op["key"], "value": before.get("value")})
            # A property ROB created cannot be un-created by set_system_property.
            # Recording it as residual is more honest than pretending to revert.
            return
        if op["kind"] == "update_record" and before.get("record"):
            self.client.call("update_record", {
                "table": op["table"], "sys_id": op["key"],
                "fields": {k: before["record"].get(k) for k in op["after"]}})
            return
        raise ExecutionRefused(f"'{op['kind']}' cannot be reverted automatically")

    def apply(self, pack, dry_run: bool = False, now: str | None = None) -> dict:
        """Apply the pack. Returns a result describing exactly what happened."""
        plan = self.preflight(pack)
        stamp = now or dt.datetime.now(dt.timezone.utc).isoformat()

        # 1. Capture live before-state for every operation, before any write.
        captured = []
        for op in pack.operations:
            captured.append({"op": op, "before": self.read_current(op)})

        preview = [
            {"kind": c["op"]["kind"], "table": c["op"]["table"], "key": c["op"]["key"],
             "label": c["op"].get("label", ""), "live_before": c["before"],
             "already_correct": self._already_correct(c["op"], c["before"])}
            for c in captured
        ]
        if dry_run:
            return {"dry_run": True, "plan": plan, "preview": preview, "captured_at": stamp,
                    "note": "Nothing was written. Backout state was read from the live instance."}

        # 2. Named update set, so every change is captured and exportable.
        us = self.client.call("create_update_set", {
            "name": f"{plan['update_set']} {stamp[:19]}",
            "description": f"ROB fix-pack {pack.name} for {pack.finding_fingerprint}. "
                           "Generated and applied by ROB with a human approval.",
        })
        update_set_id = (us.get("sys_id") or us.get("result", {}).get("sys_id") if isinstance(us, dict) else None)
        if update_set_id:
            self.client.call("switch_update_set", {"sys_id": update_set_id})

        # 3. Apply, stopping at the first failure and reversing what landed.
        applied = []
        try:
            for c in captured:
                if c["before"].get("exists") is False and c["op"]["kind"] in ("update_record", "delete_record"):
                    raise ExecutionFailed(
                        f"Record {c['op']['table']}/{c['op']['key']} no longer exists. The instance moved "
                        "since the scan; re-scan before applying.", applied, [], [])
                if self._already_correct(c["op"], c["before"]):
                    continue  # idempotent: nothing to do, and nothing to back out
                self._apply_one(c["op"])
                applied.append(c)
        except (NowAIKitError, ExecutionFailed) as exc:
            rolled_back, residual = [], []
            for c in reversed(applied):
                try:
                    self._revert_one(c["op"], c["before"])
                    rolled_back.append(c["op"]["key"])
                except (NowAIKitError, ExecutionRefused) as revert_exc:
                    residual.append({"key": c["op"]["key"], "error": str(revert_exc)})
            raise ExecutionFailed(
                f"Apply failed and was rolled back: {exc}", [c["op"]["key"] for c in applied], rolled_back, residual
            ) from exc

        # 4. Verify by reading back, not by trusting the write call's return value.
        verification = []
        for c in applied:
            after = self.read_current(c["op"])
            verification.append({"key": c["op"]["key"], "verified": self._already_correct(c["op"], after)})
        failed = [v["key"] for v in verification if not v["verified"]]

        # 5. Complete and export. The export is the rollback artefact.
        export = None
        if update_set_id:
            try:
                self.client.call("complete_update_set", {"sys_id": update_set_id})
                export = self.client.call("export_update_set", {"sys_id": update_set_id})
            except NowAIKitError as exc:
                export = {"error": str(exc)}

        return {
            "dry_run": False,
            "plan": plan,
            "applied": [c["op"]["key"] for c in applied],
            "skipped_already_correct": [c["op"]["key"] for c in captured if self._already_correct(c["op"], c["before"])],
            "verification": verification,
            "verification_failures": failed,
            "change_reference": update_set_id,
            "rollback_artefact": export,
            "backout_state": json.dumps([{"key": c["op"]["key"], "before": c["before"]} for c in captured], indent=2),
            "applied_at": stamp,
        }

    @staticmethod
    def _already_correct(op: dict, state: dict) -> bool:
        if op["kind"] == "set_property":
            return state.get("exists") and str(state.get("value")) == str(op["after"]["value"])
        if op["kind"] == "delete_record":
            return state.get("exists") is False
        record = state.get("record") or {}
        return bool(record) and all(str(record.get(k)) == str(v) for k, v in op["after"].items())


NOT_CONFIGURED = (
    "No execution mechanism is configured for this workspace. Set executor.kind to "
    "'nowaikit' in web_config.json to enable W-C on sub-production, or apply the "
    "fix-pack by hand."
)


def assert_executor_configured(config: dict) -> None:
    """Cheap check, run before anything expensive. Spawning an MCP server to
    discover that none is configured would be a slow way to say no."""
    if ((config or {}).get("executor") or {}).get("kind") != "nowaikit":
        raise ExecutionRefused(NOT_CONFIGURED)


def build_executor(config: dict, instance_id: str = "") -> NowAIKitExecutor:
    """Construct from the workspace's executor config. Raises if not configured."""
    ex = (config or {}).get("executor") or {}
    if ex.get("kind") != "nowaikit":
        raise ExecutionRefused(
            "No execution mechanism is configured for this workspace. Set executor.kind to "
            "'nowaikit' in web_config.json to enable W-C on sub-production, or apply the "
            "fix-pack by hand."
        )
    client = (WriteClient.http(ex["url"], ex.get("token", "")) if ex.get("url")
              else WriteClient.stdio(ex.get("command", "npx -y nowaikit-mcp").split(),
                                     env={"WRITE_ENABLED": "true"}))
    return NowAIKitExecutor(client, instance_id)
