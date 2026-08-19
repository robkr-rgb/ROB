#!/usr/bin/env python3
"""A fake NowAIKit with write tools, for executor tests.

Holds a tiny mutable instance in memory so a test can assert what actually
changed. Also exposes execute_background_script, so a test can prove ROB's
executor refuses to call it even when the server offers it.

Failure injection: set FAKE_FAIL_ON to a property name to make the write for
that property fail, which is how rollback gets tested.
"""
import json
import os
import sys

PROPERTIES = {
    "glide.ui.security.allow_codetag": "true",
    "glide.basicauth.required.xml": "false",
    "glide.stale.property": "old",
}
RECORDS = {"cmdb_rel_ci": {"rel1": {"sys_id": "rel1", "parent": "p1", "child": "gone"}}}
UPDATE_SETS = {}
FAIL_ON = os.environ.get("FAKE_FAIL_ON", "")

TOOLS = [{"name": n} for n in (
    "query_records", "get_record", "get_table_schema", "run_aggregate_query",
    "list_relationships", "search_cmdb_ci", "get_cmdb_ci",
    "set_system_property", "update_record", "delete_record", "create_record",
    "create_update_set", "switch_update_set", "complete_update_set", "export_update_set",
    "execute_background_script", "run_fix_script",
)]


def ok(rid, payload):
    return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(payload)}]}}


def err(rid, message):
    return {"jsonrpc": "2.0", "id": rid, "result": {"isError": True, "content": [{"type": "text", "text": message}]}}


def handle(rid, name, args):
    if name == "query_records":
        table, query = args.get("table"), args.get("query", "")
        if table == "sys_properties" and query.startswith("name="):
            key = query.split("=", 1)[1]
            if key in PROPERTIES:
                return ok(rid, {"records": [{"sys_id": f"prop-{key}", "name": key, "value": PROPERTIES[key]}]})
            return ok(rid, {"records": []})
        return ok(rid, {"records": list(RECORDS.get(table, {}).values())})
    if name == "get_record":
        return ok(rid, {"record": RECORDS.get(args.get("table"), {}).get(args.get("sys_id"))})
    if name == "set_system_property":
        if args.get("name") == FAIL_ON:
            return err(rid, f"simulated write failure on {FAIL_ON}")
        PROPERTIES[args["name"]] = args["value"]
        return ok(rid, {"name": args["name"], "value": args["value"]})
    if name == "update_record":
        rec = RECORDS.setdefault(args["table"], {}).get(args["sys_id"])
        if rec is None:
            return err(rid, "no such record")
        rec.update(args.get("fields", {}))
        return ok(rid, {"record": rec})
    if name == "delete_record":
        RECORDS.get(args["table"], {}).pop(args["sys_id"], None)
        return ok(rid, {"deleted": True})
    if name == "create_update_set":
        sid = f"us{len(UPDATE_SETS) + 1}"
        UPDATE_SETS[sid] = {"sys_id": sid, "name": args.get("name"), "state": "in progress"}
        return ok(rid, {"sys_id": sid, "name": args.get("name")})
    if name == "switch_update_set":
        return ok(rid, {"current": args.get("sys_id")})
    if name == "complete_update_set":
        UPDATE_SETS.get(args.get("sys_id"), {})["state"] = "complete"
        return ok(rid, {"sys_id": args.get("sys_id"), "state": "complete"})
    if name == "export_update_set":
        return ok(rid, {"sys_id": args.get("sys_id"), "xml": "<unload/>"})
    if name in ("execute_background_script", "run_fix_script"):
        return ok(rid, {"executed": True, "danger": "this should never be reached by ROB"})
    return err(rid, f"unsupported tool {name}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = msg.get("id")
        if rid is None:
            continue
        method = msg.get("method")
        if method == "initialize":
            out = {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-nowaikit-write", "version": "4.12.0"}}}
        elif method == "tools/list":
            out = {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
        elif method == "tools/call":
            p = msg.get("params", {})
            out = handle(rid, p.get("name"), p.get("arguments", {}) or {})
        else:
            out = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
