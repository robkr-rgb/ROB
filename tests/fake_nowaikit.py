#!/usr/bin/env python3
"""A fake NowAIKit MCP server over stdio, for tests.

Mirrors the real server's shape: initialize, tools/list, tools/call, with
query_records capped at 1000 rows and no offset parameter. It also exposes a
write tool, so tests can prove ROB's allowlist blocks it even when the server
offers it.
"""
import json
import sys

ROWS = {
    "sys_script": [
        {"sys_id": "a" * 32, "name": "Rule A", "active": "true"},
        {"sys_id": "b" * 32, "name": "Rule B", "active": "true"},
    ],
    "sys_report": [{"sys_id": "r1", "title": "All Incidents", "table": "incident", "is_public": "true"}],
    # 1000 rows: the cap, indistinguishable from "there is more".
    "cmdb_ci": [{"sys_id": f"c{i:031d}", "name": f"CI {i}"} for i in range(1000)],
}

TOOLS = [
    {"name": "query_records", "description": "Query records"},
    {"name": "run_aggregate_query", "description": "Aggregate"},
    {"name": "get_record", "description": "Get one"},
    {"name": "get_table_schema", "description": "Schema"},
    {"name": "list_relationships", "description": "Rels"},
    {"name": "search_cmdb_ci", "description": "Search CI"},
    {"name": "get_cmdb_ci", "description": "Get CI"},
    {"name": "create_record", "description": "Create (write)"},
    {"name": "update_record", "description": "Update (write)"},
]


def ok(rid, payload):
    return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(payload)}]}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method, rid = msg.get("method"), msg.get("id")
        if rid is None:
            continue  # notification
        if method == "initialize":
            out = {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-nowaikit", "version": "4.12.0"}}}
        elif method == "tools/list":
            out = {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
        elif method == "tools/call":
            params = msg.get("params", {})
            name, args = params.get("name"), params.get("arguments", {})
            if name == "query_records":
                table = args.get("table", "")
                limit = min(int(args.get("limit", 10)), 1000)
                out = ok(rid, {"records": ROWS.get(table, [])[:limit]})
            elif name == "run_aggregate_query":
                out = ok(rid, {"count": len(ROWS.get(args.get("table", ""), []))})
            elif name in ("create_record", "update_record"):
                out = ok(rid, {"written": True})
            else:
                out = {"jsonrpc": "2.0", "id": rid, "result": {
                    "isError": True, "content": [{"type": "text", "text": f"unsupported tool {name}"}]}}
        else:
            out = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
