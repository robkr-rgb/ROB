"""NowAIKit MCP integration: an alternative read path into a ServiceNow instance.

NowAIKit (https://github.com/aartiq/nowaikit, Elastic License 2.0) is a
ServiceNow MCP server with 450+ tools. ROB uses it as a *transport*, never as a
brain: responses are normalised into the same Snapshot the native extractor
produces, and rules run against the snapshot exactly as before. Determinism,
scoring and fix-pack generation are unaffected by which path fetched the data.

Three constraints are enforced here rather than assumed.

1. READ ONLY, STRUCTURALLY. `ALLOWED_TOOLS` is an allowlist of read tools. Any
   other tool name raises before a request is made, so a NowAIKit server started
   with WRITE_ENABLED=true still cannot be used by this client to write. ROB's
   read-only posture (D-002) does not depend on how the server was configured.

2. PAGINATION IS THE BINDING LIMIT. NowAIKit's `query_records` tool exposes
   table, query, fields and limit, and caps limit at 1000. It does not expose an
   offset, so there is no way to page past the first 1000 rows over MCP even
   though the underlying client supports sysparm_offset. Any table whose result
   hits the cap is recorded as an extraction gap rather than silently truncated,
   because a truncated CMDB read would produce confident, wrong findings.

3. NO FREE-TEXT PATH FOR THE AGENT. This module is called by the extractor, not
   by the agent orchestrator. The agent's five tool contracts (rob/agent.py) do
   not reach it, so nothing here widens the agent's surface.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request

# Read tools ROB is permitted to call. Deliberately small: this is the extraction
# manifest expressed as tool calls, not the whole NowAIKit surface.
ALLOWED_TOOLS = frozenset({
    "query_records",
    "get_record",
    "get_table_schema",
    "run_aggregate_query",
    "list_relationships",
    "search_cmdb_ci",
    "get_cmdb_ci",
})

# The hard ceiling NowAIKit's query_records imposes, with no offset to page past it.
MCP_ROW_LIMIT = 1000

# Imported, not restated: rows() must default to the same cap the native extractor
# uses, or a caller who omits cap would silently receive a truncated read instead
# of the declared gap. That defeat was live in the first cut of this module.
from .extractor import DEFAULT_CAP  # noqa: E402

PROTOCOL_VERSION = "2024-11-05"


class NowAIKitError(RuntimeError):
    """Transport or protocol failure. Callers degrade per table, never guess."""


class ToolNotPermitted(NowAIKitError):
    """A tool outside the read allowlist was requested. Structural, not configurable."""


# --------------------------------------------------------------------------- transports


class _StdioTransport:
    """MCP over stdio against a locally spawned `nowaikit-mcp` process."""

    def __init__(self, command: list[str], env: dict[str, str] | None = None, timeout: int = 120):
        self.timeout = timeout
        merged = dict(os.environ)
        merged.update(env or {})
        # Belt and braces: even though the allowlist blocks write tools, tell the
        # server not to enable them. Two independent controls, not one.
        merged.setdefault("WRITE_ENABLED", "false")
        merged.setdefault("CMDB_WRITE_ENABLED", "false")
        self.proc = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1, env=merged,
        )
        self._lock = threading.Lock()
        self._id = 0

    def request(self, method: str, params: dict) -> dict:
        with self._lock:
            self._id += 1
            msg = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
            if self.proc.poll() is not None:
                raise NowAIKitError("NowAIKit process is not running")
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    raise NowAIKitError("NowAIKit closed the connection")
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue  # server chatter on stdout; ignore non-JSON lines
                if payload.get("id") == self._id:
                    return payload

    def notify(self, method: str, params: dict) -> None:
        with self._lock:
            self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n")
            self.proc.stdin.flush()

    def close(self):
        try:
            self.proc.terminate()
        except Exception:
            pass


class _HttpTransport:
    """MCP over NowAIKit's HTTP transport, for a hosted server.

    This is the mode that matters for a scheduled ROB service: a desktop-local
    stdio server cannot serve an unattended scan.
    """

    def __init__(self, url: str, token: str = "", timeout: int = 120):
        self.url = url
        self.timeout = timeout
        self.headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self._lock = threading.Lock()
        self._id = 0

    def request(self, method: str, params: dict) -> dict:
        with self._lock:
            self._id += 1
            body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode()
        except urllib.error.HTTPError as exc:
            raise NowAIKitError(f"HTTP {exc.code} from NowAIKit: {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise NowAIKitError(f"Cannot reach NowAIKit at {self.url}: {exc.reason}") from exc
        for line in raw.splitlines():  # tolerate SSE framing
            line = line[6:] if line.startswith("data: ") else line
            if not line.strip():
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        raise NowAIKitError("No JSON-RPC response in NowAIKit reply")

    def notify(self, method: str, params: dict) -> None:
        try:
            self.request(method, params)
        except NowAIKitError:
            pass

    def close(self):
        pass


# --------------------------------------------------------------------------- client


class NowAIKitClient:
    """Read-only ServiceNow access via NowAIKit, shaped like the native SNClient.

    Exposes rows() and count() with the same signatures the extractor already
    uses, so `build_snapshot` works unchanged against either path. Per-table
    failures append to `access_errors`, which the extractor turns into the
    snapshot's declared gap register.
    """

    def __init__(self, transport, instance_label: str = "nowaikit"):
        self._t = transport
        self.instance_label = instance_label
        self.access_errors: list[str] = []
        self.tool_names: set[str] = set()
        self._init()

    # -- lifecycle ------------------------------------------------------------

    @classmethod
    def stdio(cls, command: list[str] | None = None, env: dict[str, str] | None = None, **kw):
        return cls(_StdioTransport(command or ["npx", "-y", "nowaikit-mcp"], env), **kw)

    @classmethod
    def http(cls, url: str, token: str = "", **kw):
        return cls(_HttpTransport(url, token), **kw)

    def _init(self):
        resp = self._t.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ROB", "version": "13"},
        })
        if "error" in resp:
            raise NowAIKitError(f"initialize failed: {resp['error']}")
        self._t.notify("notifications/initialized", {})
        listed = self._t.request("tools/list", {})
        self.tool_names = {t["name"] for t in listed.get("result", {}).get("tools", [])}

    def close(self):
        self._t.close()

    # -- capability report ----------------------------------------------------

    def capability_report(self) -> dict:
        """What this server can actually do for ROB. Part A of the inventory plan."""
        available = sorted(self.tool_names)
        write_tools = sorted(t for t in available if any(
            t.startswith(p) for p in ("create_", "update_", "delete_", "commit_", "publish_", "switch_")))
        return {
            "tools_total": len(available),
            "read_tools_rob_uses": sorted(ALLOWED_TOOLS & self.tool_names),
            "read_tools_missing": sorted(ALLOWED_TOOLS - self.tool_names),
            "write_tools_present": write_tools,
            "row_limit_per_call": MCP_ROW_LIMIT,
            "supports_offset": False,
            "verdict": (
                "Suitable for low-volume tables and breadth. Not suitable as the bulk extraction "
                "path while query_records exposes no offset: results are capped at "
                f"{MCP_ROW_LIMIT} rows per call with no way to page."
            ),
        }

    # -- tool call ------------------------------------------------------------

    #: Tools this client may call. A subclass changes policy by changing this
    #: set alone; the transport below is shared and does no policy of its own.
    PERMITTED = ALLOWED_TOOLS
    PERMISSION_HINT = (
        "ROB reads through NowAIKit; it never writes through it (D-011)."
    )

    def call(self, tool: str, arguments: dict) -> dict:
        if tool not in self.PERMITTED:
            raise ToolNotPermitted(
                f"'{tool}' is not on this client's read allowlist. {self.PERMISSION_HINT} "
                f"Permitted: {sorted(self.PERMITTED)}"
            )
        if self.tool_names and tool not in self.tool_names:
            raise NowAIKitError(f"NowAIKit server does not expose '{tool}'")
        return self._raw_call(tool, arguments)

    def _raw_call(self, tool: str, arguments: dict) -> dict:
        """Transport only. Policy lives in call()."""
        resp = self._t.request("tools/call", {"name": tool, "arguments": arguments})
        if "error" in resp:
            raise NowAIKitError(f"{tool}: {resp['error'].get('message', resp['error'])}")
        result = resp.get("result", {})
        if result.get("isError"):
            raise NowAIKitError(f"{tool}: {_text_of(result)}")
        return _parse_content(result)

    # -- SNClient-shaped surface ---------------------------------------------

    def rows(self, table: str, fields: list[str], query: str = "",
             cap: int = DEFAULT_CAP, display: bool = False) -> list[dict]:
        """Field-limited read. Declares a gap instead of silently truncating."""
        limit = min(cap, MCP_ROW_LIMIT)
        try:
            data = self.call("query_records", {
                "table": table, "query": query,
                "fields": ",".join(fields), "limit": limit,
            })
        except NowAIKitError as exc:
            self.access_errors.append(f"{table}: {exc}")
            return []
        records = _records_of(data)
        if len(records) >= limit and cap > MCP_ROW_LIMIT:
            # The honest failure. A capped CMDB read would produce confident,
            # wrong findings, so the affected rules must go silent instead.
            self.access_errors.append(
                f"{table}: NowAIKit returned the maximum {limit} rows and exposes no offset, so the "
                f"read is incomplete (requested up to {cap}). Rules depending on this table are "
                "unreliable over the MCP path; use the native extractor for it."
            )
            return []
        return records

    def count(self, table: str, query: str = "") -> int | None:
        try:
            data = self.call("run_aggregate_query", {"table": table, "query": query, "aggregate": "COUNT"})
        except NowAIKitError as exc:
            self.access_errors.append(f"{table} (count): {exc}")
            return None
        return _count_of(data)


# --------------------------------------------------------------------------- parsing


def _text_of(result: dict) -> str:
    parts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
    return "\n".join(p for p in parts if p)


def _parse_content(result: dict):
    """MCP returns content blocks; NowAIKit puts JSON in a text block."""
    if "structuredContent" in result:
        return result["structuredContent"]
    text = _text_of(result)
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"text": text}


def _records_of(data) -> list[dict]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in ("records", "result", "results", "rows", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


def _count_of(data) -> int | None:
    if isinstance(data, (int, float)):
        return int(data)
    if isinstance(data, dict):
        for key in ("count", "COUNT", "total", "value"):
            value = data.get(key)
            if isinstance(value, (int, float)):
                return int(value)
            if isinstance(value, str) and value.isdigit():
                return int(value)
        for nested in ("result", "stats", "aggregate"):
            if isinstance(data.get(nested), dict):
                found = _count_of(data[nested])
                if found is not None:
                    return found
    return None
