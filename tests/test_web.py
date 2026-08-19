"""Web app flow tests over real HTTP: setup -> login -> scan (from snapshot) ->
runs -> dashboard -> reports. Auth and traversal guards."""
import http.client
import json
import pathlib
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from http.server import ThreadingHTTPServer

from rob.web import AppState, make_handler

FIXTURE = str(pathlib.Path(__file__).parent.parent / "fixtures" / "pdi_like_snapshot.json")


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    home = tmp_path_factory.mktemp("robhome")
    state = AppState(home)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield ("127.0.0.1", httpd.server_address[1], state)
    httpd.shutdown()


def req(server, method, path, body=None, cookie=None, headers=None):
    host, port, _ = server
    c = http.client.HTTPConnection(host, port, timeout=10)
    headers = dict(headers or {})
    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    if cookie:
        headers["Cookie"] = cookie
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read().decode()
    return r, data


def test_full_web_flow(server):
    # Fresh workspace forces setup
    r, body = req(server, "GET", "/")
    assert "First run" in body and "administrator password" in body

    # Mismatched passwords rejected
    r, body = req(server, "POST", "/setup", "password=secret1&password2=other")
    assert "did not match" in body

    # Setup succeeds and creates a session
    r, _ = req(server, "POST", "/setup", "password=secret1&password2=secret1")
    assert r.status == 303
    cookie = r.getheader("Set-Cookie").split(";")[0]

    # Unauthenticated requests bounce to login
    r, _ = req(server, "GET", "/")
    assert r.status == 303 and r.getheader("Location") == "/login"

    # Wrong password refused, right password accepted
    r, body = req(server, "POST", "/login", "password=nope")
    assert "Wrong password" in body
    r, _ = req(server, "POST", "/login", "password=secret1")
    assert r.status == 303
    cookie = r.getheader("Set-Cookie").split(";")[0]

    # Overview renders. With no runs it is the empty state, which must point at settings.
    r, body = req(server, "GET", "/", cookie=cookie)
    assert r.status == 200 and "No scan runs yet" in body and "/settings" in body

    # Settings renders every configurable group, and the locked facts alongside them
    r, body = req(server, "GET", "/settings", cookie=cookie)
    assert r.status == 200
    for group in ("Connect an instance", "Policy", "Executor", "Scan defaults",
                  "Presentation", "Scheduled scan notifications", "Administrator password",
                  "Not configurable, by design"):
        assert group in body, group

    # Rules page lists library with basis
    r, body = req(server, "GET", "/rules", cookie=cookie)
    assert "ROB-SEC-003" in body and "Basis" in body

    # Scan from a snapshot file (no live instance needed in tests)
    r, _ = req(server, "POST", "/scan", f"snapshot_path={FIXTURE}", cookie=cookie)
    assert r.status == 303
    for _ in range(100):
        _, status = req(server, "GET", "/scan/status", cookie=cookie)
        j = json.loads(status)
        if j["state"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert j["state"] == "done", j
    run_id = j["run_id"]

    # Every section renders against a stored run
    for path_, needle in (("/", "Verdict"), ("/findings", "Why this severity"),
                          ("/remediation", "Ownership"), ("/coverage", "How the score is built"),
                          ("/estate", "Findings by domain across the estate")):
        r, body = req(server, "GET", path_, cookie=cookie)
        assert r.status == 200 and needle in body, (path_, needle)

    # Run assets served
    r, body = req(server, "GET", f"/runs/{run_id}/dashboard", cookie=cookie)
    assert r.status == 200 and "ROB - Instance Health" in body
    r, body = req(server, "GET", f"/runs/{run_id}/executive_summary.md", cookie=cookie)
    assert r.status == 200 and "Executive Summary" in body
    r, body = req(server, "GET", f"/runs/{run_id}/backlog.csv", cookie=cookie)
    assert r.status == 200 and body.startswith("ID,")

    # Path traversal denied
    r, _ = req(server, "GET", f"/runs/{run_id}/../../web_config.json", cookie=cookie)
    assert r.status == 404

    # Logout invalidates the session
    r, _ = req(server, "GET", "/logout", cookie=cookie)
    r, _ = req(server, "GET", "/", cookie=cookie)
    assert r.status == 303


def test_forged_cookie_rejected(server):
    r, _ = req(server, "GET", "/", cookie="rob_session=deadbeef.badsig")
    assert r.status == 303 and r.getheader("Location") == "/login"


def test_role_switch_never_follows_an_arbitrary_referer(server):
    """Referer is attacker-influenceable. It selects a known section or nothing."""
    cookie = login(server)
    r, _ = req(server, "GET", "/role?to=security", cookie=cookie,
               headers={"Referer": "https://evil.example/steal"})
    assert r.status == 303 and r.getheader("Location") == "/"
    r, _ = req(server, "GET", "/role?to=security", cookie=cookie,
               headers={"Referer": "http://127.0.0.1/findings"})
    assert r.getheader("Location") == "/findings"
    # The lens is persisted and the sidebar says what it means, run or no run
    _r, body = req(server, "GET", "/", cookie=cookie)
    assert "Exposure first" in body


def test_settings_rejection_does_not_touch_the_stored_config(server):
    cookie = login(server)
    r, _ = req(server, "POST", "/settings/instance/add",
               "url=http://cleartext.service-now.com&user=admin", cookie=cookie)
    assert r.status == 303 and "k=err" in r.getheader("Location")
    _r, body = req(server, "GET", "/settings", cookie=cookie)
    assert "cleartext.service-now.com" not in body


def login(server):
    """Sign in, setting the password first if this workspace is fresh.

    The server fixture is module-scoped, so whether setup has already run
    depends on test ordering. This helper works either way rather than
    depending on it.
    """
    _host, _port, state = server
    if not state.is_set_up:
        r, _ = req(server, "POST", "/setup", "password=secret12&password2=secret12")
    else:
        r, _ = req(server, "POST", "/login", "password=secret1")
        if r.status != 303:
            r, _ = req(server, "POST", "/login", "password=secret12")
    cookie = r.getheader("Set-Cookie")
    assert cookie, "login did not return a session"
    return cookie.split(";")[0]


def test_every_finding_carries_its_fingerprint(server):
    """Finding.fingerprint is a property, so asdict() drops it and the stored
    record has no such field. Links that identify a finding depend on it, and
    the failure mode is a silently empty href rather than an error."""
    import rob.pages as pages

    _host, _port, state = server
    v = pages.View(state)
    assert v.findings, "fixture run should have findings"
    for f in v.findings:
        assert f.get("fingerprint"), f.get("rule_id")
        assert f["fingerprint"].startswith(f["rule_id"])


def test_fix_links_are_addressable(server):
    cookie = login(server)
    _r, body = req(server, "GET", "/findings", cookie=cookie)
    assert "/fix?f=ROB-" in body, "fix links must carry a fingerprint"
    fp = body.split("/fix?f=")[1].split('"')[0]
    r, fix = req(server, "GET", "/fix?f=" + fp, cookie=cookie)
    assert r.status == 200
    # The page exists to answer "why can't I apply this", so the gates are named.
    for gate in ("Environment is sub-production", "Autonomy ceiling", "executor is configured",
                 "Global dry run"):
        assert gate in fix, gate


def test_rule_page_explains_the_rule_from_its_spec(server):
    cookie = login(server)
    r, body = req(server, "GET", "/rule?id=ROB-PERF-002", cookie=cookie)
    assert r.status == 200
    for needle in ("How ROB decides", "What it deliberately does not flag", "Basis",
                   "Reads the script body", "Remediability"):
        assert needle in body, needle
    # An unknown rule is a page, not a stack trace
    r, body = req(server, "GET", "/rule?id=ROB-NOPE-999", cookie=cookie)
    assert r.status == 200 and "Unknown rule" in body


def test_coverage_states_results_rather_than_drawing_them(server):
    cookie = login(server)
    _r, body = req(server, "GET", "/coverage", cookie=cookie)
    assert "Coverage and scoring" in body and "&amp;amp;" not in body
    assert "clean" in body, "a rule that found nothing must say so in words"
    assert "/rule?id=ROB-" in body, "every rule must be openable"
