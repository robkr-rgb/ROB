# ROB - Run Guide

## The two-minute version

```bash
./deploy/install-local.sh
rob serve
```

Then open http://127.0.0.1:8422. Or just double-click **ROB.command** in Finder,
which starts the console and opens the browser for you.

To check an installation at any time, including a fresh one:

```bash
rob doctor
```

It reports every part of ROB as working, optional-and-absent (with what that
costs you), or broken (with the fix). It touches no instance, so it is safe to
run anywhere.

`install-local.sh` puts `rob` on your PATH so the command works from any
directory. Without it you must be in the repo root, and `python3 -m rob` from
anywhere else fails with "No module named rob".

---

Everything below runs from anywhere once `rob` is on your PATH, or from the repo root. Requires **Python 3.10+** and nothing
else: ROB has no Python dependencies. Node 20+ is needed only for the optional
NowAIKit read path.

Verified on macOS with Python 3.10.12 and Node v22.

---

## 0. Try it with no ServiceNow instance (30 seconds)

A synthetic snapshot ships with the repo, so you can see the whole pipeline
before pointing ROB at anything real.

```bash
python3 -m rob scan --snapshot fixtures/pdi_like_snapshot.json --out out/
open out/dashboard.html
```

Expect 17 findings, 14 fix-packs, and a line telling you which shadow rules were
withheld.

Also useful. `rules` prints the whole library with tier, autonomy class,
confidence and basis; `history` lists stored runs.

```bash
python3 -m rob rules
python3 -m rob history
```

---

## 1. The web front-end and the agent console

This is where you actually work.

```bash
python3 -m rob serve
```

Then open **http://127.0.0.1:8422** in a browser. First run asks you to set an administrator password. Then:

| Page | What you do there |
|---|---|
| **Overview** | Connect an instance, run a scan, open past runs, download reports |
| **Agent** | See what ROB can fix right now, approve a fix, set the autonomy ceiling, read the audit trail, call a tool contract directly |
| **Rules** | The library with basis references, tier, autonomy class and confidence |

Options: `--home <dir>` (workspace, default `rob_home`), `--host`, `--port`.

**Read this before you use the Agent page.** A new workspace starts with the
autonomy ceiling at **A1** and global dry-run **on**. That combination means ROB
proposes and never acts, which is the right default. Approving a fix mints a
signed token bound to that one finding for 15 minutes, and the outcome will be an
honest refusal explaining which gate stopped it, plus the fix-pack for you to
apply yourself. Nothing writes to an instance in this version.

---

## 2. Against a real instance (native read path)

For a PDI, your admin account is acceptable (documented deviation: the product
model uses OAuth plus a dedicated service account, profile R-A in
`service-now/required-permissions.md`). Wake the PDI in a browser first; they
hibernate.

Set the password in the environment, or omit the export and be prompted.

```bash
export ROB_SN_PASSWORD='your-password'
python3 -m rob extract \
  --instance https://dev12345.service-now.com \
  --user admin \
  --snapshot-out snapshot.json
unset ROB_SN_PASSWORD

python3 -m rob scan --snapshot snapshot.json --out out/
open out/dashboard.html
```

The extractor issues GET requests only; there is no write code path. It prints
progress for 13 extraction groups and finishes with record counts. Expect one to
five minutes on a PDI. The snapshot holds configuration metadata and no
credentials; `sys_user` extraction is identifiers and login recency only.

Permission gaps are normal. They are declared in the snapshot and the affected
rules go silent rather than guessing.

---

## 3. Optional: read through NowAIKit

[NowAIKit](https://github.com/aartiq/nowaikit) is a ServiceNow MCP server. ROB
can read through it instead of its own REST client. **Licence note:** NowAIKit is
Elastic License 2.0. Free inside your organisation and for delivering work to
your clients; a commercial agreement is required to host it as a service for
third parties or to embed it in a paid product. See D-015 and D-018.

### 3a. Set NowAIKit up once

This walks you through the instance URL and credentials.

```bash
npx -y nowaikit setup
```

### 3b. Check what it can actually do for ROB

```bash
python3 -m rob nowaikit-probe
```

Against a hosted server instead:

```bash
python3 -m rob nowaikit-probe --url https://your-nowaikit-host/mcp --token "$TOKEN"
```

You get the tool count, which read tools ROB needs and whether they are present,
which write tools the server exposes (reported for your security review, never
used), the row limit and a verdict.

Try it right now without NowAIKit installed, using the bundled fake server:

```bash
python3 -m rob nowaikit-probe --server-command "python3 tests/fake_nowaikit.py"
```

### 3c. Extract through it

```bash
python3 -m rob extract --via nowaikit --snapshot-out snapshot.json
```

Hosted:

```bash
python3 -m rob extract --via nowaikit \
  --nowaikit-url https://your-nowaikit-host/mcp \
  --nowaikit-token "$TOKEN" --snapshot-out snapshot.json
```

No `--user` or `--instance` needed: NowAIKit holds its own instance credentials.

**Expect a declared gap on `cmdb_ci`.** NowAIKit's `query_records` caps at 1000
rows and exposes no offset, so there is no way to page past the first 1000. ROB
returns nothing for a capped table and says so, rather than silently truncating
and producing confident, wrong CMDB findings. Until that is fixed upstream, use
the native path for a full CMDB scan and NowAIKit for breadth on smaller tables.

Two independent controls keep this read-only: ROB's read-tool allowlist, and the
`WRITE_ENABLED=false` the stdio transport sets. A NowAIKit server started with
writes enabled still cannot be used by ROB to write.

---

## 4. Talk to ROB from Claude Desktop

ROB exposes its five contracts as an MCP server. No API key inside ROB, no model
hosting, and voice comes free from macOS dictation.

```bash
python3 -m rob mcp --home rob_home
```

That is the command Claude Desktop runs, not one you run yourself. Add this to
`~/Library/Application Support/Claude/claude_desktop_config.json`, using absolute
paths, then restart Claude Desktop. A full example is in `deploy/claude-desktop-mcp.example.json`.

```json
{
  "mcpServers": {
    "rob": {
      "command": "python3",
      "args": ["-m", "rob", "mcp", "--home", "/Users/you/Downloads/rob-mvp 6/rob_home"],
      "cwd": "/Users/you/Downloads/rob-mvp 6"
    }
  }
}
```

Then ask it things: "what's broken on dev12345", "explain the admin role finding",
"show me the fix-pack for it". Point it at the same `--home` the console uses, or
it will not see your runs.

Approving still happens in the console. Asking the agent to apply a fix returns a
refusal naming the gate, which is the intended answer, not a bug.

---

## 5. Scheduled scanning

The proactive half. No language model is involved: detection and scoring are
deterministic, so a nightly scan that reports what changed needs no model at all.

```bash
python3 -m rob scheduled-scan --home rob_home --snapshot snapshot.json
```

Against a live instance, with the password in the environment because a
scheduled job must never prompt:

```bash
export ROB_SN_PASSWORD='...'
python3 -m rob scheduled-scan --home rob_home \
  --instance https://dev12345.service-now.com --user rob.integration
```

It scans, stores the run, diffs it against the previous run by finding
fingerprint, writes the reports and notifies. By default it stays quiet when
nothing changed. Add `--always-notify` if you would rather hear from it every
night, on the grounds that silence reads the same as a broken scheduler.

Configure recipients by adding a `notify` block to `rob_home/web_config.json`.
See `deploy/notify.example.json`.

---

## 6. On a VPS

```bash
sudo ROB_HOME=/opt/rob deploy/install.sh
```

Installs a systemd service for the console and a nightly timer for the scan,
under a dedicated unprivileged user. The console binds to loopback only. Reach it
from your laptop over a tunnel:

```bash
ssh -N -L 8422:127.0.0.1:8422 you@your-vps
```

Do not put the console on a public interface until it has TLS and per-user
accounts. It currently has one shared password, which is fine on loopback.

---

## 7. Reference sources: official docs and best practices

ROB can cite the official ServiceNow documentation and your Best Practices
Library on every finding. Both are indexed once into a compact local file; a
scan never needs a clone or a login.

The docs index ships with this repo at `rob_home/servicenow_docs_index.json.gz`:
49,983 pages, 3.2 MB. To rebuild it after a docs refresh:

```bash
git clone --depth 1 https://github.com/ServiceNow/ServiceNowDocs
rob knowledge index-docs --repo ServiceNowDocs
```

To index your Best Practices Library harvest:

```bash
rob knowledge index-bpl \
  --catalog ~/Documents/Claude/Projects/BPL-Scraper/library/catalog.json \
  --files   ~/Documents/Claude/Projects/BPL-Scraper/library/files
```

Check and search them:

```bash
rob knowledge status
rob knowledge search admin role assignment
```

Once indexed, the technical report gains a **Further reading** section per
finding, and the agent gets the same links so it can cite a source rather than
assert one. Roughly half of findings get a citation; ROB does not invent one
where nothing matches well.

Both indexes store titles, areas and links only. No document or deck content is
copied: Best Practices Library assets are ServiceNow copyright behind a login,
so ROB points at them and never reproduces them.

---

## 8. Applying a fix automatically (W-C)

Off by default. With it configured, an approved fix is applied through NowAIKit
inside a named update set, on sub-production only.

Add to `rob_home/web_config.json`:

```json
{
  "executor": {"kind": "nowaikit", "command": "npx -y nowaikit-mcp"},
  "autonomy_ceilings": {"_default": "A2"},
  "global_dry_run": true
}
```

Leave `global_dry_run` on first. Approving a fix then reads the live instance
and shows you exactly what would change, without changing it. Turn dry run off
in the console's Policy panel when you are ready.

What it will and will not do:

| | |
|---|---|
| Applies | Typed record operations: system properties, field updates, record deletes |
| Refuses | Anything expressed only as a script. A script cannot be previewed, bounded or reversed per record |
| Never touches | ACLs, roles, group membership, users, even with an approval. Those go through a human |
| Always | Creates a named update set, captures backout from the live instance before the first write, verifies by reading back, rolls back what landed if a later step fails |

Most fix-packs are scripts, so most stay human-apply. That is expected, not a gap.

---

## 9. Working with findings

Measure the shadow rules. Never do this for a customer report.

```bash
python3 -m rob scan --snapshot snapshot.json --out out/ --include-shadow
```

Trend between two stored runs:

```bash
python3 -m rob diff --runs 1 2
```

Formally accept a finding. It stays visible, labelled as accepted, and expires
after 12 months.

```bash
python3 -m rob accept --fingerprint "ROB-SEC-001:sys_user_has_role (admin)" \
  --reason "Break-glass account, reviewed quarterly"
```

Outputs in `out/`: `executive_summary.md` (no sys_ids by construction),
`technical_report.md`, `findings.json`, `backlog.csv`, `dashboard.html`, and a
`fixpacks/` directory. Each fix-pack has all five elements: the fix, a read-only
dry run, application instructions, a backout artefact and a scope statement.

**Apply a fix-pack yourself:** run its dry run first, apply in sub-production,
then re-run the dry run to verify. Production goes through your own change
process.

---

## 10. Tests

`pytest` is the only dev dependency. 230 tests.

```bash
python3 -m pip install pytest
python3 -m pytest tests/ -q
```

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `No module named pytest` | Tests only. `python3 -m pip install pytest` |
| Extraction reports access gaps | Normal. Some system tables are admin-only read even on a PDI. Gaps are declared and dependent rules go silent |
| A rule you expected did not fire | Check `python3 -m rob rules`: it may be in shadow. Shadow rules are withheld until their false-positive rate is measured |
| `nowaikit-probe` hangs | The stdio server is not starting. Try `npx -y nowaikit-mcp` directly and read its output |
| NowAIKit extraction returns nothing for a table | The 1000-row cap. Read the declared gap message; use the native path for that table |
| Agent approval always refuses | By design in this version. Read the refusal: it names the gate. The executor (D-005) is Phase 2 |
| Anything at all looks wrong | Run `rob doctor` first. It names the problem and the fix |
| `No module named rob` | You are not in the repo root. Run `./deploy/install-local.sh` once and the `rob` command works from anywhere |
| Approving a fix says no executor is configured | W-C is off by default. See section 8, or apply the fix-pack by hand |
| `rob knowledge search` finds nothing | Check `rob knowledge status`. ROB declines to cite a weak match rather than pad the report |
| `rob: error: unrecognized arguments: # ...` | You pasted a command with a trailing `#` comment. zsh does not treat `#` as a comment in an interactive shell by default, so it becomes an argument. Every command in this guide is now comment-free; paste the whole line as shown |
| `git` warnings about `unable to unlink` | Only when the repo is on a mounted folder that forbids deletes. Commits still succeed |
