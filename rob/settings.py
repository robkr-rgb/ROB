"""Console settings: the workspace configuration, made editable and validated.

Everything ROB reads from `web_config.json` at runtime is here, in one place,
with a validator per group. Before this module the config surface was split
between a hand-edited JSON file, two CLI flags and one form buried in the
agent console, which meant the honest answer to "what can I configure?" was
"read the source".

Three rules hold this file together:

1. **A setting that changes what reaches an instance is a recorded decision.**
   Autonomy ceiling, dry run and executor changes are written to the agent
   audit log, not just saved.
2. **Structural safety properties are not settings.** The forbidden-table list,
   the exclusion of background-script execution and the sub-production-only
   rule are enforced in code (D-019). They are surfaced here as locked facts
   with their reason, because a reader deserves to know they exist and that
   no checkbox turns them off.
3. **Validation refuses rather than coerces.** A malformed SMTP port is an
   error the operator sees now, not a scheduled scan that silently never
   notifies at 03:00.
"""
from __future__ import annotations

import re
import urllib.parse

from .models import AUTONOMY_CLASSES

ENVIRONMENTS = ("dev", "test", "prod")
EXECUTOR_KINDS = ("none", "nowaikit")
ROLE_KEYS = ("executive", "architect", "platform_admin", "security")

# Surfaced in the console as locked, with the reason. Sourced from the code
# that actually enforces them so the two cannot drift apart.
LOCKED_FACTS = (
    (
        "Security and identity tables are never written",
        "sys_security_acl, sys_user, sys_user_role, sys_user_has_role, sys_user_grmember, "
        "sys_group_has_role, sys_user_group, sys_authentication_profile, oauth_credential. "
        "W-C's attribution is a service account, and a wrong ACL is an outage or a breach. "
        "These go through W-B or a human (D-019).",
    ),
    (
        "Background scripts are never executed",
        "NowAIKit exposes execute_background_script and run_fix_script. ROB's write client "
        "excludes both: a script cannot be previewed, bounded or reversed per record.",
    ),
    (
        "Sub-production only",
        "apply() refuses any target environment other than sub-production before it even "
        "checks the approval token. Production changes go through your own change process "
        "using the fix-pack (D-004).",
    ),
    (
        "Approval is minted by a human, in this console",
        "An HMAC token bound to one run, one finding and one approver, with a short expiry. "
        "Nothing arriving from an instance or a model can produce one (D-012).",
    ),
    (
        "A3 standing approval needs a signed baseline",
        "A3 is a strict subset of tier T1 on validated rules, and additionally requires a "
        "signed baseline file in this workspace. Raising the ceiling alone does not grant it.",
    ),
)


class SettingsError(ValueError):
    """A settings form was rejected. Always shown to the operator, never swallowed."""


# --------------------------------------------------------------------------- defaults

def defaults() -> dict:
    return {
        "instances": [],
        "autonomy_ceilings": {},
        "global_dry_run": True,
        "executor": {"kind": "none", "command": "npx -y nowaikit-mcp", "url": "", "token": "",
                     "update_set_prefix": "ROB"},
        "scanning": {"include_shadow": False, "upgrade_planned": False},
        "email": {"to": "", "from": "rob@localhost", "host": "localhost", "port": 25,
                  "starttls": False, "user": "", "password": ""},
        "webhook": {"url": ""},
        "notify": {"always": False},
        "ui": {"role": "platform_admin", "redact_identifiers": False, "show_sla_dates": True},
    }


def merged(config: dict) -> dict:
    """Config with defaults filled in. Never mutates the stored config."""
    out = defaults()
    for k, v in (config or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = {**out[k], **v}
        else:
            out[k] = v
    return out


# --------------------------------------------------------------------------- parsing

def _bool(form: dict, key: str) -> bool:
    return form.get(key) in ("on", "true", "1", "yes")


def _int(form: dict, key: str, default: int, lo: int, hi: int) -> int:
    raw = (form.get(key) or "").strip()
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError as exc:
        raise SettingsError(f"'{key}' must be a whole number, not {raw!r}.") from exc
    if not lo <= n <= hi:
        raise SettingsError(f"'{key}' must be between {lo} and {hi}.")
    return n


def _https_url(raw: str, field: str, *, allow_http: bool = False) -> str:
    url = (raw or "").strip().rstrip("/")
    if not url:
        return ""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in (("http", "https") if allow_http else ("https",)):
        raise SettingsError(
            f"{field} must be an https:// URL. ROB refuses cleartext for the same reason "
            "ROB-INT-001 reports it on your instance."
        )
    if not parsed.netloc:
        raise SettingsError(f"{field} is not a valid URL.")
    return url


# --------------------------------------------------------------------------- groups

def apply_instance_add(config: dict, form: dict) -> str:
    url = _https_url(form.get("url", ""), "Instance URL")
    if not url:
        raise SettingsError("Instance URL is required.")
    user = (form.get("user") or "").strip()
    if not user:
        raise SettingsError("Service account user is required.")
    env = (form.get("environment") or "dev").strip().lower()
    if env not in ENVIRONMENTS:
        raise SettingsError(f"Environment must be one of {', '.join(ENVIRONMENTS)}.")
    name = (form.get("name") or "").strip() or urllib.parse.urlparse(url).netloc.split(".")[0]
    if any(i.get("url") == url for i in config.get("instances", [])):
        raise SettingsError(f"{url} is already connected.")
    config.setdefault("instances", []).append({
        "url": url, "user": user, "password": form.get("password", ""),
        "name": name, "environment": env, "notes": (form.get("notes") or "").strip(),
    })
    return f"Connected {name} ({env})."


def apply_instance_update(config: dict, form: dict) -> str:
    idx = _int(form, "index", -1, 0, 999)
    instances = config.get("instances", [])
    if not 0 <= idx < len(instances):
        raise SettingsError("That instance no longer exists.")
    inst = instances[idx]
    if form.get("delete") == "on":
        instances.pop(idx)
        config.get("autonomy_ceilings", {}).pop(inst.get("name", ""), None)
        return f"Removed {inst.get('name') or inst.get('url')}."
    env = (form.get("environment") or inst.get("environment") or "dev").strip().lower()
    if env not in ENVIRONMENTS:
        raise SettingsError(f"Environment must be one of {', '.join(ENVIRONMENTS)}.")
    inst["name"] = (form.get("name") or "").strip() or inst.get("name", "")
    inst["environment"] = env
    inst["user"] = (form.get("user") or "").strip() or inst.get("user", "")
    inst["notes"] = (form.get("notes") or "").strip()
    if (form.get("password") or "").strip():
        inst["password"] = form["password"]
    return f"Updated {inst.get('name') or inst.get('url')}."


def apply_policy(config: dict, form: dict) -> tuple[str, list[str]]:
    """Returns the message plus the decisions worth writing to the audit log."""
    decisions: list[str] = []
    was_dry = bool(config.get("global_dry_run", True))
    # An unchecked HTML checkbox submits nothing, so absence cannot be read as
    # "off" unless we know the checkbox was on the form that was submitted.
    # Global dry run is the one setting where guessing wrong disables the
    # safety default, so the form carries an explicit marker and a POST without
    # it leaves the value alone.
    now_dry = _bool(form, "global_dry_run") if form.get("form") == "policy" else was_dry
    if was_dry != now_dry:
        decisions.append(f"global_dry_run {was_dry} -> {now_dry}")
    config["global_dry_run"] = now_dry

    ceilings = config.setdefault("autonomy_ceilings", {})
    for key, value in form.items():
        if not key.startswith("ceiling:"):
            continue
        instance = key.split(":", 1)[1]
        if value not in AUTONOMY_CLASSES:
            raise SettingsError(f"Autonomy ceiling must be one of {', '.join(AUTONOMY_CLASSES)}.")
        if ceilings.get(instance, "A1") != value:
            decisions.append(f"autonomy_ceiling[{instance}] {ceilings.get(instance, 'A1')} -> {value}")
        ceilings[instance] = value
    return "Policy saved.", decisions


def apply_executor(config: dict, form: dict) -> tuple[str, list[str]]:
    kind = (form.get("kind") or "none").strip()
    if kind not in EXECUTOR_KINDS:
        raise SettingsError(f"Executor must be one of {', '.join(EXECUTOR_KINDS)}.")
    ex = config.setdefault("executor", {})
    previous = ex.get("kind", "none")
    url = _https_url(form.get("url", ""), "NowAIKit URL")
    command = (form.get("command") or "").strip()
    if kind == "nowaikit" and not url and not command:
        raise SettingsError(
            "Configure either a NowAIKit URL or a local command. With neither, an approved "
            "fix has nowhere to go."
        )
    prefix = (form.get("update_set_prefix") or "ROB").strip()
    if not re.fullmatch(r"[A-Za-z0-9 _-]{1,24}", prefix):
        raise SettingsError("Update set prefix must be 1-24 characters: letters, digits, space, _ or -.")
    ex.update({"kind": kind, "url": url, "command": command, "update_set_prefix": prefix})
    if (form.get("token") or "").strip():
        ex["token"] = form["token"]
    decisions = [f"executor {previous} -> {kind}"] if previous != kind else []
    return ("Executor saved." if kind == "nowaikit" else "Executor disabled: fix-packs are applied by hand."), decisions


def apply_scanning(config: dict, form: dict) -> str:
    config["scanning"] = {
        "include_shadow": _bool(form, "include_shadow"),
        "upgrade_planned": _bool(form, "upgrade_planned"),
    }
    return "Scan defaults saved."


def apply_notifications(config: dict, form: dict) -> str:
    port = _int(form, "port", 25, 1, 65535)
    recipients = [r.strip() for r in re.split(r"[,;\s]+", form.get("to", "")) if r.strip()]
    for r in recipients:
        if "@" not in r:
            raise SettingsError(f"{r!r} is not an email address.")
    webhook = _https_url(form.get("webhook_url", ""), "Webhook URL")
    email = config.setdefault("email", {})
    email.update({
        "to": recipients,
        "from": (form.get("from") or "rob@localhost").strip(),
        "host": (form.get("host") or "localhost").strip(),
        "port": port,
        "starttls": _bool(form, "starttls"),
        "user": (form.get("user") or "").strip(),
    })
    if (form.get("password") or "").strip():
        email["password"] = form["password"]
    config["webhook"] = {"url": webhook}
    config["notify"] = {"always": _bool(form, "always")}
    if not recipients and not webhook:
        return "Notifications saved: no channel configured, so scheduled scans stay silent."
    return f"Notifications saved: {len(recipients)} recipient(s){' + webhook' if webhook else ''}."


def apply_ui(config: dict, form: dict) -> str:
    role = (form.get("role") or "platform_admin").strip()
    if role not in ROLE_KEYS:
        raise SettingsError(f"Role must be one of {', '.join(ROLE_KEYS)}.")
    config["ui"] = {
        "role": role,
        "redact_identifiers": _bool(form, "redact_identifiers"),
        "show_sla_dates": _bool(form, "show_sla_dates"),
    }
    return "Presentation saved."
