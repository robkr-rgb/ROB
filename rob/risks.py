"""Accepted-risk register (per remediation-framework.md).

Fingerprint-keyed, file-based for the skeleton. Acceptance survives re-scans,
downgrades priority one step (accepted_risk adjustment), suppresses fix-pack
generation, appears in reports as accepted (never hidden) and expires after
12 months by default, forcing re-decision.
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib

DEFAULT_TTL_DAYS = 365


def load_register(path: str | pathlib.Path) -> dict[str, dict]:
    p = pathlib.Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def save_register(path: str | pathlib.Path, register: dict[str, dict]) -> None:
    pathlib.Path(path).write_text(json.dumps(register, indent=2, sort_keys=True))


def accept(register: dict[str, dict], fingerprint: str, reason: str, accepted_by: str, now: dt.datetime, ttl_days: int = DEFAULT_TTL_DAYS) -> dict[str, dict]:
    register[fingerprint] = {
        "reason": reason,
        "accepted_by": accepted_by,
        "accepted_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + dt.timedelta(days=ttl_days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return register


def active_acceptances(register: dict[str, dict], now: dt.datetime) -> dict[str, dict]:
    """Unexpired acceptances only; expired entries are returned to normal scoring."""
    out = {}
    for fp, entry in register.items():
        try:
            expires = dt.datetime.strptime(entry["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        except (KeyError, ValueError):
            continue
        if expires > now:
            out[fp] = entry
    return out
