"""Shared helpers for fix-pack generators."""
from __future__ import annotations

import json
import re


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40]


def js_list(sys_ids: list[str]) -> str:
    return json.dumps(sys_ids)


def jexport(records) -> str:
    return json.dumps(records, indent=2)
