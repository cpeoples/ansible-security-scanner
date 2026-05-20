"""Lazy index of hand-written ``secure_fix`` Ansible snippets keyed by rule_id.

Companion data lives in ``patterns/remediations/<category>.yml``. This
keeps pattern definitions (rule, regex, severity, recommendation prose)
in their original files and concentrates the bigger, hand-crafted fix
snippets in their own per-category files for easier review.

See ``patterns/remediations/README.md`` for the schema.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_COMPANION_DIR = Path(__file__).resolve().parent.parent / "patterns" / "remediations"


@lru_cache(maxsize=1)
def _index() -> dict[str, str]:
    out: dict[str, str] = {}
    if not _COMPANION_DIR.exists():
        return out
    for yml in sorted(_COMPANION_DIR.glob("*.yml")):
        doc = yaml.safe_load(yml.read_text()) or {}
        for rid, body in (doc.get("remediations") or {}).items():
            if isinstance(body, dict):
                fix = body.get("secure_fix")
            else:
                fix = body
            if isinstance(fix, str) and fix.strip():
                out[rid] = fix.rstrip("\n")
    return out


def get(rule_id: str) -> str | None:
    return _index().get(rule_id)
