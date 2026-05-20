"""Lazy index of pattern metadata (description, recommendation, examples) keyed by rule_id.

Used by the remediation fallback to render rule-specific output for rules
that don't have a tailored handler. Every shipped pattern has at minimum a
description, so the fallback is guaranteed to produce something more
specific than the legacy boilerplate.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_PATTERNS_DIR = Path(__file__).resolve().parent.parent / "patterns"


@lru_cache(maxsize=1)
def _index() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for yml in sorted(_PATTERNS_DIR.glob("*.yml")):
        doc = yaml.safe_load(yml.read_text()) or {}
        for p in doc.get("patterns") or []:
            rid = p.get("id")
            if not rid or p.get("exclude"):
                continue
            out[rid] = {
                "description": p.get("description") or "",
                "recommendation": p.get("recommendation") or "",
                "positive_examples": p.get("positive_examples") or [],
                "negative_examples": p.get("negative_examples") or [],
                "category": p.get("category") or "",
                "title": p.get("title") or "",
                "no_ansible_remediation": bool(p.get("no_ansible_remediation", False)),
            }
    return out


def get(rule_id: str) -> dict:
    return _index().get(rule_id, {})
