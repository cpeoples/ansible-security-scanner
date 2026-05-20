#!/usr/bin/env python3
"""Rule-ID to remediation-category resolution, backed by YAML.

The authoritative source is ``rule_id_categories.yaml`` in this directory.
Each shipped pattern lists exactly one category; the loader validates that
there are no silent fallbacks at import time.

Unknown rule_ids (e.g. from third-party pattern plugins that drop into
``patterns/`` without updating the YAML) go through the keyword heuristic
below and emit a one-shot warning so contributors notice. Ultimately, the
rule_id itself is returned so callers can still render a generic fix.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_YAML_PATH = Path(__file__).resolve().parent / "rule_id_categories.yml"


def _load_mapping() -> dict[str, str]:
    with open(_YAML_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    rules_by_category = data.get("rules_by_category") or {}
    if not isinstance(rules_by_category, dict):
        raise RuntimeError(
            f"{_YAML_PATH.name}: expected 'rules_by_category' to be a mapping, "
            f"got {type(rules_by_category).__name__}"
        )
    flat: dict[str, str] = {}
    duplicates: list[tuple[str, str, str]] = []
    for category, rule_ids in rules_by_category.items():
        if not isinstance(rule_ids, list):
            raise RuntimeError(
                f"{_YAML_PATH.name}: category {category!r} must be a list, "
                f"got {type(rule_ids).__name__}"
            )
        for rid in rule_ids:
            rid_str = str(rid)
            if rid_str in flat:
                duplicates.append((rid_str, flat[rid_str], str(category)))
                continue
            flat[rid_str] = str(category)
    if duplicates:
        lines = "\n  ".join(
            f"{rid!r}: in {first!r} AND {second!r}" for rid, first, second in duplicates
        )
        raise RuntimeError(f"{_YAML_PATH.name}: duplicate rule_id(s) across categories:\n  {lines}")
    return flat


_RULE_ID_TO_CATEGORY: dict[str, str] = _load_mapping()

# Keyword-based fallback for rule_ids that aren't in the YAML (third-party
# plugins, pre-release patterns). Checked in order; first match wins.
# Entries are kept here in source for discoverability - they're intentionally
# a smaller safety net than the previous heuristic table, because any shipped
# rule_id should live in the YAML by the time it's released.
_KEYWORD_FALLBACKS: list[tuple[str, str]] = [
    ("credential", "hardcoded_credentials"),
    ("password", "hardcoded_credentials"),
    ("token", "hardcoded_credentials"),
    ("api_key", "hardcoded_credentials"),
    ("injection", "command_injection"),
    ("permission", "unsafe_permissions"),
    ("backdoor", "malicious_activity"),
    ("reverse_shell", "malicious_activity"),
    ("webshell", "malicious_activity"),
    ("exfiltration", "data_exfiltration"),
    ("http_instead", "insecure_communication"),
    ("escalation", "privilege_escalation"),
    ("template", "template_injection"),
    ("jinja", "template_injection"),
    ("openai", "ai_ml_security"),
    ("anthropic", "ai_ml_security"),
    ("llm", "ai_ml_security"),
    ("aws_", "unauthorized_cloud_access"),
    ("gcp_", "unauthorized_cloud_access"),
    ("azure_", "unauthorized_cloud_access"),
    ("k8s_", "unauthorized_cloud_access"),
    ("docker_", "unauthorized_cloud_access"),
    ("persistence", "operational_security"),
    ("tunnel", "operational_security"),
    ("supply_chain", "supply_chain"),
]


# Track rule_ids that hit the fallback so we warn at most once per id.
_warned_ids: set = set()


def resolve_category(rule_id: str) -> str:
    """Map a rule_id to its remediation category.

    Preferred path: exact lookup in the YAML table. Falls back to a small
    keyword heuristic for unknown ids (with a one-shot warning) and finally
    to the rule_id itself so the generic remediation path still renders.
    """
    cat = _RULE_ID_TO_CATEGORY.get(rule_id)
    if cat is not None:
        return cat

    for keyword, category in _KEYWORD_FALLBACKS:
        if keyword in rule_id:
            if rule_id not in _warned_ids:
                _warned_ids.add(rule_id)
                logger.warning(
                    "rule_id %r has no entry in rule_id_categories.yaml; "
                    "falling back to heuristic category %r (keyword %r). "
                    "Add it to the YAML to silence this warning.",
                    rule_id,
                    category,
                    keyword,
                )
            return category

    if rule_id not in _warned_ids:
        _warned_ids.add(rule_id)
        logger.warning(
            "rule_id %r has no entry in rule_id_categories.yaml and no "
            "keyword matched; using the rule_id as its own category.",
            rule_id,
        )
    return rule_id


__all__ = ["resolve_category"]
