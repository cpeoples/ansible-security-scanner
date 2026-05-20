"""Self-describing rule example tests.

Every pattern in ``src/ansible_security_scanner/patterns/*.yml`` may ship
with two optional arrays:

* ``positive_examples`` - strings that MUST match the rule's regex.
* ``negative_examples`` - strings that MUST NOT match the rule's regex.

The author of the rule writes these alongside the regex so that the
*intent* of the rule - "match this, don't match that" - lives next to
the regex itself. Any future regex rewrite that silently changes
semantics fails these tests loudly.

This is intentionally a pure regex-level check. Rules that fire only
after YAML resolution, cross-file taint, or context filtering are
covered by the annotation-driven playbook tests (see
``test_playbook_annotations.py``).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

SCANNER_ROOT = Path(__file__).resolve().parent.parent
PATTERNS_DIR = SCANNER_ROOT / "src" / "ansible_security_scanner" / "patterns"


def _collect_cases(kind: str) -> list[tuple[str, str, str, str]]:
    """Return ``(rule_id, pattern_file_name, regex, example)`` tuples for
    every ``positive_examples`` or ``negative_examples`` entry in every
    shipped rule.

    Kept out of a fixture because pytest's parametrize collection needs
    the values at import time, not fixture-resolution time.
    """
    cases: list[tuple[str, str, str, str]] = []
    for yml in sorted(PATTERNS_DIR.glob("*.yml")):
        doc = yaml.safe_load(yml.read_text()) or {}
        for pattern in doc.get("patterns") or []:
            for example in pattern.get(kind) or []:
                cases.append((pattern["id"], yml.name, pattern["regex"], example))
    return cases


def _compile(regex: str) -> re.Pattern[str]:
    """Compile with the same flags the scanner uses at runtime."""
    return re.compile(regex, re.IGNORECASE | re.MULTILINE)


_POSITIVE_CASES = _collect_cases("positive_examples")
_NEGATIVE_CASES = _collect_cases("negative_examples")


@pytest.mark.parametrize(
    ("rule_id", "file_name", "regex", "example"),
    _POSITIVE_CASES,
    ids=[f"{rid}::pos::{i}" for i, (rid, *_) in enumerate(_POSITIVE_CASES)],
)
def test_positive_example_matches(rule_id: str, file_name: str, regex: str, example: str) -> None:
    """Every ``positive_examples`` entry MUST match the rule's regex.

    Rules whose regex is the always-fail sentinel ``(?!)`` are AST-driven
    (the regex is a placeholder and the real check lives in the AST walker).
    Their positive examples are documentation only, so we skip them here.
    """
    if regex.strip() == "(?!)":
        pytest.skip(f"{rule_id}: AST-driven rule, regex sentinel only")
    assert _compile(regex).search(example), (
        f"Rule '{rule_id}' in {file_name}: positive example failed to match.\n"
        f"  regex:   {regex}\n  example: {example!r}"
    )


@pytest.mark.parametrize(
    ("rule_id", "file_name", "regex", "example"),
    _NEGATIVE_CASES,
    ids=[f"{rid}::neg::{i}" for i, (rid, *_) in enumerate(_NEGATIVE_CASES)],
)
def test_negative_example_does_not_match(
    rule_id: str, file_name: str, regex: str, example: str
) -> None:
    """Every ``negative_examples`` entry MUST NOT match the rule's regex."""
    match = _compile(regex).search(example)
    assert match is None, (
        f"Rule '{rule_id}' in {file_name}: negative example unexpectedly matched.\n"
        f"  regex:     {regex}\n"
        f"  example:   {example!r}\n"
        f"  matched:   {match.group(0)!r}"
    )


def test_collection_is_non_empty() -> None:
    """Sanity check: the collector found at least one example.

    Guards against a silent regression where the pattern YAMLs lose the
    ``positive_examples`` / ``negative_examples`` shape entirely and the
    parametrized tests silently collect zero cases (which pytest would
    otherwise report as "0 tests passed", a false green).
    """
    assert _POSITIVE_CASES or _NEGATIVE_CASES, (
        "No positive_examples or negative_examples were collected from any "
        "pattern file. The scaffolding is wired up but no rules have "
        "declared examples yet - add some, starting with the high-FP rules."
    )
