"""Annotation-driven playbook contract tests.

Rules that depend on runtime context (taint flow, module-sink detection,
YAML-resolved multi-line values) can't be fully covered by pure regex
examples. Those rules are covered here: the test scans curated playbooks
under ``tests/playbooks/annotations/`` and asserts expectations inlined
in the playbook itself as YAML comments.

Annotation format (case-sensitive, trailing comment on the same line):

    - name: call an internal API                      # scanner-test: reject vars_prompt_taint_uri
      uri:
        url: "{{ SPLUNK_CLOUD_url }}:8089/services"   # scanner-test: reject aws_secret_access_key
        password: "hunter2"                           # scanner-test: expect hardcoded_password

Contract:

* ``scanner-test: expect <rule_id>[, <rule_id>...]`` - the named rules
  MUST fire against this line. Guards against regex tightening that
  silently drops true positives.
* ``scanner-test: reject <rule_id>[, <rule_id>...]`` - the named rules
  MUST NOT fire against this line. Guards against false positives
  regressing.

A playbook may use both directives. A line without either directive is
neither asserted nor denied - the test is silent about it. This keeps
the corpus additive: annotate what you care about, leave the rest
alone.

The annotations are plain YAML comments - invisible to the scanner at
runtime, visible only to this test. Production ``# nosec`` / ``# noqa``
suppressions are a separate, runtime-scoped mechanism (see
``suppressions.py``) and are not touched by this file.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import pytest

SCANNER_ROOT = Path(__file__).resolve().parent.parent
ANNOTATED_DIR = SCANNER_ROOT / "tests" / "playbooks" / "annotations"

# ``# scanner-test: <verb> <rule_id>[, <rule_id>...]``
#   verb    = "expect" | "reject"
#   rule_id = snake_case or kebab-case identifiers, comma-separated
_DIRECTIVE_RE = re.compile(
    r"#\s*scanner-test:\s*(expect|reject)\s+([a-zA-Z0-9_\-, ]+?)(?:\s*#.*)?$"
)


def _parse_annotations(path: Path) -> dict[int, dict[str, set[str]]]:
    """Return ``{line_number: {"expect": {...}, "reject": {...}}}``.

    Lines without a directive are absent from the returned dict; callers
    iterate the dict keys rather than the whole file.
    """
    by_line: dict[int, dict[str, set[str]]] = defaultdict(
        lambda: {"expect": set(), "reject": set()}
    )
    for idx, line in enumerate(path.read_text().splitlines(), start=1):
        match = _DIRECTIVE_RE.search(line)
        if not match:
            continue
        verb = match.group(1)
        ids = {rid.strip() for rid in match.group(2).split(",") if rid.strip()}
        if ids:
            by_line[idx][verb].update(ids)
    return dict(by_line)


def _discover_annotated_playbooks() -> list[Path]:
    if not ANNOTATED_DIR.exists():
        return []
    return sorted(p for p in ANNOTATED_DIR.rglob("*.yml") if p.is_file())


_ANNOTATED_PLAYBOOKS = _discover_annotated_playbooks()


@pytest.fixture(scope="session")
def scanner_module():
    """Lazy-import the scanner - avoids paying the ~1s import cost
    when the annotation corpus is empty (and the test short-circuits).
    """
    from ansible_security_scanner import AnsibleSecurityScanner

    return AnsibleSecurityScanner


@pytest.fixture(scope="session")
def annotated_scans(scanner_module, request) -> dict[Path, list]:
    """Scan every annotated playbook once per session.

    Returns ``{playbook_path: [findings]}``. Skipped entirely if the
    annotations corpus is empty so a fresh checkout doesn't fail.
    """
    if not _ANNOTATED_PLAYBOOKS:
        pytest.skip("No annotated playbooks under tests/playbooks/annotations/")
    results: dict[Path, list] = {}
    for pb in _ANNOTATED_PLAYBOOKS:
        scanner = scanner_module(directory=str(pb.parent), target_files=[str(pb)])
        report = scanner.scan_directory()
        results[pb] = list(report.findings)
    return results


@pytest.mark.parametrize(
    "playbook",
    _ANNOTATED_PLAYBOOKS,
    ids=[str(p.relative_to(ANNOTATED_DIR)) for p in _ANNOTATED_PLAYBOOKS]
    if _ANNOTATED_PLAYBOOKS
    else ["_no_annotated_playbooks_"],
)
def test_playbook_annotations(playbook: Path, annotated_scans: dict[Path, list]) -> None:
    """Enforce every ``scanner-test: expect/reject`` directive."""
    from ansible_security_scanner.file_scanner import _OVERLAP_SUPPRESSION_GROUPS

    annotations = _parse_annotations(playbook)
    if not annotations:
        pytest.skip(f"{playbook.name} has no scanner-test directives")

    findings = annotated_scans[playbook]
    by_line_rule: dict[int, set[str]] = defaultdict(set)
    for f in findings:
        by_line_rule[f.line_number].add(f.rule_id)

    # An ``expect <rule_id>`` directive is satisfied when either the
    # exact rule fires OR any rule in the same overlap-suppression group
    # fires - the latter may have subsumed the expected rule. The line
    # is still proving the regex is reachable, just via the
    # higher-specificity sibling.
    def _is_expectation_satisfied(rid: str, actual: set[str]) -> bool:
        if rid in actual:
            return True
        for group in _OVERLAP_SUPPRESSION_GROUPS:
            if rid in group and any(other in actual for other in group):
                return True
        return False

    # A ``reject <rule_id>`` directive is satisfied when the exact rule
    # does not fire. Overlap-group siblings firing is fine - reject
    # annotations target ONLY the specific rule named.
    failures: list[str] = []
    for line_num, directives in sorted(annotations.items()):
        actual = by_line_rule.get(line_num, set())
        for rule_id in directives["expect"]:
            if not _is_expectation_satisfied(rule_id, actual):
                failures.append(
                    f"  line {line_num}: expected rule '{rule_id}' to fire, "
                    f"but it did not. Actual rules on this line: "
                    f"{sorted(actual) or '(none)'}"
                )
        for rule_id in directives["reject"]:
            if rule_id in actual:
                failures.append(
                    f"  line {line_num}: rule '{rule_id}' unexpectedly fired (false positive)."
                )

    if failures:
        pytest.fail(
            f"Annotation contract violated in {playbook.relative_to(SCANNER_ROOT)}:\n"
            + "\n".join(failures)
        )
