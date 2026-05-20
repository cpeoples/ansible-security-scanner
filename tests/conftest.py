"""Shared pytest fixtures for the scanner test suite.

Session-scoped fixtures cache expensive work that multiple tests repeat:
every ``yaml.safe_load`` on the 40 pattern files is paid once per test run
instead of ~5 times, saving a few seconds per suite invocation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

SCANNER_ROOT = Path(__file__).resolve().parent.parent
PATTERNS_DIR = SCANNER_ROOT / "src" / "ansible_security_scanner" / "patterns"
TESTS_DIR = SCANNER_ROOT / "tests" / "playbooks"


@pytest.fixture(scope="session")
def all_pattern_files() -> list[Path]:
    """All pattern YAML files, sorted for determinism."""
    return sorted(PATTERNS_DIR.glob("*.yml"))


@pytest.fixture(scope="session")
def all_pattern_docs(all_pattern_files: list[Path]) -> dict[Path, dict]:
    """Every pattern YAML parsed once, keyed by file path."""
    return {yml: yaml.safe_load(yml.read_text()) for yml in all_pattern_files}


@pytest.fixture(scope="session")
def all_patterns_flat(all_pattern_docs: dict[Path, dict]) -> list[tuple[Path, dict]]:
    """Flat list of (file, pattern_dict) tuples across every pattern file."""
    return [(yml, p) for yml, doc in all_pattern_docs.items() for p in (doc.get("patterns") or [])]


@pytest.fixture(scope="session")
def all_rule_ids(all_patterns_flat: list[tuple[Path, dict]]) -> set[str]:
    """Every shipped pattern's rule_id, excluding filter-only patterns.

    Patterns with ``exclude: true`` are used to SUPPRESS other findings
    on the same line (they never emit a finding of their own id); the
    ``bad_example`` full-coverage test shouldn't demand they fire.
    """
    return {p["id"] for _, p in all_patterns_flat if not p.get("exclude")}


# In-process scan fixtures.
# Running the scanner as a subprocess (the historical shape of the
# integration tests) reloads ~1000 patterns and reparses ~4000 lines of
# ``bad_example.yml`` on every invocation. For the output-format matrix
# that meant 8 subprocess boots ≈ 40s alone. By running the scan once
# per session and handing the ``ScanReport`` to every consumer we cut
# that cost to a single in-process scan (<5s) and let formatter tests
# call the formatter classes directly.


def _scan_in_process(target: Path, **kwargs):
    """Run the scanner in-process and return its ``ScanReport``.

    Mirrors what ``cli.py`` does when invoked with ``--files`` and
    ``--format json`` but skips the whole subprocess/argparse layer,
    the pattern reload, and JSON serialization-then-parse round trip.
    """
    from ansible_security_scanner import AnsibleSecurityScanner

    scanner = AnsibleSecurityScanner(
        directory=str(target.parent),
        target_files=[str(target)],
        **kwargs,
    )
    return scanner.scan_directory()


def _report_to_json_dict(report) -> dict:
    """Return the same dict shape that the CLI's ``--format json`` emits."""
    from ansible_security_scanner import JSONFormatter

    return json.loads(JSONFormatter(show_all=True).format(report))


@pytest.fixture(scope="session")
def bad_example_report():
    """Single shared scan of ``tests/playbooks/bad_example.yml``.

    Exposed as a pytest fixture so the bad-example coverage test,
    the output-format matrix, and any future consumer all share the
    work. Scoped to ``session`` because ``bad_example.yml`` is
    append-only between test runs and the scanner is deterministic.
    """
    target = TESTS_DIR / "bad_example.yml"
    if not target.exists():
        pytest.skip(f"{target} not found")
    return _scan_in_process(target)


@pytest.fixture(scope="session")
def bad_example_json(bad_example_report) -> dict:
    """JSON-formatted view of the shared bad_example scan."""
    return _report_to_json_dict(bad_example_report)


@pytest.fixture(scope="session")
def clean_example_report():
    """Single shared scan of ``tests/playbooks/clean_example.yml``."""
    target = TESTS_DIR / "clean_example.yml"
    if not target.exists():
        pytest.skip(f"{target} not found")
    return _scan_in_process(target)


@pytest.fixture(scope="session")
def clean_example_json(clean_example_report) -> dict:
    """JSON-formatted view of the shared clean_example scan."""
    return _report_to_json_dict(clean_example_report)


# Multi-file fixture scans. Roles span six files each
# (meta/defaults/tasks/main/install/harden and a top-level site.yml).
# Scanned once per session because cross-file analysis (taint tracking,
# role-meta hygiene) must see the full tree.


def _scan_directory_in_process(directory: Path):
    """Run the scanner across every YAML under ``directory``.

    Matches what the CLI does when invoked with ``--directory`` - no
    ``target_files`` restriction, so the scanner walks the role tree
    like a real user would.
    """
    from ansible_security_scanner import AnsibleSecurityScanner

    scanner = AnsibleSecurityScanner(directory=str(directory))
    return scanner.scan_directory()


@pytest.fixture(scope="session")
def multi_example_clean_report():
    """Scan of ``tests/playbooks/multi_example_clean/`` - a 6-file
    hardened role fixture. Expected to produce zero findings; guards
    against future pattern regressions that would false-positive on
    realistic role layouts.
    """
    target = TESTS_DIR / "multi_example_clean"
    if not target.exists():
        pytest.skip(f"{target} not found")
    return _scan_directory_in_process(target)


@pytest.fixture(scope="session")
def multi_example_clean_json(multi_example_clean_report) -> dict:
    """JSON-formatted view of the shared multi_example_clean scan."""
    return _report_to_json_dict(multi_example_clean_report)


@pytest.fixture(scope="session")
def multi_example_bad_report():
    """Scan of ``tests/playbooks/multi_example_bad/`` - a 6-file
    intentionally-vulnerable role fixture. Exercises cross-file
    patterns the single-file ``bad_example.yml`` can't reach:

    * cross-file taint (set_fact in site.yml -> shell sink in a role
      task file),
    * role-meta hygiene (galaxy_info without a license),
    * vars-defined secrets referenced from sibling task files,
    * multi-file SLSA / supply-chain flows.

    The specific expected-findings floor is enforced by
    ``test_multi_example_bad_known_findings``.
    """
    target = TESTS_DIR / "multi_example_bad"
    if not target.exists():
        pytest.skip(f"{target} not found")
    return _scan_directory_in_process(target)


@pytest.fixture(scope="session")
def multi_example_bad_json(multi_example_bad_report) -> dict:
    """JSON-formatted view of the shared multi_example_bad scan."""
    return _report_to_json_dict(multi_example_bad_report)
