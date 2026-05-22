"""Rule-selection (``--select`` / ``--ignore`` / ``--list-rules``) tests.

These pin the contract that lets pip-installed users run a narrow rule
set without editing site-packages. The scanner narrows the YAML pattern
list at load time (so the regex hot loop runs against fewer rules) and
gates synthetic / structural / jinja2 / taint-tracker findings at the
end of each scan_file. Both gates have to agree on the active rule set
for selection to be correct.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from ansible_security_scanner.patterns_manager import (
    RuleSelectionError,
    filter_patterns,
    known_rule_ids,
    patterns_manager,
    resolve_rule_specs,
)
from ansible_security_scanner.scanner import AnsibleSecurityScanner

REPO_ROOT = Path(__file__).resolve().parent.parent
BAD_FIXTURE = REPO_ROOT / "tests" / "playbooks" / "bad_example.yml"


def test_known_rule_ids_includes_yaml_and_synthetic() -> None:
    universe = known_rule_ids()
    assert "hardcoded_password" in universe, "yaml rule should appear"
    assert "cross_file_taint" in universe, "synthetic rule should appear"
    assert len(universe) >= 1090, f"expected at least 1090 rules, got {len(universe)}"


def test_resolve_rule_specs_literal_match() -> None:
    universe = known_rule_ids()
    assert resolve_rule_specs(["hardcoded_password"], universe) == frozenset({"hardcoded_password"})


def test_resolve_rule_specs_glob_expansion() -> None:
    universe = known_rule_ids()
    aws = resolve_rule_specs(["aws_*"], universe)
    assert len(aws) > 10, "aws_* should match many rules"
    assert all(rid.startswith("aws_") for rid in aws)


def test_resolve_rule_specs_comma_split() -> None:
    universe = known_rule_ids()
    out = resolve_rule_specs(["hardcoded_password,curl_pipe_to_shell"], universe)
    assert out == frozenset({"hardcoded_password", "curl_pipe_to_shell"})


def test_resolve_rule_specs_unknown_id_raises() -> None:
    with pytest.raises(RuleSelectionError, match="hardcoded_pasword"):
        resolve_rule_specs(["hardcoded_pasword"], known_rule_ids())


def test_resolve_rule_specs_glob_with_zero_matches_raises() -> None:
    with pytest.raises(RuleSelectionError, match="zzz_no_such_prefix_"):
        resolve_rule_specs(["zzz_no_such_prefix_*"], known_rule_ids())


def test_resolve_rule_specs_empty_returns_empty() -> None:
    assert resolve_rule_specs(None, known_rule_ids()) == frozenset()
    assert resolve_rule_specs([], known_rule_ids()) == frozenset()
    assert resolve_rule_specs([""], known_rule_ids()) == frozenset()


def test_filter_patterns_select_narrows() -> None:
    raw = patterns_manager.discover_and_load_patterns()
    narrowed = filter_patterns(raw, select=frozenset({"hardcoded_password"}), ignore=None)
    flat = [p.id for pats in narrowed.values() for p in pats]
    assert flat == ["hardcoded_password"]


def test_filter_patterns_ignore_drops() -> None:
    raw = patterns_manager.discover_and_load_patterns()
    narrowed = filter_patterns(raw, select=None, ignore=frozenset({"hardcoded_password"}))
    flat = {p.id for pats in narrowed.values() for p in pats}
    assert "hardcoded_password" not in flat
    assert len(flat) >= 1000, "ignoring one rule should leave the rest intact"


def test_filter_patterns_select_and_ignore_intersect() -> None:
    raw = patterns_manager.discover_and_load_patterns()
    narrowed = filter_patterns(
        raw,
        select=frozenset({"hardcoded_password", "hardcoded_api_key"}),
        ignore=frozenset({"hardcoded_api_key"}),
    )
    flat = [p.id for pats in narrowed.values() for p in pats]
    assert flat == ["hardcoded_password"]


def test_filter_patterns_no_filter_returns_input() -> None:
    raw = patterns_manager.discover_and_load_patterns()
    assert filter_patterns(raw, select=None, ignore=None) is raw


@pytest.mark.skipif(not BAD_FIXTURE.exists(), reason="fixture playbook not present")
def test_select_only_runs_named_rule() -> None:
    """A single-rule scan must produce only that rule_id (plus the meta
    rule_ids ``scan_error`` / ``suspicious_suppression`` that report on
    the scan itself)."""
    scanner = AnsibleSecurityScanner(
        directory=str(BAD_FIXTURE.parent),
        target_files=[str(BAD_FIXTURE)],
        select_rules=["hardcoded_password"],
    )
    report = scanner.scan_directory()
    rule_ids = {f.rule_id for f in report.findings}
    assert rule_ids - {"scan_error", "suspicious_suppression"} <= {"hardcoded_password"}
    assert "hardcoded_password" in rule_ids, "fixture must produce the selected rule"


@pytest.mark.skipif(not BAD_FIXTURE.exists(), reason="fixture playbook not present")
def test_ignore_drops_named_rule_only() -> None:
    """``--ignore X`` must remove X but keep everything else."""
    baseline = AnsibleSecurityScanner(
        directory=str(BAD_FIXTURE.parent), target_files=[str(BAD_FIXTURE)]
    ).scan_directory()
    baseline_ids = {f.rule_id for f in baseline.findings}
    assert "hardcoded_password" in baseline_ids, (
        "test precondition: fixture must produce hardcoded_password under default scan"
    )

    filtered = AnsibleSecurityScanner(
        directory=str(BAD_FIXTURE.parent),
        target_files=[str(BAD_FIXTURE)],
        ignore_rules=["hardcoded_password"],
    ).scan_directory()
    filtered_ids = {f.rule_id for f in filtered.findings}
    assert "hardcoded_password" not in filtered_ids, (
        "ignored rule must be absent from filtered scan"
    )
    # Most of the rule_ids should overlap. Overlap-suppression can flip
    # a small number of rule_ids in either direction (when an ignored
    # rule's finding was previously suppressing a co-located rule, or
    # vice versa). Cap the symmetric difference at a small fraction of
    # the rule set so we catch real regressions but tolerate the few
    # legitimate suppression-cascade shifts.
    symmetric_diff = (filtered_ids ^ baseline_ids) - {"hardcoded_password"}
    assert len(symmetric_diff) <= 5, (
        f"--ignore should not perturb more than a handful of other rule_ids; "
        f"got delta={sorted(symmetric_diff)}"
    )


def test_unknown_rule_id_raises_at_construction() -> None:
    with pytest.raises(RuleSelectionError):
        AnsibleSecurityScanner(directory=".", select_rules=["definitely_not_a_real_rule"])


def test_select_glob_keeps_only_matching_rules() -> None:
    scanner = AnsibleSecurityScanner(directory=".", select_rules=["aws_*"])
    assert scanner.active_rule_ids is not None
    assert all(rid.startswith("aws_") for rid in scanner.active_rule_ids)
    assert len(scanner.active_rule_ids) > 10


def test_default_construction_leaves_active_rule_ids_none() -> None:
    """Backward compat: scanner with no select/ignore must keep
    ``active_rule_ids = None`` so the cached pattern data passes through
    untouched and the synthetic gate never fires."""
    scanner = AnsibleSecurityScanner(directory=".")
    assert scanner.active_rule_ids is None
    assert scanner.file_scanner.active_rule_ids is None


def test_cache_isolation_between_scanners() -> None:
    """Two scanners constructed back-to-back with different filters must
    each see their own pattern set. Regression guard for the singleton's
    cache: filter results must be a derived view, not a mutation.

    The narrowed scanner keeps the user's selected rules PLUS any
    ``exclude: true`` patterns (those suppress overlapping false
    positives across rules and dropping them would cause spurious
    findings). So the count is ``len(selected) + N_excludes``."""
    a = AnsibleSecurityScanner(directory=".", select_rules=["hardcoded_password"])
    a_total = sum(len(v) for v in a.file_scanner.pattern_data.values())
    a_active_ids = {p.id for v in a.file_scanner.pattern_data.values() for p in v if not p.exclude}
    assert a_active_ids == {"hardcoded_password"}, (
        f"scanner A's selected (non-exclude) rules should be just hardcoded_password; got {a_active_ids}"
    )
    assert a_total <= 5, f"scanner A should be tiny (selected + a few excludes); got {a_total}"

    b = AnsibleSecurityScanner(directory=".")
    b_total = sum(len(v) for v in b.file_scanner.pattern_data.values())
    assert b_total > 1000, (
        f"scanner B (no filter) should see all rules; got {b_total}. "
        f"Singleton cache was likely mutated by scanner A."
    )


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Invoke the CLI in a subprocess so we test the real entry point.

    Runs against the same Python interpreter pytest is using, with the
    repo root on PYTHONPATH so the editable install resolves correctly.
    """
    return subprocess.run(
        [sys.executable, "-m", "ansible_security_scanner", *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )


def test_cli_list_rules_prints_every_id_to_stdout() -> None:
    result = _run_cli("--list-rules")
    assert result.returncode == 0
    ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    universe = known_rule_ids()
    assert set(ids) == universe, "stdout list must match the canonical universe"


def test_cli_list_rules_header_goes_to_stderr() -> None:
    """The header is diagnostic; piping ``--list-rules | grep ...`` must
    not see the count line. Keeps the rule-id list machine-readable."""
    result = _run_cli("--list-rules")
    assert "rule_ids known" in result.stderr
    assert "rule_ids known" not in result.stdout


def test_cli_list_rules_detailed_emits_tsv_with_metadata() -> None:
    """``--list-rules-detailed`` must emit one TSV row per rule_id with
    the canonical four columns (``rule_id<TAB>severity<TAB>category
    <TAB>title``). YAML rules carry real metadata; synthetic and
    code-emitted rule_ids carry the documented ``<synthetic>`` sentinel
    so consumers can filter them out.
    """
    result = _run_cli("--list-rules-detailed")
    assert result.returncode == 0

    parsed = [line.split("\t") for line in result.stdout.splitlines() if line.strip()]
    assert all(len(cols) == 4 for cols in parsed), (
        f"every row must have exactly 4 tab-separated columns; "
        f"first malformed: {next((r for r in parsed if len(r) != 4), None)!r}"
    )
    assert {cols[0] for cols in parsed} == known_rule_ids(), (
        "row count must match the canonical rule_id universe"
    )

    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    yaml_severities = {cols[1] for cols in parsed if cols[1] != "<synthetic>"}
    assert yaml_severities, "expected at least one YAML-backed rule"
    assert yaml_severities <= valid_severities, (
        f"YAML severities must be one of {sorted(valid_severities)}; saw {sorted(yaml_severities)}"
    )


def test_cli_list_rules_detailed_header_goes_to_stderr() -> None:
    result = _run_cli("--list-rules-detailed")
    assert "rule_ids known" in result.stderr
    assert "rule_ids known" not in result.stdout


def test_cli_unknown_rule_id_exits_2() -> None:
    result = _run_cli("--select", "definitely_not_a_real_rule")
    assert result.returncode == 2
    assert "definitely_not_a_real_rule" in result.stderr


def test_cli_select_runs_only_named_rule() -> None:
    if not BAD_FIXTURE.exists():
        pytest.skip("fixture playbook not present")
    result = _run_cli(
        "--select",
        "hardcoded_password",
        "--directory",
        str(BAD_FIXTURE.parent),
        "--files",
        str(BAD_FIXTURE),
        "--format",
        "json",
        "--exit-zero",
    )
    assert result.returncode == 0, f"stderr={result.stderr}"
    payload = json.loads(result.stdout)
    rule_ids = {f["rule_id"] for f in payload["findings"]}
    assert rule_ids - {"scan_error", "suspicious_suppression"} <= {"hardcoded_password"}


def test_env_var_select_resolves_in_constructor(monkeypatch) -> None:
    """``ANSIBLE_SEC_SCANNER_SELECT`` is read at CLI parse time (see
    ``cli.create_argument_parser``), so the resolution we test here is
    the constructor's own handling of an explicit kwarg. The CLI plumbs
    one to the other via the existing _env_str helper covered in
    test_cli_env_overrides.py."""
    monkeypatch.delenv("ANSIBLE_SEC_SCANNER_SELECT", raising=False)
    scanner = AnsibleSecurityScanner(directory=".", select_rules=["hardcoded_password"])
    assert scanner.active_rule_ids == frozenset({"hardcoded_password"})


def test_env_var_ignore_resolves_in_constructor(monkeypatch) -> None:
    monkeypatch.delenv("ANSIBLE_SEC_SCANNER_IGNORE", raising=False)
    scanner = AnsibleSecurityScanner(directory=".", ignore_rules=["hardcoded_password"])
    assert scanner.active_rule_ids is not None
    assert "hardcoded_password" not in scanner.active_rule_ids
    assert "curl_pipe_to_shell" in scanner.active_rule_ids
