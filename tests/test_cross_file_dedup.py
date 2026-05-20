#!/usr/bin/env python3
"""Tests for cross-file finding deduplication.

Covers the ``_dedup_cross_file`` helper and the scanner-level
``dedup_cross_file`` flag that together collapse findings sharing the
same ``(rule_id, canonicalized-code-snippet)`` across multiple files
into a single representative finding with a ``duplicates`` list of
the additional affected locations.

The design intent is:
  * By default (flag off) the scanner emits one finding per location,
    matching historical behavior. Existing consumers MUST see no change.
  * With the flag on, findings collapse and the squashed siblings are
    preserved on the representative's ``duplicates`` field so nothing
    is silently dropped - the reporter can still list every location.
  * Two findings are considered duplicates ONLY when both rule_id and
    the whitespace-normalized snippet match. Different secrets,
    different module targets, or different variable names MUST produce
    distinct keys; we do not canonicalize identifiers.
"""

from __future__ import annotations

from ansible_security_scanner.file_scanner import (
    _canonicalize_snippet,
    _dedup_cross_file,
)
from ansible_security_scanner.models import SecurityFinding


def _make_finding(
    file_path: str,
    line_number: int,
    rule_id: str = "hardcoded_password",
    code_snippet: str = 'password: "Sup3rS3cr3t!"',
) -> SecurityFinding:
    return SecurityFinding(
        file_path=file_path,
        line_number=line_number,
        rule_id=rule_id,
        severity="HIGH",
        title="t",
        description="d",
        recommendation="r",
        code_snippet=code_snippet,
        remediation_example="",
    )


class TestCanonicalizeSnippet:
    def test_empty_and_none_safe(self) -> None:
        assert _canonicalize_snippet("") == ""
        assert _canonicalize_snippet(None) == ""

    def test_collapses_whitespace_runs(self) -> None:
        assert (
            _canonicalize_snippet("uri:\n        validate_certs:   no") == "uri: validate_certs: no"
        )

    def test_trims_surrounding_whitespace(self) -> None:
        assert _canonicalize_snippet("   hello  world  \n") == "hello world"

    def test_preserves_identifier_differences(self) -> None:
        """Different literals MUST produce different keys."""
        assert _canonicalize_snippet('password: "a"') != _canonicalize_snippet('password: "b"')


class TestDedupCrossFile:
    def test_empty_input_returns_empty(self) -> None:
        assert _dedup_cross_file([]) == []

    def test_unique_findings_are_unchanged(self) -> None:
        """If every finding has a distinct (rule, canonical-snippet), dedup
        is a pass-through with empty ``duplicates`` lists."""
        findings = [
            _make_finding("a.yml", 1, code_snippet='password: "a"'),
            _make_finding("b.yml", 2, code_snippet='password: "b"'),
            _make_finding("c.yml", 3, code_snippet='password: "c"'),
        ]
        out = _dedup_cross_file(findings)
        assert len(out) == 3
        assert all(f.duplicates == [] for f in out)

    def test_collapses_identical_snippets_across_files(self) -> None:
        findings = [
            _make_finding("zzz.yml", 10),
            _make_finding("aaa.yml", 20),
            _make_finding("mmm.yml", 30),
        ]
        out = _dedup_cross_file(findings)
        assert len(out) == 1
        # Representative is the lex-smallest (file, line) pair.
        rep = out[0]
        assert rep.file_path == "aaa.yml"
        assert rep.line_number == 20
        # Every sibling location is preserved.
        assert rep.duplicates == [
            {"file_path": "mmm.yml", "line_number": 30},
            {"file_path": "zzz.yml", "line_number": 10},
        ]

    def test_does_not_collapse_different_rule_ids(self) -> None:
        """Identical snippets but different rules MUST NOT collapse."""
        findings = [
            _make_finding("a.yml", 1, rule_id="hardcoded_password"),
            _make_finding("a.yml", 1, rule_id="plaintext_password_should_be_vaulted"),
        ]
        out = _dedup_cross_file(findings)
        assert len(out) == 2
        assert all(f.duplicates == [] for f in out)

    def test_does_not_collapse_different_snippets(self) -> None:
        """Same rule but different secret values MUST NOT collapse."""
        findings = [
            _make_finding("a.yml", 1, code_snippet='password: "secretA"'),
            _make_finding("b.yml", 2, code_snippet='password: "secretB"'),
        ]
        out = _dedup_cross_file(findings)
        assert len(out) == 2
        assert all(f.duplicates == [] for f in out)

    def test_whitespace_normalization_merges_reindented_copies(self) -> None:
        """Two findings against a task that was re-indented between variant
        playbooks should still collapse, because whitespace is normalized."""
        findings = [
            _make_finding(
                "a.yml",
                1,
                code_snippet="uri:\n  validate_certs: no",
            ),
            _make_finding(
                "b.yml",
                99,
                code_snippet="uri:\n        validate_certs:   no",
            ),
        ]
        out = _dedup_cross_file(findings)
        assert len(out) == 1
        assert out[0].file_path == "a.yml"
        assert out[0].duplicates == [{"file_path": "b.yml", "line_number": 99}]

    def test_representative_selection_is_stable(self) -> None:
        """Running dedup twice picks the same representative each time."""
        findings = [
            _make_finding("x.yml", 50),
            _make_finding("a.yml", 5),
            _make_finding("a.yml", 3),  # same file, earlier line -> winner
            _make_finding("m.yml", 1),
        ]
        out1 = _dedup_cross_file(list(findings))
        out2 = _dedup_cross_file(list(findings))
        assert len(out1) == 1
        assert (out1[0].file_path, out1[0].line_number) == ("a.yml", 3)
        assert (out2[0].file_path, out2[0].line_number) == ("a.yml", 3)

    def test_output_sorted_by_location(self) -> None:
        """Final result ordering is deterministic."""
        findings = [
            _make_finding("z.yml", 1, code_snippet="only-in-z"),
            _make_finding("a.yml", 1, code_snippet="only-in-a"),
            _make_finding("m.yml", 1, code_snippet="only-in-m"),
        ]
        out = _dedup_cross_file(findings)
        assert [f.file_path for f in out] == ["a.yml", "m.yml", "z.yml"]

    def test_mixed_duplicates_and_uniques(self) -> None:
        """A mix of collapsible and non-collapsible findings round-trips
        correctly: the collapsible ones merge, the unique ones pass through."""
        findings = [
            _make_finding("a.yml", 1, code_snippet="shared"),
            _make_finding("b.yml", 2, code_snippet="shared"),
            _make_finding("c.yml", 3, code_snippet="unique-c"),
            _make_finding("d.yml", 4, code_snippet="unique-d"),
        ]
        out = _dedup_cross_file(findings)
        assert len(out) == 3
        by_file = {f.file_path: f for f in out}
        assert by_file["a.yml"].duplicates == [{"file_path": "b.yml", "line_number": 2}]
        assert by_file["c.yml"].duplicates == []
        assert by_file["d.yml"].duplicates == []


class TestScannerDedupFlag:
    def test_flag_defaults_false_and_preserves_count(self, tmp_path) -> None:
        """Scanner with default flag matches the pre-feature finding count."""
        from ansible_security_scanner.scanner import AnsibleSecurityScanner

        # Create two playbooks with the same hardcoded password.
        for name in ("a.yml", "b.yml"):
            (tmp_path / name).write_text(
                "- hosts: all\n"
                "  tasks:\n"
                "    - name: set pw\n"
                "      ansible.builtin.set_fact:\n"
                '        password: "Sup3rS3cr3t!"\n'
            )
        scanner_off = AnsibleSecurityScanner(directory=str(tmp_path))
        report_off = scanner_off.scan_directory()
        pw_off = [f for f in report_off.findings if f.rule_id == "hardcoded_password"]
        assert len(pw_off) == 2
        assert all(f.duplicates == [] for f in pw_off)

    def test_flag_on_collapses_cross_file_duplicates(self, tmp_path) -> None:
        from ansible_security_scanner.scanner import AnsibleSecurityScanner

        for name in ("a.yml", "b.yml", "c.yml"):
            (tmp_path / name).write_text(
                "- hosts: all\n"
                "  tasks:\n"
                "    - name: set pw\n"
                "      ansible.builtin.set_fact:\n"
                '        password: "Sup3rS3cr3t!"\n'
            )
        scanner_on = AnsibleSecurityScanner(directory=str(tmp_path), dedup_cross_file=True)
        report_on = scanner_on.scan_directory()
        pw_on = [f for f in report_on.findings if f.rule_id == "hardcoded_password"]
        assert len(pw_on) == 1
        rep = pw_on[0]
        # Two siblings preserved on the representative.
        assert len(rep.duplicates) == 2
        sibling_files = {d["file_path"] for d in rep.duplicates}
        # Representative is one of the three; the other two are in duplicates.
        all_files = sibling_files | {rep.file_path}
        assert {p.name for p in tmp_path.glob("*.yml")} == {p.split("/")[-1] for p in all_files}


class TestFormattersRenderDuplicates:
    """Each formatter that surfaces human-readable locations must not lose
    the duplicates list when cross-file dedup collapsed a finding. JSON and
    YAML are automatic via ``dataclasses.asdict``; Markdown, HTML, and
    SARIF need explicit rendering hooks that we verify here.
    """

    def _finding_with_dups(self) -> SecurityFinding:
        f = _make_finding("primary.yml", 10, rule_id="hardcoded_password")
        f.duplicates = [
            {"file_path": "sibling1.yml", "line_number": 20},
            {"file_path": "sibling2.yml", "line_number": 30},
        ]
        # severity HIGH so both Markdown and HTML formatters render it.
        f.severity = "HIGH"
        return f

    def _make_report(self, finding: SecurityFinding):
        from ansible_security_scanner.models import ScanReport, SecurityScore

        return ScanReport(
            scan_timestamp="2026-01-01T00:00:00Z",
            ansible_directory=".",
            total_files_scanned=3,
            scanned_file_names=["primary.yml", "sibling1.yml", "sibling2.yml"],
            findings=[finding],
            summary={
                "total_findings": 1,
                "total": 1,
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
            },
            security_score=SecurityScore(
                overall_score=90.0,
                risk_score=10.0,
                category_scores={},
                severity_breakdown={"HIGH": 1},
                file_scores={"primary.yml": 90.0},
                recommendations_count=0,
            ),
        )

    def test_markdown_renders_duplicates_block(self) -> None:
        from ansible_security_scanner.formatters.markdown import MarkdownFormatter

        report = self._make_report(self._finding_with_dups())
        out = MarkdownFormatter().format(report)
        assert "Also affects 2 other location(s)" in out
        assert "`sibling1.yml`" in out and "Line 20" in out
        assert "`sibling2.yml`" in out and "Line 30" in out

    def test_html_renders_duplicates_details(self) -> None:
        from ansible_security_scanner.formatters.html import HTMLFormatter

        report = self._make_report(self._finding_with_dups())
        out = HTMLFormatter().format(report)
        assert "Also affects 2 other location(s)" in out
        assert "sibling1.yml" in out and "Line 20" in out
        assert "sibling2.yml" in out and "Line 30" in out

    def test_sarif_appends_duplicates_as_physical_locations(self) -> None:
        import json as _json

        from ansible_security_scanner.formatters.sarif import SARIFFormatter

        report = self._make_report(self._finding_with_dups())
        raw = SARIFFormatter().format(report)
        doc = _json.loads(raw)
        [result] = doc["runs"][0]["results"]
        # 1 primary + 2 duplicate locations == 3 entries.
        assert len(result["locations"]) == 3
        uris = [loc["physicalLocation"]["artifactLocation"]["uri"] for loc in result["locations"]]
        assert uris[0] == "primary.yml"  # representative is always first
        assert set(uris[1:]) == {"sibling1.yml", "sibling2.yml"}

    def test_json_passes_duplicates_through(self) -> None:
        import json as _json

        from ansible_security_scanner.formatters.json import JSONFormatter

        report = self._make_report(self._finding_with_dups())
        doc = _json.loads(JSONFormatter().format(report))
        [finding] = doc["findings"]
        assert finding["duplicates"] == [
            {"file_path": "sibling1.yml", "line_number": 20},
            {"file_path": "sibling2.yml", "line_number": 30},
        ]
