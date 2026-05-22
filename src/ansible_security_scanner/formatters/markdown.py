#!/usr/bin/env python3
"""
Markdown output formatter for Ansible Security Scanner
"""

import re
from datetime import datetime

from ..link_resolver import (
    resolve_atlas,
    resolve_cis,
    resolve_cwe,
    resolve_hipaa,
    resolve_mitre,
    resolve_nist,
    resolve_pci,
    resolve_soc2,
    resolve_stig,
)
from ..models import ScanReport, SecurityFinding
from ._policy import voice as _voice_policy
from .base import OutputFormatter, ReportEmojis


class MarkdownFormatter(OutputFormatter):
    """Formats report as Markdown"""

    @staticmethod
    def _inline_code_snippet(code_snippet: str, match_line: str = "") -> str:
        """Single-line preview of the offending code for inline rendering.

        Prefers ``match_line`` (set by the scanner at finding-creation time)
        so the inline ``**Code:**`` summary shows the exact triggering line.
        Falls back to the first non-empty, non-task-title line of
        ``code_snippet`` for callers that don't have a match line. Multi-line
        snippets get a trailing ellipsis so readers know the full body lives
        in the fenced ``Vulnerable Code`` block below.
        """
        snippet_lines = [ln for ln in (code_snippet or "").splitlines() if ln.strip()]
        is_multi = len(snippet_lines) > 1
        ml = (match_line or "").strip()
        if ml:
            return f"{ml} ..." if is_multi else ml
        if not snippet_lines:
            return ""
        if is_multi and re.match(r"^\s*-\s*name\s*:", snippet_lines[0], re.IGNORECASE):
            preview = snippet_lines[1].strip()
        else:
            preview = snippet_lines[0].strip()
        return f"{preview} ..." if is_multi else preview

    @staticmethod
    def _framework_coverage(finding: SecurityFinding) -> str:
        """Return a markdown block of resolved framework links, or '' if none.

        Each id is resolved individually so we preserve the pattern-authored
        order. Unknown ids render as an unlinked code span rather than being
        dropped - the catalog test prevents this in-tree, but third-party
        pattern packs may ship IDs we don't know about.
        """
        if not (
            finding.cwe
            or finding.mitre_attack
            or finding.cis_controls
            or finding.nist_controls
            or finding.pci_dss
            or finding.hipaa
            or finding.soc2
            or finding.stig
            or finding.mitre_atlas
        ):
            return ""

        sections: list[str] = []

        def _line(label: str, raw_ids, resolver) -> None:
            if not raw_ids:
                return
            rendered = []
            for raw in raw_ids:
                ref = resolver(raw)
                if ref:
                    rendered.append(f"[{ref.id}]({ref.url}) - {ref.name}")
                else:
                    rendered.append(f"`{raw}`")
            sections.append(f"  - {label}: " + "; ".join(rendered))

        _line("CWE", finding.cwe, resolve_cwe)
        _line("MITRE ATT&CK", finding.mitre_attack, resolve_mitre)
        _line("MITRE ATLAS", finding.mitre_atlas, resolve_atlas)
        _line("CIS Controls", finding.cis_controls, resolve_cis)
        _line("NIST 800-53", finding.nist_controls, resolve_nist)
        _line("PCI-DSS v4", finding.pci_dss, resolve_pci)
        _line("HIPAA §164.312", finding.hipaa, resolve_hipaa)
        _line("SOC 2 TSC", finding.soc2, resolve_soc2)
        _line("DISA STIG", finding.stig, resolve_stig)
        if not sections:
            return ""
        # Leading newline produces a blank line between the preceding bullet
        # line and the coverage block; trailing newline keeps the template's
        # gap sizing consistent whether or not coverage is present.
        return "\n- **Framework Coverage:**\n" + "\n".join(sections)

    @staticmethod
    def _duplicates_block(finding: SecurityFinding) -> str:
        """Render the ``duplicates`` list (if any) as a collapsed details block.

        When cross-file dedup collapses a finding, the additional affected
        locations live on ``finding.duplicates`` as ``{"file_path": ...,
        "line_number": ...}`` dicts. We surface them under a short headline
        so reviewers know this is one of many call sites; the full list is
        nested inside a ``<details>`` element to avoid overwhelming the
        default report view when a single vuln touches dozens of files.
        Returns ``""`` when there are no duplicates.
        """
        dups = getattr(finding, "duplicates", None) or []
        if not dups:
            return ""
        n = len(dups)
        items = "\n".join(
            f"  - `{d.get('file_path', '?')}` (Line {d.get('line_number', '?')})" for d in dups
        )
        return (
            f"\n- **Also affects {n} other location(s)** "
            f"<details><summary>expand</summary>\n\n{items}\n\n</details>"
        )

    @staticmethod
    def _issue_density_row(report: ScanReport) -> str:
        """Render the 'Issue Density' row for the Overall Security Posture
        table. Returns an empty string (no row) when only one file was
        scanned - per-file density on a single file is just the total count
        and adds nothing. Kept as a helper so the template stays readable."""
        if report.total_files_scanned <= 1:
            return ""
        density = report.summary["total_findings"] / report.total_files_scanned
        if density > 20:
            badge = f"{ReportEmojis.VERY_HIGH} Very High"
        elif density > 10:
            badge = f"{ReportEmojis.HIGH} High"
        elif density > 5:
            badge = f"{ReportEmojis.MODERATE} Moderate"
        else:
            badge = f"{ReportEmojis.LOW} Low"
        return f"| Issue Density | {density:.1f} per file | {badge} |\n"

    @staticmethod
    def _active_policy_section(report: ScanReport) -> str:
        """Render an ``### Active Scan Policy`` block disclosing
        ``--select`` / ``--ignore`` narrowing. Returns ``""`` when the
        scan ran with the full rule universe.
        """
        voicing = _voice_policy(report.selected_rule_ids, report.ignored_rule_ids)
        if voicing is None:
            return ""
        head = voicing.head_template.format(select="`--select`", ignore="`--ignore`")
        rules_block = "\n".join(f"- `{rid}`" for rid in voicing.rule_ids)
        return (
            "\n### Active Scan Policy\n\n"
            f"> {head}. The score above reflects this policy rather than a clean codebase.\n\n"
            f"<details><summary>Affected rules ({len(voicing.rule_ids)})</summary>\n\n"
            f"{rules_block}\n\n"
            "</details>\n\n"
        )

    def format(self, report: ScanReport) -> str:
        """Render ``report`` as a Markdown document with anchor links and per-finding remediation examples."""

        security_status = self.score_calculator.get_security_status(
            report.security_score.overall_score
        )
        risk_level = self.score_calculator.get_risk_level(report.security_score.risk_score)

        status_emoji = {"Excellent": "🟢", "Good": "🟡", "Fair": "🟠", **ReportEmojis.SCORE_STATUS}

        risk_emoji = {"Minimal": "🟢", "Low": "🟡", "Medium": "🟠", **ReportEmojis.RISK_STATUS}

        policy_qualifier = (
            " *(active policy)*" if report.selected_rule_ids or report.ignored_rule_ids else ""
        )
        # Render a human-friendly timestamp for the header while keeping the
        # raw ISO-8601 value in report.scan_timestamp intact (JSON/SARIF/JUnit
        # formatters depend on the precise form). Falls back gracefully if the
        # timestamp is not parseable (tests sometimes inject sentinel strings).
        try:
            _parsed = datetime.fromisoformat(report.scan_timestamp)
            scan_date_display = _parsed.strftime("%Y-%m-%d %H:%M:%S") + (
                " UTC" if _parsed.tzinfo is None else ""
            )
        except (ValueError, TypeError):
            scan_date_display = report.scan_timestamp

        # When --files was used (even with a single positional dir), the
        # `directory` field is either the cwd default (".") or a narrow subtree
        # that does not reflect what was actually scanned. Surface the file
        # list directly and drop the misleading "Directory: ." line.
        files_were_explicit = bool(report.scanned_file_names) and report.total_files_scanned == len(
            report.scanned_file_names
        )
        if files_were_explicit and report.total_files_scanned <= 5:
            scope_block = "**Scanned Files:** " + ", ".join(
                f"`{n}`" for n in report.scanned_file_names
            )
        elif files_were_explicit:
            scope_block = f"**Scanned Files:** {report.total_files_scanned} file(s)"
        else:
            file_tail = (
                " (" + ", ".join(report.scanned_file_names) + ")"
                if len(report.scanned_file_names) <= 5 and report.scanned_file_names
                else ""
            )
            scope_block = (
                f"**Directory:** {report.ansible_directory}  \n"
                f"**Files Scanned:** {report.total_files_scanned}{file_tail}"
            )

        # Markdown renderers collapse consecutive non-empty lines into a single
        # line unless each line ends with two spaces (the hard-break syntax).
        # Header lines (Scan Date / Directory|Scanned Files) must use that.
        # We assemble via an explicit NBSP-free two-space string so that the
        # hard-break is visible in the rendered report without leaving literal
        # trailing whitespace in the source file (which trips W291/editor
        # "strip trailing whitespace" tooling).
        hb = "  "
        markdown = f"""# {ReportEmojis.SECURITY} Ansible Security Scan Report

**Scan Date:** {scan_date_display}{hb}
{scope_block}

## {ReportEmojis.SUMMARY} Executive Summary

### Overall Security Posture
| Metric | Score | Status |
|--------|-------|--------|
| Security Score | {report.security_score.overall_score}/100{policy_qualifier} | {status_emoji.get(security_status, "❓")} {security_status} |
| Risk Level | {report.security_score.risk_score}/100 | {risk_emoji.get(risk_level, "❓")} {risk_level} |
| Total Issues | {report.summary["total_findings"]} | {f"{ReportEmojis.URGENT} URGENT" if report.summary["total_findings"] > 50 else f"{ReportEmojis.ATTENTION} Attention Needed" if report.summary["total_findings"] > 0 else f"{ReportEmojis.CLEAN} Clean"} |
{self._issue_density_row(report)}{self._active_policy_section(report)}### Risk Distribution
| Severity | Count | Impact |
|----------|-------|---------|
| {ReportEmojis.CRITICAL_ISSUE} CRITICAL | {report.summary["critical"]} | {f"{ReportEmojis.STOP} Stop deployment" if report.summary["critical"] > 0 else f"{ReportEmojis.NONE} None"} |
| {ReportEmojis.HIGH_ISSUE} HIGH | {report.summary["high"]} | {f"{ReportEmojis.WARNING} Address immediately" if report.summary["high"] > 0 else f"{ReportEmojis.NONE} None"} |
| {ReportEmojis.MEDIUM_ISSUE} MEDIUM | {report.summary["medium"]} | {f"{ReportEmojis.PLAN} Plan remediation" if report.summary["medium"] > 0 else f"{ReportEmojis.NONE} None"} |
| {ReportEmojis.LOW_ISSUE} LOW | {report.summary["low"]} | {f"{ReportEmojis.MONITOR} Monitor and improve" if report.summary["low"] > 0 else f"{ReportEmojis.NONE} None"} |

"""

        if report.security_score.category_scores:
            markdown += """### Security Categories Breakdown
| Category | Score | Status |
|----------|-------|--------|"""

            for category, score in report.security_score.category_scores.items():
                cat_status = self.score_calculator.get_security_status(score)
                cat_emoji = status_emoji.get(cat_status, "❓")
                markdown += f"\n| {category.replace('_', ' ').title()} | {score}/100 | {cat_emoji} {cat_status} |"

        # File-level breakdown
        if report.security_score.file_scores:
            markdown += """

### File Security Scores
| File | Score | Status | Issues |
|------|-------|--------|--------|"""

            for file_path, score in sorted(report.security_score.file_scores.items()):
                file_issues = len([f for f in report.findings if f.file_path == file_path])
                file_status = self.score_calculator.get_security_status(score)
                file_emoji = status_emoji.get(file_status, "❓")
                markdown += f"\n| `{file_path}` | {score}/100 | {file_emoji} {file_status} | {file_issues} |"

        # Critical findings section
        if report.summary["critical"] > 0:
            markdown += f"""

## {ReportEmojis.CRITICAL} CRITICAL Issues Requiring Immediate Action

> **{ReportEmojis.WARNING} WARNING:** These issues pose severe security risks and must be addressed before production deployment.

"""
            critical_findings = [f for f in report.findings if f.severity == "CRITICAL"]

            # Determine how many to show based on show_all flag
            if self.show_all:
                critical_findings_to_show = critical_findings
            else:
                critical_findings_to_show = critical_findings[:10]

            for i, finding in enumerate(critical_findings_to_show, 1):
                markdown += f"""
### {i}. `{finding.rule_id}` · {finding.title}
- **File:** `{finding.file_path}` (Line {finding.line_number})
- **Issue:** {finding.description}
- **Code:** `{self._inline_code_snippet(finding.code_snippet, finding.match_line)}`{self._framework_coverage(finding)}{self._duplicates_block(finding)}

{finding.remediation_example}

---

"""

            if not self.show_all and len(critical_findings) > 10:
                markdown += f"*... and {len(critical_findings) - 10} more critical issues*\n"
                markdown += (
                    f"*Use --show-all flag to see all {len(critical_findings)} critical issues*\n"
                )

        # High priority findings
        if report.summary["high"] > 0:
            markdown += """

## 🔴 HIGH Priority Issues

"""
            high_findings = [f for f in report.findings if f.severity == "HIGH"]

            high_findings_to_show = high_findings if self.show_all else high_findings[:5]

            for _i, finding in enumerate(high_findings_to_show, 1):
                markdown += f"""
**`{finding.rule_id}` · {finding.title}**
- File: `{finding.file_path}` (Line {finding.line_number})
- Issue: {finding.description}
- Code: `{self._inline_code_snippet(finding.code_snippet, finding.match_line)}`{self._framework_coverage(finding)}{self._duplicates_block(finding)}

{finding.remediation_example}

---

"""

            if not self.show_all and len(high_findings) > 5:
                markdown += f"*... and {len(high_findings) - 5} more high priority issues*\n"

        markdown += f"""

## {ReportEmojis.IMPROVEMENTS} Recommended Actions

### Immediate Actions (Next 24 hours)
"""
        if report.summary["critical"] > 0:
            markdown += f"- {ReportEmojis.CRITICAL} **Address all {report.summary['critical']} CRITICAL issues** - these pose immediate security risks\n"
        if report.summary["high"] > 0:
            markdown += f"- {ReportEmojis.HIGH_ISSUE} **Review all {report.summary['high']} HIGH priority issues** - plan fixes within 1 week\n"

        markdown += f"""
### Security Improvements
- {ReportEmojis.SECURE} **Use ansible-vault** for all credentials and secrets
- 🛡️ **Replace shell/command modules** with specific Ansible modules where possible
- {ReportEmojis.SEARCH} **Implement input validation** for all user-provided variables
- 🌐 **Use HTTPS** for all external communications
- {ReportEmojis.NOTES} **Add security testing** to your CI/CD pipeline

---
*Generated by Ansible Security Scanner on {report.scan_timestamp}*
"""

        return markdown
