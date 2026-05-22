#!/usr/bin/env python3
"""
HTML output formatter for Ansible Security Scanner
"""

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


class HTMLFormatter(OutputFormatter):
    """Formats report as HTML with light/dark mode toggle"""

    def _framework_coverage_html(self, finding: SecurityFinding) -> str:
        """Return an HTML framework-coverage block, or '' if finding has none.

        Rendered inline with the finding header (between description and the
        collapsible details) so reviewers see the framework mapping without
        having to expand the code section. Unknown ids render as plain text
        - never silently dropped - for the same reason as in the Markdown
        formatter.
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

        groups: list[tuple[str, list[tuple[str, str, str]]]] = []

        def _collect(label: str, raw_ids, resolver) -> None:
            if not raw_ids:
                return
            rendered: list[tuple[str, str, str]] = []
            for raw in raw_ids:
                ref = resolver(raw)
                if ref:
                    rendered.append((ref.id, ref.url, ref.name))
                else:
                    rendered.append((raw, "", ""))
            groups.append((label, rendered))

        _collect("CWE", finding.cwe, resolve_cwe)
        _collect("MITRE ATT&CK", finding.mitre_attack, resolve_mitre)
        _collect("MITRE ATLAS", finding.mitre_atlas, resolve_atlas)
        _collect("CIS Controls", finding.cis_controls, resolve_cis)
        _collect("NIST 800-53", finding.nist_controls, resolve_nist)
        _collect("PCI-DSS v4", finding.pci_dss, resolve_pci)
        _collect("HIPAA §164.312", finding.hipaa, resolve_hipaa)
        _collect("SOC 2 TSC", finding.soc2, resolve_soc2)
        _collect("DISA STIG", finding.stig, resolve_stig)
        if not groups:
            return ""

        lines_html: list[str] = []
        for label, items in groups:
            chips = []
            for id_text, url, name in items:
                id_safe = self._escape_html(id_text)
                name_safe = self._escape_html(name) if name else ""
                if url:
                    chips.append(
                        f'<a class="fw-chip" href="{self._escape_html(url)}" '
                        f'target="_blank" rel="noopener noreferrer" '
                        f'title="{name_safe}">{id_safe}</a>'
                    )
                else:
                    chips.append(f'<span class="fw-chip fw-chip-bare">{id_safe}</span>')
            lines_html.append(
                f'<div class="fw-row"><span class="fw-label">{self._escape_html(label)}:</span> '
                + " ".join(chips)
                + "</div>"
            )

        return (
            '<div class="framework-coverage">'
            f'<div class="fw-title">{ReportEmojis.TAG} Framework Coverage</div>'
            + "".join(lines_html)
            + "</div>"
        )

    def _render_active_policy(self, report: ScanReport) -> str:
        """Render the ``--select`` / ``--ignore`` disclosure panel.

        Mirrors :meth:`MarkdownFormatter._active_policy_section` via the
        shared voicing helper so the report file and the HTML report
        read identically. Returns ``""`` when neither flag was used so
        the HTML structure is unchanged for default scans.
        """
        voicing = _voice_policy(report.selected_rule_ids, report.ignored_rule_ids)
        if voicing is None:
            return ""
        head = voicing.head_template.format(
            select="<code>--select</code>", ignore="<code>--ignore</code>"
        )
        items = "\n".join(
            f"<li><code>{self._escape_html(rid)}</code></li>" for rid in voicing.rule_ids
        )
        return (
            '\n        <div class="active-policy" style="'
            "margin: 20px 0; padding: 15px; border-left: 4px solid #f39c12; "
            'background: #fffbe6;">'
            f"<strong>Active scan policy:</strong> {head}. "
            "The score above reflects this policy rather than a clean codebase."
            f'<details style="margin-top: 10px;"><summary>Affected rules '
            f"({len(voicing.rule_ids)})</summary>"
            f'<ul style="margin: 8px 0 0 20px;">{items}</ul></details></div>'
        )

    def _duplicates_block_html(self, finding: SecurityFinding) -> str:
        """Render a collapsed HTML block listing cross-file duplicate locations.

        Same intent as the Markdown variant: when cross-file dedup collapses
        a finding, surface a short "also affects N" headline with a
        details/summary toggle that expands to the full ``file:line`` list.
        No-op when ``finding.duplicates`` is empty, so the HTML shape is
        unchanged for scanners that don't run dedup.
        """
        dups = getattr(finding, "duplicates", None) or []
        if not dups:
            return ""
        items = "".join(
            f"<li><code>{self._escape_html(d.get('file_path') or '?')}</code>"
            f" - Line {d.get('line_number', '?')}</li>"
            for d in dups
        )
        return (
            '<details class="duplicates-block" style="margin-top:8px;">'
            f"<summary>Also affects {len(dups)} other location(s)</summary>"
            f'<ul style="margin-top:6px;">{items}</ul>'
            "</details>"
        )

    def format(self, report: ScanReport) -> str:
        score_color = self._get_score_color(report.security_score.overall_score)
        policy_html = self._render_active_policy(report)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ansible Security Scan Report</title>
    <style>
        :root {{
            --bg-color: #f5f5f5;
            --container-bg: white;
            --text-color: #2c3e50;
            --secondary-text: #34495e;
            --border-color: #ddd;
            --summary-bg: #ecf0f1;
            --finding-bg: #fafafa;
            --code-bg: #f8f9fa;
            --code-border: #e9ecef;
            --nav-bg: #f8f9fa;
            --nav-border: #007bff;
            --file-bg: #f1f3f4;
            --file-border: #17a2b8;
            --shadow: rgba(0,0,0,0.1);
            --remediation-bg: #e8f5e8;
            --remediation-border: #27ae60;
            --alert-bg: #fff3cd;
            --alert-border: #ffc107;
            --improvements-bg: #d1ecf1;
            --improvements-border: #17a2b8;
            --link-color: #007bff;
            --link-hover-bg: #e7f3ff;
        }}

        [data-theme="dark"] {{
            --bg-color: #1a1a1a;
            --container-bg: #2d2d2d;
            --text-color: #e0e0e0;
            --secondary-text: #b0b0b0;
            --border-color: #404040;
            --summary-bg: #363636;
            --finding-bg: #333333;
            --code-bg: #2a2a2a;
            --code-border: #404040;
            --nav-bg: #2a2a2a;
            --nav-border: #4a9eff;
            --file-bg: #3a3a3a;
            --file-border: #4a9eff;
            --shadow: rgba(0,0,0,0.3);
            --remediation-bg: #2a4a2a;
            --remediation-border: #4caf50;
            --alert-bg: #4a4a2a;
            --alert-border: #ffc107;
            --improvements-bg: #2a3a4a;
            --improvements-border: #4a9eff;
            --link-color: #4a9eff;
            --link-hover-bg: #2a3a4a;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--bg-color);
            transition: all 0.3s ease;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: var(--container-bg);
            border-radius: 12px;
            box-shadow: 0 4px 6px var(--shadow);
            margin-top: 20px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
        }}

        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 8px;
            position: relative;
        }}

        .theme-toggle {{
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(255, 255, 255, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.3);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s ease;
        }}

        .theme-toggle:hover {{
            background: rgba(255, 255, 255, 0.3);
        }}

        h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }}

        .scan-info {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: var(--summary-bg);
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid var(--nav-border);
            transition: all 0.3s ease;
        }}

        .summary-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px var(--shadow);
        }}

        .summary-title {{
            font-size: 0.9rem;
            color: var(--secondary-text);
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }}

        .summary-value {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-color);
        }}

        .score-circle {{
            width: 80px;
            height: 80px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            font-weight: 700;
            color: white;
            margin: 0 auto 10px;
            background: conic-gradient(
                {score_color} 0deg {int(report.security_score.overall_score * 3.6)}deg,
                #e0e0e0 {int(report.security_score.overall_score * 3.6)}deg 360deg
            );
        }}

        .score-inner {{
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: var(--container-bg);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-color);
        }}

        .navigation {{
            background: var(--nav-bg);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 30px;
            border-left: 4px solid var(--nav-border);
        }}

        .nav-links {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
        }}

        .nav-link {{
            color: var(--link-color);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 20px;
            transition: all 0.3s ease;
            font-weight: 500;
        }}

        .nav-link:hover {{
            background: var(--link-hover-bg);
            transform: translateY(-1px);
        }}

        .section {{
            margin-bottom: 40px;
        }}

        .section-title {{
            font-size: 1.8rem;
            margin-bottom: 20px;
            color: var(--text-color);
            border-bottom: 2px solid var(--nav-border);
            padding-bottom: 10px;
            font-weight: 600;
        }}

        .findings-container {{
            display: grid;
            gap: 20px;
        }}

        .finding {{
            background: var(--finding-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            transition: all 0.3s ease;
        }}

        .finding:hover {{
            box-shadow: 0 4px 12px var(--shadow);
            transform: translateY(-2px);
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}

        .finding-title {{
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--text-color);
            flex: 1;
            min-width: 200px;
        }}

        .severity-badge {{
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .severity-CRITICAL {{
            background: #e74c3c;
            color: white;
        }}

        .severity-HIGH {{
            background: #e67e22;
            color: white;
        }}

        .severity-MEDIUM {{
            background: #f39c12;
            color: white;
        }}

        .severity-LOW {{
            background: #3498db;
            color: white;
        }}

        .finding-meta {{
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            flex-wrap: wrap;
            font-size: 0.9rem;
            color: var(--secondary-text);
        }}

        .meta-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}

        .finding-description {{
            margin-bottom: 15px;
            line-height: 1.6;
        }}

        .framework-coverage {{
            background: var(--summary-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 10px 14px;
            margin-bottom: 15px;
            font-size: 0.9rem;
        }}

        .fw-title {{
            font-weight: 600;
            margin-bottom: 8px;
            color: var(--text-color);
        }}

        .fw-row {{
            margin: 4px 0;
            line-height: 1.6;
        }}

        .fw-label {{
            font-weight: 600;
            color: var(--secondary-text);
            margin-right: 6px;
        }}

        .fw-chip {{
            display: inline-block;
            padding: 2px 8px;
            margin: 2px 4px 2px 0;
            border-radius: 4px;
            background: var(--container-bg);
            border: 1px solid var(--border-color);
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.82rem;
            text-decoration: none;
            color: var(--text-color);
        }}

        .fw-chip:hover {{
            background: var(--code-bg);
        }}

        .fw-chip-bare {{
            opacity: 0.75;
        }}

        .code-block {{
            background: var(--code-bg);
            border: 1px solid var(--code-border);
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            position: relative;
        }}

        .code-block::before {{
            content: 'Code';
            position: absolute;
            top: -10px;
            left: 15px;
            background: var(--container-bg);
            padding: 2px 8px;
            font-size: 0.75rem;
            color: var(--secondary-text);
            border-radius: 3px;
        }}

        .remediation-section {{
            background: var(--remediation-bg);
            border: 1px solid var(--remediation-border);
            border-radius: 6px;
            padding: 20px;
            margin-top: 20px;
        }}

        .remediation-title {{
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-color);
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .remediation-title::before {{
            content: '🔧';
            font-size: 1.2rem;
        }}

        .file-info {{
            background: var(--file-bg);
            border: 1px solid var(--file-border);
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 20px;
        }}

        .file-path {{
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9rem;
            color: var(--text-color);
            font-weight: 600;
        }}

        .line-number {{
            color: var(--secondary-text);
            font-size: 0.85rem;
        }}

        .collapsible {{
            background: var(--container-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin: 10px 0;
            overflow: hidden;
        }}

        .collapsible-header {{
            background: var(--nav-bg);
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
            transition: background-color 0.3s ease;
        }}

        .collapsible-header:hover {{
            background: var(--link-hover-bg);
        }}

        .collapsible-content {{
            padding: 20px;
            display: none;
        }}

        .collapsible.active .collapsible-content {{
            display: block;
        }}

        .collapsible-icon {{
            transition: transform 0.3s ease;
        }}

        .collapsible.active .collapsible-icon {{
            transform: rotate(180deg);
        }}

        .stats-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: var(--container-bg);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px var(--shadow);
        }}

        .stats-table th,
        .stats-table td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        .stats-table th {{
            background: var(--nav-bg);
            font-weight: 600;
            color: var(--text-color);
        }}

        .stats-table tr:hover {{
            background: var(--finding-bg);
        }}

        .alert {{
            background: var(--alert-bg);
            border: 1px solid var(--alert-border);
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }}

        .alert-icon {{
            font-size: 1.2rem;
            margin-top: 2px;
        }}

        .improvements {{
            background: var(--improvements-bg);
            border: 1px solid var(--improvements-border);
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }}

        .improvements h3 {{
            margin-bottom: 15px;
            color: var(--text-color);
        }}

        .improvements ul {{
            list-style: none;
            padding: 0;
        }}

        .improvements li {{
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }}

        .improvements li:last-child {{
            border-bottom: none;
        }}

        .improvements li::before {{
            content: '✅';
            font-size: 1rem;
            margin-top: 2px;
        }}

        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: var(--secondary-text);
            font-size: 0.9rem;
            border-top: 1px solid var(--border-color);
        }}

        @media (max-width: 768px) {{
            .container {{
                margin: 10px;
                padding: 15px;
            }}

            .summary-grid {{
                grid-template-columns: 1fr;
            }}

            .finding-header {{
                flex-direction: column;
                align-items: flex-start;
            }}

            .finding-meta {{
                flex-direction: column;
                gap: 10px;
            }}

            .nav-links {{
                flex-direction: column;
                gap: 10px;
            }}

            .theme-toggle {{
                position: static;
                margin-bottom: 20px;
            }}

            h1 {{
                font-size: 2rem;
            }}
        }}

        .scroll-to-top {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: var(--nav-border);
            color: white;
            border: none;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            cursor: pointer;
            display: none;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            box-shadow: 0 4px 12px var(--shadow);
            transition: all 0.3s ease;
        }}

        .scroll-to-top:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px var(--shadow);
        }}

        .scroll-to-top.visible {{
            display: flex;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <button class="theme-toggle" onclick="toggleTheme()">🌓 Toggle Theme</button>
            <h1>{ReportEmojis.SECURITY} Ansible Security Report</h1>
            <div class="scan-info">
                <strong>Scanned:</strong> {report.scan_timestamp}<br>
                <strong>Directory:</strong> {report.ansible_directory}<br>
                <strong>Files:</strong> {report.total_files_scanned}
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-title">Security Score</div>
                <div class="score-circle">
                    <div class="score-inner">{report.security_score.overall_score}</div>
                </div>
            </div>
            <div class="summary-card">
                <div class="summary-title">Total Issues</div>
                <div class="summary-value">{report.summary["total_findings"]}</div>
            </div>
            <div class="summary-card">
                <div class="summary-title">Critical</div>
                <div class="summary-value" style="color: #e74c3c;">{report.summary["critical"]}</div>
            </div>
            <div class="summary-card">
                <div class="summary-title">High</div>
                <div class="summary-value" style="color: #e67e22;">{report.summary["high"]}</div>
            </div>
        </div>
{policy_html}
        <div class="navigation">
            <div class="nav-links">
                <a href="#summary" class="nav-link">{ReportEmojis.SUMMARY} Summary</a>
                <a href="#critical-findings" class="nav-link">{ReportEmojis.CRITICAL} Critical Issues</a>
                <a href="#high-findings" class="nav-link">{ReportEmojis.HIGH_ISSUE} High Issues</a>
                <a href="#medium-findings" class="nav-link">{ReportEmojis.MEDIUM_ISSUE} Medium Issues</a>
                <a href="#low-findings" class="nav-link">{ReportEmojis.LOW_ISSUE} Low Issues</a>
                <a href="#improvements" class="nav-link">{ReportEmojis.IMPROVEMENTS} Improvements</a>
            </div>
        </div>"""

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            severity_findings = [f for f in report.findings if f.severity == severity]
            if severity_findings:
                emoji_map = ReportEmojis.SEVERITY_MAP

                html_content += f"""
        <div class="section" id="{severity.lower()}-findings">
            <h2 class="section-title">{emoji_map[severity]} {severity.title()} Priority Issues ({len(severity_findings)})</h2>
            <div class="findings-container">"""

                for _i, finding in enumerate(severity_findings):
                    html_content += f"""
                <div class="finding">
                    <div class="finding-header">
                        <div class="finding-title">{finding.title}</div>
                        <span class="severity-badge severity-{finding.severity}">{finding.severity}</span>
                    </div>

                    <div class="file-info">
                        <div class="file-path">{ReportEmojis.FILE} {finding.file_path}</div>
                        <div class="line-number">Line {finding.line_number}</div>
                    </div>

                    <div class="finding-meta">
                        <div class="meta-item">
                            <span>{ReportEmojis.TAG}</span>
                            <span>Rule: {finding.rule_id}</span>
                        </div>
                    </div>

                    <div class="finding-description">
                        {finding.description}
                    </div>
                    {self._framework_coverage_html(finding)}
                    {self._duplicates_block_html(finding)}

                    <div class="collapsible">
                        <div class="collapsible-header" onclick="toggleCollapsible(this)">
                            <span>{ReportEmojis.DETAILS} View Details & Code</span>
                            <span class="collapsible-icon">▼</span>
                        </div>
                        <div class="collapsible-content">
                            <div class="code-block">
                                <pre><code>{self._escape_html(finding.code_snippet)}</code></pre>
                            </div>

                            <div class="remediation-section">
                                <div class="remediation-title">Recommended Fix</div>
                                <div>{self._format_remediation_for_html(finding.remediation_example)}</div>
                            </div>
                        </div>
                    </div>
                </div>"""

                html_content += """
            </div>
        </div>"""

        html_content += f"""
        <div class="improvements" id="improvements">
            <h3>{ReportEmojis.IMPROVEMENTS} Recommended Security Improvements</h3>
            <ul>
                <li>Use ansible-vault for all sensitive data and credentials</li>
                <li>Replace shell/command modules with specific Ansible modules where possible</li>
                <li>Implement input validation for all user-provided variables</li>
                <li>Use HTTPS for all external communications</li>
                <li>Add security testing to your CI/CD pipeline</li>
                <li>Regular security audits and dependency updates</li>
                <li>Implement least-privilege access controls</li>
                <li>Use proper error handling and logging practices</li>
            </ul>
        </div>

        <div class="footer">
            <p>Generated by Ansible Security Scanner * {report.scan_timestamp}</p>
            <p>🔒 Keep your infrastructure secure</p>
        </div>
    </div>

    <button class="scroll-to-top" onclick="scrollToTop()">↑</button>

    <script>
        function toggleTheme() {{
            const body = document.body;
            const currentTheme = body.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            body.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        }}

        function toggleCollapsible(header) {{
            const collapsible = header.parentElement;
            collapsible.classList.toggle('active');
        }}

        function scrollToTop() {{
            window.scrollTo({{
                top: 0,
                behavior: 'smooth'
            }});
        }}

        // Initialize theme from localStorage
        document.addEventListener('DOMContentLoaded', function() {{
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.body.setAttribute('data-theme', savedTheme);

            // Show scroll to top button when scrolling
            window.addEventListener('scroll', function() {{
                const scrollButton = document.querySelector('.scroll-to-top');
                if (window.pageYOffset > 300) {{
                    scrollButton.classList.add('visible');
                }} else {{
                    scrollButton.classList.remove('visible');
                }}
            }});

            // Smooth scrolling for navigation links
            document.querySelectorAll('.nav-link').forEach(link => {{
                link.addEventListener('click', function(e) {{
                    e.preventDefault();
                    const targetId = this.getAttribute('href').substring(1);
                    const targetElement = document.getElementById(targetId);
                    if (targetElement) {{
                        targetElement.scrollIntoView({{
                            behavior: 'smooth',
                            block: 'start'
                        }});
                    }}
                }});
            }});
        }});
    </script>
</body>
</html>"""

        return html_content

    def _get_score_color(self, score):
        """Get color based on security score"""
        if score >= 80:
            return "#27ae60"  # Green
        if score >= 60:
            return "#f39c12"  # Orange
        if score >= 40:
            return "#e67e22"  # Dark orange
        return "#e74c3c"  # Red

    def _escape_html(self, text):
        """Escape HTML special characters"""
        if not text:
            return ""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    def _format_remediation_for_html(self, remediation_text):
        """Format remediation text for HTML display"""
        if not remediation_text:
            return ""

        text = str(remediation_text)
        text = text.replace("```yaml", '<pre><code class="yaml">')
        text = text.replace("```", "</code></pre>")
        text = text.replace("**", "<strong>", 1).replace("**", "</strong>", 1)
        text = text.replace("\n", "<br>")

        return text
