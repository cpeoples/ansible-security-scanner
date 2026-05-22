#!/usr/bin/env python3
"""
JUnit XML output formatter for Ansible Security Scanner
"""

import xml.etree.ElementTree as ET

from ..models import ScanReport
from .base import OutputFormatter

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class JUnitFormatter(OutputFormatter):
    """Formats report as JUnit XML"""

    def format(self, report: ScanReport) -> str:
        try:
            root = ET.Element("testsuites")
            root.set("name", "Ansible Security Scan")
            root.set("tests", str(report.summary["total_findings"]))
            root.set("failures", str(report.summary["critical"] + report.summary["high"]))
            root.set("errors", str(report.summary["medium"] + report.summary["low"]))

            self._append_active_policy(root, report)

            for severity in _SEVERITIES:
                matching = [f for f in report.findings if f.severity == severity]
                if not matching:
                    continue
                suite = ET.SubElement(root, "testsuite")
                suite.set("name", f"Security {severity}")
                suite.set("tests", str(len(matching)))
                suite.set("failures", str(len(matching)))

                for f in matching:
                    case = ET.SubElement(suite, "testcase")
                    case.set("name", f.title)
                    case.set("classname", f.file_path)
                    failure = ET.SubElement(case, "failure")
                    failure.set("message", f.description)
                    failure.set("type", f.rule_id)
                    failure.text = (
                        f"File: {f.file_path}:{f.line_number}\n"
                        f"Code: {f.code_snippet}\n"
                        f"Recommendation: {f.recommendation}"
                    )

            ET.indent(root, space="  ")
            return ET.tostring(root, encoding="unicode", xml_declaration=True)

        except Exception as e:
            return f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="Ansible Security Scan" tests="0" failures="0" errors="0">
  <e>Failed to generate JUnit XML: {str(e)}</e>
</testsuites>"""

    @staticmethod
    def _append_active_policy(root: ET.Element, report: ScanReport) -> None:
        """Surface ``--select`` / ``--ignore`` scoping under ``<properties>``.

        ``<properties>`` is the canonical slot CI test dashboards
        (Jenkins, GitLab CI, GitHub Actions) read for suite-level
        metadata. Skipped entirely when no policy is in effect so the
        default JUnit output stays byte-stable.
        """
        if not report.selected_rule_ids and not report.ignored_rule_ids:
            return
        props = ET.SubElement(root, "properties")
        if report.selected_rule_ids:
            prop = ET.SubElement(props, "property")
            prop.set("name", "ansible-security-scanner.selected_rule_ids")
            prop.set("value", ",".join(report.selected_rule_ids))
        if report.ignored_rule_ids:
            prop = ET.SubElement(props, "property")
            prop.set("name", "ansible-security-scanner.ignored_rule_ids")
            prop.set("value", ",".join(report.ignored_rule_ids))
