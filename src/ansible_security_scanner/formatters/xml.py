#!/usr/bin/env python3
"""
XML output formatter for Ansible Security Scanner
"""

import re
import xml.etree.ElementTree as ET

from ..models import ScanReport
from .base import OutputFormatter, ReportEmojis


def _clean_markdown_for_xml(text) -> str:
    """Strip markdown formatting + emojis. ElementTree handles XML escaping
    on serialization, so we must NOT escape `<`/`>`/`&` here - that would
    double-encode, e.g. '<script>' -> '&amp;lt;script&amp;gt;'."""
    if not text:
        return ""
    text = str(text)
    text = re.sub(r"```[^`]*```", "", text)
    text = re.sub(r"^#+\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = ReportEmojis.strip_emojis(text)
    return re.sub(r"\n\s*\n", "\n", text).strip()


class XMLFormatter(OutputFormatter):
    """Formats report as XML"""

    def format(self, report: ScanReport) -> str:
        try:
            root = ET.Element("AnsibleSecurityScanReport")
            root.set("version", "1.0")
            root.set("generated", str(report.scan_timestamp))

            header = ET.SubElement(root, "Header")
            ET.SubElement(header, "ScanTimestamp").text = str(report.scan_timestamp)
            ET.SubElement(header, "AnsibleDirectory").text = str(report.ansible_directory)
            ET.SubElement(header, "TotalFilesScanned").text = str(report.total_files_scanned)

            summary = ET.SubElement(root, "Summary")
            ET.SubElement(summary, "TotalFindings").text = str(report.summary["total_findings"])
            ET.SubElement(summary, "Critical").text = str(report.summary["critical"])
            ET.SubElement(summary, "High").text = str(report.summary["high"])
            ET.SubElement(summary, "Medium").text = str(report.summary["medium"])
            ET.SubElement(summary, "Low").text = str(report.summary["low"])

            security_score = ET.SubElement(root, "SecurityScore")
            ET.SubElement(security_score, "OverallScore").text = str(
                report.security_score.overall_score
            )
            ET.SubElement(security_score, "RiskScore").text = str(report.security_score.risk_score)

            findings = ET.SubElement(root, "Findings")
            for finding in report.findings:
                finding_elem = ET.SubElement(findings, "Finding")
                finding_elem.set("severity", str(finding.severity))
                finding_elem.set("ruleId", str(finding.rule_id))

                ET.SubElement(finding_elem, "FilePath").text = str(finding.file_path)
                ET.SubElement(finding_elem, "LineNumber").text = str(finding.line_number)
                ET.SubElement(finding_elem, "Title").text = _clean_markdown_for_xml(finding.title)
                ET.SubElement(finding_elem, "Description").text = _clean_markdown_for_xml(
                    finding.description
                )
                ET.SubElement(finding_elem, "Recommendation").text = _clean_markdown_for_xml(
                    finding.recommendation
                )
                ET.SubElement(finding_elem, "CodeSnippet").text = _clean_markdown_for_xml(
                    finding.code_snippet
                )
                ET.SubElement(finding_elem, "RemediationExample").text = _clean_markdown_for_xml(
                    finding.remediation_example
                )

            ET.indent(root, space="  ")
            return ET.tostring(root, encoding="unicode", xml_declaration=True)

        except Exception as e:
            return f"""<?xml version="1.0" encoding="UTF-8"?>
<AnsibleSecurityScanReport version="1.0" generated="{report.scan_timestamp}">
  <Error>Failed to generate full XML report: {str(e)}</Error>
  <ScanTimestamp>{report.scan_timestamp}</ScanTimestamp>
  <OverallSecurityScore>{report.security_score.overall_score}</OverallSecurityScore>
  <TotalFindings>{report.summary["total_findings"]}</TotalFindings>
</AnsibleSecurityScanReport>"""
