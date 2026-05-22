#!/usr/bin/env python3
"""
CSV output formatter for Ansible Security Scanner.

Emits a flat ``findings -> rows`` table with a fixed column header so
spreadsheet/Pandas/Excel consumers can ingest the file directly.

Active scan policy (``--select`` / ``--ignore``) is intentionally NOT
disclosed here: there is no scan-level row to attach it to without
breaking the CSV column contract. Use a structured format (json, yaml,
markdown, html, xml, sarif, gitlab-sast, junit, cyclonedx) when policy
disclosure matters alongside the findings.
"""

import csv
import io
import re

from ..models import ScanReport
from .base import OutputFormatter

_COLUMNS = [
    "File Path",
    "Line Number",
    "Rule ID",
    "Severity",
    "Title",
    "Description",
    "Recommendation",
    "Code Snippet",
    "Remediation Example",
]


def _clean_markdown_for_csv(text) -> str:
    """Strip markdown + collapse all whitespace runs (CRLF, tabs, blank lines)
    to single spaces so a finding fits on one CSV row without Excel wrapping."""
    if not text:
        return ""
    text = str(text)
    text = re.sub(r"```[^`]*```", "", text)
    text = re.sub(r"^#+\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


class CSVFormatter(OutputFormatter):
    """Formats report as CSV"""

    def format(self, report: ScanReport) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(_COLUMNS)
        for f in report.findings:
            writer.writerow(
                [
                    f.file_path,
                    f.line_number,
                    f.rule_id,
                    f.severity,
                    _clean_markdown_for_csv(f.title),
                    _clean_markdown_for_csv(f.description),
                    _clean_markdown_for_csv(f.recommendation),
                    _clean_markdown_for_csv(f.code_snippet),
                    _clean_markdown_for_csv(f.remediation_example),
                ]
            )
        return buf.getvalue()
