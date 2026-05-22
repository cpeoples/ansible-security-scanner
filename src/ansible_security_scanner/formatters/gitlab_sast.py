#!/usr/bin/env python3
"""
GitLab SAST output formatter for Ansible Security Scanner.

Emits a ``gl-sast-report.json`` payload conforming to GitLab's SAST report
schema (https://gitlab.com/gitlab-org/security-products/security-report-schemas).
GitLab ingests this format natively via the ``artifacts:reports:sast``
CI keyword, powering the Security Dashboard, the MR security widget, and
Vulnerability Management.

This is intentionally a separate formatter from :mod:`sarif` (GitHub /
generic code-scanning) and :mod:`json` (human-readable / custom tooling).
GitLab's schema overlaps with SARIF semantically but is NOT a SARIF
consumer - the top-level shape is different and GitLab rejects SARIF
uploads in the SAST report slot.

Schema version pin
------------------
We emit schema ``15.2.1`` - the stable target as of 2026. GitLab
accepts older minor versions and is permissive about extra properties,
so this version will continue to be accepted on newer runners. Bump the
constant if GitLab ever hard-drops this version.
"""

from __future__ import annotations

import hashlib
import json

from ..link_resolver import (
    resolve_cwe,
    resolve_owasp_appsec,
    resolve_owasp_asvs,
    resolve_owasp_llm,
)
from ..models import ScanReport, SecurityFinding
from .base import OutputFormatter

# GitLab expects title-case severity words. Anything outside this set is
# coerced to ``Unknown`` per the schema so we never ship an invalid value.
_SEVERITY_TO_GITLAB = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
}

# Pinned schema version we claim to emit. See module docstring.
_SCHEMA_VERSION = "15.2.1"
_SCANNER_ID = "ansible-security-scanner"
_SCANNER_NAME = "Ansible Security Scanner"
_SCANNER_URL = "https://github.com/cpeoples/ansible-security-scanner"
_VENDOR_NAME = "cpeoples"


class GitLabSastFormatter(OutputFormatter):
    """Formats report as GitLab SAST JSON (``gl-sast-report.json``)."""

    def format(self, report: ScanReport) -> str:
        try:
            vulns = [self._finding_to_vuln(f) for f in report.findings]
            payload = {
                "version": _SCHEMA_VERSION,
                "vulnerabilities": vulns,
                "scan": self._scan_block(report, success=True),
            }
            return json.dumps(payload, indent=2, default=str, ensure_ascii=False)
        except Exception as e:
            # Mirror SARIF's failure mode: still emit a parseable report so
            # downstream `artifacts:reports:sast` ingestion doesn't choke on
            # a truncated file - just mark the scan unsuccessful.
            return json.dumps(
                {
                    "version": _SCHEMA_VERSION,
                    "vulnerabilities": [],
                    "scan": self._scan_block(report, success=False, error_message=str(e)),
                },
                indent=2,
                ensure_ascii=False,
            )

    # per-finding

    def _finding_to_vuln(self, f: SecurityFinding) -> dict:
        severity = _SEVERITY_TO_GITLAB.get(f.severity, "Unknown")
        identifiers = self._identifiers_for(f)

        # GitLab's `id` is a per-finding opaque string; the schema requires
        # stability across runs for tracking to work. We build it from the
        # rule id + file + line + a short hash of the code snippet so that
        # cosmetic unrelated edits don't rotate the id.
        stable_id = self._stable_finding_id(f)

        vuln = {
            "id": stable_id,
            "category": "sast",
            "name": f.title or f.rule_id,
            "message": f.title or f.rule_id,
            "description": self._build_description(f),
            "severity": severity,
            "scanner": {"id": _SCANNER_ID, "name": _SCANNER_NAME},
            "location": {
                "file": f.file_path,
                "start_line": f.line_number,
                "end_line": f.line_number,
            },
            "identifiers": identifiers,
        }

        # `solution` is the schema-named field for remediation guidance -
        # GitLab's UI renders it verbatim in the vulnerability detail pane.
        solution = self._build_solution(f)
        if solution:
            vuln["solution"] = solution

        # Tracking signatures let GitLab de-dup across scans even when a
        # rule moves a few lines. Mirror the semgrep analyzer's shape.
        vuln["tracking"] = {
            "type": "source",
            "items": [
                {
                    "file": f.file_path,
                    "line_start": f.line_number,
                    "line_end": f.line_number,
                    "signatures": [
                        {
                            "algorithm": "scope_offset",
                            "value": f"{f.file_path}|{f.rule_id}:{f.line_number}",
                        }
                    ],
                }
            ],
        }
        return vuln

    # identifiers

    def _identifiers_for(self, f: SecurityFinding) -> list[dict]:
        """Build the GitLab ``identifiers[]`` array.

        Schema requirement: at least one identifier per vulnerability, and
        the FIRST identifier is treated as the primary one for dedup. We
        always put our own ``rule_id`` identifier first so findings are
        tracked by rule (not by CWE, which can map many -> one).

        Secondary identifiers follow in this priority order so the most
        stable external references float near the top:

        1. Our scanner's rule id (primary)
        2. CWE ids
        3. OWASP Top-10 ids (app-sec + LLM) extracted from description/refs
        4. MITRE ATT&CK / ATLAS ids (as ``atlas_id`` / ``mitre_attack_id``)
        """
        idents: list[dict] = []

        idents.append(
            {
                "type": "ansible_security_scanner_rule_id",
                "name": f"Ansible Security Scanner rule: {f.rule_id}",
                "value": f.rule_id,
                "url": f.help_uri or _SCANNER_URL,
            }
        )

        for raw in f.cwe:
            ref = resolve_cwe(raw)
            numeric = raw.split("-")[-1] if "-" in raw else raw
            idents.append(
                {
                    "type": "cwe",
                    "name": ref.name if ref else (raw if raw.startswith("CWE-") else f"CWE-{raw}"),
                    "value": numeric,
                    "url": ref.url
                    if ref and ref.url
                    else f"https://cwe.mitre.org/data/definitions/{numeric}.html",
                }
            )

        # OWASP identifiers come from structured fields (owasp_appsec /
        # owasp_llm / owasp_asvs) on the finding - no more scraping free
        # text. `owasp` is the standard GitLab identifier type; ASVS is
        # surfaced as `owasp_asvs` so a GitLab-aware UI can treat it
        # distinctly from the Top-10 while still namespacing it under OWASP.
        for raw in f.owasp_appsec:
            ref = resolve_owasp_appsec(raw)
            if ref is None:
                continue
            idents.append(
                {
                    "type": "owasp",
                    "name": f"{ref.id} - {ref.name}",
                    "value": ref.id,
                    "url": ref.url,
                }
            )
        for raw in f.owasp_llm:
            ref = resolve_owasp_llm(raw)
            if ref is None:
                continue
            idents.append(
                {
                    "type": "owasp",
                    "name": f"{ref.id} - {ref.name}",
                    "value": ref.id,
                    "url": ref.url,
                }
            )
        for raw in f.owasp_asvs:
            ref = resolve_owasp_asvs(raw)
            if ref is None:
                continue
            idents.append(
                {
                    "type": "owasp_asvs",
                    "name": f"ASVS {ref.id} - {ref.name}",
                    "value": ref.id,
                    "url": ref.url,
                }
            )

        idents.extend(
            {
                "type": "mitre_attack",
                "name": f"MITRE ATT&CK {raw}",
                "value": raw,
                "url": f"https://attack.mitre.org/techniques/{raw.replace('.', '/')}/",
            }
            for raw in f.mitre_attack
        )

        idents.extend(
            {
                "type": "mitre_atlas",
                "name": f"MITRE ATLAS {raw}",
                "value": raw,
                "url": f"https://atlas.mitre.org/techniques/{raw}",
            }
            for raw in f.mitre_atlas
        )

        # Dedup by (type, value) while preserving order - same identifier
        # can sneak in via both cwe[] and references[] on occasion.
        seen: set[tuple[str, str]] = set()
        unique: list[dict] = []
        for ident in idents:
            key = (ident["type"], ident["value"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(ident)
        return unique

    # description / solution text

    @staticmethod
    def _build_description(f: SecurityFinding) -> str:
        """Return a GitLab-friendly markdown-ish description.

        Includes the rule description, the offending code snippet (so the
        reviewer doesn't have to click through to find it), and any
        ``references[]`` the pattern carried - formatted as a Markdown
        bullet list which GitLab renders in the MR widget.
        """
        parts: list[str] = []
        if f.description:
            parts.append(f.description.strip())
        if f.code_snippet:
            parts.append(f"\n\n**Offending code:**\n```\n{f.code_snippet.strip()}\n```")
        if f.references:
            parts.append("\n\n**References:**")
            parts.extend(f"- {url}" for url in f.references)
        return "".join(parts) or f.title or f.rule_id

    @staticmethod
    def _build_solution(f: SecurityFinding) -> str:
        """Return the best remediation string we have for this finding.

        Preference order: full rendered ``remediation_example`` (already
        markdown-formatted), then the plain ``recommendation`` sentence,
        then empty. GitLab renders markdown in ``solution`` so the rich
        example is a better UX when available.
        """
        if f.remediation_example:
            return f.remediation_example.strip()
        if f.recommendation:
            return f.recommendation.strip()
        return ""

    # stable id

    @staticmethod
    def _stable_finding_id(f: SecurityFinding) -> str:
        """Build a deterministic id from rule + location + snippet hash.

        GitLab treats the vulnerability ``id`` as an opaque string but
        requires it to be stable across re-scans for tracking to dedup
        correctly. A hash of ``(rule_id, file, line, code_snippet)`` gives
        us that without exposing any PII / secret content in the id
        itself (the snippet is only hashed, not embedded).
        """
        key = f"{f.rule_id}|{f.file_path}|{f.line_number}|{f.code_snippet or ''}"
        digest = hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()
        return f"{f.rule_id}:{digest[:16]}"

    # scan metadata

    def _scan_block(
        self,
        report: ScanReport,
        *,
        success: bool,
        error_message: str | None = None,
    ) -> dict:
        """Build the ``scan{}`` block GitLab uses for pipeline metadata.

        ``start_time``/``end_time`` both use ``report.scan_timestamp``
        because the scanner does not currently track wall-clock run
        duration. GitLab accepts identical values.
        """
        scanner = {
            "id": _SCANNER_ID,
            "name": _SCANNER_NAME,
            "url": _SCANNER_URL,
            "vendor": {"name": _VENDOR_NAME},
            "version": self._scanner_version(),
        }
        block = {
            "analyzer": scanner,
            "scanner": scanner,
            "type": "sast",
            "start_time": report.scan_timestamp,
            "end_time": report.scan_timestamp,
            "status": "success" if success else "failure",
        }
        if report.selected_rule_ids or report.ignored_rule_ids:
            block["options"] = {
                "active_policy": {
                    "selected_rule_ids": list(report.selected_rule_ids),
                    "ignored_rule_ids": list(report.ignored_rule_ids),
                }
            }
        if not success and error_message:
            block["messages"] = [{"level": "fatal", "value": error_message}]
        return block

    @staticmethod
    def _scanner_version() -> str:
        """Return the running package version, falling back gracefully.

        Avoids a hard import cycle on ``ansible_security_scanner`` during
        formatter unit tests that construct this class in isolation.
        """
        try:
            from .. import __version__ as pkg_version

            return str(pkg_version) or "0.0.0"
        except Exception:
            return "0.0.0"
