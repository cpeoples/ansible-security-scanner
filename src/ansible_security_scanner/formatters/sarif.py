#!/usr/bin/env python3
"""
SARIF output formatter for Ansible Security Scanner.

Emits fully-compliant SARIF 2.1.0 with rich rule metadata:

- ``tool.driver.rules[]`` is populated from the distinct rule IDs in the
  report (deduped). Each rule carries ``name``, ``shortDescription``,
  ``fullDescription``, ``helpUri``, ``defaultConfiguration.level``, and
  ``properties.precision`` + ``properties.tags`` (CWE-xxx, CIS-xxx,
  MITRE-Txxxx). This is what GitHub code-scanning and Sonar-style viewers
  render as the "rule detail" pane.

- Each ``result`` also carries the tags on its own ``properties`` so
  filtering by tag works regardless of whether the viewer supports the
  rule-level or result-level form.
"""

import json

from ..link_resolver import (
    resolve_atlas,
    resolve_cis,
    resolve_cwe,
    resolve_mitre,
    resolve_owasp_appsec,
    resolve_owasp_asvs,
    resolve_owasp_llm,
)
from ..models import ScanReport, SecurityFinding
from .base import OutputFormatter

_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

# SARIF "security-severity" is a 0-10 number used by code-scanning systems
# (GitHub Advanced Security, for example) to rank results. This is how we
# surface our 4-tier CRITICAL/HIGH/MEDIUM/LOW to those viewers.
_SEVERITY_TO_SCORE = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.0",
    "LOW": "3.0",
}


class SARIFFormatter(OutputFormatter):
    """Formats report as SARIF 2.1.0 with rich rule metadata."""

    def format(self, report: ScanReport) -> str:
        try:
            rules = self._build_rules_catalog(report.findings)
            rule_id_to_index = {r["id"]: idx for idx, r in enumerate(rules)}
            taxonomies = self._build_taxonomies(report.findings)

            driver: dict = {
                "name": "Ansible Security Scanner",
                "version": "1.0.0",
                "informationUri": "https://github.com/cpeoples/ansible-security-scanner",
                "rules": rules,
            }
            policy_props = self._active_policy_properties(report)
            if policy_props:
                driver["properties"] = policy_props

            run_block = {
                "tool": {"driver": driver},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": "python -m ansible_security_scanner --format sarif",
                        "startTimeUtc": report.scan_timestamp,
                        "endTimeUtc": report.scan_timestamp,
                    }
                ],
                "results": [self._finding_to_result(f, rule_id_to_index) for f in report.findings],
            }
            if taxonomies:
                run_block["taxonomies"] = taxonomies

            sarif_data = {
                "$schema": "https://json.schemas.sarif.org/2.1.0/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [run_block],
            }
            return json.dumps(sarif_data, indent=2, default=str, ensure_ascii=False)

        except Exception as e:
            return json.dumps(
                {
                    "$schema": "https://json.schemas.sarif.org/2.1.0/sarif-schema-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "Ansible Security Scanner"}},
                            "results": [],
                            "invocations": [
                                {
                                    "executionSuccessful": False,
                                    "toolExecutionNotifications": [
                                        {"message": {"text": f"Error: {e}"}}
                                    ],
                                }
                            ],
                        }
                    ],
                },
                indent=2,
                ensure_ascii=False,
            )

    def _build_rules_catalog(self, findings: list[SecurityFinding]) -> list[dict]:
        """Return the deduped list of rule definitions for tool.driver.rules.

        For each rule ID we pick the *first* finding we see and promote
        its metadata (title, description, recommendation, help_uri,
        precision, CWE/CIS/MITRE tags) to the rule level.
        """
        seen: dict[str, dict] = {}
        for f in findings:
            if f.rule_id in seen:
                continue
            seen[f.rule_id] = self._finding_to_rule(f)
        return list(seen.values())

    def _finding_to_rule(self, f: SecurityFinding) -> dict:
        tags = self._tags_for(f)
        rule = {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.title or f.rule_id},
            "fullDescription": {"text": f.description or f.title or f.rule_id},
            "help": {
                "text": f.recommendation or "See the scanner documentation for guidance.",
                "markdown": f.remediation_example or f.recommendation or "",
            },
            "defaultConfiguration": {
                "level": _SEVERITY_TO_SARIF_LEVEL.get(f.severity, "note"),
            },
            "properties": {
                "precision": f.precision or "high",
                "tags": tags,
                "security-severity": _SEVERITY_TO_SCORE.get(f.severity, "3.0"),
                "severity": f.severity,
            },
        }
        help_uri = self._help_uri_for(f)
        if help_uri:
            rule["helpUri"] = help_uri
        relationships = self._relationships_for(f)
        if relationships:
            rule["relationships"] = relationships
        return rule

    def _finding_to_result(self, f: SecurityFinding, rule_id_to_index: dict[str, int]) -> dict:
        level = _SEVERITY_TO_SARIF_LEVEL.get(f.severity, "note")
        # SARIF's ``locations`` is an array. When cross-file dedup has
        # collapsed N duplicates into this finding, we emit the primary
        # location first (kept at index 0 so SARIF consumers that look
        # at ``locations[0]`` still see the representative) and append
        # each duplicate as an additional physical location. This keeps
        # the result count down without losing any affected call site.
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {
                        "startLine": f.line_number,
                        "endLine": f.line_number,
                    },
                }
            }
        ]
        for dup in getattr(f, "duplicates", None) or []:
            dup_path = dup.get("file_path")
            dup_line = dup.get("line_number")
            if not dup_path or not isinstance(dup_line, int):
                continue
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": dup_path},
                        "region": {
                            "startLine": dup_line,
                            "endLine": dup_line,
                        },
                    }
                }
            )
        result = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_id_to_index.get(f.rule_id, -1),
            "level": level,
            "message": {"text": f.description or f.title},
            "locations": locations,
            "properties": {
                "title": f.title,
                "recommendation": f.recommendation,
                "codeSnippet": f.code_snippet,
                "remediationExample": f.remediation_example,
                "precision": f.precision or "high",
                "tags": self._tags_for(f),
                "security-severity": _SEVERITY_TO_SCORE.get(f.severity, "3.0"),
                "severity": f.severity,
            },
        }
        if f.suppressed_by:
            result["suppressions"] = [
                {
                    "kind": "inSource",
                    "justification": f.suppressed_by,
                }
            ]
        if f.fix_patch:
            result["fixes"] = [
                {
                    "description": {"text": "Auto-generated remediation patch"},
                    "artifactChanges": [
                        {
                            "artifactLocation": {"uri": f.file_path},
                            "replacements": [
                                {
                                    "deletedRegion": {
                                        "startLine": f.line_number,
                                        "endLine": f.line_number,
                                    },
                                    "insertedContent": {"text": f.fix_patch},
                                }
                            ],
                        }
                    ],
                }
            ]
        return result

    # Each entry: (SecurityFinding attr, prefix tag, separator, acceptable-
    # existing-prefix predicate tuple). When the raw id already matches the
    # predicate we emit it unchanged; otherwise we prefix with tag+sep. Most
    # frameworks separate the prefix with ``-`` (e.g. ``CWE-79``), but
    # MITRE ATT&CK numeric IDs already look like ``T1234`` so we prefix with
    # the bare letter ``T`` and no separator.
    _TAG_SPECS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
        ("cwe", "CWE", "-", ("CWE-",)),
        ("cis_controls", "CIS", "-", ("CIS",)),
        ("mitre_attack", "T", "", ("MITRE", "T")),
        ("nist_controls", "NIST", "-", ("NIST",)),
        ("pci_dss", "PCI-DSS", "-", ("PCI",)),
        ("hipaa", "HIPAA", "-", ("HIPAA",)),
        ("soc2", "SOC2", "-", ("SOC",)),
        ("stig", "STIG", "-", ("STIG", "V-")),
        # ATLAS IDs already carry the `AML.` prefix - keep as-is. Fallback
        # prefixes anything ill-shaped so the tag remains identifiable.
        ("mitre_atlas", "ATLAS", "-", ("AML",)),
        # OWASP tags are namespaced to keep the three lists unambiguous when
        # they appear side-by-side in code-scanning UIs (e.g. `OWASP-A03:2021`
        # vs `OWASP-LLM03` vs `OWASP-ASVS-V13.3.1`).
        ("owasp_appsec", "OWASP", "-", ("OWASP",)),
        ("owasp_llm", "OWASP", "-", ("OWASP",)),
        ("owasp_asvs", "OWASP-ASVS", "-", ("OWASP",)),
        # CVE ids already carry the `CVE-` prefix; pass through as-is.
        ("cve", "CVE", "-", ("CVE-",)),
    )

    @staticmethod
    def _active_policy_properties(report: ScanReport) -> dict:
        """Return ``tool.driver.properties`` describing CLI rule scoping.

        SARIF allows arbitrary scanner metadata under
        ``tool.driver.properties``; code-scanning UIs (GitHub Advanced
        Security, generic SARIF viewers) surface it in the run / rule
        detail pane. Empty when no policy is in effect so default scans
        keep the same SARIF shape.
        """
        if not report.selected_rule_ids and not report.ignored_rule_ids:
            return {}
        return {
            "activePolicy": {
                "selectedRuleIds": list(report.selected_rule_ids),
                "ignoredRuleIds": list(report.ignored_rule_ids),
            }
        }

    @staticmethod
    def _tags_for(f: SecurityFinding) -> list[str]:
        """Return deduplicated CWE/CIS/MITRE tags for a finding.

        Compliance-framework tags (NIST 800-53, PCI-DSS, HIPAA, SOC 2, STIG)
        are also emitted when the finding references them so SARIF consumers
        that filter by tag (e.g. GitHub Code Scanning) can pivot on any
        of them without a separate lookup. Each tag is namespaced so a
        dashboard can cleanly partition them by framework.
        """
        tags: list[str] = ["security"]
        for attr, prefix, sep, accepted in SARIFFormatter._TAG_SPECS:
            for raw in getattr(f, attr, None) or ():
                upper = raw.upper()
                if any(upper.startswith(p) for p in accepted):
                    tags.append(raw)
                else:
                    tags.append(f"{prefix}{sep}{raw}")
        return list(dict.fromkeys(tags))

    @staticmethod
    def _help_uri_for(f: SecurityFinding) -> str:
        """Return the best helpUri for a finding.

        Priority: an explicit ``finding.help_uri`` wins (a pattern author has
        chosen a specific deep link). Otherwise we prefer a cataloged CWE
        URL (code-scanning UIs surface it prominently), then MITRE, then CIS,
        then the first free-form reference. Empty string when nothing fits.
        """
        if f.help_uri:
            return f.help_uri
        for raw in f.cwe:
            ref = resolve_cwe(raw)
            if ref and ref.url:
                return ref.url
        for raw in f.mitre_attack:
            ref = resolve_mitre(raw)
            if ref and ref.url:
                return ref.url
        for raw in f.cis_controls:
            ref = resolve_cis(raw)
            if ref and ref.url:
                return ref.url
        if f.references:
            return f.references[0]
        return ""

    @staticmethod
    def _relationships_for(f: SecurityFinding) -> list[dict]:
        """Build SARIF taxonomy relationships for the finding's framework ids.

        Each resolved CWE/MITRE id becomes a ``relationships[]`` entry with
        ``kinds: ["relevant"]`` and a ``target`` that references a taxonomy
        entry added in ``_build_taxonomies``. CIS is intentionally excluded
        from relationships because it has no public machine-readable
        taxonomy with stable URIs - it still flows through properties.tags.
        """
        rels: list[dict] = []
        for raw in f.cwe:
            ref = resolve_cwe(raw)
            if ref:
                rels.append(
                    {
                        "target": {
                            "id": ref.id,
                            "toolComponent": {"name": "CWE"},
                        },
                        "kinds": ["relevant"],
                    }
                )
        for raw in f.mitre_attack:
            ref = resolve_mitre(raw)
            if ref:
                rels.append(
                    {
                        "target": {
                            "id": ref.id,
                            "toolComponent": {"name": "MITRE ATT&CK"},
                        },
                        "kinds": ["relevant"],
                    }
                )
        for raw in getattr(f, "mitre_atlas", None) or ():
            ref = resolve_atlas(raw)
            if ref:
                rels.append(
                    {
                        "target": {
                            "id": ref.id,
                            "toolComponent": {"name": "MITRE ATLAS"},
                        },
                        "kinds": ["relevant"],
                    }
                )
        for raw in getattr(f, "owasp_appsec", None) or ():
            ref = resolve_owasp_appsec(raw)
            if ref:
                rels.append(
                    {
                        "target": {
                            "id": ref.id,
                            "toolComponent": {"name": "OWASP Top 10"},
                        },
                        "kinds": ["relevant"],
                    }
                )
        for raw in getattr(f, "owasp_llm", None) or ():
            ref = resolve_owasp_llm(raw)
            if ref:
                rels.append(
                    {
                        "target": {
                            "id": ref.id,
                            "toolComponent": {"name": "OWASP LLM Top 10"},
                        },
                        "kinds": ["relevant"],
                    }
                )
        for raw in getattr(f, "owasp_asvs", None) or ():
            ref = resolve_owasp_asvs(raw)
            if ref:
                rels.append(
                    {
                        "target": {
                            "id": ref.id,
                            "toolComponent": {"name": "OWASP ASVS v5.0.0"},
                        },
                        "kinds": ["relevant"],
                    }
                )
        return rels

    @staticmethod
    def _build_taxonomies(findings: list[SecurityFinding]) -> list[dict]:
        """Return SARIF ``taxonomies[]`` describing the CWE and MITRE schemes.

        Only emits a taxonomy block if at least one finding references that
        framework. Each taxonomy lists *only* the ids used in this run -
        this keeps the SARIF file proportionate instead of inlining the
        entire MITRE catalog.
        """
        used_cwe: dict[str, tuple[str, str]] = {}
        used_mitre: dict[str, tuple[str, str]] = {}
        used_atlas: dict[str, tuple[str, str]] = {}
        used_owasp_appsec: dict[str, tuple[str, str]] = {}
        used_owasp_llm: dict[str, tuple[str, str]] = {}
        used_owasp_asvs: dict[str, tuple[str, str]] = {}

        for f in findings:
            for raw in f.cwe:
                ref = resolve_cwe(raw)
                if ref:
                    used_cwe[ref.id] = (ref.name, ref.url)
            for raw in f.mitre_attack:
                ref = resolve_mitre(raw)
                if ref:
                    used_mitre[ref.id] = (ref.name, ref.url)
            for raw in getattr(f, "mitre_atlas", None) or ():
                ref = resolve_atlas(raw)
                if ref:
                    used_atlas[ref.id] = (ref.name, ref.url)
            for raw in getattr(f, "owasp_appsec", None) or ():
                ref = resolve_owasp_appsec(raw)
                if ref:
                    used_owasp_appsec[ref.id] = (ref.name, ref.url)
            for raw in getattr(f, "owasp_llm", None) or ():
                ref = resolve_owasp_llm(raw)
                if ref:
                    used_owasp_llm[ref.id] = (ref.name, ref.url)
            for raw in getattr(f, "owasp_asvs", None) or ():
                ref = resolve_owasp_asvs(raw)
                if ref:
                    used_owasp_asvs[ref.id] = (ref.name, ref.url)

        taxonomies: list[dict] = []
        if used_cwe:
            taxonomies.append(
                {
                    "name": "CWE",
                    "organization": "MITRE",
                    "shortDescription": {"text": "Common Weakness Enumeration"},
                    "informationUri": "https://cwe.mitre.org/",
                    "taxa": [
                        {
                            "id": cid,
                            "name": name,
                            "shortDescription": {"text": name},
                            "helpUri": url,
                        }
                        for cid, (name, url) in sorted(used_cwe.items())
                    ],
                }
            )
        if used_mitre:
            taxonomies.append(
                {
                    "name": "MITRE ATT&CK",
                    "organization": "MITRE",
                    "shortDescription": {"text": "MITRE ATT&CK Enterprise Matrix"},
                    "informationUri": "https://attack.mitre.org/",
                    "taxa": [
                        {
                            "id": mid,
                            "name": name,
                            "shortDescription": {"text": name},
                            "helpUri": url,
                        }
                        for mid, (name, url) in sorted(used_mitre.items())
                    ],
                }
            )
        if used_atlas:
            taxonomies.append(
                {
                    "name": "MITRE ATLAS",
                    "organization": "MITRE",
                    "shortDescription": {
                        "text": "MITRE Adversarial Threat Landscape for AI Systems"
                    },
                    "informationUri": "https://atlas.mitre.org/",
                    "taxa": [
                        {
                            "id": aid,
                            "name": name,
                            "shortDescription": {"text": name},
                            "helpUri": url,
                        }
                        for aid, (name, url) in sorted(used_atlas.items())
                    ],
                }
            )
        if used_owasp_appsec:
            taxonomies.append(
                {
                    "name": "OWASP Top 10",
                    "organization": "OWASP Foundation",
                    "shortDescription": {"text": "OWASP Top 10 Application Security Risks"},
                    "informationUri": "https://owasp.org/Top10/",
                    "taxa": [
                        {
                            "id": oid,
                            "name": name,
                            "shortDescription": {"text": name},
                            "helpUri": url,
                        }
                        for oid, (name, url) in sorted(used_owasp_appsec.items())
                    ],
                }
            )
        if used_owasp_llm:
            taxonomies.append(
                {
                    "name": "OWASP LLM Top 10",
                    "organization": "OWASP Foundation",
                    "shortDescription": {
                        "text": "OWASP Top 10 for Large Language Model Applications"
                    },
                    "informationUri": "https://genai.owasp.org/llm-top-10/",
                    "taxa": [
                        {
                            "id": oid,
                            "name": name,
                            "shortDescription": {"text": name},
                            "helpUri": url,
                        }
                        for oid, (name, url) in sorted(used_owasp_llm.items())
                    ],
                }
            )
        if used_owasp_asvs:
            taxonomies.append(
                {
                    "name": "OWASP ASVS v5.0.0",
                    "organization": "OWASP Foundation",
                    "shortDescription": {
                        "text": "OWASP Application Security Verification Standard v5.0.0"
                    },
                    "informationUri": "https://owasp.org/www-project-application-security-verification-standard/",
                    "taxa": [
                        {
                            "id": oid,
                            "name": name,
                            "shortDescription": {"text": name},
                            "helpUri": url,
                        }
                        for oid, (name, url) in sorted(used_owasp_asvs.items())
                    ],
                }
            )
        return taxonomies
