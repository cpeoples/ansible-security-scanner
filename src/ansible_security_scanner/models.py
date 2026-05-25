#!/usr/bin/env python3
"""
Data models for Ansible Security Scanner
"""

from dataclasses import dataclass, field


@dataclass
class SecurityFinding:
    """Represents a security finding in an Ansible playbook"""

    file_path: str
    line_number: int
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    recommendation: str
    code_snippet: str
    remediation_example: str
    # Enrichment carried from SecurityPattern (optional, default empty)
    cwe: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)
    cis_controls: list[str] = field(default_factory=list)
    # Compliance-framework enrichment (additive; existing consumers keep
    # working because these default to empty lists and no existing field
    # was renamed or removed).
    nist_controls: list[str] = field(default_factory=list)
    pci_dss: list[str] = field(default_factory=list)
    hipaa: list[str] = field(default_factory=list)
    soc2: list[str] = field(default_factory=list)
    stig: list[str] = field(default_factory=list)
    # MITRE ATLAS - AI/ML adversarial technique catalog (e.g. "AML.T0051"
    # for LLM Prompt Injection). Additive alongside mitre_attack.
    mitre_atlas: list[str] = field(default_factory=list)
    # OWASP catalogs - app-sec Top 10 (2021 + 2017), LLM Top 10 v1.1, and
    # ASVS v5.0.0. All additive and optional; default-empty lists preserve
    # backward compatibility with every existing formatter.
    owasp_appsec: list[str] = field(default_factory=list)
    owasp_llm: list[str] = field(default_factory=list)
    owasp_asvs: list[str] = field(default_factory=list)
    # CVE identifiers when a rule maps to disclosed vulnerabilities, e.g.
    # ``["CVE-2024-3094"]``. Optional - most rules detect classes of weakness.
    cve: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    help_uri: str = ""
    precision: str = "high"
    # Autofix dry-run: if a rule knows how to patch itself,
    # the engine attaches a unified-diff-style hint here.
    fix_patch: str = ""
    # Suppression comments: if a finding was suppressed by an inline
    # suppression directive (see suppressions.py for the accepted forms),
    # we record that rather than dropping it silently - so audits can see
    # what was suppressed.
    suppressed_by: str = ""
    # Cross-file deduplication: when ``--dedup-across-files`` is enabled,
    # findings that share a canonical ``(rule_id, normalized-snippet)``
    # are collapsed to a single representative finding. The suppressed
    # sibling locations - each a ``{"file_path": ..., "line_number": ...}``
    # mapping - are preserved here so reports can still surface every
    # affected call site even though only one finding is emitted.
    # Empty list when dedup is off or when a finding had no duplicates.
    duplicates: list[dict] = field(default_factory=list)
    # Single-line preview of the exact offending line - used by formatters
    # for inline summaries (markdown ``**Code:**``, terminal one-liners,
    # JSON ``match_line``). Distinct from ``code_snippet``, which now
    # carries the full enclosing YAML task block. Defaults to ``""``;
    # formatters fall back to deriving a preview from ``code_snippet``.
    match_line: str = ""


@dataclass
class SecurityScore:
    """Security scoring breakdown"""

    overall_score: float  # 0-100
    risk_score: float  # 0-100 (inverse of security)
    category_scores: dict[str, float]  # Score per category
    severity_breakdown: dict[str, int]  # Count by severity
    file_scores: dict[str, float]  # Score per file
    recommendations_count: int


@dataclass
class ScanReport:
    """Complete scan report"""

    scan_timestamp: str
    ansible_directory: str
    total_files_scanned: int
    scanned_file_names: list[str]  # List of specific files that were scanned
    findings: list[SecurityFinding]
    summary: dict[str, int]
    security_score: SecurityScore
    # Suppression metadata from the inline-suppression hardening. Defaults preserve backward
    # compatibility for any code that constructs ScanReport positionally.
    suppressed_count: int = 0
    suppression_warnings: list[str] = field(default_factory=list)
    suppressed_gate_failed: bool = False
    # CLI rule scoping. Populated by ``main()`` after the report is built so
    # every formatter can disclose ``--select`` / ``--ignore`` narrowing
    # uniformly: a 100/100 score with a long ``ignored_rule_ids`` list reads
    # very differently from a clean codebase.
    selected_rule_ids: list[str] = field(default_factory=list)
    ignored_rule_ids: list[str] = field(default_factory=list)
    # Dependency inventory collected during the scan (Galaxy collections,
    # roles, pip packages, bindep system packages, EE base images). Used by
    # the CycloneDX SBOM formatter. Defaults to an empty list so every
    # existing positional/keyword ScanReport(...) call continues to work.
    components: list[dict[str, str]] = field(default_factory=list)
