#!/usr/bin/env python3
"""
Patterns Manager for Ansible Security Scanner
Handles loading and managing security patterns from YAML files
"""

from __future__ import annotations

import fnmatch
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class SecurityPattern:
    """Represents a single security pattern from a pattern file"""

    id: str
    severity: str
    title: str
    description: str
    regex: str
    recommendation: str
    category: str
    plugin_name: str
    plugin_version: str
    exclude: bool = False
    # Enrichment fields (all optional, default empty) - populated from YAML
    # and consumed by formatters (SARIF tags, compliance filter, etc.)
    cwe: list[str] = field(default_factory=list)  # e.g. ["CWE-78", "CWE-494"]
    mitre_attack: list[str] = field(default_factory=list)  # e.g. ["T1059.004", "T1195.002"]
    cis_controls: list[str] = field(
        default_factory=list
    )  # e.g. ["CIS-4.1", "CIS-5.2"] (CIS Ansible Benchmark)
    # Compliance-framework enrichment (all additive, all optional). Pattern
    # authors add these alongside the existing cwe/mitre/cis tags as
    # plain YAML lists. Resolvers in `link_resolver.py` validate every id
    # at CI time so typos fail the build.
    nist_controls: list[str] = field(default_factory=list)  # e.g. ["AC-3", "AC-6(9)"]
    pci_dss: list[str] = field(default_factory=list)  # e.g. ["3.5.1", "8.3.1"]
    hipaa: list[str] = field(default_factory=list)  # e.g. ["164.312(a)(1)", "164.312(e)(2)(ii)"]
    soc2: list[str] = field(default_factory=list)  # e.g. ["CC6.1", "CC6.6"]
    stig: list[str] = field(default_factory=list)  # e.g. ["V-230221", "V-242390"]
    # MITRE ATLAS - AI/ML adversarial technique catalog (namespaced with
    # `AML.` prefix, e.g. "AML.T0051.000" for direct prompt injection).
    # Additive alongside the existing mitre_attack tags; consumed by the
    # same link_resolver -> formatter pipeline.
    mitre_atlas: list[str] = field(default_factory=list)  # e.g. ["AML.T0010", "AML.T0051"]
    # OWASP catalogs - app-sec Top 10 (2021 + 2017 legacy), LLM Top 10 v1.1
    # (AI/ML apps), and ASVS v4.0.3 requirements. Additive; resolved by
    # link_resolver.resolve_owasp_* and surfaced in SARIF / GitLab SAST /
    # CycloneDX the same way other compliance tags are.
    owasp_appsec: list[str] = field(default_factory=list)  # e.g. ["A03:2021", "A07:2021"]
    owasp_llm: list[str] = field(default_factory=list)  # e.g. ["LLM01", "LLM07"]
    owasp_asvs: list[str] = field(default_factory=list)  # e.g. ["V2.4.4", "V9.1.1"]
    cve: list[str] = field(default_factory=list)  # e.g. ["CVE-2024-3094"]
    references: list[str] = field(default_factory=list)  # URLs to docs, blog posts, advisories
    help_uri: str = ""  # single canonical URL for help text (SARIF helpUri)
    precision: str = "high"  # SARIF precision: high | medium | low | very-high
    # Multi-line / evasion-resistant scanning
    # When True, the regex is applied against a rolling multi-line window of
    # the file (not just a single line). Window size defaults to 10 lines -
    # large enough to catch cross-task patterns that authors might split
    # across lines to evade a line-only scanner, but small enough that we do
    # not flag unrelated tasks. Set per-pattern with `window: N` in YAML.
    multiline: bool = False
    window: int = 10
    # Self-describing test cases
    # Rule authors declare the rule's intent alongside the regex. A generic
    # pytest parametrizes across every rule and asserts: `positive_examples`
    # MUST match, `negative_examples` MUST NOT match. Regex rewrites that
    # silently change semantics break these tests loudly instead of slipping
    # through CI. Keeping the examples in the rule file puts the ground truth
    # next to the thing it documents - whoever changes the regex must touch
    # the examples too.
    positive_examples: list[str] = field(default_factory=list)
    negative_examples: list[str] = field(default_factory=list)

    def __post_init__(self):
        # Pre-compile the regex once per pattern. Hot-path scanning calls
        # `re.search` for every pattern on every line of every file - with
        # 600+ patterns that exceeds Python's internal re-cache (512 entries)
        # and forces recompilation on every call. Caching here cuts per-file
        # scan time measurably on large repos. The multi-line flavor is only
        # compiled for patterns that opt into multi-line windowing OR use the
        # cross-line idiom `[\s\S]`; for the ~600 pure line-only patterns we
        # skip the second compile entirely. Callers in file_scanner.py
        # tolerate `_compiled_multiline is None` by falling back to a live
        # re.compile, so this is safe even if a pattern sneaks through.
        needs_multiline = self.multiline or r"[\s\S]" in self.regex
        try:
            self._compiled = re.compile(self.regex, re.IGNORECASE)
            self._compiled_multiline = (
                re.compile(self.regex, re.IGNORECASE | re.MULTILINE) if needs_multiline else None
            )
        except re.error:
            self._compiled = None
            self._compiled_multiline = None


@dataclass
class PatternFileInfo:
    """Metadata about a pattern file"""

    name: str
    version: str
    author: str
    description: str
    file_path: str


class PatternsManager:
    """Manages loading and validation of security patterns"""

    def __init__(self):
        self.pattern_files: dict[str, PatternFileInfo] = {}
        self.loaded_patterns: dict[str, list[SecurityPattern]] = {}

        self.patterns_dir = Path(__file__).parent / "patterns"
        # Cache the result of discover_and_load_patterns so a single process
        # does not re-parse 30+ YAML files and recompile 950+ regexes on every
        # call. The scanner, score-calculator, and file-scanner all call this
        # during a single scan - without caching each call cost ~3s.
        self._cached_pattern_data: dict[str, list[SecurityPattern]] | None = None

    def invalidate_cache(self) -> None:
        """Drop cached pattern data (tests / hot-reload use cases)."""
        self._cached_pattern_data = None
        self.pattern_files.clear()

    def discover_and_load_patterns(self) -> dict[str, list[SecurityPattern]]:
        """
        Discover and load all patterns from the patterns directory.
        Returns patterns organized by category for compatibility with existing system.
        """
        if self._cached_pattern_data is not None:
            return self._cached_pattern_data

        if not self.patterns_dir.exists():
            logger.info("No patterns directory found, using built-in patterns only")
            self._cached_pattern_data = {}
            return self._cached_pattern_data

        all_patterns = {}

        if self.patterns_dir.exists():
            for pattern_file in self.patterns_dir.glob("*.yml"):
                try:
                    plugin_patterns = self._load_pattern_file(pattern_file)
                    if plugin_patterns:
                        for pattern in plugin_patterns:
                            if pattern.category not in all_patterns:
                                all_patterns[pattern.category] = []
                            all_patterns[pattern.category].append(pattern)
                except Exception as e:
                    logger.warning("Failed to load pattern file %s: %s", pattern_file, e)

        logger.info(
            "Loaded %d pattern files with %d total patterns",
            len(self.pattern_files),
            sum(len(patterns) for patterns in all_patterns.values()),
        )
        self._cached_pattern_data = all_patterns
        return all_patterns

    def _load_pattern_file(self, file_path: Path) -> list[SecurityPattern]:
        """Load a single pattern file"""
        try:
            with open(file_path, encoding="utf-8") as f:
                plugin_data = yaml.safe_load(f)

            if not self._validate_pattern_structure(plugin_data, file_path):
                return []

            pattern_file_info = PatternFileInfo(
                name=plugin_data["name"],
                version="library-version",  # Will be set from package version
                author=plugin_data.get("author", "unknown"),
                description=plugin_data.get("description", ""),
                file_path=str(file_path),
            )

            self.pattern_files[pattern_file_info.name] = pattern_file_info

            patterns = []
            for pattern_data in plugin_data.get("patterns", []):
                try:
                    pattern = SecurityPattern(
                        id=pattern_data["id"],
                        severity=pattern_data.get("severity", "MEDIUM").upper(),
                        title=pattern_data.get("title", pattern_data["id"]),
                        description=pattern_data.get("description", ""),
                        regex=pattern_data["regex"],
                        recommendation=pattern_data.get(
                            "recommendation", "Review and secure this pattern"
                        ),
                        category=pattern_data.get("category", "custom"),
                        plugin_name=pattern_file_info.name,
                        plugin_version=pattern_file_info.version,
                        exclude=pattern_data.get("exclude", False),
                        cwe=list(pattern_data.get("cwe", []) or []),
                        mitre_attack=list(pattern_data.get("mitre_attack", []) or []),
                        cis_controls=list(pattern_data.get("cis_controls", []) or []),
                        nist_controls=list(pattern_data.get("nist_controls", []) or []),
                        pci_dss=list(pattern_data.get("pci_dss", []) or []),
                        hipaa=list(pattern_data.get("hipaa", []) or []),
                        soc2=list(pattern_data.get("soc2", []) or []),
                        stig=list(pattern_data.get("stig", []) or []),
                        mitre_atlas=list(pattern_data.get("mitre_atlas", []) or []),
                        owasp_appsec=list(pattern_data.get("owasp_appsec", []) or []),
                        owasp_llm=list(pattern_data.get("owasp_llm", []) or []),
                        owasp_asvs=list(pattern_data.get("owasp_asvs", []) or []),
                        cve=list(pattern_data.get("cve", []) or []),
                        references=list(pattern_data.get("references", []) or []),
                        help_uri=pattern_data.get("help_uri", "") or "",
                        precision=pattern_data.get("precision", "high") or "high",
                        multiline=bool(pattern_data.get("multiline", False)),
                        window=int(pattern_data.get("window", 10) or 10),
                        positive_examples=list(pattern_data.get("positive_examples", []) or []),
                        negative_examples=list(pattern_data.get("negative_examples", []) or []),
                    )

                    try:
                        re.compile(pattern.regex)
                    except re.error as e:
                        logger.warning(
                            "Invalid regex in %s, pattern %s: %s", file_path, pattern.id, e
                        )
                        continue

                    patterns.append(pattern)

                except KeyError as e:
                    logger.warning("Missing required field %s in pattern from %s", e, file_path)
                    continue

            self.loaded_patterns[pattern_file_info.name] = patterns
            logger.debug(
                "Loaded pattern file '%s' with %d patterns",
                pattern_file_info.name,
                len(patterns),
            )
            return patterns

        except yaml.YAMLError as e:
            logger.warning("Invalid YAML in pattern file %s: %s", file_path, e)
            return []
        except Exception as e:
            logger.warning("Error loading pattern file %s: %s", file_path, e)
            return []

    def _validate_pattern_structure(self, plugin_data: dict[str, Any], file_path: Path) -> bool:
        """Validate that a pattern file has the required structure"""
        required_fields = ["name", "patterns"]

        for required_field in required_fields:
            if required_field not in plugin_data:
                logger.warning(
                    "Pattern file %s missing required field: %s", file_path, required_field
                )
                return False

        if not isinstance(plugin_data["patterns"], list):
            logger.warning("Pattern file %s: 'patterns' must be a list", file_path)
            return False

        for i, pattern in enumerate(plugin_data["patterns"]):
            if not isinstance(pattern, dict):
                logger.warning("Plugin %s: pattern %d must be a dictionary", file_path, i)
                return False

            required_pattern_fields = ["id", "regex"]
            for required_field in required_pattern_fields:
                if required_field not in pattern:
                    logger.warning(
                        "Plugin %s: pattern %d missing required field: %s",
                        file_path,
                        i,
                        required_field,
                    )
                    return False

        return True

    def convert_plugins_to_legacy_format(
        self, plugin_patterns: dict[str, list[SecurityPattern]]
    ) -> dict[str, dict[str, Any]]:
        """
        Convert pattern data to the legacy format expected by the existing system.
        This ensures backward compatibility.
        """
        legacy_patterns = {}

        for category, patterns in plugin_patterns.items():
            if not patterns:
                continue

            # Group patterns by severity for the legacy format
            pattern_regexes = [p.regex for p in patterns]

            # Use the first pattern's metadata as representative (they should be similar within a category)
            first_pattern = patterns[0]

            legacy_patterns[category] = {
                "patterns": pattern_regexes,
                "severity": first_pattern.severity,
                "title": f"{category.replace('_', ' ').title()} (Plugin)",
                "description": first_pattern.description
                or f"Security issues detected by {category} plugins",
                "recommendation": first_pattern.recommendation
                or "Review and address the security issues identified by the plugin patterns",
            }

        return legacy_patterns

    def get_plugin_info(self) -> list[PatternFileInfo]:
        """Get information about all loaded pattern files"""
        return list(self.pattern_files.values())

    def get_patterns_by_plugin(self, plugin_name: str) -> list[SecurityPattern]:
        """Get all patterns from a specific pattern file"""
        return self.loaded_patterns.get(plugin_name, [])

    def validate_pattern_file(self, file_path: Path) -> dict[str, Any]:
        """
        Validate a pattern file and return validation results.
        Useful for CLI tools and testing.
        """
        results = {"valid": False, "errors": [], "warnings": [], "pattern_count": 0}

        try:
            with open(file_path, encoding="utf-8") as f:
                plugin_data = yaml.safe_load(f)

            if self._validate_pattern_structure(plugin_data, file_path):
                results["valid"] = True
                results["pattern_count"] = len(plugin_data.get("patterns", []))

                # Additional validation checks
                for pattern in plugin_data.get("patterns", []):
                    try:
                        re.compile(pattern["regex"])
                    except re.error as e:
                        results["warnings"].append(
                            f"Pattern '{pattern.get('id', 'unknown')}' has invalid regex: {e}"
                        )

        except yaml.YAMLError as e:
            results["errors"].append(f"Invalid YAML: {e}")
        except Exception as e:
            results["errors"].append(f"Error reading file: {e}")

        return results


# Global patterns manager instance
patterns_manager = PatternsManager()


class RuleSelectionError(ValueError):
    """Raised when --select / --ignore references a rule_id or glob that
    matches no known rule. Surfaced to the CLI as a usage error (exit 2)."""


def _normalize_specs(specs: Iterable[str] | None) -> tuple[str, ...]:
    """Split comma- or whitespace-separated specs into a tuple of tokens.

    Accepts ``None`` / ``""`` / ``["a,b", "c"]`` / ``"a b , c"`` and
    yields ``("a", "b", "c")``. Order preserved so error messages quote
    user input verbatim. Empty result if no tokens found.
    """
    if not specs:
        return ()
    if isinstance(specs, str):
        specs = [specs]
    tokens: list[str] = []
    for spec in specs:
        for tok in re.split(r"[,\s]+", str(spec).strip()):
            if tok:
                tokens.append(tok)
    return tuple(tokens)


def resolve_rule_specs(
    specs: Iterable[str] | None,
    known_rule_ids: Iterable[str],
) -> frozenset[str]:
    """Resolve glob/literal rule-id specs against the universe of known
    rule_ids, returning the matched id set.

    Globs use ``fnmatch`` (``*``/``?``/``[...]``); literals must match a
    known rule_id exactly. A spec that matches nothing is a hard error -
    surfacing typos loudly is the whole point of this function. Each
    spec is matched independently so a typo in one element doesn't
    silently get rescued by a wildcard in another.
    """
    tokens = _normalize_specs(specs)
    if not tokens:
        return frozenset()
    universe = frozenset(known_rule_ids)
    matched: set[str] = set()
    unmatched: list[str] = []
    for tok in tokens:
        if any(ch in tok for ch in "*?["):
            hits = {rid for rid in universe if fnmatch.fnmatchcase(rid, tok)}
        else:
            hits = {tok} if tok in universe else set()
        if not hits:
            unmatched.append(tok)
        else:
            matched.update(hits)
    if unmatched:
        raise RuleSelectionError(
            f"Unknown rule id(s) or glob(s): {unmatched!r}. "
            f"Run with --list-rules to see every known rule_id."
        )
    return frozenset(matched)


# Rule_ids that are emitted by structural code paths (taint tracker,
# parse-error reporter, suppression auditor) but are not declared in
# any pattern YAML and are not registered in
# ``synthetic_rule_frameworks.SYNTHETIC_RULE_FRAMEWORKS``. They still
# need to be part of the ``known_rule_ids`` universe so ``--select`` /
# ``--ignore`` can reference them and ``--list-rules`` is exhaustive.
# Keep this list short - prefer registering new rule_ids in the
# synthetic_rule_frameworks catalog so framework-tag enrichment works
# automatically. These are the meta-rules that report on the scan
# itself and don't carry framework tags.
_CODE_EMITTED_RULE_IDS: frozenset[str] = frozenset(
    {
        "cross_file_taint",
        "scan_error",
        "suspicious_suppression",
    }
)


def known_rule_ids() -> frozenset[str]:
    """Return every rule_id the scanner can possibly emit.

    Union of (a) every rule loaded from the YAML pattern files and (b)
    every synthetic rule_id registered in ``synthetic_rule_frameworks``.
    This is the universe ``--select`` / ``--ignore`` resolve against and
    the set ``--list-rules`` prints. Lazy-imports the synthetic registry
    to avoid a circular import at module-load time.
    """
    from .synthetic_rule_frameworks import SYNTHETIC_RULE_FRAMEWORKS

    yaml_ids = {
        p.id
        for patterns in patterns_manager.discover_and_load_patterns().values()
        for p in patterns
    }
    return frozenset(yaml_ids | set(SYNTHETIC_RULE_FRAMEWORKS) | _CODE_EMITTED_RULE_IDS)


def known_rule_categories() -> dict[str, str]:
    """Return a ``{rule_id: category}`` map for every rule in the YAML
    pattern files.

    Synthetic and code-emitted rule ids are deliberately omitted - they
    have no native category and the consumer (the MR-comment renderer)
    falls them back into a single ``other`` bucket. Lazy-imports
    nothing; the YAML walk is shared with ``known_rule_ids``.
    """
    return {
        p.id: p.category
        for patterns in patterns_manager.discover_and_load_patterns().values()
        for p in patterns
    }


def filter_patterns(
    pattern_data: dict[str, list[SecurityPattern]],
    *,
    select: frozenset[str] | None = None,
    ignore: frozenset[str] | None = None,
) -> dict[str, list[SecurityPattern]]:
    """Return a narrowed copy of ``pattern_data`` keyed by category.

    ``select`` whitelists rule_ids; everything else is dropped. ``ignore``
    blacklists rule_ids; everything else is kept. When both are given,
    ``select`` is applied first then ``ignore`` removes from the kept
    set (so ``select`` defines the universe and ``ignore`` carves out of
    it). ``None`` for either means "no filter on this side". The input
    dict is never mutated. Empty categories are pruned so downstream
    iteration sees only meaningful keys.
    """
    if select is None and ignore is None:
        return pattern_data
    out: dict[str, list[SecurityPattern]] = {}
    for category, patterns in pattern_data.items():
        kept = [
            p
            for p in patterns
            if (select is None or p.id in select) and (ignore is None or p.id not in ignore)
        ]
        if kept:
            out[category] = kept
    return out
