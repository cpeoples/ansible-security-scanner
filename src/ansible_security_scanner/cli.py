#!/usr/bin/env python3
"""
Command line interface for Ansible Security Scanner
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import replace
from pathlib import Path

from .file_scanner import _ALWAYS_EMITTED_RULE_IDS
from .patterns_manager import (
    RuleListingRow,
    RuleSelectionError,
    known_rule_categories,
    known_rule_ids,
    known_rule_metadata,
    resolve_rule_specs,
)
from .scanner import AnsibleSecurityScanner
from .utils import get_exit_code, get_formatter_class, parse_changed_files, setup_logging

logger = logging.getLogger(__name__)


# Map from output-file extension to the implied --format value. Used
# when --output is given without an explicit --format.
_OUTPUT_EXTENSION_TO_FORMAT: dict[str, str] = {
    ".md": "markdown",
    ".markdown": "markdown",
    ".json": "json",
    ".xml": "xml",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".csv": "csv",
    ".html": "html",
    ".htm": "html",
    ".sarif": "sarif",
}


# Inverse map; used by --output-per-file to name each per-file report.
_FORMAT_TO_OUTPUT_EXTENSION: dict[str, str] = {
    "markdown": ".md",
    "json": ".json",
    "xml": ".xml",
    "yaml": ".yml",
    "csv": ".csv",
    "html": ".html",
    "junit": ".xml",
    "sarif": ".sarif",
    "gl-sast": ".json",
    "gitlab-sast": ".json",
    "cyclonedx": ".json",
    "sbom": ".json",
}


# Formats whose output describes the scan as a whole (e.g. CycloneDX
# SBOM) and don't make sense per-file. --output-per-file refuses these.
_AGGREGATE_ONLY_FORMATS: frozenset[str] = frozenset({"cyclonedx", "sbom"})

_SEVERITY_RANK: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# Sentinel row for `--list-rules-detailed` when a rule_id has no YAML
# backing (synthetic / code-emitted). The CLI documents the
# ``<synthetic>`` placeholder so consumers can filter it out cleanly.
_SYNTHETIC_LISTING_ROW: RuleListingRow = {
    "severity": "<synthetic>",
    "category": "<synthetic>",
    "title": "<synthetic>",
}


def _infer_format_from_output_path(output_path: str) -> str | None:
    """Return the ``--format`` value implied by ``output_path``'s suffix,
    or ``None`` if the suffix isn't a known report extension.

    Lower-cased lookup so ``Report.JSON`` infers ``json`` the same way
    ``report.json`` does. Returns ``None`` (not the default) when the
    suffix is missing or unknown - callers fall back to the explicit
    ``--format`` choice or the Markdown default in that case.
    """
    if not output_path:
        return None
    suffix = Path(output_path).suffix.lower()
    return _OUTPUT_EXTENSION_TO_FORMAT.get(suffix)


# Default output directory used when the user passes
# ``--output-per-file`` without ``--output``. Chosen to be
# self-documenting ("hey, there are security reports here") and to
# avoid colliding with common project directories (``reports/``,
# ``build/``). A matching ``.gitignore`` snippet is suggested in the
# README so CI doesn't accidentally commit generated artefacts.
_DEFAULT_OUTPUT_PER_FILE_DIR = "security-reports"


# Epilog shown at the bottom of ``--help``. Uses
# ``RawDescriptionHelpFormatter`` so the examples render as a
# pre-formatted block instead of being re-wrapped into prose. Every
# example here is copy-paste runnable after ``pip install
# ansible-security-scanner`` - keep it that way if you add more.
_HELP_EPILOG = """\
Examples:
  # Scan the current directory and print a Markdown report to the terminal
  ansible-security-scanner

  # Scan a specific playbook and write a SARIF report for GitHub Code Scanning
  ansible-security-scanner --files site.yml --output report.sarif

  # CI/CD: scan an Ansible project and emit a GitLab SAST report
  ansible-security-scanner --directory ansible/ --output gl-sast-report.json

  # Per-file reports (one Markdown report per scanned playbook)
  ansible-security-scanner --directory ansible/ --output-per-file --format markdown

  # Only fail the build on CIS-Secrets findings (filter + non-zero exit)
  ansible-security-scanner --directory ansible/ --compliance CIS-Secrets

  # Dry-run autofix: emit a unified diff of the changes the scanner would make
  ansible-security-scanner --files site.yml --fix --fix-output fixes.patch

  # CI/CD: post a concise findings summary on the current GitHub PR
  ansible-security-scanner --gh-comment      # inside a pull_request workflow

  # CI/CD: same for GitLab (works on self-hosted - uses CI_SERVER_URL)
  ansible-security-scanner --gl-comment      # inside a merge_request_event pipeline

Exit codes:
  0   no findings at or above HIGH severity (or --exit-zero passed)
  1   one or more HIGH-severity findings
  2   one or more CRITICAL findings, a suppression gate failure,
      or a CLI-usage error (e.g. --output would overwrite an input file)

Output format inference:
  When you pass --output <path> without --format, the format is
  inferred from the file extension: .md/.markdown=markdown, .json=json,
  .xml=xml, .yml/.yaml=yaml, .csv=csv, .html/.htm=html, .sarif=sarif.
  An explicit --format always wins; a warning is logged if the two
  disagree so pipeline mistakes are loud rather than silent.

Documentation:
  https://github.com/cpeoples/ansible-security-scanner
"""


_ENV_TRUE = frozenset({"1", "true", "yes", "on"})
_ENV_FALSE = frozenset({"0", "false", "no", "off", ""})


def _env_str(name: str, default: str | None = None) -> str | None:
    """Return the env var if set and non-empty, else ``default``."""
    value = os.environ.get(name)
    return value if value else default


def _env_int(name: str, default: int) -> int:
    """Return the env var parsed as an int, falling back to ``default``.

    A non-integer value logs a warning and falls back so a typo in a CI
    image's env block can't take down every run.
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using default %d", name, raw, default)
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    """Return the env var parsed as a bool, falling back to ``default``."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    lowered = raw.strip().lower()
    if lowered in _ENV_TRUE:
        return True
    if lowered in _ENV_FALSE:
        return default if lowered == "" else False
    logger.warning(
        "%s=%r is not a boolean (expected one of %s / %s); using default %s",
        name,
        raw,
        sorted(_ENV_TRUE),
        sorted(_ENV_FALSE - {""}),
        default,
    )
    return default


def _env_choice(name: str, choices: tuple[str, ...], default: str | None = None) -> str | None:
    """Return the env var if it matches one of ``choices`` (case-insensitive)."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    normalized = raw.strip()
    for choice in choices:
        if normalized.lower() == choice.lower():
            return choice
    logger.warning(
        "%s=%r is not one of %s; using default %r",
        name,
        raw,
        list(choices),
        default,
    )
    return default


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser"""
    parser = argparse.ArgumentParser(
        prog="ansible-security-scanner",
        description=(
            "Scan Ansible playbooks, roles, and collections for security "
            "vulnerabilities, hardcoded credentials, insecure defaults, and "
            "compliance gaps (OWASP / CIS / NIST / PCI-DSS / HIPAA / SOC2 / "
            "STIG / MITRE ATT&CK). Supports Markdown, JSON, SARIF, JUnit, "
            "GitLab SAST, CycloneDX SBOM, CSV, HTML, XML, and YAML output."
        ),
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--directory",
        "-d",
        default=_env_str("ANSIBLE_SEC_SCANNER_DIRECTORY", "."),
        help="Directory to scan for Ansible YAML files (default: current directory; "
        "override with ANSIBLE_SEC_SCANNER_DIRECTORY)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=_env_str("ANSIBLE_SEC_SCANNER_OUTPUT"),
        help="Output file for the report (default: console output, specify filename to save to file; "
        "override with ANSIBLE_SEC_SCANNER_OUTPUT)",
    )
    parser.add_argument(
        "--output-per-file",
        action="store_true",
        help="Instead of writing a single aggregate report, write one report "
        "per scanned YAML file. ``--output`` must be a directory (created if "
        "missing). Scanned file paths are preserved under the output directory, "
        "with the format-appropriate extension appended (e.g. "
        "``roles/webapp/tasks/main.yml`` -> "
        "``<output-dir>/roles/webapp/tasks/main.yml.md``). Useful for "
        "CI systems that upload per-file artifacts (GitHub Code Scanning, "
        "GitLab SAST per-path reports, Jenkins per-module dashboards).",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=[
            "markdown",
            "json",
            "xml",
            "yaml",
            "csv",
            "html",
            "junit",
            "sarif",
            "gl-sast",
            "gitlab-sast",
            "cyclonedx",
            "sbom",
        ],
        # Default is resolved in ``main()`` so we can distinguish
        # "user passed --format" from "user accepted the default".
        # When None, the real default is ``markdown`` - unless the
        # user passed ``--output foo.json`` (or similar) in which
        # case the format is inferred from the extension. See
        # ``_infer_format_from_output_path``. ANSIBLE_SEC_SCANNER_FORMAT
        # can supply a default; the CLI flag still wins.
        default=_env_choice(
            "ANSIBLE_SEC_SCANNER_FORMAT",
            (
                "markdown",
                "json",
                "xml",
                "yaml",
                "csv",
                "html",
                "junit",
                "sarif",
                "gl-sast",
                "gitlab-sast",
                "cyclonedx",
                "sbom",
            ),
        ),
        help=(
            "Output format (default: markdown; inferred from the "
            "--output extension when that flag is set, e.g. "
            "--output report.json implies --format json; "
            "override default with ANSIBLE_SEC_SCANNER_FORMAT)"
        ),
    )
    parser.add_argument("--files", nargs="+", help="Specific files to scan (space separated)")
    parser.add_argument(
        "--changed-files", help="Scan only changed files (from CI/CD variable or file list)"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument(
        "--allowlist",
        default=_env_str("ANSIBLE_SEC_SCANNER_ALLOWLIST"),
        help="Path to allowlist YAML config (default: .security-scanner-allowlist.yml next to package; "
        "override with ANSIBLE_SEC_SCANNER_ALLOWLIST)",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        default=_env_bool("ANSIBLE_SEC_SCANNER_EXIT_ZERO"),
        help="Always exit with code 0 (useful for CI/CD when you want to generate reports but not fail builds; "
        "override default with ANSIBLE_SEC_SCANNER_EXIT_ZERO=1)",
    )
    parser.add_argument(
        "--show-suppressed",
        action="store_true",
        help="Include findings that were suppressed by inline # nosec / # noqa comments in the report",
    )
    parser.add_argument(
        "--no-suppressions",
        action="store_true",
        help="Ignore every # nosec / # noqa directive in the scanned tree. "
        "Used by release gates or audit runs where authors are not allowed "
        "to silence findings.",
    )
    parser.add_argument(
        "--fail-on-suppressed",
        action="store_true",
        help="Exit with a non-zero status if any finding in the tree is suppressed "
        "by a # nosec / # noqa directive. Combine with --show-suppressed to see which.",
    )
    parser.add_argument(
        "--max-suppressions",
        type=int,
        default=None,
        metavar="N",
        help="Exit with a non-zero status if more than N findings are suppressed "
        "across the tree. Useful as a suppression budget gate in CI.",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Dry-run autofix. For rules the scanner knows how to repair "
        "(no_log/ignore_errors/validate_certs/mode 0777/etc.), attach a "
        "unified-diff patch to each finding. Never writes to disk - use "
        "--fix-output to save the patch, then apply with `git apply`.",
    )
    parser.add_argument(
        "--fix-output",
        metavar="PATH",
        help="With --fix: write the concatenated unified-diff patch to PATH "
        "instead of printing it to stderr. The file can be applied with "
        "`git apply PATH` after review.",
    )
    parser.add_argument(
        "--scan-git-history",
        action="store_true",
        help="Opt-in: after scanning the live files, also scan each tracked "
        "file at its previous commits for hardcoded credentials that were "
        "later removed. Secrets committed once stay in git history forever. "
        "This adds latency - off by default.",
    )
    parser.add_argument(
        "--git-history-max-commits",
        type=int,
        default=50,
        metavar="N",
        help="With --scan-git-history: cap each file at N historical commits "
        "(default: 50). Larger values find older leaks at the cost of "
        "scan time.",
    )
    parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=_env_int("ANSIBLE_SEC_SCANNER_JOBS", 1),
        metavar="N",
        help="Run the per-file scan stage on N worker threads "
        "(default: 1 = sequential; override with ANSIBLE_SEC_SCANNER_JOBS). "
        "Safe on any repo size; "
        "findings are sorted downstream so output is "
        "byte-for-byte identical to a serial run.",
    )
    parser.add_argument(
        "--dedup-across-files",
        action="store_true",
        help="Collapse findings that share (rule_id, normalized snippet) "
        "across multiple files into a single representative finding. The "
        "other affected (file, line) locations are preserved in the "
        "representative's `duplicates` list (visible in JSON/YAML/SARIF "
        "output). Intended for repos with many near-identical variant "
        "playbooks (fork families) where the same task text repeats "
        "verbatim and inflates the report. Off by default - existing "
        "consumers keep the per-location shape.",
    )
    parser.add_argument(
        "--compliance",
        metavar="TAG[,TAG...]",
        help="Filter the report to findings that carry at least one of the "
        "given compliance tags. Matches case-insensitive against each "
        "finding's cis_controls field. Examples: "
        "`--compliance CIS-Secrets`, `--compliance CIS-3.3,CIS-Docker`. "
        "Use `--compliance list` to print every tag present in the scan.",
    )
    parser.add_argument(
        "--severity",
        metavar="LEVEL",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=_env_choice(
            "ANSIBLE_SEC_SCANNER_SEVERITY",
            ("CRITICAL", "HIGH", "MEDIUM", "LOW"),
        ),
        help="Filter the report to findings at or above the given severity "
        "(CRITICAL > HIGH > MEDIUM > LOW). Default: no filter, all "
        "severities are shown. CI integrations that want a quieter "
        "report can pass `--severity HIGH` to drop style/hygiene "
        "findings (LOW/MEDIUM) without affecting exit codes - those "
        "still gate on HIGH/CRITICAL regardless of this flag. "
        "Override default with ANSIBLE_SEC_SCANNER_SEVERITY.",
    )
    parser.add_argument(
        "--select",
        metavar="RULE[,RULE...]",
        default=_env_str("ANSIBLE_SEC_SCANNER_SELECT"),
        help="Run ONLY the listed rules; every other rule is skipped at "
        "scan time (not post-filtered) so single-rule runs are fast on "
        "large repos. Accepts comma-separated rule_ids and fnmatch globs "
        "(e.g. `--select aws_*,hardcoded_password`). An unknown rule_id "
        "is a usage error (exit 2). Override default with "
        "ANSIBLE_SEC_SCANNER_SELECT. Combine with `--list-rules` to "
        "discover rule_ids.",
    )
    parser.add_argument(
        "--ignore",
        metavar="RULE[,RULE...]",
        default=_env_str("ANSIBLE_SEC_SCANNER_IGNORE"),
        help="Drop the listed rules from the scan. Same syntax as "
        "--select (comma-separated, fnmatch globs supported). When "
        "both flags are set, --select defines the universe and --ignore "
        "carves out of it. An unknown rule_id is a usage error (exit 2). "
        "Override default with ANSIBLE_SEC_SCANNER_IGNORE.",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Print every known rule_id (one per line, sorted) and exit. "
        "Use with `--select` / `--ignore` to discover the universe of "
        "rule_ids. Output is plain text on stdout so it's pipeable to "
        "grep/awk/fzf.",
    )
    parser.add_argument(
        "--list-rules-detailed",
        action="store_true",
        help="Like `--list-rules` but emits a TSV of "
        "`rule_id<TAB>severity<TAB>category<TAB>title` so operators can "
        "disambiguate findings whose display title is shared by more "
        "than one rule_id (the canonical example: two distinct rules "
        'both titled "SetUID Binary Creation"). Synthetic / '
        "code-emitted rule_ids carry sentinel placeholders for "
        "severity/category/title - their identity is the rule_id "
        "itself.",
    )

    # MR / PR commenting
    # Post (or update) a concise findings summary on the current PR
    # (GitHub) or MR (GitLab). Platform detection is env-only - see
    # ``comment.detect_platform``. Tokens are read from env vars
    # only; never from CLI flags (so they never land in shell history
    # or CI logs). Long and short aliases are both wired because
    # operators have strong opinions about which form reads better in
    # their CI YAML - we support both rather than picking a side.
    mr_group = parser.add_argument_group(
        "Merge-request / pull-request commenting",
        "Post a concise findings summary on the current MR/PR. Platform "
        "is detected from CI env vars; tokens come from env vars only "
        "(GITHUB_TOKEN, GITLAB_TOKEN, CI_JOB_TOKEN, or the scanner-specific "
        "ANSIBLE_SEC_SCANNER_* variants). The comment is edited in place "
        "on subsequent scans of the same MR/PR; once findings reach zero "
        "the comment flips to a 'resolved' banner.",
    )
    mr_group.add_argument(
        "--github-comment",
        "--gh-comment",
        dest="github_comment",
        action="store_true",
        help="Post / update a summary comment on the current GitHub PR. "
        "Must run inside a pull_request GitHub Actions workflow. Never "
        "fails the build on its own - comment errors are logged and "
        "the scanner's exit code is driven by findings only.",
    )
    mr_group.add_argument(
        "--gitlab-comment",
        "--gl-comment",
        dest="gitlab_comment",
        action="store_true",
        help="Post / update a summary comment on the current GitLab MR. "
        "Must run inside a merge_request_event pipeline. Works against "
        "self-hosted GitLab instances (CI_SERVER_URL drives the API URL). "
        "Never fails the build on its own.",
    )
    mr_group.add_argument(
        "--mr-comment-full-report",
        metavar="PATH",
        default=None,
        help="With --github-comment / --gitlab-comment: write the full "
        "Markdown report to PATH alongside posting the concise MR comment "
        "(default: security-reports/report.md). The comment "
        "links to this file so reviewers can click through from the "
        "dashboard view.",
    )
    mr_group.add_argument(
        "--mr-comment-scope-changed-files",
        dest="mr_comment_scope_changed_files",
        action="store_true",
        default=True,
        help="Auto-scope the scan to the MR/PR's changed files when no "
        "explicit --files / --changed-files is passed (default: on). "
        "Off -> scan the full repo even inside an MR pipeline.",
    )
    mr_group.add_argument(
        "--no-mr-comment-scope-changed-files",
        dest="mr_comment_scope_changed_files",
        action="store_false",
        help="Disable the auto-scope-to-changed-files behaviour (scan "
        "the full --directory even inside an MR pipeline).",
    )
    mr_group.add_argument(
        "--inline-comments",
        dest="inline_comments",
        action="store_true",
        default=False,
        help="Also post per-finding inline review threads (GitLab "
        "Discussions / GitHub GraphQL) on each offending diff line. "
        "Off-diff findings post as file-level threads. Idempotent: "
        "stale threads are resolved on re-runs.",
    )
    mr_group.add_argument(
        "--no-inline-comments",
        dest="inline_comments",
        action="store_false",
        help="Disable inline review threads (default).",
    )

    return parser


def handle_target_files(args) -> list[str] | None:
    """Validate path-shaped CLI inputs and decide which files to scan.

    Validates ``--directory`` (must be an existing directory) and
    ``--files`` (each entry must be a file, not a directory) up front,
    failing with exit code 2 on a usage error. Without these guards the
    scanner accepts a swapped-flag invocation, walks an empty file set,
    and writes a structurally valid but empty report - which reads as
    "no findings" to anyone glancing at the output.

    Returns ``None`` to mean "no explicit file list - scan the directory
    tree". Returning an empty list would mean "the user asked for these
    specific files and there happen to be zero of them," which is a
    different (terminal) case the caller already handles before reaching
    this function.
    """
    directory = Path(args.directory)
    if not directory.is_dir():
        if directory.is_file():
            logger.error(
                "--directory expects a directory, not a file. Got: %s. "
                "To scan a single file, use --files %s instead.",
                args.directory,
                args.directory,
            )
        else:
            logger.error(
                "--directory %s does not exist or is not a directory.",
                args.directory,
            )
        sys.exit(2)

    target_files: list[str] | None = None

    if args.changed_files:
        changed_files_input = args.changed_files
        if changed_files_input.startswith("$"):
            env_var = changed_files_input[1:]  # strip leading ``$``
            changed_files_input = os.environ.get(env_var, "")
            logger.info("Using environment variable %s: %s", env_var, changed_files_input)

        target_files = parse_changed_files(changed_files_input)

        if not target_files:
            logger.info("No yml files in changed files, skipping scan")
            sys.exit(0)

    elif args.files:
        directories = [f for f in args.files if Path(f).is_dir()]
        if directories:
            logger.error(
                "--files expects file paths, not directories. Got: %s. "
                "To scan a directory tree, drop --files and use --directory %s "
                "(or just pass the directory positionally).",
                ", ".join(directories),
                directories[0],
            )
            sys.exit(2)
        target_files = args.files
        logger.info("Scanning specific files: %s", target_files)

    return target_files


def write_output(
    output: str, output_path: str | None = None, format_name: str = "markdown"
) -> None:
    """Write output to file or console"""
    if output_path:
        logger.info("Writing %s output to %s", format_name.upper(), output_path)
        logger.info("Output content length: %d", len(output))

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)

        logger.info("File written successfully. File size: %d bytes", output_file.stat().st_size)
        logger.info("Report generated: %s", output_path)
    else:
        print(output)
        logger.info("Report output to console (use --output to save to file)")


def _safe_relative_path(file_path: str, base: Path) -> Path:
    """Turn a finding's ``file_path`` into a safe relative path under
    ``base``. Handles three shapes:

    * Absolute paths that live under the scan root -> relativised.
    * Absolute paths *outside* the scan root -> flattened to the
      basename so we never traverse ``..`` out of the output directory.
    * Relative paths -> kept as-is.

    Path traversal guards: we resolve the final output path and
    confirm it's still inside ``base`` before returning it. Any path
    containing ``..`` after normalisation falls back to the basename.
    The ``@<sha>`` suffix emitted by ``--scan-git-history`` is stripped
    - history findings all share a playbook's path, so they'd collide
    in the per-file view; instead we collapse them into that
    playbook's report.
    """
    # Strip git-history stamp so historical findings merge into the
    # live file's per-file report rather than spawning a sibling.
    if "@" in file_path:
        file_path = file_path.split("@", 1)[0]

    p = Path(file_path)
    if p.is_absolute():
        try:
            p = p.relative_to(Path.cwd())
        except ValueError:
            p = Path(p.name)

    if ".." in p.parts:
        p = Path(p.name)

    return p


def write_per_file_outputs(
    report,
    scanner,
    formatter_class,
    output_dir: str,
    format_name: str,
    scanned_files: list[str] | None,
) -> int:
    """Split an aggregate ``ScanReport`` into one report per scanned
    YAML file and write each to ``output_dir``. Returns the number of
    files written.

    Every scanned file gets a report - even files with zero findings
    - so a CI system iterating over ``output_dir`` sees a 1:1 mapping
    between inputs and reports. Findings are partitioned by
    ``finding.file_path``; files without findings get an empty
    ``ScanReport`` (still summarised, still scored) so downstream
    tooling can detect "scan ran, found nothing" vs. "scan didn't run".
    """
    base = Path(output_dir)
    base.mkdir(parents=True, exist_ok=True)

    # Findings carry file paths relative to ``scanner.directory``; the
    # CLI may have passed ``--files`` as absolute or CWD-relative paths.
    # Normalise both sides against a single anchor (the scan directory)
    # so the same logical file doesn't appear twice under different
    # string forms.
    scan_root = Path(getattr(scanner, "directory", report.ansible_directory)).resolve()

    def _anchor(p: str) -> Path:
        """Return the resolved absolute path for ``p``, treating
        bare relative paths as relative to the scan root first and
        CWD second. Never raises; returns a Path() for unrecognised
        inputs so callers don't need to branch.
        """
        raw = Path(p)
        if raw.is_absolute():
            try:
                return raw.resolve()
            except OSError:
                return raw
        candidate = scan_root / raw
        if candidate.exists():
            try:
                return candidate.resolve()
            except OSError:
                return candidate
        try:
            return raw.resolve()
        except OSError:
            return raw

    # Partition findings by their ``file_path``. Strip ``@sha`` suffixes
    # so git-history findings merge into the live file's report.
    by_file: dict[str, list] = {}
    for f in report.findings:
        key = f.file_path.split("@", 1)[0] if "@" in f.file_path else f.file_path
        by_file.setdefault(key, []).append(f)

    # Build an anchor -> key map from the finding paths first so those
    # (scanner-relative) keys become the canonical display form; the
    # CLI-provided ``scanned_files`` only contribute entries for files
    # that produced zero findings.
    resolved_to_key: dict[Path, str] = {}
    for key in by_file:
        resolved_to_key[_anchor(key)] = key
    if scanned_files:
        for s in scanned_files:
            anchor = _anchor(s)
            if anchor in resolved_to_key:
                continue
            # Prefer the scanner-relative form so the output layout
            # matches what the aggregate report would display.
            try:
                display = str(anchor.relative_to(scan_root))
            except ValueError:
                display = s
            resolved_to_key[anchor] = display
    if not resolved_to_key and report.scanned_file_names:
        for s in report.scanned_file_names:
            resolved_to_key.setdefault(_anchor(s), s)

    all_files = sorted(resolved_to_key.values())

    ext = _FORMAT_TO_OUTPUT_EXTENSION.get(format_name, ".txt")
    base_resolved = base.resolve()
    written = 0

    for file_key in all_files:
        findings = by_file.get(file_key, [])
        summary = scanner._generate_summary(findings)

        # Per-file security score: re-score with just this file's
        # findings so each report's score reflects that file's health.
        try:
            per_file_score = scanner.score_calculator.calculate_security_score(findings, 1)
        except Exception:
            per_file_score = report.security_score

        per_file_report = replace(
            report,
            findings=findings,
            summary=summary,
            security_score=per_file_score,
            total_files_scanned=1,
            scanned_file_names=[file_key],
        )

        formatter = formatter_class(show_all=True)
        rendered = formatter.format(per_file_report)

        rel = _safe_relative_path(file_key, base_resolved)
        dest = base_resolved / (str(rel) + ext)

        # Guard: ensure we never write outside the output directory
        # even when a finding reported a weird path. ``resolve()``
        # normalises ``..`` and symlinks; if the result escapes
        # ``base_resolved`` we fall back to the basename.
        dest_resolved = dest.resolve()
        try:
            dest_resolved.relative_to(base_resolved)
        except ValueError:
            dest = base_resolved / (Path(file_key).name + ext)
            dest_resolved = dest.resolve()

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(rendered, encoding="utf-8")
        written += 1

    logger.info(
        "Wrote %d per-file %s report(s) to %s",
        written,
        format_name.upper(),
        output_dir,
    )
    return written


def _resolve_mr_context(args) -> object | None:
    """Pre-scan hook: if the user asked for an MR/PR comment, detect the
    platform context from CI env vars and return it. Returns ``None``
    when no MR-comment flag is set or when detection fails (detection
    logs a warning in that case - see ``comment.detect_platform``).

    Having this as a standalone helper keeps ``main()`` short and lets
    tests patch the detection seam without mocking the entire CLI
    module. We deliberately resolve GitLab *before* GitHub when both
    flags are passed so operators running in a cross-posting matrix
    job (rare but valid) get a deterministic order - GitLab is the
    user's primary platform per the task brief.
    """
    if not (getattr(args, "gitlab_comment", False) or getattr(args, "github_comment", False)):
        return None

    # Import lazily so the scanner still works when httpx isn't
    # installed (e.g. air-gapped dev envs that never use MR comments).
    from . import comment

    if args.gitlab_comment:
        ctx = comment.detect_platform("gitlab")
        if ctx is not None:
            return ctx
    if args.github_comment:
        ctx = comment.detect_platform("github")
        if ctx is not None:
            return ctx
    return None


def _maybe_scope_to_changed_files(args, ctx, existing_target_files: list | None) -> list | None:
    """When MR-comment mode is on and the user didn't narrow the scan
    with ``--files`` / ``--changed-files``, ask the platform for the
    MR/PR's changed files and use them as the scan target.

    Returns the resolved target-files list (possibly unchanged). Never
    raises - any fetch error logs a warning and falls back to the
    caller-provided list, so a flaky API call degrades to "scan the
    full --directory" rather than silently skipping the scan.
    """
    if ctx is None:
        return existing_target_files
    if existing_target_files:
        return existing_target_files
    if not getattr(args, "mr_comment_scope_changed_files", True):
        return existing_target_files

    from . import comment

    fetched = comment.fetch_changed_files(ctx)
    if not fetched:
        logger.warning(
            "MR-comment mode: could not fetch changed files from %s; "
            "falling back to scanning --directory %s in full.",
            ctx.platform,
            args.directory,
        )
        return existing_target_files

    # Keep only YAML files - the scanner only looks at those anyway
    # and most MRs touch many non-YAML files (docs, tests, etc.) we
    # don't care about. Case-insensitive suffix check so ``.YML``
    # files from Windows editors still match.
    yaml_files = [f for f in fetched if f.lower().endswith((".yml", ".yaml"))]
    if not yaml_files:
        logger.info(
            "MR-comment mode: no YAML files changed in this %s; nothing to scan.",
            ctx.platform,
        )
        # Return an empty list (not None) so the scanner skips the
        # whole tree rather than treating "no files" as "scan all".
        return []
    logger.info(
        "MR-comment mode: scoping scan to %d changed YAML file(s) from %s.",
        len(yaml_files),
        ctx.platform,
    )
    return yaml_files


def _resolve_run_policy(args) -> tuple[list[str], list[str], dict[str, str]]:
    """Resolve ``--select`` / ``--ignore`` globs to concrete sorted
    rule-id lists and build a ``{rule_id: category}`` map for the
    transparency renderer.

    Returns ``([selected], [ignored], categories)``. Both lists are
    empty (and ``categories`` is empty) when neither flag is set.
    Glob errors are swallowed - typos already crashed the scan in
    ``main`` via the resolver call there; the swallow here is
    defence-in-depth so a comment-rendering glitch never aborts a
    post that would otherwise succeed.
    """
    select_spec = getattr(args, "select", None)
    ignore_spec = getattr(args, "ignore", None)
    if not select_spec and not ignore_spec:
        return [], [], {}

    universe = known_rule_ids()
    try:
        selected = sorted(resolve_rule_specs([select_spec], universe)) if select_spec else []
        ignored = sorted(resolve_rule_specs([ignore_spec], universe)) if ignore_spec else []
    except RuleSelectionError:
        return [], [], {}
    return selected, ignored, known_rule_categories()


def _post_mr_comment(args, ctx, report, scanner) -> None:
    """Post-scan hook: render the concise MR comment, write the
    full-report artifact, then POST/PATCH the comment. Warn-and-
    continue on every error so the scanner's exit code stays driven
    by findings alone.

    The full-report artifact is ALWAYS written (even on zero findings)
    so CI artifact-upload globs don't need to special-case missing
    files, and so the resolved-state comment can still link to proof
    that the scan ran.
    """
    if ctx is None:
        return

    from . import comment

    selected_rule_ids, ignored_rule_ids, category_for_rule = _resolve_run_policy(args)

    # Always write the full Markdown report alongside the comment so
    # reviewers can click through from the dashboard. We use the
    # Markdown formatter unconditionally here regardless of the
    # user's ``--format`` choice - the comment links to Markdown
    # because that's what renders natively on GitHub/GitLab.
    try:
        md_formatter_cls = get_formatter_class("markdown")
        md_formatter = md_formatter_cls(show_all=True)
        rendered_full_report = md_formatter.format(report)
    except Exception as exc:
        logger.warning(
            "MR-comment mode: failed to render full Markdown report: %s. "
            "Posting a comment without a full-report link.",
            exc,
        )
        rendered_full_report = ""

    full_report_path: Path | None = None
    if rendered_full_report:
        try:
            target = Path(args.mr_comment_full_report) if args.mr_comment_full_report else None
            full_report_path = comment.write_full_report_artifact(rendered_full_report, path=target)
        except OSError as exc:
            logger.warning(
                "MR-comment mode: failed to write full-report artifact: %s. "
                "Comment will still post without a report link.",
                exc,
            )
            full_report_path = None

    full_report_link: str | None = None
    if full_report_path is not None:
        # Comment renders in the web UI; absolute CI-runner paths leak the
        # runner's filesystem and break for reviewers. Prefer a relative
        # link, fall back to the basename for out-of-workspace artifacts.
        try:
            full_report_link = str(full_report_path.resolve().relative_to(Path.cwd().resolve()))
        except ValueError:
            full_report_link = full_report_path.name
            logger.info(
                "MR-comment mode: full-report artifact %s is outside the "
                "workspace; linking by basename %r.",
                full_report_path,
                full_report_link,
            )

    body = comment.render_comment_body(
        report.findings,
        ctx,
        security_score=getattr(report.security_score, "overall_score", None),
        full_report_link=full_report_link,
        previous=comment.fetch_existing_marker(ctx),
        scan_root=Path(scanner.directory) if getattr(scanner, "directory", None) else None,
        inline_mode=getattr(args, "inline_comments", False),
        ignored_rule_ids=ignored_rule_ids,
        selected_rule_ids=selected_rule_ids,
        category_for_rule=category_for_rule,
    )
    result = comment.post_or_update_comment(ctx, body)

    if result.error:
        logger.warning(
            "MR-comment mode: %s comment post failed (%s). Scanner exit code is unaffected.",
            ctx.platform,
            result.error,
        )
        return

    action = "updated" if result.updated else "posted"
    link_hint = f" ({result.comment_url})" if result.comment_url else ""
    if result.previous_findings_count is not None and not report.findings:
        logger.info(
            "MR-comment: %s resolved-state comment on %s%s (previous scan had %d finding(s)).",
            action,
            ctx.platform,
            link_hint,
            result.previous_findings_count,
        )
    else:
        logger.info(
            "MR-comment: %s comment on %s%s (findings=%d, bytes=%d).",
            action,
            ctx.platform,
            link_hint,
            result.findings_count,
            result.bytes_written,
        )

    if getattr(args, "inline_comments", False):
        _post_inline_comments(args, ctx, report, scanner, ignored_rule_ids, selected_rule_ids)


def _post_inline_comments(args, ctx, report, scanner, ignored_rule_ids, selected_rule_ids) -> None:
    """Post per-finding inline review comments alongside the summary."""
    from . import comment

    changed = comment.fetch_changed_files(ctx) or []
    scan_root = Path(scanner.directory) if getattr(scanner, "directory", None) else None
    inline_result = comment.post_inline_comments(
        report.findings,
        ctx,
        changed_files=set(changed) or None,
        scan_root=scan_root,
        ignored_rule_ids=ignored_rule_ids,
        selected_rule_ids=selected_rule_ids,
    )
    if inline_result.error:
        logger.warning(
            "Inline comments: %s post failed (%s). Scanner exit code is unaffected.",
            ctx.platform,
            inline_result.error,
        )


def main():
    """Main entry point"""
    # Parse once to detect whether the user explicitly passed --output (argparse
    # doesn't expose "was this flag set?", so we inspect the first pass's None
    # default before re-parsing with defaults applied).
    parser = create_argument_parser()
    args, unknown = parser.parse_known_args()
    output_specified = args.output is not None
    # ``--format`` now defaults to ``None`` (see
    # ``create_argument_parser``) so we can tell explicit from implicit
    # choices and let ``--output`` infer the format by extension when
    # no explicit ``--format`` is present.
    explicit_format = args.format
    args = parser.parse_args()

    # Configure logging FIRST so the inference diagnostics below
    # honour ``--verbose`` (INFO messages are otherwise silent).
    setup_logging(args.verbose)

    # ``--list-rules`` / ``--list-rules-detailed`` short-circuit
    # everything else: print the universe and exit cleanly.
    # Pipe-friendly (sorted, one rule_id per line on stdout, TSV when
    # detailed); diagnostics go to stderr so ``| grep`` stays clean.
    if args.list_rules or args.list_rules_detailed:
        ids = sorted(known_rule_ids())
        header = f"# {len(ids)} rule_ids known to ansible-security-scanner"
        if args.list_rules_detailed:
            meta = known_rule_metadata()
            print(f"{header} (rule_id<TAB>severity<TAB>category<TAB>title)", file=sys.stderr)
            for rid in ids:
                row = meta.get(rid, _SYNTHETIC_LISTING_ROW)
                print(f"{rid}\t{row['severity']}\t{row['category']}\t{row['title']}")
        else:
            print(header, file=sys.stderr)
            for rid in ids:
                print(rid)
        sys.exit(0)

    # Resolve the effective output format. Precedence:
    #   1. Explicit ``--format`` wins unconditionally.
    #   2. Otherwise, infer from the ``--output`` file extension.
    #   3. Fall back to ``markdown`` (historical default).
    # If ``--format`` is explicit AND ``--output`` implies a
    # different format, warn and honour the explicit choice - users
    # overwhelmingly write ``--output report.json --format sarif``
    # intending the SARIF content; silently renaming would hide
    # pipeline bugs.
    inferred_format = _infer_format_from_output_path(args.output) if output_specified else None
    if explicit_format is not None:
        effective_format = explicit_format
        if inferred_format is not None and inferred_format != explicit_format:
            logger.warning(
                "--output %s suggests --format %s but --format %s was "
                "specified explicitly; honouring the explicit format. "
                "Either rename the output file to match --format or "
                "remove --format to accept the inferred value.",
                args.output,
                inferred_format,
                explicit_format,
            )
    elif inferred_format is not None:
        effective_format = inferred_format
        logger.info(
            "Inferred --format %s from --output %s",
            inferred_format,
            args.output,
        )
    else:
        effective_format = "markdown"
        if output_specified:
            # User wrote ``--output foo.unknownext`` with no
            # ``--format``; warn so they know Markdown content is
            # about to land in a file with the wrong suffix.
            logger.warning(
                "--output %s has no recognised extension; defaulting to "
                "--format markdown. Known extensions: %s",
                args.output,
                ", ".join(sorted(set(_OUTPUT_EXTENSION_TO_FORMAT))),
            )
    args.format = effective_format

    # Safety check: refuse to overwrite a file that's in the set of
    # inputs being scanned. The ``--output foo.yml`` idiom is common
    # and ``.yml`` is a valid report format extension (YAML), so
    # without this guard an invocation like
    #   ``ansible-security-scanner --files site.yml --output site.yml``
    # would silently overwrite the playbook with a YAML-formatted
    # scan report. Compare on resolved absolute paths so relative /
    # absolute / ``./foo`` forms all collide correctly.
    if output_specified and args.output:
        output_resolved = Path(args.output).resolve()
        collision_sources: list[str] = []
        if args.files:
            collision_sources.extend(args.files)
        for src in collision_sources:
            try:
                if Path(src).resolve() == output_resolved:
                    logger.error(
                        "--output %s resolves to the same path as an input "
                        "file. Refusing to overwrite a scanned file with a "
                        "scan report. Pick a different --output path.",
                        args.output,
                    )
                    sys.exit(2)
            except OSError:
                continue

    # ``--output-per-file`` preconditions: require the format to be
    # non-aggregate, and require the output path to be a directory
    # (or not exist yet - we'll create it). Failing these early avoids
    # running a full scan only to fail on write.
    #
    # Smart default: when the user passes ``--output-per-file`` without
    # ``--output``, we write to ``./security-reports/``. This is the
    # single most common invocation ("give me one report per file")
    # and requiring --output for it felt boilerplatey. The directory
    # name is intentionally self-documenting so an engineer looking
    # at the repo later doesn't wonder "what are these files?".
    if args.output_per_file:
        if args.format in _AGGREGATE_ONLY_FORMATS:
            logger.error(
                "--output-per-file is not supported for --format %s; that "
                "format describes the scan as a whole. Drop --output-per-file "
                "or switch to a per-finding format (markdown, json, sarif, ...).",
                args.format,
            )
            sys.exit(2)
        if not args.output:
            args.output = _DEFAULT_OUTPUT_PER_FILE_DIR
            logger.info(
                "--output-per-file with no --output; defaulting to %s/ (pass --output to override)",
                _DEFAULT_OUTPUT_PER_FILE_DIR,
            )
        output_as_path = Path(args.output)
        if output_as_path.exists() and not output_as_path.is_dir():
            logger.error(
                "--output-per-file expects --output %s to be a directory, "
                "but a file already exists at that path. Delete the file "
                "or pick a different --output path.",
                args.output,
            )
            sys.exit(2)

    target_files = handle_target_files(args)

    # Resolve the MR/PR context up front (if any) so we can scope the
    # scan to just the changed files. ``_resolve_mr_context`` is
    # cheap (env-var reads only) and logs its own warnings, so we
    # call it unconditionally on behalf of all downstream hooks.
    mr_ctx = _resolve_mr_context(args)
    scoped_target_files = _maybe_scope_to_changed_files(args, mr_ctx, target_files)

    # Distinguish "platform reported zero changed YAML files" (empty
    # list) from "no MR scoping applied" (None / non-empty list). The
    # former must short-circuit to the resolved-state comment path
    # without calling the scanner at all - otherwise the scanner's
    # ``target_files=[]`` would fall through and scan the whole
    # directory, posting spurious findings on an MR that didn't
    # touch any YAML.
    mr_scoped_to_empty = (
        mr_ctx is not None
        and isinstance(scoped_target_files, list)
        and len(scoped_target_files) == 0
    )
    target_files = scoped_target_files if not mr_scoped_to_empty else None

    try:
        scanner = AnsibleSecurityScanner(
            args.directory,
            target_files,
            args.allowlist,
            show_suppressed=args.show_suppressed,
            disable_suppressions=args.no_suppressions,
            fail_on_suppressed=args.fail_on_suppressed,
            max_suppressions=args.max_suppressions,
            fix_mode=args.fix,
            scan_git_history=args.scan_git_history,
            git_history_max_commits=args.git_history_max_commits,
            jobs=args.jobs,
            dedup_cross_file=args.dedup_across_files,
            select_rules=[args.select] if args.select else None,
            ignore_rules=[args.ignore] if args.ignore else None,
        )
    except RuleSelectionError as exc:
        logger.error("%s", exc)
        sys.exit(2)

    if args.ignore:
        _, ignored_preview, _ = _resolve_run_policy(args)
        unignorable = sorted(set(ignored_preview) & _ALWAYS_EMITTED_RULE_IDS)
        if unignorable:
            logger.warning(
                "--ignore listed always-emitted rule(s) %s; these still fire "
                "(they detect scan failures and audit-evasion attempts).",
                ", ".join(unignorable),
            )

    # MR touched no YAML - produce an empty report so the downstream pipeline
    # (formatter -> write -> MR comment) still runs and the user gets a
    # resolved-state comment rather than a confusing "scan found lots of
    # findings because we fell back to the whole tree" outcome.
    report = scanner._create_empty_report() if mr_scoped_to_empty else scanner.scan_directory()

    # Stamp the resolved CLI rule policy onto the report so every formatter
    # can disclose ``--select`` / ``--ignore`` narrowing uniformly.
    selected_rule_ids, ignored_rule_ids, _ = _resolve_run_policy(args)
    if selected_rule_ids or ignored_rule_ids:
        report = replace(
            report,
            selected_rule_ids=selected_rule_ids,
            ignored_rule_ids=ignored_rule_ids,
        )

    # --compliance: filter to findings whose cis_controls overlap with the
    # requested set. `--compliance list` prints every tag present so users
    # can discover what's available for their scan's rule set.
    if args.compliance:
        if args.compliance.lower() == "list":
            all_tags = sorted({tag for f in report.findings for tag in f.cis_controls})
            print("Compliance tags present in this scan:", file=sys.stderr)
            for tag in all_tags:
                print(f"  {tag}", file=sys.stderr)
            sys.exit(0)
        wanted = {t.strip().lower() for t in args.compliance.split(",") if t.strip()}
        kept = [f for f in report.findings if {t.lower() for t in f.cis_controls} & wanted]
        dropped = len(report.findings) - len(kept)
        report.findings = kept
        # Rebuild summary so counts reflect the filtered set.
        report.summary = scanner._generate_summary(kept)
        logger.info(
            "--compliance %s: kept %d finding(s), dropped %d non-matching",
            args.compliance,
            len(kept),
            dropped,
        )

    # --severity LEVEL: post-filter to findings at or above the requested
    # severity. Same pattern as --compliance: filter the report after the
    # scan completes (so suppression, dedup, etc. all run against the full
    # finding set), then rebuild the summary so the report's totals
    # reflect what's actually shown. Exit-code logic is untouched - the
    # exit-code stage gates on raw HIGH/CRITICAL counts from the
    # post-filter findings, which is the right semantics: if a user asks
    # to ONLY see HIGH+, they still want a non-zero exit when HIGH+
    # findings exist, but a clean exit otherwise.
    if args.severity:
        floor = _SEVERITY_RANK[args.severity]
        kept_sev = [
            f for f in report.findings if _SEVERITY_RANK.get((f.severity or "").upper(), 0) >= floor
        ]
        dropped_sev = len(report.findings) - len(kept_sev)
        report.findings = kept_sev
        report.summary = scanner._generate_summary(kept_sev)
        logger.info(
            "--severity %s: kept %d finding(s), dropped %d below floor",
            args.severity,
            len(kept_sev),
            dropped_sev,
        )

    # --fix: write (or print) the concatenated unified-diff patch before
    # the main report output. This keeps the normal stdout pipeline
    # reserved for the human/CI-consumable report and puts the patch in
    # a separate stream/file.
    if args.fix:
        patch_blocks = [f.fix_patch for f in report.findings if f.fix_patch]
        patch_blob = "\n".join(patch_blocks)
        if args.fix_output:
            with open(args.fix_output, "w", encoding="utf-8") as fh:
                fh.write(patch_blob)
            logger.info("--fix: wrote %d patch hunk(s) to %s", len(patch_blocks), args.fix_output)
        else:
            if patch_blob:
                print(patch_blob, file=sys.stderr)
            logger.info(
                "--fix: proposed %d patch hunk(s) (dry-run - no files modified)",
                len(patch_blocks),
            )

    # Generate output using the appropriate formatter. In per-file
    # mode we hand the aggregate report to ``write_per_file_outputs``
    # which rebuilds and renders one ``ScanReport`` per scanned file;
    # in normal mode we render the aggregate once and write it.
    try:
        formatter_class = get_formatter_class(args.format)
        if args.output_per_file:
            write_per_file_outputs(
                report,
                scanner,
                formatter_class,
                args.output,
                args.format,
                target_files,
            )
        else:
            formatter = formatter_class(show_all=True)
            write_output(
                formatter.format(report),
                args.output if output_specified else None,
                args.format,
            )
    except Exception as e:
        logger.error("Error generating %s output: %s", args.format, e)
        sys.exit(1)

    # Post-scan MR/PR comment hook. Runs after the main report is
    # written so a comment-API hiccup never blocks the on-disk
    # artefact pipeline. ``_post_mr_comment`` is a no-op when no MR
    # flags are set or when ``_resolve_mr_context`` returned None.
    _post_mr_comment(args, mr_ctx, report, scanner)

    # Log summary information
    logger.info(
        "Security Score: %d/100 (%s)%s",
        report.security_score.overall_score,
        scanner.score_calculator.get_security_status(report.security_score.overall_score),
        " (active policy)" if report.selected_rule_ids or report.ignored_rule_ids else "",
    )
    logger.info(
        "Total Issues: %d (Critical: %d, High: %d)",
        report.summary["total_findings"],
        report.summary["critical"],
        report.summary["high"],
    )
    if report.selected_rule_ids:
        head = f"Scan limited to {len(report.selected_rule_ids)} rule(s) via --select"
        if report.ignored_rule_ids:
            head += f" (and {len(report.ignored_rule_ids)} further suppressed via --ignore)"
        logger.info("%s", head)
    elif report.ignored_rule_ids:
        logger.info(
            "%d rule(s) suppressed via --ignore",
            len(report.ignored_rule_ids),
        )
    if report.suppressed_count:
        logger.info(
            "Suppressed Findings: %d (use --show-suppressed to view%s)",
            report.suppressed_count,
            ", --no-suppressions to disable" if not args.no_suppressions else "",
        )
    if report.suppression_warnings:
        logger.warning("Invalid suppression directives: %d", len(report.suppression_warnings))
        for w in report.suppression_warnings[:20]:
            logger.warning("  %s", w)

    # Exit with appropriate code based on findings (unless --exit-zero).
    # The suppression gate takes precedence over severity-based exit codes
    # when it fires - a release gate that says "no suppressions allowed"
    # must fail regardless of how clean the findings look.
    exit_code = get_exit_code(report, args.exit_zero)
    if report.suppressed_gate_failed and not args.exit_zero:
        if exit_code == 0:
            exit_code = 2
        logger.error(
            "Suppression gate failed: %d finding(s) suppressed "
            "(fail_on_suppressed=%s, max_suppressions=%s)",
            report.suppressed_count,
            args.fail_on_suppressed,
            args.max_suppressions,
        )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
