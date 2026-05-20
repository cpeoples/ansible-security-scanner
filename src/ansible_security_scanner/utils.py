#!/usr/bin/env python3
"""
Utility functions for Ansible Security Scanner
"""

import logging
from pathlib import Path

from .formatters import (
    CSVFormatter,
    CycloneDXFormatter,
    GitLabSastFormatter,
    HTMLFormatter,
    JSONFormatter,
    JUnitFormatter,
    MarkdownFormatter,
    SARIFFormatter,
    XMLFormatter,
    YAMLFormatter,
)

logger = logging.getLogger(__name__)


_SUPPORTED_SUFFIXES = (".yml", ".yaml", ".j2", ".cfg")


def parse_changed_files(changed_files_str: str) -> list[str]:
    """Parse a CHANGED_FILES env-var or file-list string into scannable paths.

    Accepts any of newline / space / comma separators so the same input
    works for ``git diff --name-only`` (newlines), CI variables that
    space-join paths, and hand-written comma lists. Filters down to the
    file types this scanner actually understands (``.yml``, ``.yaml``,
    ``.j2``, ``.cfg``) so a diff containing source/markdown files is
    silently passed through untouched.
    """
    if not changed_files_str:
        return []

    files: list[str] = []

    for delimiter in ["\n", " ", ","]:
        if delimiter in changed_files_str:
            files = [f.strip() for f in changed_files_str.split(delimiter)]
            break
    else:
        files = [changed_files_str.strip()]

    scannable = [f for f in files if f and f.endswith(_SUPPORTED_SUFFIXES)]

    logger.info("Parsed %d scannable files from changed files: %s", len(scannable), scannable)
    return scannable


def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")


def get_formatter_class(format_name: str):
    """Get the appropriate formatter class for the given format"""
    formatters = {
        "markdown": MarkdownFormatter,
        "json": JSONFormatter,
        "xml": XMLFormatter,
        "yaml": YAMLFormatter,
        "csv": CSVFormatter,
        "html": HTMLFormatter,
        "junit": JUnitFormatter,
        "sarif": SARIFFormatter,
        "gl-sast": GitLabSastFormatter,
        "gitlab-sast": GitLabSastFormatter,
        "cyclonedx": CycloneDXFormatter,
        "sbom": CycloneDXFormatter,
    }

    formatter_class = formatters.get(format_name.lower())
    if formatter_class is None:
        raise ValueError(f"Unsupported format: {format_name}")
    return formatter_class


def validate_target_files(target_files: list[str], repo_root: str) -> list[str]:
    """Resolve target files against ``repo_root`` and keep the ones that
    exist with a scannable suffix (``.yml``/``.yaml``/``.j2``/``.cfg``).
    """
    repo_path = Path(repo_root)
    valid_files: list[str] = []

    for target in target_files:
        file_path = Path(target)
        if not file_path.exists():
            file_path = repo_path / target

        if file_path.exists() and file_path.suffix in _SUPPORTED_SUFFIXES:
            valid_files.append(str(file_path))
        else:
            logger.warning("Skipping invalid file: %s", target)

    return valid_files


def get_exit_code(report, exit_zero: bool = False) -> int:
    """Determine the appropriate exit code based on findings"""
    if exit_zero:
        return 0
    if report.summary["critical"] > 0:
        return 2
    if report.summary["high"] > 0:
        return 1
    return 0
