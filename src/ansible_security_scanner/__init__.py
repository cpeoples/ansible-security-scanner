"""Ansible Security Scanner - public package surface.

Import everything the user is expected to reach directly from the top level
(formatters, the scanner, the data models). Nothing in this module should
do real work at import time - no side-effecting CLI calls, no heavy
computation. Just wire up names.
"""

try:
    from ._version import __version__
except ImportError:
    __version__ = "0.0.0.dev0"

__author__ = "Chris Peoples"
__description__ = "Ansible Security Scanner"

from .cli import main
from .dependency_collector import DependencyCollector
from .file_scanner import FileScanner
from .fix_proposer import FixProposer
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
from .models import ScanReport, SecurityFinding, SecurityScore
from .patterns_manager import patterns_manager
from .remediations import RemediationGenerator
from .scanner import AnsibleSecurityScanner
from .score_calculator import ScoreCalculator
from .taint_tracker import TaintTracker
from .utils import get_exit_code, get_formatter_class, parse_changed_files, setup_logging
from .variable_extractor import VariableExtractor

__all__ = [
    "AnsibleSecurityScanner",
    "SecurityFinding",
    "SecurityScore",
    "ScanReport",
    "patterns_manager",
    "FileScanner",
    "TaintTracker",
    "FixProposer",
    "DependencyCollector",
    "ScoreCalculator",
    "VariableExtractor",
    "RemediationGenerator",
    "MarkdownFormatter",
    "JSONFormatter",
    "XMLFormatter",
    "YAMLFormatter",
    "CSVFormatter",
    "HTMLFormatter",
    "JUnitFormatter",
    "SARIFFormatter",
    "GitLabSastFormatter",
    "CycloneDXFormatter",
    "parse_changed_files",
    "setup_logging",
    "get_formatter_class",
    "get_exit_code",
    "main",
    "__version__",
]
