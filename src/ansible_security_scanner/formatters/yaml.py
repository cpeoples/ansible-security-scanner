#!/usr/bin/env python3
"""
YAML output formatter for Ansible Security Scanner
"""

from dataclasses import asdict

import yaml

from ..models import ScanReport
from .base import OutputFormatter


class YAMLFormatter(OutputFormatter):
    """Formats report as YAML"""

    def format(self, report: ScanReport) -> str:
        return yaml.dump(asdict(report), indent=2)
