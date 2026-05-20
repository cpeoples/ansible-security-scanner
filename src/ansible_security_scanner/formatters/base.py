#!/usr/bin/env python3
"""
Base output formatter for Ansible Security Scanner
"""

import re

from ..models import ScanReport
from ..score_calculator import ScoreCalculator


class ReportEmojis:
    """Centralized emoji constants for consistent formatting across all report types"""

    # Main icons
    SECURITY = "🔒"
    SUMMARY = "📊"
    CRITICAL = "🚨"
    WARNING = "⚠️"
    SUCCESS = "✅"
    ERROR = "❌"
    FIRE = "🔥"
    STOP = "🛑"

    # Severity levels
    CRITICAL_ISSUE = "🚨"
    HIGH_ISSUE = "🔴"
    MEDIUM_ISSUE = "🟠"
    LOW_ISSUE = "🟡"

    # Status indicators
    URGENT = "🚨"
    ATTENTION = "⚠️"
    CLEAN = "✅"
    NONE = "✅"

    # Risk levels
    VERY_HIGH = "🔥"
    HIGH = "🟠"
    MODERATE = "🟡"
    LOW = "✅"

    # Actions
    TOOLS = "🔧"
    IMPROVEMENTS = "🔧"
    SECURE = "🔐"
    SEARCH = "🔍"
    NOTES = "📝"
    PLAN = "📋"
    MONITOR = "📝"

    # File and content
    FILE = "📄"
    TAG = "🏷️"
    DETAILS = "📋"

    # Score status mapping
    SCORE_STATUS = {"Poor": "🔴", "Critical": "🚨", "Severe": "🛑"}

    # Severity mapping
    SEVERITY_MAP = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

    # Risk level mapping
    RISK_STATUS = {"High": "🔴", "Severe": "🚨"}

    # Additional commonly used emojis for formatters
    SHIELD = "🛡️"
    GLOBE = "🌐"
    LOCK = "🔒"
    KEY = "🔑"
    FOLDER = "📁"
    DOCUMENT = "📄"
    CHART = "📈"
    TARGET = "🎯"
    LIGHTBULB = "💡"
    WRENCH = "🔧"
    GEAR = "⚙️"
    COMPUTER = "💻"
    TROPHY = "🏆"
    ROCKET = "🚀"
    LIGHTNING = "⚡"
    PALETTE = "🎨"
    PACKAGE = "📦"

    @classmethod
    def get_severity_emoji(cls, severity: str) -> str:
        """Get emoji for a given severity level"""
        return cls.SEVERITY_MAP.get(severity.upper(), "❓")

    @classmethod
    def get_status_emoji(cls, status: str) -> str:
        """Get emoji for a given status"""
        return cls.SCORE_STATUS.get(status, "❓")

    @classmethod
    def strip_emojis(cls, text: str) -> str:
        """Remove all emojis from text for formats that don't support them"""
        if not text:
            return ""
        return re.sub(
            r"[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF\U00002600-\U000027BF\U0001F900-\U0001F9FF\U0001F018-\U0001F270\U0001F200-\U0001F23F\U0001F000-\U0001F02F\U0001F0A0-\U0001F0FF]+",
            "",
            text,
        )


class OutputFormatter:
    """Base class for output formatters"""

    def __init__(self, show_all: bool = False):
        self.show_all = show_all
        self.score_calculator = ScoreCalculator()

    def format(self, report: ScanReport) -> str:
        """Format the report - to be implemented by subclasses"""
        raise NotImplementedError
