#!/usr/bin/env python3
"""
Security score calculation for Ansible Security Scanner
"""

from collections import Counter
from dataclasses import dataclass

from .models import SecurityFinding, SecurityScore
from .patterns_manager import patterns_manager

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


@dataclass(frozen=True)
class _ScoreWeights:
    """Severity penalties and the volume-density rule applied per scope.

    Volume penalty: ``(total - threshold) * step``, only when ``total > threshold``.
    """

    critical: float
    high: float
    medium: float
    low: float
    volume_threshold: int = 0
    volume_step: float = 0.0

    def deduct(self, counts: Counter[str], total: int) -> float:
        score = 100.0
        score -= counts["CRITICAL"] * self.critical
        score -= counts["HIGH"] * self.high
        score -= counts["MEDIUM"] * self.medium
        score -= counts["LOW"] * self.low
        if total > self.volume_threshold:
            score -= (total - self.volume_threshold) * self.volume_step
        return max(0.0, score)


_OVERALL = _ScoreWeights(critical=15, high=8, medium=3, low=1)
_PER_CATEGORY = _ScoreWeights(
    critical=20, high=12, medium=5, low=2, volume_threshold=2, volume_step=3
)
_PER_FILE = _ScoreWeights(
    critical=18, high=10, medium=4, low=1.5, volume_threshold=3, volume_step=2
)


# Score -> label thresholds, in descending order. ``status`` is consulted
# for the "how secure?" framing, ``risk`` for the "how exposed?" framing.
_STATUS_LABELS = (
    (90, "Excellent"),
    (75, "Good"),
    (60, "Fair"),
    (40, "Poor"),
    (20, "Critical"),
    (0, "Severe"),
)
_RISK_LABELS = (
    (80, "Severe"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Minimal"),
)


def _count_severities(findings: list[SecurityFinding]) -> Counter[str]:
    counts: Counter[str] = Counter(dict.fromkeys(_SEVERITIES, 0))
    counts.update(f.severity for f in findings if f.severity in _SEVERITIES)
    return counts


def _bucket(findings: list[SecurityFinding], key) -> dict[str, list[SecurityFinding]]:
    buckets: dict[str, list[SecurityFinding]] = {}
    for f in findings:
        k = key(f)
        if k is None:
            continue
        buckets.setdefault(k, []).append(f)
    return buckets


class ScoreCalculator:
    """Calculates security scores from finding counts and severities."""

    def calculate_security_score(
        self, findings: list[SecurityFinding], scanned_files: int
    ) -> SecurityScore:
        severity_counts = _count_severities(findings)
        total_issues = len(findings)

        if total_issues == 0:
            base_score = 100.0
        else:
            base_score = _OVERALL.deduct(severity_counts, total_issues)
            # Extra penalty for multiple CRITICALs so one-vs-many is visible
            # in the score rather than saturating at the base deduction.
            extra_critical = max(0, severity_counts["CRITICAL"] - 1)
            base_score -= extra_critical * 5
            # File coverage: how widespread are issues across the scanned tree?
            if scanned_files > 0:
                files_with_issues = len({f.file_path for f in findings})
                base_score -= (files_with_issues / scanned_files) * 10
            # Density: extra penalty when the repo accumulates many findings.
            if total_issues > 5:
                base_score -= min(15, (total_issues - 5) * 1.5)
            base_score = max(0.0, base_score)

        return SecurityScore(
            overall_score=round(base_score),
            risk_score=round(100 - base_score),
            category_scores=self._calculate_category_scores(findings),
            severity_breakdown=dict(severity_counts),
            file_scores=self._calculate_file_scores(findings),
            recommendations_count=len({f.recommendation for f in findings}),
        )

    def _calculate_category_scores(self, findings: list[SecurityFinding]) -> dict[str, float]:
        pattern_data = patterns_manager.discover_and_load_patterns()
        rule_to_category = {
            pattern.id: category
            for category, patterns in pattern_data.items()
            for pattern in patterns
        }

        scores: dict[str, float] = dict.fromkeys(pattern_data, 100.0)
        bucketed = _bucket(findings, lambda f: rule_to_category.get(f.rule_id))
        for category, group in bucketed.items():
            counts = _count_severities(group)
            scores[category] = round(_PER_CATEGORY.deduct(counts, len(group)))
        return scores

    def _calculate_file_scores(self, findings: list[SecurityFinding]) -> dict[str, float]:
        scores: dict[str, float] = {}
        for file_path, group in _bucket(findings, lambda f: f.file_path).items():
            counts = _count_severities(group)
            scores[file_path] = round(_PER_FILE.deduct(counts, len(group)))
        return scores

    @staticmethod
    def _label_for(score: float, table: tuple[tuple[int, str], ...]) -> str:
        for threshold, label in table:
            if score >= threshold:
                return label
        return table[-1][1]

    def get_security_status(self, score: float) -> str:
        return self._label_for(score, _STATUS_LABELS)

    def get_risk_level(self, risk_score: float) -> str:
        return self._label_for(risk_score, _RISK_LABELS)
