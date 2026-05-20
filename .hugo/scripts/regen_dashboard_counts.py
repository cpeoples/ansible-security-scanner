#!/usr/bin/env python3
"""Regenerate the numeric cells of `.hugo/content/dashboard.md`.

Preserves the existing category rows (names, slugs, order, URLs, markdown
structure) - only the numeric cells and the top Scanner Overview block are
rewritten. Run by the `dashboard-counts` pre-commit hook on every commit that
touches `dashboard.md` or any pattern YAML.

Exits non-zero if the file changes (pre-commit uses this to re-stage).
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
PATTERNS = ROOT / "src" / "ansible_security_scanner" / "patterns"
DASHBOARD = ROOT / ".hugo" / "content" / "dashboard.md"

_ROW_RE = re.compile(
    r"(?P<prefix>\|\s*\[[^\]]+\]\(/patterns/(?P<slug>[a-z0-9_]+)/\)\s*)"
    r"\|\s*\d+\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*\d+\s*\|"
)


def main() -> int:
    patterns: list[dict] = []
    for yml in sorted(PATTERNS.glob("*.yml")):
        data = yaml.safe_load(yml.read_text()) or {}
        patterns.extend(data.get("patterns") or [])

    total = len(patterns)
    categories = {p["category"] for p in patterns if p.get("category")}
    severity_total: Counter[str] = Counter((p.get("severity") or "").upper() for p in patterns)
    by_category: dict[str, Counter[str]] = {}
    for p in patterns:
        cat = p.get("category")
        if not cat:
            continue
        by_category.setdefault(cat, Counter())[(p.get("severity") or "").upper()] += 1

    if not DASHBOARD.exists():
        # Generated artifact: only present after the docs build has run.
        # In CI / fresh checkouts the file isn't on disk yet, so there's
        # nothing for this hook to keep in sync. Re-run after `task.py docs`.
        return 0

    original = DASHBOARD.read_text()
    text = original

    text = re.sub(
        r"(\|\s*Total Rules\s*\|\s*\*\*)\d+(\*\*\s*\|)",
        rf"\g<1>{total}\g<2>",
        text,
    )
    text = re.sub(
        r"(\|\s*Pattern Categories\s*\|\s*\*\*)\d+(\*\*\s*\|)",
        rf"\g<1>{len(categories)}\g<2>",
        text,
    )
    for label in ("critical", "high", "medium", "low"):
        text = re.sub(
            rf'(<span class="severity-{label}">{label.upper()}</span> Rules \|\s*)\d+(\s*\|)',
            lambda m, v=severity_total.get(label.upper(), 0): f"{m.group(1)}{v}{m.group(2)}",
            text,
        )

    def _row(match: re.Match) -> str:
        slug = match.group("slug")
        counts = by_category.get(slug)
        if not counts:
            return match.group(0)
        total_c = sum(counts.values())
        return (
            f"{match.group('prefix')}| {total_c} | "
            f"{counts.get('CRITICAL', 0)} | {counts.get('HIGH', 0)} | "
            f"{counts.get('MEDIUM', 0)} | {counts.get('LOW', 0)} |"
        )

    text = _ROW_RE.sub(_row, text)

    if text == original:
        return 0
    DASHBOARD.write_text(text)
    return 1


if __name__ == "__main__":
    sys.exit(main())
