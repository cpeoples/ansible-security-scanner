#!/usr/bin/env python3
"""Regenerate the rule, category, and severity counts in ``README.md``.

Replaces the existing ``readme-rule-counts`` pre-commit one-liner. Run by
the ``readme-rule-counts`` pre-commit hook on every commit that touches
``README.md`` or any pattern YAML.

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
README = ROOT / "README.md"


def main() -> int:
    patterns: list[dict] = []
    for yml in sorted(PATTERNS.glob("*.yml")):
        data = yaml.safe_load(yml.read_text()) or {}
        patterns.extend(data.get("patterns") or [])

    rules = len(patterns)
    cats = len({p["category"] for p in patterns if p.get("category")})
    sev = Counter((p.get("severity") or "").upper() for p in patterns)

    original = README.read_text()
    text = original

    text = re.sub(r"<!--RULES-->\d+<!--/RULES-->", f"<!--RULES-->{rules}<!--/RULES-->", text)
    text = re.sub(r"<!--CATS-->\d+<!--/CATS-->", f"<!--CATS-->{cats}<!--/CATS-->", text)
    text = re.sub(
        r"(#security-checks-)\d+(-categories-)\d+(-rules)",
        rf"\g<1>{cats}\g<2>{rules}\g<3>",
        text,
    )
    text = re.sub(r"(img\.shields\.io/badge/Rules-)\d+(-)", rf"\g<1>{rules}\g<2>", text)

    for tag, label in (("CRIT", "CRITICAL"), ("HIGH", "HIGH"), ("MED", "MEDIUM"), ("LOW", "LOW")):
        text = re.sub(
            rf"<!--{tag}-->\d+<!--/{tag}-->",
            f"<!--{tag}-->{sev.get(label, 0)}<!--/{tag}-->",
            text,
        )

    if text == original:
        return 0
    README.write_text(text)
    return 1


if __name__ == "__main__":
    sys.exit(main())
