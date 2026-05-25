#!/usr/bin/env python3
"""Enforce a blank line before every rule entry in pattern YAML files.

Idempotent: running on a clean tree is a no-op (exit 0); running on a file
it had to fix exits 1 so pre-commit re-stages the change.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PATTERNS = ROOT / "src" / "ansible_security_scanner" / "patterns"


def _fix_lines(lines: list[str]) -> list[str]:
    out: list[str] = []
    for line in lines:
        if line.startswith("  - id:") and out:
            prev = out[-1].rstrip("\n")
            stripped = prev.lstrip()
            is_blank = prev.strip() == ""
            is_comment = stripped.startswith("#")
            is_patterns_header = prev.rstrip() == "patterns:"
            if not (is_blank or is_comment or is_patterns_header):
                out.append("\n")
        out.append(line)
    return out


def main() -> int:
    changed = 0
    for yml in sorted(PATTERNS.glob("*.yml")):
        original = yml.read_text()
        lines = original.splitlines(keepends=True)
        fixed = _fix_lines(lines)
        new_text = "".join(fixed)
        if new_text != original:
            yml.write_text(new_text)
            changed += 1
            print(f"fixed: {yml.relative_to(ROOT)}", file=sys.stderr)
    return 1 if changed else 0


if __name__ == "__main__":
    sys.exit(main())
