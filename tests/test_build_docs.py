"""Tests for the Hugo doc builder's framework chip rendering."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def build_docs():
    """Load build_docs.py as a module via importlib (it lives outside
    the package's import path on purpose -- it's a standalone build
    tool)."""
    repo_root = Path(__file__).resolve().parents[1]
    script_path = repo_root / ".hugo" / "scripts" / "build_docs.py"
    spec = importlib.util.spec_from_file_location("build_docs", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_render_chips_empty_when_rule_has_no_metadata(build_docs):
    assert build_docs._render_framework_chips({"id": "noop_rule"}) == ""


def test_render_chips_emits_cve_chip_with_nvd_url(build_docs):
    out = build_docs._render_framework_chips({"id": "x", "cve": ["CVE-2024-3094"]})
    assert 'class="framework-chips"' in out
    assert "framework-chip-cve" in out
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2024-3094"' in out
    assert ">CVE-2024-3094</a>" in out
    assert 'target="_blank"' in out
    assert 'rel="noopener"' in out


def test_render_chips_synthesizes_uncatalogued_cve(build_docs):
    out = build_docs._render_framework_chips({"id": "x", "cve": ["CVE-1999-0001"]})
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-1999-0001"' in out


def test_render_chips_normalizes_lowercase_cve_input(build_docs):
    out = build_docs._render_framework_chips({"id": "x", "cve": ["cve-2024-3094"]})
    assert ">CVE-2024-3094</a>" in out


def test_render_chips_caps_overflow_with_summary(build_docs):
    cap = build_docs._MAX_CHIPS_PER_ROW
    overflow = 2
    cves = [f"CVE-2024-{1000 + i:04d}" for i in range(cap + overflow)]
    out = build_docs._render_framework_chips({"id": "x", "cve": cves})
    assert out.count("framework-chip framework-chip-cve") == cap
    assert 'class="framework-chip-more"' in out
    assert f">+{overflow} more</span>" in out


def test_render_chips_drops_unresolvable_silently(build_docs):
    out = build_docs._render_framework_chips({"id": "x", "cve": ["not-a-cve", "CVE-2024-3094"]})
    assert ">CVE-2024-3094</a>" in out
    assert "not-a-cve" not in out


def test_render_chips_renders_cwe_and_mitre_in_priority_order(build_docs):
    out = build_docs._render_framework_chips(
        {
            "id": "x",
            "cve": ["CVE-2024-3094"],
            "cwe": ["CWE-94"],
            "mitre_attack": ["T1059.004"],
        }
    )
    cve_idx = out.index("CVE-2024-3094")
    cwe_idx = out.index("CWE-94")
    mitre_idx = out.index("T1059.004")
    assert cve_idx < cwe_idx < mitre_idx
    assert "framework-chip-cwe" in out
    assert "framework-chip-mitre" in out
    assert 'href="https://cwe.mitre.org/data/definitions/94.html"' in out
    assert 'href="https://attack.mitre.org/techniques/T1059/004/"' in out


def test_render_chips_overflow_counts_across_frameworks(build_docs):
    """Chip cap is global across taxonomies, not per-taxonomy."""
    cap = build_docs._MAX_CHIPS_PER_ROW
    cves = [f"CVE-2024-{1000 + i:04d}" for i in range(cap)]
    cwes = ["CWE-78", "CWE-94"]
    mitres = ["T1059"]
    out = build_docs._render_framework_chips(
        {"id": "x", "cve": cves, "cwe": cwes, "mitre_attack": mitres}
    )
    visible = out.count('class="framework-chip ')
    assert visible == cap
    overflow = len(cves) + len(cwes) + len(mitres) - cap
    assert f">+{overflow} more</span>" in out


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Jinja2: |safe filter", r"Jinja2: \|safe filter"),
        ("a|b|c", r"a\|b\|c"),
        ("line one\nline two", "line one line two"),
        ("plain title", "plain title"),
        ("", ""),
    ],
)
def test_escape_table_cell(build_docs, raw, expected):
    assert build_docs._escape_table_cell(raw) == expected


def test_authored_pattern_rows_have_six_columns(build_docs):
    """Every shipped pattern, rendered through the same escape helper
    the build script uses, must produce exactly the five
    column-separators (six cells) of the rule table. This is the
    contract that broke when ``Jinja2: |safe filter ...`` shifted
    everything right of Title; it guards against any future title or
    description regrowing an unescaped ``|``.
    """
    bad: list[str] = []
    for yml in sorted(build_docs.PATTERNS_DIR.glob("*.yml")):
        for p in build_docs.load_patterns(yml).get("patterns", []) or []:
            title = build_docs._escape_table_cell(p.get("title", ""))
            desc = build_docs._escape_table_cell(p.get("description", ""))
            row = f"| rid | sev | {title} | {desc} | chips |"
            unescaped = sum(
                1 for i, c in enumerate(row) if c == "|" and (i == 0 or row[i - 1] != "\\")
            )
            if unescaped != 6:
                bad.append(f"  {yml.name}::{p.get('id', '?')} -> {unescaped} cells")
    assert not bad, "rows with the wrong column count:\n" + "\n".join(bad)


def test_strip_readme_badge_block_removes_marker_block(build_docs):
    """Marker-wrapped block is removed; surrounding prose is preserved."""
    src = (
        "# Title\n\n"
        "<!-- BADGES_START - drop me -->\n"
        "[![CI](https://example/ci.svg)](https://example/ci)\n"
        "[![PyPI](https://example/pypi.svg)](https://example/pypi)\n"
        "<!-- BADGES_END -->\n\n"
        "Body paragraph stays.\n"
    )
    out = build_docs._strip_readme_badge_block(src)
    assert "BADGES_START" not in out
    assert "BADGES_END" not in out
    assert "ci.svg" not in out
    assert "pypi.svg" not in out
    assert "Body paragraph stays." in out
    assert out.startswith("# Title\n\n")


def test_strip_readme_badge_block_is_noop_without_markers(build_docs):
    """Files without the markers must round-trip byte-for-byte."""
    src = "# Title\n\nNo badges here, just prose.\n"
    assert build_docs._strip_readme_badge_block(src) == src


def test_strip_readme_badge_block_runs_on_live_readme(build_docs):
    """The live README must contain the marker block, and stripping it
    must remove every shields.io / api.scorecard.dev URL. Catches an
    accidental marker rename or a badge URL added outside the markers.
    """
    repo_root = Path(__file__).resolve().parents[1]
    readme = (repo_root / "README.md").read_text()
    assert "<!-- BADGES_START" in readme, (
        "README is missing the BADGES_START marker - the Hugo build will "
        "ship the badge row to the docs home page."
    )
    stripped = build_docs._strip_readme_badge_block(readme)
    assert "img.shields.io" not in stripped
    assert "api.scorecard.dev" not in stripped
