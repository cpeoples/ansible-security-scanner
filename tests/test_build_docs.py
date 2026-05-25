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


def test_render_chips_renders_one_per_framework(build_docs):
    out = build_docs._render_framework_chips(
        {
            "id": "x",
            "cwe": ["CWE-77", "CWE-78", "CWE-94"],
        }
    )
    assert out.count("framework-chip framework-chip-cwe") == 1
    assert ">CWE-77</a>" in out
    assert "CWE-78" not in out
    assert "CWE-94" not in out


def test_render_chips_drops_unresolvable_silently(build_docs):
    out = build_docs._render_framework_chips({"id": "x", "cve": ["not-a-cve", "CVE-2024-3094"]})
    assert ">CVE-2024-3094</a>" in out
    assert "not-a-cve" not in out


def test_render_chips_skips_unresolvable_to_find_first_resolvable(build_docs):
    out = build_docs._render_framework_chips({"id": "x", "cwe": ["not-a-cwe", "CWE-78", "CWE-94"]})
    assert out.count("framework-chip framework-chip-cwe") == 1
    assert ">CWE-78</a>" in out


def test_render_chips_renders_all_five_claimed_frameworks(build_docs):
    out = build_docs._render_framework_chips(
        {
            "id": "x",
            "cwe": ["CWE-78"],
            "mitre_attack": ["T1059.004"],
            "owasp_appsec": ["A03:2021"],
            "owasp_asvs": ["V13.3.1"],
            "nist_controls": ["SI-10"],
            "cis_controls": ["CIS-4.1"],
        }
    )
    for css in (
        "framework-chip-cwe",
        "framework-chip-mitre",
        "framework-chip-owasp",
        "framework-chip-asvs",
        "framework-chip-nist",
        "framework-chip-cis",
    ):
        assert css in out, f"missing {css} chip"
    cwe_idx = out.index("CWE-78")
    mitre_idx = out.index("T1059.004")
    owasp_idx = out.index("A03:2021")
    asvs_idx = out.index("V13.3.1")
    nist_idx = out.index("SI-10")
    cis_idx = out.index("CIS-4.1")
    assert cwe_idx < mitre_idx < owasp_idx < asvs_idx < nist_idx < cis_idx


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


def test_strip_leading_h1_extracts_markdown_form(build_docs):
    """A leading ``# Title`` line is consumed and its text returned."""
    body, title = build_docs._strip_leading_h1("# My Title\n\nBody paragraph.\n")
    assert title == "My Title"
    assert body == "Body paragraph.\n"


def test_strip_leading_h1_extracts_html_form(build_docs):
    """The HTML form (``<h1 align="center"><img/>Title</h1>``) used by the
    centred README header is consumed the same way as the Markdown form,
    inline tags are stripped from the extracted title, and embedded
    whitespace is collapsed so the front-matter stays YAML-clean.
    """
    src = (
        '<h1 align="center">\n'
        '  <img src="docs/assets/ansible.svg" alt="" height="32" align="center" />\n'
        "  Ansible Security Scanner\n"
        "</h1>\n\n"
        "Body paragraph.\n"
    )
    body, title = build_docs._strip_leading_h1(src)
    assert title == "Ansible Security Scanner"
    assert body == "Body paragraph.\n"


def test_strip_leading_h1_runs_on_live_readme(build_docs):
    """Live README must not produce a body that begins with an H1 after the
    badge and leading-H1 strip; the Hugo theme renders its own H1 from the
    front-matter ``title:`` so any second H1 would stack two titles.
    """
    repo_root = Path(__file__).resolve().parents[1]
    readme = (repo_root / "README.md").read_text()
    stripped_badges = build_docs._strip_readme_badge_block(readme)
    body, title = build_docs._strip_leading_h1(stripped_badges)
    if title is not None:
        assert title == "Ansible Security Scanner"
    assert not body.lstrip().startswith("<h1")
    assert not body.lstrip().startswith("# ")


def test_category_pages_do_not_render_yaml_author_field(build_docs):
    """The ``author:`` field in pattern YAMLs is build metadata, not page
    content. Guards against ``*Author:`` lines reappearing on rendered pages.
    """
    content_dir = Path(build_docs.CONTENT_DIR) / "patterns"
    if not content_dir.exists():
        pytest.skip("docs not built; run build_docs.py first")
    offenders: list[str] = []
    for md in sorted(content_dir.glob("*.md")):
        if md.name == "_index.md":
            continue
        if "*Author:" in md.read_text():
            offenders.append(md.name)
    assert not offenders, "category pages still emit '*Author:' lines: " + ", ".join(offenders)
