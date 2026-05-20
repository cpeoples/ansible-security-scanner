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
