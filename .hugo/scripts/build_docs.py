#!/usr/bin/env python3
"""Build script to generate Hugo documentation for the Ansible Security
Scanner.

Sources of truth:

  1. ``README.md``          -> ``content/_index.md`` (home page)
  2. ``docs/<slug>.md``     -> ``content/<slug>.md`` for each long-form section
  3. ``src/.../patterns/*.yml`` -> ``content/patterns/<category>.md`` (rule tables)
                                  + ``content/dashboard.md`` (aggregate summary)

The split between README and ``docs/`` is the design rule: the README stays a
short landing page, and every long reference section (CLI flags, env vars,
output formats, ...) lives in its own ``docs/<slug>.md``. That way GitHub
renders each section directly via relative links and Hugo renders the same
file with theme-side navigation, search, and front-matter -- no two-source
drift.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
HUGO_DIR = SCRIPT_DIR.parent
ROOT_DIR = HUGO_DIR.parent
PATTERNS_DIR = ROOT_DIR / "src" / "ansible_security_scanner" / "patterns"
README_FILE = ROOT_DIR / "README.md"
DOCS_DIR = ROOT_DIR / "docs"
CONTENT_DIR = HUGO_DIR / "content"
DOCS_ASSETS_DIR = DOCS_DIR / "assets"
STATIC_ASSETS_DIR = HUGO_DIR / "static" / "assets"
STATIC_IMAGES_DIR = HUGO_DIR / "static" / "images"

_BASE_URL = os.environ.get("HUGO_BASEURL", "/").strip()
if not _BASE_URL.endswith("/"):
    _BASE_URL = _BASE_URL + "/"
ASSET_URL_PREFIX = _BASE_URL + "assets/"

# Make the in-repo package importable so chip rendering uses the same
# resolvers as the scanner runtime. Failure leaves resolvers as None and
# chips simply don't render.
sys.path.insert(0, str(ROOT_DIR / "src"))
try:
    from ansible_security_scanner.link_resolver import (  # noqa: E402
        resolve_cve,
        resolve_cwe,
        resolve_mitre,
    )
except Exception:  # pragma: no cover - hugo-only build environment
    resolve_cve = resolve_cwe = resolve_mitre = None  # type: ignore[assignment]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Curated docs/<slug>.md -> Hugo page registry. ``weight`` controls the
# sidebar order (lower = higher in the nav). Gaps of 10 leave room to
# insert new pages without renumbering everything below them.
DOC_PAGES: dict[str, dict[str, object]] = {
    "cli": {"title": "CLI Reference", "weight": 20},
    "environment": {"title": "Environment", "weight": 30},
    "api": {"title": "Python API", "weight": 40},
    "output-formats": {"title": "Output Formats", "weight": 50},
    "allowlist": {"title": "Allowlist", "weight": 60},
    "ci-cd": {"title": "CI/CD", "weight": 70},
    "mr-pr-comments": {"title": "PR/MR Comments", "weight": 80},
    "custom-patterns": {"title": "Custom Patterns", "weight": 90},
    "scoring": {"title": "Scoring", "weight": 100},
    "testing": {"title": "Testing", "weight": 110},
    "limitations": {"title": "Limitations", "weight": 120},
    "releasing": {"title": "Releasing", "weight": 130},
}

# Slugs that the README links to as ``docs/<slug>.md``. We rewrite those to
# Hugo's pretty-URL layout (``/<slug>/``) when emitting ``content/_index.md``
# AND when emitting individual section pages, so cross-page links resolve
# correctly on the site without changing the GitHub-side links.
_DOCS_LINK_RE = re.compile(r"\(docs/([\w-]+)\.md(#[\w-]+)?\)")
_INTRA_DOCS_LINK_RE = re.compile(r"\(([\w-]+)\.md(#[\w-]+)?\)")

_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
_BREAK_AFTER_CHARS = ("_", ",", ".")


def _inject_code_break_opportunities(body: str) -> str:
    """Insert ``<wbr>`` break hints inside Markdown inline code spans.

    Skips fenced code blocks (``` / ~~~) so code samples round-trip
    verbatim. Codespans become raw ``<code>`` tags because Markdown
    escapes HTML inside backticks.
    """

    def _replace(match: re.Match[str]) -> str:
        inner = match.group(1)
        for ch in _BREAK_AFTER_CHARS:
            inner = inner.replace(ch, f"{ch}<wbr>")
        return f"<code>{inner}</code>"

    out: list[str] = []
    in_fence = False
    fence_marker = ""
    for line in body.splitlines(keepends=True):
        stripped = line.lstrip()
        if not in_fence and (stripped.startswith("```") or stripped.startswith("~~~")):
            in_fence = True
            fence_marker = stripped[:3]
            out.append(line)
            continue
        if in_fence:
            if stripped.startswith(fence_marker):
                in_fence = False
                fence_marker = ""
            out.append(line)
            continue
        out.append(_INLINE_CODE_RE.sub(_replace, line))
    return "".join(out)


def _category_label(category_key: str, yaml_doc: dict) -> str:
    """Resolve a human-readable label for a pattern category.

    Pattern files author their own label in the top-level ``name:`` field,
    which is the canonical source. We strip a trailing " Patterns" suffix
    (present on most files) since the page already lives under the
    "Security Patterns" section - "Command Injection Patterns" reads as
    "Command Injection Patterns Patterns" in breadcrumbs otherwise.

    If a file is missing ``name:`` (shouldn't happen, but don't crash docs
    over it), fall back to a title-cased version of the filename.
    """
    name = (yaml_doc or {}).get("name", "").strip()
    if not name:
        return category_key.replace("_", " ").title()
    for suffix in (" Patterns", " Pattern"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name


def clean_content_dir() -> None:
    """Remove all generated content before rebuilding."""
    if CONTENT_DIR.exists():
        for child in CONTENT_DIR.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            elif child.name != "_index.md":
                child.unlink()


def load_patterns(yml_path: Path) -> dict:
    """Load a pattern YAML file and return parsed data."""
    with open(yml_path) as f:
        return yaml.safe_load(f) or {}


def copy_docs_assets() -> None:
    if not DOCS_ASSETS_DIR.exists():
        return
    if STATIC_ASSETS_DIR.exists():
        shutil.rmtree(STATIC_ASSETS_DIR)
    STATIC_ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    copied = 0
    for src in DOCS_ASSETS_DIR.iterdir():
        if src.is_file():
            shutil.copy2(src, STATIC_ASSETS_DIR / src.name)
            copied += 1
    print(f"Copied {copied} README asset(s) -> static/assets/")

    favicon_src = DOCS_ASSETS_DIR / "ansible.svg"
    if favicon_src.exists():
        STATIC_IMAGES_DIR.mkdir(parents=True, exist_ok=True)
        for name in ("favicon.svg", "logo.svg"):
            shutil.copy2(favicon_src, STATIC_IMAGES_DIR / name)
        print(f"Seeded favicon/logo from {favicon_src.name} -> static/images/")


def _rewrite_links_for_hugo(body: str) -> str:
    """Rewrite Markdown links so they resolve under Hugo's pretty URLs.

    On GitHub, README links to sections look like ``(docs/cli.md)`` and
    cross-section links inside a docs file look like ``(allowlist.md)``;
    Hugo serves those at ``/cli/`` and ``/allowlist/`` respectively. The
    rewrite is a pure function of the text - no AST round-trip - so it
    composes safely with the rest of the pipeline.
    """
    body = _DOCS_LINK_RE.sub(lambda m: f"(/{m.group(1)}/{m.group(2) or ''})", body)
    body = _INTRA_DOCS_LINK_RE.sub(
        lambda m: f"(/{m.group(1)}/{m.group(2) or ''})" if m.group(1) in DOC_PAGES else m.group(0),
        body,
    )
    return body


_LEADING_H1_RE = re.compile(r"^#\s+(?P<title>.+?)\s*$\n+", re.MULTILINE)
_LEADING_HTML_H1_RE = re.compile(
    r"\A\s*<h1\b[^>]*>(?P<title>.*?)</h1>\s*\n+",
    re.DOTALL | re.IGNORECASE,
)
_BADGES_BLOCK_RE = re.compile(
    r"<!--\s*BADGES_START\b.*?-->\n.*?\n<!--\s*BADGES_END\s*-->\n*",
    re.DOTALL,
)


def _strip_readme_badge_block(content: str) -> str:
    """Drop the GitHub-only badge row when emitting the Hugo home page.

    The badge row (CI / Scorecard / rule count / PyPI / sigstore) is for
    evaluators on github.com - the docs site already exposes that
    metadata via theme chrome (search, version selector, repo link), and
    rendering it on every doc home-page load would trigger third-party
    network calls. Markers are ``<!-- BADGES_START -->`` /
    ``<!-- BADGES_END -->`` so the strip stays deterministic.
    """
    return _BADGES_BLOCK_RE.sub("", content)


def _strip_leading_h1(content: str) -> tuple[str, str | None]:
    """Strip the first leading ``# Title`` line from ``content``.

    Returns ``(content_without_h1, raw_title)``. ``raw_title`` is
    ``None`` when no leading H1 was found. The caller decides whether
    to use the extracted title (home page) or discard it (doc pages
    where the title is curated in ``DOC_PAGES``).

    Both Markdown (``# Title``) and HTML (``<h1>Title</h1>``) forms are
    supported - the README home page uses the HTML form to centre the
    title row on GitHub, but the Hugo theme renders its own H1 from
    front-matter, so either form would otherwise produce two stacked
    titles in the rendered docs.
    """
    match = _LEADING_H1_RE.match(content)
    if not match:
        match = _LEADING_HTML_H1_RE.match(content)
    if not match:
        return content, None
    title = re.sub(r"<[^>]+>", "", match.group("title")).strip()
    title = re.sub(r"\s+", " ", title)
    return content[match.end() :], title


def build_index() -> None:
    """Convert README.md to the Hugo home page."""
    print("Converting README.md -> content/_index.md")
    if not README_FILE.exists():
        print("  WARNING: README.md not found, creating placeholder")
        content = "# Ansible Security Scanner\n\nDocumentation coming soon."
    else:
        content = README_FILE.read_text()

    content = _strip_readme_badge_block(content)
    content = re.sub(
        r'(src|href)="docs/assets/',
        lambda m: f'{m.group(1)}="{ASSET_URL_PREFIX}',
        content,
    )
    content = _rewrite_links_for_hugo(content)
    content = _inject_code_break_opportunities(content)

    content, raw_title = _strip_leading_h1(content)
    title = raw_title or "Ansible Security Scanner"

    heading_pre = (
        f'<img src="{ASSET_URL_PREFIX}ansible.svg" alt="" height="40" '
        'style="vertical-align:middle;margin-right:0.6rem;" />'
    )

    frontmatter = (
        f"---\n"
        f'title: "{title}"\n'
        f"weight: 1\n"
        f"alwaysopen: true\n"
        f"headingPre: '{heading_pre}'\n"
        f"---\n\n"
    )
    CONTENT_DIR.mkdir(parents=True, exist_ok=True)
    (CONTENT_DIR / "_index.md").write_text(frontmatter + content)
    print("  Created content/_index.md")


def build_doc_pages() -> None:
    """Render each ``docs/<slug>.md`` into ``content/<slug>.md`` with
    Hugo front-matter pulled from the curated ``DOC_PAGES`` registry.

    The ``docs/`` directory is the single source of truth: a missing
    ``docs/<slug>.md`` for a registered slug is an error (we'd rather
    fail the docs build loudly than silently ship a stale inline copy
    the way the previous generator did).
    """
    print("Generating doc pages from docs/...")
    if not DOCS_DIR.exists():
        print("  WARNING: docs/ not found; skipping doc page generation")
        return

    for slug, meta in DOC_PAGES.items():
        src_path = DOCS_DIR / f"{slug}.md"
        if not src_path.exists():
            raise FileNotFoundError(
                f"DOC_PAGES has '{slug}' but {src_path} is missing. "
                "Either add the file or remove the entry from DOC_PAGES."
            )
        body = _rewrite_links_for_hugo(src_path.read_text())
        body = _inject_code_break_opportunities(body)
        body, _ = _strip_leading_h1(body)
        front = f'---\ntitle: "{meta["title"]}"\nweight: {meta["weight"]}\n---\n\n'
        (CONTENT_DIR / f"{slug}.md").write_text(front + body)
        print(f"  Created content/{slug}.md")


def severity_badge(severity: str) -> str:
    sev = severity.upper()
    css_class = f"severity-{sev.lower()}"
    return f'<span class="{css_class}">{sev}</span>'


# Refs-column chip configuration: (yaml_field, resolver, chip_css_class).
# Order is the triage order rendered in the cell: CVE, then CWE, then
# MITRE ATT&CK. Other taxonomies (OWASP, ASVS, CIS) ship in JSON/SARIF/
# comment output but stay out of the docs table to keep it scannable.
_CHIP_FRAMEWORKS = (
    ("cve", resolve_cve, "framework-chip-cve"),
    ("cwe", resolve_cwe, "framework-chip-cwe"),
    ("mitre_attack", resolve_mitre, "framework-chip-mitre"),
)
_MAX_CHIPS_PER_ROW = 12


def _escape_table_cell(text: str) -> str:
    """Make a YAML string safe to drop between Markdown table separators.

    A literal ``|`` inside a cell shifts every following column right
    (the ``Jinja2: |safe filter ...`` regression); a newline breaks the
    single-row constraint of a Markdown table.
    """
    return text.replace("|", "\\|").replace("\n", " ")


def _render_framework_chips(pattern: dict) -> str:
    """Render a sparse chip strip of resolvable framework refs for one rule.

    Returns ``""`` when nothing resolves so chip-less rows stay visually
    identical to the pre-chip layout. Unresolvable ids are dropped: the
    framework-catalog test in ``tests/test_framework_catalog.py`` already
    fails the build on any rule that cites an unresolvable id, so
    anything reaching here has a guaranteed deep link.
    """
    if resolve_cve is None:
        return ""
    chips: list[str] = []
    overflow = 0
    for field, resolver, css in _CHIP_FRAMEWORKS:
        if resolver is None:
            continue
        for raw in pattern.get(field) or []:
            ref = resolver(raw)
            if ref is None:
                continue
            if len(chips) >= _MAX_CHIPS_PER_ROW:
                overflow += 1
                continue
            chips.append(
                f'<a class="framework-chip {css}" href="{ref.url}" '
                f'target="_blank" rel="noopener">{ref.id}</a>'
            )
    if not chips:
        return ""
    if overflow:
        chips.append(f'<span class="framework-chip-more">+{overflow} more</span>')
    return '<div class="framework-chips">' + "".join(chips) + "</div>"


def build_pattern_pages() -> dict:
    """Generate a Hugo page for each pattern category YAML file."""
    print("Generating pattern documentation pages...")

    if not PATTERNS_DIR.exists():
        print("  WARNING: src/patterns/ not found")
        return {}

    patterns_content_dir = CONTENT_DIR / "patterns"
    patterns_content_dir.mkdir(parents=True, exist_ok=True)

    index_front = (
        "---\n"
        'title: "Security Patterns"\n'
        "weight: 200\n"
        "collapsibleMenu: true\n"
        "alwaysopen: false\n"
        "---\n\n"
    )
    index_body = (
        "The Ansible Security Scanner ships with **pattern plugins** organized by "
        "threat category. Each YAML file in `src/patterns/` is auto-discovered at "
        "scan time -- no code changes needed to add new rules.\n\n"
        "Browse the categories below to see every rule, its severity, and what it detects.\n"
    )
    (patterns_content_dir / "_index.md").write_text(index_front + index_body)

    all_stats: dict = {}
    yml_files = sorted(PATTERNS_DIR.glob("*.yml"))

    for weight_idx, yml_path in enumerate(yml_files, start=1):
        data = load_patterns(yml_path)
        patterns = data.get("patterns", [])
        category_key = yml_path.stem
        label = _category_label(category_key, data)
        file_desc = data.get("description", "")
        file_author = data.get("author", "")

        sev_counts: dict = {}
        for p in patterns:
            sev = p.get("severity", "MEDIUM").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        all_stats[category_key] = {
            "label": label,
            "count": len(patterns),
            "severity_counts": sev_counts,
        }

        sorted_patterns = sorted(
            patterns,
            key=lambda p: (
                SEVERITY_ORDER.get(p.get("severity", "MEDIUM").upper(), 9),
                p.get("id", ""),
            ),
        )

        page = f'---\ntitle: "{label}"\nweight: {weight_idx * 10}\n---\n\n'

        if file_desc:
            page += f"{file_desc}\n\n"
        if file_author:
            page += f"*Author: {file_author}*\n\n"

        page += "**" + str(len(patterns)) + "** rules in `" + yml_path.name + "`\n\n"

        sev_summary_parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in sev_counts:
                sev_summary_parts.append(f"{severity_badge(sev)}: {sev_counts[sev]}")
        if sev_summary_parts:
            page += " | ".join(sev_summary_parts) + "\n\n"

        page += '<div class="pattern-table">\n\n'
        page += "| Rule ID | Severity | Title | Description | Refs |\n"
        page += "|---------|----------|-------|-------------|------|\n"
        for p in sorted_patterns:
            rid = p.get("id", "unknown")
            sev = p.get("severity", "MEDIUM").upper()
            title = _escape_table_cell(p.get("title", rid.replace("_", " ").title()))
            desc = _escape_table_cell(p.get("description", ""))
            chips = _render_framework_chips(p) or '<span class="framework-chip-empty">—</span>'
            # <wbr> after each underscore lets the browser break long IDs
            # at word seams. Markdown code spans would escape the tag, so
            # we emit an explicit <code> element.
            rid_html = '<code class="rule-id">' + rid.replace("_", "_<wbr>") + "</code>"
            page += f"| {rid_html} | {severity_badge(sev)} | {title} | {desc} | {chips} |\n"

        page += "\n</div>\n"

        child_path = patterns_content_dir / f"{category_key}.md"
        child_path.write_text(page)
        print(f"  Created patterns/{category_key}.md ({len(patterns)} rules)")

    return all_stats


def build_summary_page(all_stats: dict) -> None:
    """Generate a summary/dashboard page with aggregate stats."""
    print("Generating summary page...")

    total_rules = sum(s["count"] for s in all_stats.values())
    total_categories = len(all_stats)

    global_sev: dict = {}
    for stats in all_stats.values():
        for sev, cnt in stats["severity_counts"].items():
            global_sev[sev] = global_sev.get(sev, 0) + cnt

    page = '---\ntitle: "Dashboard"\nweight: 10\n---\n\n'
    page += "## Scanner Overview\n\n"
    page += "| Metric | Value |\n"
    page += "|--------|-------|\n"
    page += f"| Total Rules | **{total_rules}** |\n"
    page += f"| Pattern Categories | **{total_categories}** |\n"

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in global_sev:
            page += f"| {severity_badge(sev)} Rules | {global_sev[sev]} |\n"

    page += "\n## Rules by Category\n\n"
    page += "| Category | Rules | Critical | High | Medium | Low |\n"
    page += "|----------|-------|----------|------|--------|-----|\n"

    sorted_cats = sorted(all_stats.items(), key=lambda kv: kv[1]["count"], reverse=True)
    for cat_key, stats in sorted_cats:
        label = stats["label"]
        cnt = stats["count"]
        sc = stats["severity_counts"]
        page += (
            f"| [{label}](/patterns/{cat_key}/) "
            f"| {cnt} "
            f"| {sc.get('CRITICAL', 0)} "
            f"| {sc.get('HIGH', 0)} "
            f"| {sc.get('MEDIUM', 0)} "
            f"| {sc.get('LOW', 0)} |\n"
        )

    (CONTENT_DIR / "dashboard.md").write_text(page)
    print("  Created content/dashboard.md")


def main() -> None:
    print("Building Hugo documentation for Ansible Security Scanner...\n")

    clean_content_dir()
    copy_docs_assets()

    build_index()
    build_doc_pages()
    all_stats = build_pattern_pages()
    build_summary_page(all_stats)

    total = sum(s["count"] for s in all_stats.values())
    print(f"\nDone: {total} rules across {len(all_stats)} categories")


if __name__ == "__main__":
    main()
