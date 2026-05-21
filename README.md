# <img src="docs/assets/ansible.svg" alt="" height="32" align="center" /> Ansible Security Scanner

A security scanner for Ansible playbooks. Detects malicious code, unauthorized cloud access, offensive tooling, reverse shells, data exfiltration, and 500+ additional security anti-patterns. Generates detailed reports with remediation guidance.

**<!--RULES-->1091<!--/RULES--> rules** across **<!--CATS-->31<!--/CATS--> categories** -- all auto-discovered from YAML pattern plugins.

> [!NOTE]
> **Scope.** This is a *static, pattern-based* scanner - one layer in a defense-in-depth strategy. Pair it with the runtime controls you already trust (AAP/AWX approval gates, execution-environment lockdown, network egress policy, code review) for full coverage. See [Limitations](docs/limitations.md) for the specific classes of issue this layer cannot catch on its own.

## Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License & Attribution](#license--attribution)

### Built with

<div style="display:flex !important;flex-wrap:wrap;align-items:center;gap:1.25rem;margin:0.5rem 0 1rem;">
  <a href="https://www.python.org/" title="Python" style="display:inline-flex !important;align-items:center;"><img src="docs/assets/python.svg" alt="Python" height="28" style="display:inline-block;" /></a>
  &nbsp;
  <a href="https://yaml.org/" title="YAML" style="display:inline-flex !important;align-items:center;"><img src="docs/assets/yaml.svg" alt="YAML" height="28" style="display:inline-block;" /></a>
  &nbsp;
  <a href="https://docs.pytest.org/" title="Pytest" style="display:inline-flex !important;align-items:center;"><img src="docs/assets/pytest.svg" alt="Pytest" height="28" style="display:inline-block;" /></a>
  &nbsp;
  <a href="https://gohugo.io/" title="Hugo" style="display:inline-flex !important;align-items:center;"><img src="docs/assets/hugo.svg" alt="Hugo" height="28" style="display:inline-block;" /></a>
  &nbsp;
  <a href="https://docs.gitlab.com/ee/ci/" title="GitLab CI" style="display:inline-flex !important;align-items:center;"><img src="docs/assets/gitlab.svg" alt="GitLab CI" height="28" style="display:inline-block;" /></a>
  &nbsp;
  <a href="https://docs.github.com/actions" title="GitHub Actions" style="display:inline-flex !important;align-items:center;"><img src="docs/assets/githubactions.svg" alt="GitHub Actions" height="28" style="display:inline-block;" /></a>
</div>

## Installation

```bash
pip install ansible-security-scanner
```

Requires Python 3.11+. Installs an `ansible-security-scanner` command on your PATH.

## Quick Start

After `pip install ansible-security-scanner`, try one of these:

```bash
# 1. Scan the current directory, print a Markdown report to the terminal
ansible-security-scanner

# 2. Scan a project and write a SARIF report for GitHub Code Scanning
ansible-security-scanner --directory ansible/ --output results.sarif

# 3. CI/CD: emit a GitLab SAST report (auto-populates the Security Dashboard)
ansible-security-scanner --directory ansible/ --output gl-sast-report.json

# 4. One Markdown report per scanned playbook (lands under ./security-reports/)
ansible-security-scanner --directory ansible/ --output-per-file --format markdown

# 5. Only fail the build on secrets-related findings
ansible-security-scanner --directory ansible/ --compliance CIS-Secrets

# 6. Dry-run autofix - emit a unified diff of the changes the scanner would make
ansible-security-scanner --files site.yml --fix --fix-output fixes.patch

# 7. CI/CD: post a concise findings comment on the current PR / MR
#    (auto-detects GitHub Actions vs. GitLab CI; works on self-hosted).
ansible-security-scanner --gh-comment    # inside a pull_request workflow
ansible-security-scanner --gl-comment    # inside a merge_request_event pipeline

# Full list of flags & examples:
ansible-security-scanner --help
```

**Smart defaults**

- **No `--format` given?** If you pass `--output report.sarif`, the format
  is inferred from the extension (`.sarif` -> SARIF, `.json` -> JSON,
  `.md`/`.markdown` -> Markdown, `.html`/`.htm` -> HTML, `.xml` -> XML,
  `.yml`/`.yaml` -> YAML, `.csv` -> CSV). An explicit `--format` always
  wins; the scanner logs a warning if the two disagree so pipeline
  misconfigurations fail loudly.
- **No `--output` given with `--output-per-file`?** Reports land under
  `./security-reports/` (a self-documenting directory; add it to
  `.gitignore`).
- **`--output` would overwrite an input file?** The scanner refuses and
  exits with code 2 - common footgun when running
  `--files site.yml --output site.yml` with `.yml`-as-format inference.

**Working from a source checkout?** Use `python main.py ...` instead of the
installed CLI - it's a thin shim around the same entry point.

## Project Structure

```
ansible-security-scanner/                      # repo root (hyphenated - matches PyPI)
├── pyproject.toml                             # packaging + pytest + hatch-vcs
├── README.md
├── CONTRIBUTING.md
├── RELEASING.md                               # maintainer release runbook
├── LICENSE / NOTICE                           # Apache-2.0 + attribution terms
├── main.py                                    # local dev entry point (py main.py ...)
├── .github/workflows/                         # CI, release, docs workflows
├── .hugo/                                     # Hugo documentation site
│   ├── scripts/build_docs.py                  # Generates Hugo content from docs/ + patterns
│   └── content/                               # Generated .md pages (do not edit by hand)
├── docs/                                      # Long-form prose docs (source of truth)
│   ├── assets/                                # Images & SVGs the README references
│   ├── cli.md                                 # CLI Reference (and exit codes, suppressions, dedup)
│   ├── environment.md                         # Environment Variables
│   ├── api.md                                 # Programmatic API
│   ├── output-formats.md
│   ├── allowlist.md
│   ├── ci-cd.md
│   ├── mr-pr-comments.md
│   ├── custom-patterns.md
│   ├── scoring.md
│   ├── testing.md
│   ├── limitations.md
│   └── releasing.md
├── src/
│   └── ansible_security_scanner/              # the Python package
│       ├── cli.py                             # CLI (--directory, --fix, --compliance, ...)
│       ├── scanner.py                         # Multi-pass orchestrator
│       ├── file_scanner.py                    # Per-file rules (line patterns, AST walkers)
│       ├── taint_tracker.py                   # Cross-file taint analysis
│       ├── fix_proposer.py                    # Dry-run unified-diff patch generator
│       ├── dependency_collector.py            # SBOM inventory
│       ├── suppressions.py                    # Inline `# nosec` parser
│       ├── models.py                          # SecurityFinding, ScanReport, SecurityScore
│       ├── score_calculator.py                # Severity-weighted scoring
│       ├── patterns_manager.py                # Loads pattern YAML plugins
│       ├── patterns/                          # 29+ YAML pattern plugins (auto-discovered)
│       ├── remediations/                      # One module per category
│       └── formatters/                        # markdown, json, xml, yaml, csv, html, junit, sarif, gitlab_sast, cyclonedx
└── tests/
    ├── test_integration.py                    # End-to-end scanner tests
    ├── test_formatters.py                     # Formatter unit tests
    ├── test_remediations.py                   # Remediation generator unit tests
    └── playbooks/
        ├── bad_example.yml                    # Triggers every rule (100% coverage)
        ├── clean_example.yml                  # Zero findings (false-positive guard)
        ├── multi_example_bad/                 # 6-file role fixture (cross-file taint)
        └── multi_example_clean/               # 6-file hardened role fixture (zero findings)
```

## Documentation

The long-form documentation is split by topic. Each page is a standalone
Markdown file in [`docs/`](docs/) - GitHub renders them inline, and the
Hugo site at [GitHub Pages](#documentation-site) serves the same content
with a navigation sidebar and search.

| Topic | Source |
|---|---|
| **CLI flags, exit codes, suppressions, cross-file dedup** | [`docs/cli.md`](docs/cli.md) |
| **Environment variables (auth, defaults, `--changed-files`)** | [`docs/environment.md`](docs/environment.md) |
| **Programmatic Python API** | [`docs/api.md`](docs/api.md) |
| **Output formats (Markdown, JSON, SARIF, GL-SAST, SBOM, ...)** | [`docs/output-formats.md`](docs/output-formats.md) |
| **Allowlist / suppressing findings** | [`docs/allowlist.md`](docs/allowlist.md) |
| **CI/CD integration (GitLab CI, GitHub Actions)** | [`docs/ci-cd.md`](docs/ci-cd.md) |
| **MR / PR comments (auto-detected, self-hosted-aware)** | [`docs/mr-pr-comments.md`](docs/mr-pr-comments.md) |
| **Adding custom patterns** | [`docs/custom-patterns.md`](docs/custom-patterns.md) |
| **Security score model** | [`docs/scoring.md`](docs/scoring.md) |
| **Testing** | [`docs/testing.md`](docs/testing.md) |
| **Limitations of static analysis** | [`docs/limitations.md`](docs/limitations.md) |
| **Releasing** | [`docs/releasing.md`](docs/releasing.md) |

### Documentation site

Full documentation is auto-generated from the [`docs/`](docs/) Markdown
files plus the pattern YAML plugins, and published via Hugo + GitHub
Pages on every push to `main`.

The build pipeline (`.github/workflows/scanner-docs.yml`) runs:

1. `build_docs.py` - copies each `docs/<slug>.md` into Hugo's `content/`
   with appropriate front-matter, and generates one rule-table page per
   pattern category.
2. Hugo builds a static site with the
   [Relearn](https://mcshelby.github.io/hugo-theme-relearn/) theme.
3. The site is deployed to GitHub Pages.

To preview locally:

```bash
# Generate content
python .hugo/scripts/build_docs.py

# Download theme (first time only)
cd .hugo
curl -sL https://github.com/McShelby/hugo-theme-relearn/archive/refs/heads/main.tar.gz | tar -xz -C themes/
mv themes/hugo-theme-relearn-main themes/hugo-theme-relearn

# Serve locally
hugo server
```

## Requirements

- Python 3.11+
- PyYAML >= 6.0
- Jinja2 >= 3.0
- httpx >= 0.27 (used by `--github-comment` / `--gitlab-comment` only)

For development work from source:

```bash
pip install -e ".[dev]"
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full dev-environment
walkthrough, pattern-authoring guide, and PR checklist.

**TL;DR for a first-time clone:**

```bash
git clone --recurse-submodules https://github.com/cpeoples/ansible-security-scanner.git
cd ansible-security-scanner
python -m venv .venv && source .venv/bin/activate
python task.py install        # editable install + test/lint/build deps
python task.py test           # run the full pytest suite
python task.py scan ./tests/playbooks/bad_example.yml   # try the scanner locally
```

**Common contribution paths:**

1. **Add a security pattern** - drop a YAML plugin in
   `src/ansible_security_scanner/patterns/` (auto-discovered at startup).
   See [§3 of `CONTRIBUTING.md`](CONTRIBUTING.md#3-adding-a-new-security-pattern)
   for the schema and validation steps.
2. **Add a remediation generator** - create a module in
   `src/ansible_security_scanner/remediations/`, then wire it into
   `remediation_generator.py`.
3. **Add an output formatter** - subclass `base.BaseFormatter` under
   `src/ansible_security_scanner/formatters/` and register it in
   `utils.get_formatter_class`.
4. **Run the gates before opening a PR** - `python task.py test` (full
   suite), `python task.py lint`, `python task.py build`.

## License & Attribution

This project is licensed under the [Apache License, Version 2.0](LICENSE).

**If you use, fork, embed, or build on this project, please retain attribution
to the original repository and contributors.** The [`NOTICE`](NOTICE) file at
the repo root spells out exactly what is required.

In plain English:

- You can use this scanner commercially, modify it, embed it in larger tools,
  or build a paid product on top of it - no fee, no permission needed.
- You must keep the `LICENSE` and `NOTICE` files in any redistribution.
- If you fork this project or ship a derivative work (for example, a
  rebranded scanner, a hosted service, or a SaaS wrapper), you must state
  that it is derived from **Ansible Security Scanner** by Chris Peoples and
  link back to the original repository:
  <https://github.com/cpeoples/ansible-security-scanner>.
- The project name **"Ansible Security Scanner"** / `ansible-security-scanner`
  is a reserved mark of the original author (Apache-2.0 §6). Your fork is
  welcome - under a different name.
- Apache-2.0 includes an explicit **patent grant** and a **retaliation clause**:
  if you sue the project or its contributors over a patent related to the
  software, your rights under the license terminate automatically.

See [`NOTICE`](NOTICE) for the full attribution terms and
[`LICENSE`](LICENSE) for the Apache-2.0 text.
