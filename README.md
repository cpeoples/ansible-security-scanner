<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand-mark.svg">
    <img src="docs/assets/brand-mark-light.svg" alt="Ansible Security Scanner" width="560">
  </picture>
</div>
<!-- BADGES_START - stripped from the Hugo docs build; see .hugo/scripts/build_docs.py -->
<p align="center">
  <a href="https://github.com/cpeoples/ansible-security-scanner/actions/workflows/scanner-ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/cpeoples/ansible-security-scanner/scanner-ci.yml?branch=main&label=CI&style=flat-square&logo=github&logoColor=white" alt="CI" /></a>&nbsp;&nbsp;
  <a href="https://www.bestpractices.dev/en/projects/12942/baseline-3"><img src="https://img.shields.io/badge/OpenSSF%20Baseline-Level%203-blueviolet?style=flat-square" alt="OpenSSF Baseline Level 3" /></a>&nbsp;&nbsp;
  <a href="https://scorecard.dev/viewer/?uri=github.com/cpeoples/ansible-security-scanner"><img src="https://img.shields.io/ossf-scorecard/github.com/cpeoples/ansible-security-scanner?style=flat-square&label=OpenSSF%20Scorecard" alt="OpenSSF Scorecard" /></a>&nbsp;&nbsp;
  <a href="https://github.com/cpeoples/ansible-security-scanner/security/code-scanning"><img src="https://img.shields.io/github/actions/workflow/status/cpeoples/ansible-security-scanner/codeql.yml?branch=main&label=CodeQL&style=flat-square&logo=github&logoColor=white" alt="CodeQL" /></a>&nbsp;&nbsp;
  <a href="https://github.com/cpeoples/ansible-security-scanner/actions/workflows/pip-audit.yml"><img src="https://img.shields.io/github/actions/workflow/status/cpeoples/ansible-security-scanner/pip-audit.yml?branch=main&label=pip-audit&style=flat-square&logo=python&logoColor=white" alt="pip-audit" /></a>&nbsp;&nbsp;
  <a href="https://owasp.org/www-community/Source_Code_Analysis_Tools"><img src="https://img.shields.io/badge/OWASP-Listed-000000?style=flat-square&logo=owasp&logoColor=white" alt="OWASP Listed" /></a>&nbsp;&nbsp;
  <a href="https://github.com/ansible-community/awesome-ansible#tools"><img src="https://img.shields.io/badge/Awesome-Ansible-fc60a8?style=flat-square&logo=awesomelists&logoColor=white" alt="Listed on Awesome Ansible" /></a>&nbsp;&nbsp;
  <a href="src/ansible_security_scanner/patterns"><img src="https://img.shields.io/badge/Rules-1102-blue?style=flat-square&logo=ansible&logoColor=white" alt="Rules" /></a>&nbsp;&nbsp;
  <a href="https://pypi.org/project/ansible-security-scanner/"><img src="https://img.shields.io/pypi/v/ansible-security-scanner?style=flat-square&logo=pypi&logoColor=white&label=PyPI" alt="PyPI" /></a>&nbsp;&nbsp;
  <a href="https://github.com/cpeoples/ansible-security-scanner/releases/latest"><img src="https://img.shields.io/badge/SLSA-Level%203-success?style=flat-square&logo=slsa&logoColor=white" alt="SLSA Build Level 3" /></a>&nbsp;&nbsp;
  <a href="https://github.com/cpeoples/ansible-security-scanner/releases/latest"><img src="https://img.shields.io/badge/SBOM-CycloneDX-success?style=flat-square&logo=cyclonedx&logoColor=white" alt="CycloneDX SBOM" /></a>&nbsp;&nbsp;
  <a href="https://github.com/cpeoples/ansible-security-scanner/releases/latest"><img src="https://img.shields.io/badge/Sigstore-verified-success?style=flat-square&logo=sigstore&logoColor=white" alt="Sigstore verified" /></a>
</p>
<!-- BADGES_END -->

Static SAST scanner for Ansible playbooks, roles, collections, task files, vars, and inventories. Detects malicious code, RCE, command and template injection, hardcoded credentials, supply-chain risk, unauthorized cloud access, lateral movement, and reverse shells. Outputs SARIF, CycloneDX SBOM, GitLab SAST, JUnit, JSON, HTML, and Markdown reports with remediation guidance. Findings map to CWE, OWASP Top 10, OWASP ASVS, MITRE ATT&CK, NIST, and CIS. CI-native, autofix-capable, DevSecOps-ready.

**<!--RULES-->1102<!--/RULES--> rules** across **<!--CATS-->31<!--/CATS--> categories** -- all auto-discovered from YAML pattern plugins.

**<!--CRIT-->413<!--/CRIT--> critical**, <!--HIGH-->537<!--/HIGH--> high, <!--MED-->132<!--/MED--> medium, <!--LOW-->19<!--/LOW--> low. [Per-category breakdown on the dashboard.](https://cpeoples.github.io/ansible-security-scanner/dashboard/)

> [!NOTE]
> **Scope.** This is a *static, pattern-based* scanner - one layer in a defense-in-depth strategy. Pair it with the runtime controls you already trust (AAP/AWX approval gates, execution-environment lockdown, network egress policy, code review) for full coverage. See [Limitations](docs/limitations.md) for the specific classes of issue this layer cannot catch on its own.

## Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [What it detects](#what-it-detects)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Requirements](#requirements)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Security](#security)
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

### Homebrew

```bash
brew install cpeoples/tap/ansible-security-scanner
```

Available via the [`cpeoples/homebrew-tap`](https://github.com/cpeoples/homebrew-tap) Homebrew tap.

### pre-commit

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/cpeoples/ansible-security-scanner
    rev: v0.1.31
    hooks:
      - id: ansible-security-scanner
```

Two hook IDs are exposed:

- `ansible-security-scanner` — scans only the staged YAML / `*.j2` / `*.cfg` files. Runs on every commit.
- `ansible-security-scanner-all` — scans the full repository tree. Wired to the `pre-push` and `manual` stages so it doesn't fire on every commit; trigger it with `pre-commit run --hook-stage pre-push ansible-security-scanner-all` or in CI.

## Quick Start

After installing, try one of these:

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

## What it detects

The scanner ships <!--RULES-->1102<!--/RULES--> rules across <!--CATS-->31<!--/CATS--> auto-discovered categories. Highlights:

**Malicious code and post-exploitation**

- Reverse shells, webshell deployment, system compromise, lateral movement
- Anti-forensics, obfuscation and evasion, tunneling, offensive tooling

**Code execution and injection**

- Command injection, template injection, variable injection
- Jinja lookup RCE, dangerous Ansible modules, binary planting

**Secrets and supply chain**

- Hardcoded credentials and API keys
- Supply-chain risk (Galaxy collections, ad-hoc downloads, untrusted URLs)
- Data exfiltration, webhook exposure, external URL contact

**Cloud, IaC, and platform hardening**

- Unauthorized cloud access, Kubernetes insecure specs
- Privilege escalation, unsafe permissions, environment hijacking
- Insecure communication (TLS, SSH, plaintext protocols)

**AI/ML and operational hygiene**

- AI/ML supply-chain and prompt-injection risks
- Ansible hygiene, Ansible-specific anti-patterns, operational security

Every rule includes severity, framework mappings (CWE, OWASP Top 10, OWASP ASVS, MITRE ATT&CK, NIST, CIS Controls), vulnerable and remediated examples, and remediation guidance. Findings are deduplicated across files via cross-file taint tracking. See the [rule dashboard](https://cpeoples.github.io/ansible-security-scanner/dashboard/) for a per-category, per-severity breakdown.

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

## FAQ

**What does Ansible Security Scanner scan?**

Ansible playbooks, roles, collections, task files, vars, and inventories. It
detects malicious code, RCE, command and template injection, hardcoded
credentials, supply-chain risk, unauthorized cloud access, lateral movement,
and reverse shells.

**How is this different from `ansible-lint`?**

`ansible-lint` focuses on style and best practices. Ansible Security Scanner
is a SAST tool focused on security signals: dataflow taint tracking,
supply-chain risk, secrets, and known attack patterns mapped to OWASP, CWE,
NIST, CIS, and MITRE ATT&CK.

**Does it run in CI/CD?**

Yes. It outputs SARIF, CycloneDX SBOM, GitLab SAST, JUnit, JSON, HTML, and
Markdown. GitHub Actions, GitLab CI, and Jenkins are all supported, and
PR/MR comments can be posted automatically.

**Is it free to use?**

Yes. Ansible Security Scanner is Apache-2.0 licensed and free to use
commercially.

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

## Security

This repository runs three GitHub-native security checks on every push
and pull request:

- **Dependabot** ([`.github/dependabot.yml`](.github/dependabot.yml)) -
  weekly update PRs for `pip` and `github-actions` ecosystems, plus
  out-of-band security advisories.
- **CodeQL** (default setup, configured in repo settings) - SAST against
  the Python in `src/ansible_security_scanner/`.
- **Secret scanning + push protection** - alerts on credential-shaped
  strings in tracked files.

### Why some paths are excluded from secret scanning

Because this *is* a security scanner, the repo ships two structurally
required corpora that look exactly like real secrets:

1. **Hand-curated negative fixtures** (`tests/playbooks/bad_example.yml`
   and `tests/playbooks/multi_example_bad/**`) - the integration tests
   feed these to the scanner to assert each rule class fires correctly.
   They contain deliberate hardcoded credentials, fake AWS keys, and
   embedded SQS URLs; nothing here is a real credential.
2. **Pattern-pack `vulnerable_examples:` blocks**
   (`src/ansible_security_scanner/patterns/**`) - rule definitions
   document, by design, the literal strings each rule is meant to
   match. These blocks are rendered into the generated rule docs that
   ship at <https://cpeoples.github.io/ansible-security-scanner/>.

Both surfaces are excluded via [`.github/secret_scanning.yml`](.github/secret_scanning.yml),
where each entry is annotated with the structural reason it's there.

### Privacy

The scanner runs locally and does not phone home. There is no
telemetry, no analytics, no usage pings, and no remote rule fetch.
Comment posting is the only outbound network call, and it only
fires when you pass `--mr-comment` (or the equivalent) with an
explicit token; the target host is the GitLab or GitHub instance
you point it at.

### Reporting a vulnerability

Open a private security advisory via the
[Security tab](https://github.com/cpeoples/ansible-security-scanner/security/advisories/new)
rather than a public issue. Vulnerabilities in the scanner itself
(e.g. a code path that lets an attacker leak unredacted secrets through
an MR comment) are in scope; vulnerabilities in *Ansible playbooks
detected by the scanner* are not - those belong to the playbook's
maintainer.

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

## AI-assistance disclosure

This project follows the
[Ansible community AI policy](https://docs.ansible.com/projects/ansible/latest/community/ai_policy.html).
LLM tooling has helped with scaffolding, refactoring, test generation,
and documentation. All of it is reviewed, edited, and tested by a human
before being committed. The rules, threat models, and design decisions
are mine, and every PR runs the full test, lint, and security gate
before merge.
