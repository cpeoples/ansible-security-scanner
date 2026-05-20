# Contributing to Ansible Security Scanner

Thanks for taking the time to contribute. This guide covers both of the
common contribution flows:

1. **Adding or tuning a security pattern** (the most frequent kind of PR)
2. **Improving the scanner itself** (bug fixes, new formatters, remediation
   logic, etc.)

Before you start, please read
[`NOTICE`](./NOTICE) - it lays out what's expected of anyone shipping a
derivative of this project (Apache 2.0 Section 4 + reserved project name).

---

## 1. Set up your dev environment

```bash
git clone --recurse-submodules https://github.com/cpeoples/ansible-security-scanner.git
cd ansible-security-scanner

# If you already cloned without `--recurse-submodules`, pull the Hugo theme in now:
#   git submodule update --init --recursive

python -m venv .venv
source .venv/bin/activate

# Installs the package in editable mode plus test/lint/build deps
python task.py install

# One-time: install the git pre-commit hook so ruff runs automatically
# on every commit. Without this, lint will only run in CI.
pre-commit install
```

Everything else in this file assumes that virtualenv is activated (or that
you'll let `task.py` auto-discover it under `./.venv`).

## 2. Use `task.py` for the common loops

`task.py` is a zero-dependency stdlib script that wraps the commands
contributors reach for most often. Run `python task.py help` for the full
list. The ones you'll use daily:

| Command                                | What it does                                         |
| -------------------------------------- | ---------------------------------------------------- |
| `python task.py test`                  | Full pytest run (1327+ tests at the time of writing) |
| `python task.py test -- -k <expr>`     | Filtered pytest run                                  |
| `python task.py lint`                  | `ruff check` + `ruff format --check` + `mypy` if installed |
| `python task.py scan <path>`           | Run the scanner against a local directory            |
| `python task.py build`                 | Build wheel+sdist and run `twine check --strict`     |
| `python task.py docs`                  | Regenerate the Hugo docs                             |
| `python task.py clean`                 | Remove `build/`, `dist/`, `.pytest_cache`, etc.      |

You do not need to install `make`, `poetry`, or any other task runner.

## 3. Adding a new security pattern

Patterns live in YAML files under
`src/ansible_security_scanner/patterns/`. Each file is a plugin; the
scanner discovers them automatically at startup via `patterns_manager`.

### 3.1 Scaffold a new pattern file

```bash
python -m ansible_security_scanner.patterns_cli create "Your Pattern Name" your_patterns.yml
# Move the generated file into the plugins directory once you're happy with it.
```

### 3.2 Pattern file structure

```yaml
name: "Short descriptive name shown in the plugin list"
author: "your-github-username"
description: "What class of vulnerabilities this plugin detects"

patterns:
  - id: "unique_rule_id"          # snake_case, globally unique
    category: "hardcoded_credentials"
    severity: "CRITICAL"            # CRITICAL | HIGH | MEDIUM | LOW
    title: "Human-readable title"
    description: "One sentence explaining the risk"
    regex: "your_regex_here"
    recommendation: "Short actionable remediation hint"
    # Optional enrichment fields - populated on the finding and consumed
    # by formatters (SARIF tags, compliance filters, etc.):
    cwe: ["CWE-798"]
    mitre_attack: ["T1552.001"]
    cis_controls: ["CIS-3.11"]
    references: ["https://..."]
    help_uri: "https://..."
    precision: "high"               # SARIF precision level
    # Optional multi-line / evasion-resistant matching:
    multiline: false
    window: 10                      # how many lines of context the regex sees
    # Optional inline examples - the preferred way to lock rule behaviour
    # in. ``tests/test_rule_examples.py`` auto-discovers both lists and
    # asserts that every ``positive_examples`` entry triggers the rule
    # while every ``negative_examples`` entry does NOT. A new rule with
    # these fields gets free CI protection against regex drift.
    positive_examples:
      - "shell: curl -fsSL https://example.com/install.sh | bash"
      - "ansible.builtin.shell: wget -qO- http://get.example.com | sh"
    negative_examples:
      - "shell: 'echo bash pipe test'"   # unrelated bash mention
      - "# shell: curl x | bash"         # commented-out line
```

### 3.3 Validate before you commit

```bash
python -m ansible_security_scanner.patterns_cli validate path/to/your_patterns.yml
python -m ansible_security_scanner.patterns_cli list
```

### 3.4 Test your pattern

**Preferred:** add `positive_examples` / `negative_examples` inline in
the pattern YAML (see §3.2). The test runner at
`tests/test_rule_examples.py` auto-discovers every pattern file and
asserts each example - no new Python test file needed.

```bash
# Run just the example-driven rule tests:
.venv/bin/python -m pytest tests/test_rule_examples.py -v

# Or run the full suite:
python task.py test
```

If your rule needs more than a single-line example (cross-file taint,
multi-task flow, etc.), add a real fixture playbook under
`tests/playbooks/` plus a Python test:

```python
# tests/test_your_patterns.py
def test_your_rule_detects_vulnerable_code(tmp_path):
    pb = tmp_path / "bad.yml"
    pb.write_text("- hosts: all\n  tasks:\n    - shell: 'echo AKIA{{ ... }}'\n")
    # ...invoke the scanner, assert the finding...
```

You can also quickly eyeball behaviour against a hand-written playbook:

```bash
python task.py scan ./examples/your_test_playbook.yml
```

To verify your new rule fires in isolation (no noise from other rules
on the fixture), use `--select`:

```bash
ansible-security-scanner --select <your_rule_id> --files examples/your_test_playbook.yml
```

`--select` accepts comma-separated literals or fnmatch globs
(`--select aws_*`), and `--list-rules` prints every shipped rule_id one
per line on stdout. Both flags also honor the
`ANSIBLE_SEC_SCANNER_SELECT` / `_IGNORE` environment variables.

### 3.5 Renaming a rule ID (backward-compat aliases)

Rule IDs appear in user allowlists and inline `# nosec: <rule_id>`
suppressions, so renaming one is a breaking change for every downstream
consumer. Instead of hard-renaming, register the old name as an alias
in `src/ansible_security_scanner/suppressions.py`:

```python
_RULE_ID_ALIASES: dict[str, str] = {
    # Format: {old_id: new_id}. One-way - the new ID is canonical.
    "shell_with_dash_c": "shell_inline_compound_command",
    "interpreter_with_dash_c": "interpreter_inline_code_execution",
}
```

With the alias in place, existing `# nosec: shell_with_dash_c
reason="..."` directives keep working unchanged; the scanner resolves
`shell_with_dash_c` -> `shell_inline_compound_command` before matching.
Drop the alias entry in a later release once consumers have migrated.

### 3.6 Cross-rule overlap suppression

When two rules fire on the same `(file, line)` they often describe the
same vulnerability from different angles - e.g. a line with `curl -fsSL
https://raw.githubusercontent.com/... | bash` matches every rule in the
pipe-to-shell family at once. To keep reports actionable, the scanner
deduplicates these via `_OVERLAP_SUPPRESSION_GROUPS` in
`src/ansible_security_scanner/file_scanner.py`:

```python
_OVERLAP_SUPPRESSION_GROUPS: tuple[tuple[str, ...], ...] = (
    # Order inside a group is specificity - the leftmost rule wins
    # when multiple members fire on the same line.
    (
        "raw_github_script_exec",            # most specific
        "curl_pipe_to_shell",
        "curl_wget_pipe_shell_install_oneliner",
        "download_pipe_to_shell",
        "shell_pipe_to_interpreter",         # most generic
    ),
    # ... more groups ...
)
```

If your new rule genuinely describes the same vuln as an existing rule,
add both IDs to a group (ordered most-specific first) so the report
doesn't double-count. If you're intentionally carving out a *different*
failure mode on the same line, leave it out - two findings at the same
location is fine when they recommend different fixes.

Corresponding integration tests in `tests/test_integration.py` and
`tests/test_playbook_annotations.py` are already overlap-aware; `expect
<rule_id>` directives are satisfied if any member of the rule's overlap
group fires.

## 4. Writing good regex patterns

The scanner pre-compiles every pattern once (see
`SecurityPattern.__post_init__` in `patterns_manager.py`), so pattern cost
at scan time is basically the regex's own complexity. Keep them fast and
specific:

```yaml
# Good - word boundary, exact AWS key format
regex: "\\bAKIA[0-9A-Z]{16}\\b"

# Good - escaped literal, anchored
regex: "docker\\.sock"

# Good - avoids matching in comments
regex: "^(?!\\s*#)\\s*password:"
```

Avoid:

```yaml
regex: "password"                # too broad - flags every doc comment
regex: "password: \"admin123\""  # too specific - only catches this literal
regex: "password: [unclosed"     # invalid - scanner logs a warning and skips
```

Use the `category` that matches an existing remediation generator where
possible - otherwise your finding will render with a generic remediation
template. The full list of categories lives in
`src/ansible_security_scanner/remediations/_category_map.py`.

### 4.1 Remediation quality contract

Every shipped rule must produce a remediation that (a) is specific to
the rule and (b) ships a copy-pasteable Ansible fix. Two contract tests
in `tests/test_remediations.py` enforce this:

- `test_remediation_is_relevant_to_the_rule` - the output must mention a
  distinctive token from the rule's own `title` or `recommendation`,
  and must not regress to legacy boilerplate.
- `test_remediation_includes_secure_fix_yaml_block` - the output must
  contain a `✅ Secure Fix` heading followed by a fenced ```yaml block.

Three ways to satisfy the Secure Fix contract, in order of preference:

1. Add `negative_examples:` to the rule in its pattern YAML. The metadata
   renderer renders the first entry as the Secure Fix block.
2. Add a `secure_fix:` entry under the rule's id in
   `src/ansible_security_scanner/patterns/remediations/<category>.yml`
   (preferred when the fix is large enough to deserve its own diff).
3. Add a tailored handler in `remediations/<category>.py` that emits its
   own `✅ Secure Fix` heading + fenced ```yaml block.

If the rule's correct response is procedural (escalate, audit, run via
a reviewed IaC pipeline, vendor patch) and a copy-pasteable Ansible task
would actively mislead the user, set `no_ansible_remediation: true` on
the rule's pattern YAML entry instead. The renderer then emits a
`✅ Secure Response` prose block sourced from `recommendation:`, which
this contract treats as compliant.

The repo ships a helper that batch-applies the `no_ansible_remediation`
flag from a curated list at `scripts/data/procedural_rule_ids.txt`:

```bash
python scripts/stamp_no_ansible_remediation.py
```

The script is idempotent. Add a rule_id to `procedural_rule_ids.txt` and
re-run; remove and re-run to revert.

### 4.2 New rule contribution checklist

Every new rule has to clear the following contracts before CI will let it
land. Each item maps to a parametrised test that runs once per shipped
rule, so a missing field is reported with the offending `rule_id` rather
than a generic failure.

| # | Requirement | Enforced by |
|---|---|---|
| 1 | All seven required fields are populated and non-empty: `id`, `title`, `description`, `severity`, `category`, `recommendation`, `regex` (severity is one of `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). | `tests/test_release_contract.py::test_required_metadata_present` |
| 2 | `description` is at least **60 characters**. Stub one-liners are rejected; expand to describe the threat model, attacker capability, or specific shape the regex matches. | `tests/test_release_contract.py::test_description_meets_minimum_length` |
| 3 | At least one framework tag is set: any of `cwe`, `mitre_attack`, `cis_controls`, `nist_controls`, `owasp_appsec`, `owasp_asvs`, `owasp`, `pci_dss`, `hipaa`, `soc2`, `iso27001`, or `stig`. This is what the compliance filter pivots on. | `tests/test_release_contract.py::test_every_rule_has_a_framework_tag` |
| 4 | At least one `positive_examples` entry. Each entry must match the rule's regex under `re.IGNORECASE \| re.MULTILINE`. AST-walker rules (`regex: "(?!)"`) and rules in `SYNTHETIC_RULE_IDS` are exempt. | `tests/test_release_contract.py::test_every_finding_rule_has_a_positive_example` and `tests/test_rule_examples.py` |
| 5 | Every `negative_examples` entry must NOT match the regex. (Same flags.) Lock in the FP shape that motivated the carve-out. | `tests/test_rule_examples.py` |
| 6 | The remediation includes a `✅ Secure Fix` heading and a fenced ```yaml block AND mentions a distinctive token from the rule's `title` / `recommendation`. Three legal ways to satisfy this - see §4.1. Procedural-only rules opt out via `no_ansible_remediation: true`. | `tests/test_remediations.py::test_remediation_is_relevant_to_the_rule`, `tests/test_remediations.py::test_remediation_includes_secure_fix_yaml_block` |
| 7 | If your rule adds a new CLI flag, document it in `README.md` (the `## CLI Reference` section). | `tests/test_release_contract.py::test_every_argparse_flag_is_documented_in_readme` |
| 8 | If you add a name to `ansible_security_scanner.__all__`, document it in `README.md` (the `## Programmatic API` section). | `tests/test_release_contract.py::test_every_public_api_symbol_is_documented_in_readme` |

Run the gates locally before opening a PR:

```bash
.venv/bin/python -m pytest tests/test_release_contract.py tests/test_remediations.py tests/test_rule_examples.py -q
```

When a contract fails, the test name + `rule_id` in the parametrised test
id tells you exactly which rule and which contract to fix - no log-diving
required. If you can't satisfy a contract for a legitimate reason (e.g.
the rule is an AST sentinel), the right move is to extend the carve-out
rules in the test rather than to lower the bar.

## 5. Severity guidelines

| Severity  | Use when...                                                   |
| --------- | ----------------------------------------------------------- |
| CRITICAL  | Immediate compromise: hardcoded secret, RCE, root on host   |
| HIGH      | Clear path to privilege escalation, dangerous cloud action  |
| MEDIUM    | Weakness that increases attack surface but isn't exploitable alone |
| LOW       | Best-practice violation, stale config, missing hardening    |

Findings are scored by severity in `score_calculator.py`. Over-tagging as
CRITICAL breaks security-gate thresholds in downstream CI pipelines, so be
honest about impact.

## 6. Improving the scanner itself

Bug fixes, new output formatters, remediation improvements, performance work
- all welcome. Before opening a PR:

1. Run the full test suite: `python task.py test` (must be green).
2. Run lint: `python task.py lint`.
3. Build + validate the package: `python task.py build` (wheel + sdist must
   pass `twine check --strict`).
4. If your change affects the CLI or output formats, update the
   auto-generated docs: `python task.py docs`.

### Commit & PR style

- Keep commits focused. A pattern file addition is one PR; a scanner
  refactor is another.
- If you're touching suppressions, taint tracking, or the dispatch table
  in `remediation_generator.py`, add a regression test that would have
  failed before your fix.
- Attribution matters: you keep your commit authorship on the PR, and
  you'll be listed as a contributor in the project history.

## 7. Where things live

```
src/ansible_security_scanner/
├── cli.py                        # argparse entrypoint -> main()
├── scanner.py                    # Orchestrator: reads files once, dispatches to FileScanner / TaintTracker / DependencyCollector / FixProposer.
├── file_scanner.py               # Per-file scanning (line patterns, structural walkers, Jinja2 AST, suppressions).
├── taint_tracker.py              # Cross-file taint analysis.
├── fix_proposer.py               # Dry-run unified-diff patches for --fix.
├── dependency_collector.py       # Builds the SBOM component inventory from Ansible/Galaxy/pip/bindep/EE manifests.
├── _ast_helpers.py               # Shared YAML walkers used by the above.
├── patterns_manager.py           # YAML plugin loader + SecurityPattern (with cached compiled regex)
├── patterns/*.yml                # Every shipped detection rule
├── remediations/
│   ├── remediation_generator.py  # Dispatch - one entry per category
│   ├── _category_map.py          # rule_id -> category lookup + keyword fallback
│   └── <category>.py             # Per-category fix renderers
├── formatters/                   # Markdown, JSON, SARIF, CycloneDX, ...
├── comment.py               # GitHub/GitLab MR/PR commenter (env-only platform detection, httpx clients, marker-based edit-in-place, Dashboard+Drilldown renderer).
└── utils.py                      # Argument helpers, logging setup, exit codes
```

## 8. Getting help

- Check existing patterns in `src/ansible_security_scanner/patterns/`
  for examples.
- Open a GitHub issue if you're unsure whether a change is in scope.
- Look at the test files in `tests/` for the expected shape of a
  new regression test.

Happy contributing.
