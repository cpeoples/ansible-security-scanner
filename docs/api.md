# Python API

The package exposes a stable Python API for callers that want to embed the
scanner instead of shelling out. Everything in `ansible_security_scanner.__all__`
is considered public surface and follows semantic versioning.

This page is the full reference. For day-to-day CLI usage see
[CLI Reference](cli.md); for output shapes see [Output Formats](output-formats.md).

---

## Quick start

```python
from ansible_security_scanner import AnsibleSecurityScanner, JSONFormatter

scanner = AnsibleSecurityScanner(directory="ansible/")
report = scanner.scan_directory()

print(f"{len(report.findings)} findings; score {report.security_score.overall_score}/100")
print(JSONFormatter().format(report))
```

Two things to notice:

* `scanner.scan_directory()` returns a `ScanReport` dataclass — never `None`,
  never an exception for a clean scan. Failures during file parsing become
  `scan_error` findings inside the report rather than raised exceptions.
* Formatters expose `format(report) -> str` (not `format_report`). The
  output is a fully self-contained string ready to write to a file or pipe.

---

## Public surface (re-exported from `ansible_security_scanner`)

| Symbol | Kind | What it is |
|---|---|---|
| `AnsibleSecurityScanner` | class | The orchestrator. Constructed with scan options, returns a `ScanReport` from `scan_directory()`. |
| `ScanReport`, `SecurityFinding`, `SecurityScore` | dataclass | Result types. See [Data models](#data-models). |
| `MarkdownFormatter`, `JSONFormatter`, `XMLFormatter`, `YAMLFormatter`, `CSVFormatter`, `HTMLFormatter`, `JUnitFormatter`, `SARIFFormatter`, `GitLabSastFormatter`, `CycloneDXFormatter` | class | Shipped formatters. Each is a subclass of `OutputFormatter` (`from ansible_security_scanner.formatters import OutputFormatter`) with a `format(report) -> str` method. |
| `RemediationGenerator` | class | Renders a per-finding remediation block. |
| `FixProposer` | class | Generates unified-diff autofix patches for high-confidence rules (used internally when `fix_mode=True`). |
| `TaintTracker` | class | Cross-file variable-flow tracker; usually constructed by the scanner, not directly. |
| `DependencyCollector` | class | Builds the SBOM component list from `requirements.yml`, `meta/main.yml`, `execution-environment.yml`, `bindep.txt`. |
| `FileScanner`, `VariableExtractor`, `ScoreCalculator` | class | Lower-level building blocks; useful for custom formatters or test harnesses. |
| `patterns_manager` | module-level singleton | The pattern registry. Use `patterns_manager.discover_and_load_patterns()` to enumerate every shipped rule grouped by category. |
| `parse_changed_files`, `setup_logging`, `get_formatter_class`, `get_exit_code` | function | CLI helpers exposed for embedding scenarios. |
| `main` | function | The CLI entry point as if invoked from the shell — `main(["scan", "playbooks/"])`. |
| `__version__` | str | The package version (PEP 440). |

Symbols that live one level deeper and are also part of the public contract:

| Import | Purpose |
|---|---|
| `from ansible_security_scanner.patterns_manager import SecurityPattern, RuleSelectionError, resolve_rule_specs, known_rule_ids, filter_patterns` | Pattern object, glob/literal rule selection, error type |
| `from ansible_security_scanner.link_resolver import FrameworkReference, resolve_cwe, resolve_mitre, resolve_atlas, resolve_cis, resolve_nist, resolve_pci, resolve_hipaa, resolve_soc2, resolve_stig, resolve_owasp_appsec, resolve_owasp_llm, resolve_owasp_asvs, resolve_cve, resolve_all, known_ids` | Turn raw framework IDs into deep-link records |
| `from ansible_security_scanner.formatters import OutputFormatter, ReportEmojis` | Base class for custom formatters |

---

## `AnsibleSecurityScanner`

Construction options (all keyword-only after `directory`/`target_files`/`allowlist_path`/`show_suppressed`):

```python
AnsibleSecurityScanner(
    directory: str = ".",
    target_files: list[str] | None = None,
    allowlist_path: str | None = None,
    show_suppressed: bool = False,
    *,
    disable_suppressions: bool = False,
    fail_on_suppressed: bool = False,
    max_suppressions: int | None = None,
    fix_mode: bool = False,
    scan_git_history: bool = False,
    git_history_max_commits: int = 50,
    jobs: int = 1,
    dedup_cross_file: bool = False,
    select_rules: Iterable[str] | None = None,
    ignore_rules: Iterable[str] | None = None,
)
```

| Argument | Type | Default | Effect |
|---|---|---|---|
| `directory` | `str` | `"."` | Scan root. Walks recursively for `*.yml`, `*.yaml`, `*.j2`, `*.cfg`. Dot-prefixed files are excluded unless explicitly listed in `target_files`. |
| `target_files` | `list[str]` \| `None` | `None` | If set, only these paths are scanned (resolved against `directory`). |
| `allowlist_path` | `str` \| `None` | `None` | Path to allowlist YAML. See [Allowlist](allowlist.md). |
| `show_suppressed` | `bool` | `False` | Surface findings hidden by inline `# nosec` / `# noqa` directives. |
| `disable_suppressions` | `bool` | `False` | Ignore every suppression directive in the tree. Release-gate mode. |
| `fail_on_suppressed` | `bool` | `False` | Sets `report.suppressed_gate_failed = True` if any finding was suppressed. |
| `max_suppressions` | `int` \| `None` | `None` | Sets the gate flag if more than N suppressions occurred. |
| `fix_mode` | `bool` | `False` | Attach unified-diff autofix patches to each finding's `fix_patch` when a rule supports it. |
| `scan_git_history` | `bool` | `False` | Also scan past commits for leaked secrets. |
| `git_history_max_commits` | `int` | `50` | Commit horizon when `scan_git_history=True`. |
| `jobs` | `int` | `1` | Worker threads for the per-file scan pass. Findings are sorted downstream so the report is bit-for-bit equivalent regardless of `jobs`. |
| `dedup_cross_file` | `bool` | `False` | Collapse findings sharing `(rule_id, normalized-snippet)` across files. Sibling locations are preserved on `finding.duplicates`. |
| `select_rules` | `Iterable[str]` \| `None` | `None` | Whitelist of rule IDs / fnmatch globs (also accepts comma-separated strings). Unknown IDs raise `RuleSelectionError` at construction time. |
| `ignore_rules` | `Iterable[str]` \| `None` | `None` | Blacklist applied after `select_rules`. Same syntax. |

### `scan_directory() -> ScanReport`

Runs the full pipeline and returns a populated [`ScanReport`](#scanreport).
Never raises for scanning errors — file-level failures are surfaced as
synthetic `scan_error` findings inside the report so a single broken
playbook does not abort the whole run.

```python
scanner = AnsibleSecurityScanner(
    directory="ansible/",
    select_rules=["aws_*", "hardcoded_password"],
    ignore_rules="curl_pipe_to_shell",
    jobs=4,
    fix_mode=True,
)
report = scanner.scan_directory()

for f in report.findings:
    print(f.severity, f.rule_id, f.file_path, f.line_number)
    if f.fix_patch:
        print(f.fix_patch)
```

---

## Data models

All result types are plain `@dataclass` instances — they pickle, JSON-serialise
(via `dataclasses.asdict`), and are safe to inspect or mutate after a scan.

### `ScanReport`

`from ansible_security_scanner import ScanReport`

| Field | Type | Notes |
|---|---|---|
| `scan_timestamp` | `str` | ISO-8601 UTC timestamp of when the scan began. |
| `ansible_directory` | `str` | The `directory` argument passed to the scanner. |
| `total_files_scanned` | `int` | Count of files actually opened and scanned. |
| `scanned_file_names` | `list[str]` | Resolved paths of every file scanned. |
| `findings` | `list[SecurityFinding]` | Every finding (including synthetic ones like `scan_error` and `cross_file_taint`). Already sorted by severity then file then line. |
| `summary` | `dict[str, int]` | Counts keyed by lowercased severity: `{"critical": int, "high": int, "medium": int, "low": int, "info": int, "total": int}`. |
| `security_score` | `SecurityScore` | Aggregate score breakdown (see below). |
| `suppressed_count` | `int` | Number of findings suppressed by inline `# nosec` / `# noqa`. |
| `suppression_warnings` | `list[str]` | Warnings about suspicious suppressions detected during the scan. |
| `suppressed_gate_failed` | `bool` | `True` if `fail_on_suppressed=True` or `max_suppressions` was exceeded. |
| `components` | `list[dict[str, str]]` | Dependency inventory used by the CycloneDX SBOM formatter (Galaxy collections, roles, pip packages, bindep packages, EE base images). |

### `SecurityScore`

`from ansible_security_scanner import SecurityScore`

| Field | Type | Notes |
|---|---|---|
| `overall_score` | `float` | 0–100, where 100 is clean. |
| `risk_score` | `float` | 0–100, the inverse of `overall_score` (higher = riskier). |
| `category_scores` | `dict[str, float]` | Per-category score (e.g. `"command_injection"`, `"hardcoded_credentials"`). |
| `severity_breakdown` | `dict[str, int]` | Same shape as `ScanReport.summary` but emitted by the calculator. |
| `file_scores` | `dict[str, float]` | Per-file score keyed by resolved path. |
| `recommendations_count` | `int` | Total recommendations across findings (used by Markdown/HTML reports). |

See [Scoring](scoring.md) for how the numbers are computed.

### `SecurityFinding`

`from ansible_security_scanner import SecurityFinding`

The richest object in the report. Core identification:

| Field | Type | Notes |
|---|---|---|
| `file_path` | `str` | Relative path of the file containing the finding. |
| `line_number` | `int` | 1-indexed line. `0` for findings that don't bind to a single line (e.g. file-level metadata findings). |
| `rule_id` | `str` | Stable identifier — what `select_rules` / `ignore_rules` and inline `# nosec rule_id` match against. |
| `severity` | `str` | One of `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"INFO"`. |
| `title` | `str` | Short headline. |
| `description` | `str` | Multi-paragraph explanation safe for Markdown rendering. |
| `recommendation` | `str` | What to do about it. |
| `code_snippet` | `str` | The matched line(s) verbatim (already redacted for credential rules). |
| `remediation_example` | `str` | A correct rewrite of the snippet. |

Framework enrichment (all default to `[]`; lists of canonical IDs that resolve
through [`link_resolver`](#framework-deep-link-resolvers)):

| Field | Catalog |
|---|---|
| `cwe` | CWE — `["CWE-78", "CWE-494"]` |
| `mitre_attack` | MITRE ATT&CK Enterprise — `["T1059.004"]` |
| `mitre_atlas` | MITRE ATLAS (AI/ML) — `["AML.T0051.000"]` |
| `cis_controls` | CIS Controls / Ansible Benchmark — `["CIS-4.1"]` |
| `nist_controls` | NIST 800-53 — `["AC-3", "AC-6(9)"]` |
| `pci_dss` | PCI-DSS v4 — `["3.5.1"]` |
| `hipaa` | HIPAA §164 — `["164.312(a)(1)"]` |
| `soc2` | SOC 2 TSC — `["CC6.1"]` |
| `stig` | DISA STIG Vulnerability IDs — `["V-230221"]` |
| `owasp_appsec` | OWASP Top 10 (2021/2017) — `["A03:2021"]` |
| `owasp_llm` | OWASP LLM Top 10 — `["LLM01"]` |
| `owasp_asvs` | OWASP ASVS v5.0.0 — `["V13.3.1"]` |
| `cve` | CVE — `["CVE-2024-3094"]` |

Other metadata:

| Field | Type | Notes |
|---|---|---|
| `references` | `list[str]` | Free-form URLs to advisories, blog posts, vendor docs. |
| `help_uri` | `str` | Single canonical help URL (used as SARIF `helpUri`). |
| `precision` | `str` | SARIF precision: `"very-high"` \| `"high"` \| `"medium"` \| `"low"`. Default `"high"`. |
| `fix_patch` | `str` | Unified-diff patch when `fix_mode=True` and the rule supports autofix; `""` otherwise. |
| `suppressed_by` | `str` | The directive that suppressed the finding (only populated when `show_suppressed=True`). |
| `duplicates` | `list[dict]` | When `dedup_cross_file=True`, sibling locations as `[{"file_path": ..., "line_number": ...}, ...]`. |

---

## Pattern selection

Rule selection happens in three layers, all importable from
`ansible_security_scanner.patterns_manager`:

```python
from ansible_security_scanner.patterns_manager import (
    SecurityPattern,
    RuleSelectionError,
    resolve_rule_specs,
    known_rule_ids,
    filter_patterns,
    patterns_manager,
)
```

### `known_rule_ids() -> frozenset[str]`

Returns every rule ID the scanner can possibly emit — the union of every
rule loaded from the YAML pattern files plus the synthetic IDs registered
in `synthetic_rule_frameworks` (`cross_file_taint`, `scan_error`,
`suspicious_suppression`).

```python
ids = known_rule_ids()
print(len(ids), "rules total")
print(sorted(r for r in ids if r.startswith("aws_")))
```

### `resolve_rule_specs(specs, known_rule_ids) -> frozenset[str]`

Resolves a mix of literal IDs, fnmatch globs, and comma-separated tokens
into a concrete set of matched rule IDs. Each spec is matched
independently — a glob in one spec does **not** rescue a typo in
another. Unknown specs raise `RuleSelectionError`.

```python
universe = known_rule_ids()
selected = resolve_rule_specs(["aws_*", "hardcoded_password"], universe)
# selected == frozenset({"aws_secret_access_key", "aws_access_key_id", ..., "hardcoded_password"})

resolve_rule_specs(["typo_does_not_exist"], universe)
# raises RuleSelectionError
```

### `RuleSelectionError`

`ValueError` subclass; surfaces user typos at construction time rather
than partway through a scan. The CLI maps it to exit code 2.

### `filter_patterns(pattern_data, *, select=None, ignore=None) -> dict[str, list[SecurityPattern]]`

Pure function; never mutates its input. Useful when running the scanner
internals directly:

```python
from ansible_security_scanner.patterns_manager import patterns_manager, filter_patterns

all_patterns = patterns_manager.discover_and_load_patterns()
narrowed = filter_patterns(all_patterns, select=frozenset({"hardcoded_password"}))
```

### `SecurityPattern`

The dataclass that backs every YAML rule. Selected fields:

| Field | Type | Notes |
|---|---|---|
| `id`, `severity`, `title`, `description`, `regex`, `recommendation`, `category` | `str` | Core. |
| `plugin_name`, `plugin_version` | `str` | Pattern-file metadata. |
| `cwe`, `mitre_attack`, `mitre_atlas`, `cis_controls`, `nist_controls`, `pci_dss`, `hipaa`, `soc2`, `stig`, `owasp_appsec`, `owasp_llm`, `owasp_asvs`, `cve` | `list[str]` | Framework enrichment. |
| `references`, `help_uri`, `precision` | docs hooks |
| `multiline`, `window` | `bool`, `int` | Multi-line scan window for cross-task regexes. |
| `positive_examples`, `negative_examples` | `list[str]` | Self-test corpus enforced by `tests/test_pattern_examples.py`. |

---

## Framework deep-link resolvers

Every framework taxonomy on a finding (CWE, MITRE ATT&CK, ATLAS, CIS, NIST,
PCI-DSS, HIPAA, SOC 2, STIG, OWASP App-Sec / LLM / ASVS, CVE) can be
turned into a structured record with a display name and canonical URL.

```python
from ansible_security_scanner.link_resolver import (
    FrameworkReference,
    resolve_cwe, resolve_mitre, resolve_atlas, resolve_cis,
    resolve_nist, resolve_pci, resolve_hipaa, resolve_soc2,
    resolve_stig, resolve_owasp_appsec, resolve_owasp_llm,
    resolve_owasp_asvs, resolve_cve,
    resolve_all, known_ids,
)
```

The catalogs are loaded once per process from
`src/ansible_security_scanner/frameworks/*.yml`. No network, no runtime
fetching.

### `FrameworkReference`

Frozen dataclass returned by every resolver:

| Field | Type | Notes |
|---|---|---|
| `framework` | `str` | Display name — `"CWE"`, `"MITRE ATT&CK"`, `"OWASP LLM Top 10"`, etc. |
| `id` | `str` | Canonical ID (resolvers normalise spelling — `cwe-78`, `CWE_78`, `cwe 78` all collapse to `CWE-78`). |
| `name` | `str` | Human-readable name. |
| `url` | `str` | Canonical deep-link URL. |
| `extras` | `dict[str, str]` | Catalog-specific metadata — e.g. MITRE `tactics`, CIS `control` family. |

### Single-framework resolvers

Every resolver returns `FrameworkReference | None` and is tolerant of
sloppy input. `None` means "not in the catalog"; CVE is the lone
exception — any well-formed `CVE-YYYY-NNNN` synthesises a
`https://nvd.nist.gov/vuln/detail/...` reference rather than failing
closed.

```python
ref = resolve_mitre("T1059.007")
print(ref.framework, ref.id, ref.url)
# MITRE ATT&CK T1059.007 https://attack.mitre.org/techniques/T1059/007/

resolve_cwe("cwe-78").url
# 'https://cwe.mitre.org/data/definitions/78.html'

resolve_cve("CVE-2024-3094").url
# 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094'

resolve_mitre("T9999.999")  # unknown technique
# None
```

### `resolve_all(...)`

Convenience for resolving every framework on a finding in one call:

```python
from ansible_security_scanner.link_resolver import resolve_all

refs = resolve_all(
    cwe_ids=finding.cwe,
    mitre_ids=finding.mitre_attack,
    atlas_ids=finding.mitre_atlas,
    cis_ids=finding.cis_controls,
    nist_ids=finding.nist_controls,
    pci_ids=finding.pci_dss,
    hipaa_ids=finding.hipaa,
    soc2_ids=finding.soc2,
    stig_ids=finding.stig,
    owasp_appsec_ids=finding.owasp_appsec,
    owasp_llm_ids=finding.owasp_llm,
    owasp_asvs_ids=finding.owasp_asvs,
    cve_ids=finding.cve,
)
for r in refs:
    print(f"[{r.framework}] {r.id}: {r.url}")
```

Unknown IDs are silently dropped (fail-closed). The framework-catalog
test in `tests/test_framework_catalog.py` guarantees zero in-repo drops,
so a `None` here means the ID came from an external pattern.

### `known_ids() -> dict[str, frozenset]`

Returns the set of catalogued IDs per framework slug (`"cwe"`,
`"mitre_attack"`, `"mitre_atlas"`, `"cis_controls"`, `"nist_800_53"`,
`"pci_dss"`, `"hipaa"`, `"soc2"`, `"stig"`, `"owasp_appsec"`,
`"owasp_llm"`, `"owasp_asvs"`, `"cve"`). Used by tests; useful for
building dashboards or coverage reports.

---

## Custom formatters

Every shipped formatter extends `OutputFormatter`:

```python
from ansible_security_scanner.formatters import OutputFormatter, ReportEmojis

class OutputFormatter:
    def __init__(self, show_all: bool = False): ...
    def format(self, report: ScanReport) -> str: ...   # subclasses override
```

The contract is intentionally minimal: `format(report) -> str`. Anything
the formatter needs (file metadata, framework deep links, scoring
detail) it can read off the dataclass directly.

### Recipe — Slack-style summary

```python
from ansible_security_scanner import AnsibleSecurityScanner
from ansible_security_scanner.formatters import OutputFormatter

class SlackFormatter(OutputFormatter):
    def format(self, report) -> str:
        criticals = [f for f in report.findings if f.severity == "CRITICAL"]
        if not criticals:
            return ":white_check_mark: No critical findings."
        lines = [f":rotating_light: *{len(criticals)} CRITICAL findings*"]
        for f in criticals[:10]:
            lines.append(f"- `{f.rule_id}` in `{f.file_path}:{f.line_number}`")
        return "\n".join(lines)

report = AnsibleSecurityScanner(directory="ansible/").scan_directory()
print(SlackFormatter().format(report))
```

### Recipe — emit framework deep links per finding

```python
from ansible_security_scanner.formatters import OutputFormatter
from ansible_security_scanner.link_resolver import resolve_all

class EnrichedJSONLFormatter(OutputFormatter):
    def format(self, report) -> str:
        import json
        out = []
        for f in report.findings:
            refs = resolve_all(
                cwe_ids=f.cwe, mitre_ids=f.mitre_attack, atlas_ids=f.mitre_atlas,
                cis_ids=f.cis_controls, nist_ids=f.nist_controls,
                pci_ids=f.pci_dss, hipaa_ids=f.hipaa, soc2_ids=f.soc2,
                stig_ids=f.stig, owasp_appsec_ids=f.owasp_appsec,
                owasp_llm_ids=f.owasp_llm, owasp_asvs_ids=f.owasp_asvs,
                cve_ids=f.cve,
            )
            out.append(json.dumps({
                "rule": f.rule_id,
                "severity": f.severity,
                "loc": f"{f.file_path}:{f.line_number}",
                "frameworks": [{"id": r.id, "url": r.url} for r in refs],
            }))
        return "\n".join(out)
```

---

## CI / gating recipes

### Programmatic CI gate

Everything you need to fail a CI job lives on the report. No need to
shell out to the CLI — embed the scanner and exit with the same codes
the CLI uses:

```python
import sys
from ansible_security_scanner import AnsibleSecurityScanner, get_exit_code

report = AnsibleSecurityScanner(
    directory=".",
    fail_on_suppressed=True,        # any inline # nosec -> gate fails
    max_suppressions=5,             # ... or more than 5 suppressions does
    select_rules=["aws_*", "hardcoded_*", "command_injection_*"],
).scan_directory()

if report.suppressed_gate_failed:
    print("Suppression gate failed", file=sys.stderr)
    sys.exit(2)

sys.exit(get_exit_code(report))
# get_exit_code: 2 if any CRITICAL, 1 if any HIGH, 0 otherwise.
# Pass exit_zero=True to always return 0 (advisory mode).
```

### Scan only changed files in a PR

`parse_changed_files` accepts the noisy outputs CI tends to produce
(newline-separated `git diff --name-only`, space-joined env vars,
comma-joined hand input) and filters to scannable extensions:

```python
import os
from ansible_security_scanner import (
    AnsibleSecurityScanner, parse_changed_files, JSONFormatter,
)

changed = parse_changed_files(os.environ.get("CHANGED_FILES", ""))
if not changed:
    print("No scannable files changed; skipping.")
    raise SystemExit(0)

report = AnsibleSecurityScanner(directory=".", target_files=changed).scan_directory()
print(JSONFormatter().format(report))
```

### Pick a formatter by name

The CLI's `--format` flag is backed by `get_formatter_class`, which is
also part of the public surface:

```python
from ansible_security_scanner import AnsibleSecurityScanner, get_formatter_class

report = AnsibleSecurityScanner(directory=".").scan_directory()
formatter_cls = get_formatter_class(os.environ.get("REPORT_FORMAT", "markdown"))
print(formatter_cls().format(report))
```

Accepted names: `markdown`, `json`, `xml`, `yaml`, `csv`, `html`,
`junit`, `sarif`, `gl-sast` / `gitlab-sast`, `cyclonedx` / `sbom`.
Unknown names raise `ValueError`.

---

## Advanced recipes

### Discover and introspect every shipped rule

```python
from ansible_security_scanner.patterns_manager import patterns_manager

for category, patterns in patterns_manager.discover_and_load_patterns().items():
    print(f"== {category} ({len(patterns)} rules)")
    for p in patterns:
        print(f"  {p.id:40s} {p.severity:8s} cwe={p.cwe} mitre={p.mitre_attack}")
```

### Iterate findings with autofix patches

```python
from ansible_security_scanner import AnsibleSecurityScanner

report = AnsibleSecurityScanner(directory=".", fix_mode=True).scan_directory()
for f in report.findings:
    if f.fix_patch:
        print(f"# Patch for {f.rule_id} at {f.file_path}:{f.line_number}")
        print(f.fix_patch)
```

`fix_patch` is a unified diff. To preview without writing, render it
with `difflib.HtmlDiff` or pipe through `git apply --check`.

### Inspect suppressions instead of silencing them

```python
report = AnsibleSecurityScanner(
    directory=".",
    show_suppressed=True,
    fail_on_suppressed=True,
).scan_directory()

for f in report.findings:
    if f.suppressed_by:
        print(f"SUPPRESSED: {f.rule_id} at {f.file_path}:{f.line_number}")
        print(f"  by: {f.suppressed_by}")

if report.suppression_warnings:
    print("Suspicious suppressions:")
    for w in report.suppression_warnings:
        print(f"  - {w}")

if report.suppressed_gate_failed:
    raise SystemExit("Gate failed: suppressions present.")
```

### Cross-file deduplication for fork-family repos

```python
report = AnsibleSecurityScanner(
    directory="forks/",
    dedup_cross_file=True,
).scan_directory()

for f in report.findings:
    if f.duplicates:
        print(f"{f.rule_id}: representative at {f.file_path}:{f.line_number}")
        for dup in f.duplicates:
            print(f"  - also at {dup['file_path']}:{dup['line_number']}")
```

### Serialise a `SecurityFinding` to JSON

Findings are plain dataclasses, so `dataclasses.asdict` is enough:

```python
import json
from dataclasses import asdict
from ansible_security_scanner import AnsibleSecurityScanner

report = AnsibleSecurityScanner(directory=".").scan_directory()
print(json.dumps([asdict(f) for f in report.findings[:5]], indent=2))
```

### Drive the CLI from Python

```python
from ansible_security_scanner import main

# Equivalent to: ansible-security-scanner -d ansible/ --format json --output report.json
main(["-d", "ansible/", "--format", "json", "--output", "report.json"])
```

`main` returns an integer exit code; it does not call `sys.exit` itself.

---

## Versioning & stability

* Anything in `ansible_security_scanner.__all__` follows semver: breaking
  changes bump the major version.
* `link_resolver` and `patterns_manager.{SecurityPattern,
  RuleSelectionError, resolve_rule_specs, known_rule_ids,
  filter_patterns}` are also part of the public contract.
* `OutputFormatter` (the formatter base class) is public; adding new
  optional methods is non-breaking, removing any is not.
* Names that start with an underscore, or live inside modules not listed
  on this page (`_ast_helpers`, `playbook_classifier`, etc.), are
  internal and may change without notice.
* `__version__` reflects the installed package; introspect it with
  `importlib.metadata.version("ansible-security-scanner")` if you need
  it without importing.
