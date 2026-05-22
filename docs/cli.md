# CLI Reference

```
ansible-security-scanner [OPTIONS]

Scan:
  -d, --directory DIR             Directory to scan (default: .)
  --files FILE [FILE ...]         Scan specific files only
  --changed-files VAR             Scan only changed files (CI/CD variable or list)
  --allowlist PATH                Path to allowlist YAML
                                  (default: .security-scanner-allowlist.yml)

Output:
  -f, --format FORMAT             markdown | json | xml | yaml | csv | html
                                  | junit | sarif | gl-sast | cyclonedx | sbom
                                  (inferred from --output extension if omitted)
  -o, --output FILE               Save report to file (default: console)
  --output-per-file               Write one report per scanned YAML file instead
                                  of one aggregate. --output must be a directory;
                                  defaults to ./security-reports/ if omitted.
                                  Scanned paths are preserved under the output
                                  dir and suffixed with the format's canonical
                                  extension (e.g. roles/web/tasks.yml ->
                                  roles/web/tasks.yml.md). Not supported with
                                  cyclonedx/sbom (aggregate-only).
  --exit-zero                     Always exit 0 (report but don't fail builds)
  -v, --verbose                   Enable debug logging

Engine upgrades (opt-in):
  --fix                           Dry-run autofix: annotate findings with a
                                  unified diff patch for high-confidence rules
                                  (no files are modified)
  --fix-output PATH               With --fix: write the concatenated patches to
                                  a file for easy review in `git apply --check`

  --scan-git-history              Scan historical versions of tracked files for
                                  leaked secrets
  --git-history-max-commits N     With --scan-git-history: limit history depth
                                  (default 50)

  --compliance TAG[,TAG...]       Filter findings to specific CIS control tags
  --compliance list               Print every compliance tag the rule bundle
                                  exposes

  --dedup-across-files            Collapse identical findings (same rule + same
                                  normalized snippet) across multiple files into
                                  a single representative finding. Other
                                  affected locations are preserved on the
                                  representative's `duplicates` list (visible in
                                  JSON / YAML / SARIF / Markdown / HTML).

Suppression controls (inline, on-line):
  --show-suppressed               Include suppressed findings in the report
                                  (default: hidden)
  --no-suppressions               Ignore every inline `# nosec` / `# noqa`
                                  directive - for release gates and audit runs
                                  where authors cannot silence findings
  --fail-on-suppressed            Non-zero exit if *any* finding in the tree is
                                  suppressed
  --max-suppressions N            Non-zero exit if more than N findings are
                                  suppressed (budget gate)

Filtering & performance:
  --severity LEVEL                Filter the report to findings at or above
                                  LEVEL (CRITICAL > HIGH > MEDIUM > LOW).
                                  Default: no filter. Exit codes still gate on
                                  HIGH / CRITICAL regardless of this flag.
  --select RULE[,RULE...]         Run ONLY the listed rules. Accepts comma-
                                  separated rule_ids and fnmatch globs (e.g.
                                  `aws_*,hardcoded_password`). Filtering happens
                                  at scan time so single-rule runs are fast on
                                  large repos. Unknown rule_id -> exit 2.
  --ignore RULE[,RULE...]         Drop the listed rules from the scan. Same
                                  syntax as --select. When both flags are
                                  given, --select defines the universe and
                                  --ignore carves out of it.
  --list-rules                    Print every known rule_id (one per line,
                                  sorted) and exit. Pipe-friendly: header goes
                                  to stderr, rule_ids to stdout. Combine with
                                  `grep` / `fzf` to discover what to --select.
  --list-rules-detailed           Like --list-rules but emits a TSV of
                                  `rule_id<TAB>severity<TAB>category<TAB>title`
                                  so operators can disambiguate findings whose
                                  display title is shared by more than one
                                  rule_id. Synthetic / code-emitted rule_ids
                                  carry `<synthetic>` placeholders for
                                  severity/category/title.
  --jobs N, -j N                  Run the per-file scan stage on N worker
                                  threads (default: 1 = sequential). The
                                  downstream sort makes the final report
                                  bit-for-bit identical to a serial run, so
                                  safe to set high (e.g. 4-8) on large repos.

MR / PR commenting (CI/CD):
  --github-comment, --gh-comment  Post/update a concise findings summary on the
                                  current GitHub PR. Must run in a pull_request
                                  workflow. Token: GITHUB_TOKEN / GH_TOKEN /
                                  ANSIBLE_SEC_SCANNER_GITHUB_TOKEN.
  --gitlab-comment, --gl-comment  Post/update a concise findings summary on the
                                  current GitLab MR. Must run in a
                                  merge_request_event pipeline. Works against
                                  self-hosted instances via CI_SERVER_URL.
                                  Token: GITLAB_TOKEN / CI_JOB_TOKEN /
                                  ANSIBLE_SEC_SCANNER_GITLAB_TOKEN.
  --mr-comment-full-report PATH   Full-report artifact location
                                  (default: security-reports/report.md).
                                  The MR comment links to this file.
  --no-mr-comment-scope-changed-files
                                  Disable the default "scan only the MR's
                                  changed YAML files" behaviour - scan the full
                                  --directory even inside an MR pipeline.
  --inline-comments               Also post per-finding inline review threads
                                  on each offending diff line (GitLab
                                  Discussions API / GitHub GraphQL). Off-diff
                                  findings fall back to file-level threads.
                                  Idempotent on re-runs.
  --no-inline-comments            Disable inline review threads (default).
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | No CRITICAL or HIGH findings (or `--exit-zero` passed) |
| 1    | One or more HIGH-severity findings |
| 2    | One or more CRITICAL findings, a suppression-gate failure, or a CLI-usage error (e.g. `--output` would overwrite an input file, `--output-per-file` used with `cyclonedx`) |

## Multi-file Ansible projects

The scanner is designed for realistic multi-file Ansible trees - playbooks,
roles, `group_vars/`, `host_vars/`, inventory files, Jinja2 templates (`*.j2`),
`ansible.cfg`, `requirements.yml`, `meta/main.yml`, `execution-environment.yml`,
and `bindep.txt` are all auto-discovered and routed to the correct rule set.

Cross-file analysis is turned on by default:

- **Taint tracking** - a secret registered in `vars/secrets.yml` is reported
  when it leaks into a `debug:` task in `tasks/show.yml`.
- **Dependency inventory** - a `requirements.yml` at the root plus a
  `meta/main.yml` inside `roles/web/` both contribute to the same SBOM.
- **Jinja2 AST** - templates embedded in playbooks (`{{ ... }}`) and standalone
  `.j2` files are both parsed with Jinja2's native AST for precision that pure
  regex can't match.

## Inline suppressions

Suppress a specific rule on a specific line with a trailing comment:

```yaml
- name: legacy bootstrap (will be replaced in Q3)
  ansible.builtin.shell: curl http://legacy.example.com/setup.sh | bash
  # nosec: curl_pipe_to_shell reason="CHG-12345 tracked deprecation, removal in v3"
```

Rules:

- A rule id (or `*`) is **required** - bare `# nosec` is rejected and surfaced
  as a scanner warning.
- A quoted `reason="..."` is **required** - unreasoned suppressions are rejected.
- Critical-severity rules (credential harvesting, reverse shells, RCE
  primitives, privilege escalation) are **unsuppressable**; the directive is
  ignored and a `suspicious_suppression` meta-finding fires.
- Every suppressed finding still appears in the report with
  `suppressed_by=<rule>:<reason>` metadata, so auditors can trace what got
  muted and why.
- Legacy aliases `# security-scan:ignore` and `# ansible-security:ignore` are
  still accepted.

## Cross-file finding deduplication

Real-world Ansible repos often contain families of near-identical
"fork-variant" playbooks - for example, `deploy.yml`, `deploy_cloud.yml`, and
`deploy_alt.yml` share almost every task verbatim. Without help, the same
vulnerability (say, a literal `password: "Sup3rS3cr3t!"` on an
`ansible.builtin.uri` task) shows up as N separate findings - one per file -
which drowns out genuinely distinct issues.

Pass `--dedup-across-files` to collapse these into one representative finding
per `(rule_id, canonicalized-snippet)` pair. The other affected locations are
preserved on the finding's `duplicates` list - nothing is silently dropped.

```bash
ansible-security-scanner --directory ansible/ --dedup-across-files \
    --format json --output findings.json
```

Each finding in the output now carries:

```jsonc
{
  "file_path": "deploy.yml",          // the representative location
  "line_number": 187,
  "rule_id": "hardcoded_password",
  "code_snippet": "password: \"Sup3rS3cr3t!\"",
  "duplicates": [                     // every other affected call site
    { "file_path": "deploy_cloud.yml", "line_number": 187 },
    { "file_path": "deploy_alt.yml",   "line_number": 187 }
  ]
}
```

How the formatters surface duplicates:

- **JSON / YAML** - `duplicates` is emitted alongside other finding fields.
- **Markdown / HTML** - a collapsed *"Also affects N other location(s)"*
  toggle appears under each CRITICAL / HIGH finding; expanding it lists every
  sibling `file:line` pair.
- **SARIF** - each duplicate becomes an additional entry in the result's
  `locations[]` array (the representative is always `locations[0]`).

Off by default - existing consumers that want one-finding-per-location
behaviour keep it.

## Cross-rule overlap suppression (automatic)

In addition to file-level dedup, the scanner runs a *rule-level* overlap pass
on every scan so two distinct rules don't double-report the same vulnerability
at the same location. For example, when a line matches both
`curl_pipe_to_shell` (generic) and `raw_github_script_exec` (more specific),
only the latter is emitted. The groupings are maintained in
`_OVERLAP_SUPPRESSION_GROUPS` in
[`file_scanner.py`](../src/ansible_security_scanner/file_scanner.py). This is
on by default; there is no flag - it's a correctness guarantee, not an
opt-in.
