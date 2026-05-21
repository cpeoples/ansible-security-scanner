# MR / PR Comments

Post (or update) a concise, reviewer-friendly findings summary on the current
pull request (GitHub) or merge request (GitLab). The comment is **edited in
place** on every subsequent scan of the same branch - no comment threads, no
duplicate noise - and flips to a "All security findings resolved" banner
(citing how many findings were cleaned up and which rule IDs) once the MR is
clean.

## Key properties

- **Platform is detected from CI env vars only.** No config file, no flag, no
  network probe - just `GITHUB_ACTIONS` / `GITHUB_REPOSITORY` / `GITHUB_REF`
  (GitHub) or `CI_SERVER_URL` / `CI_PROJECT_ID` / `CI_MERGE_REQUEST_IID`
  (GitLab).
- **Self-hosted GitLab / GitHub Enterprise is transparent.** The scanner
  reads `CI_SERVER_URL` / `GITHUB_SERVER_URL` and talks to that API endpoint -
  works against on-prem instances out of the box.
- **Tokens come from env vars only.** Never from CLI flags or config - so
  tokens never land in shell history, CI logs, or a stray `--help`. The
  scanner looks for `GITHUB_TOKEN` / `GH_TOKEN` (or a scanner-specific
  `ANSIBLE_SEC_SCANNER_GITHUB_TOKEN`) on GitHub, and `GITLAB_TOKEN` /
  `CI_JOB_TOKEN` (or `ANSIBLE_SEC_SCANNER_GITLAB_TOKEN`) on GitLab.
- **Scan is auto-scoped to the MR's changed files** by default, so the
  comment only talks about files the MR actually touches. Override with
  `--no-mr-comment-scope-changed-files` to scan the full `--directory` inside
  an MR pipeline.
- **Big MRs degrade gracefully.** A Dashboard + Drilldown renderer keeps
  comments under GitHub's 65 536-character limit even on thousand-finding
  MRs: the top rules get full detail, the rest collapse into a summary line
  pointing at the artifact report.
- **Warn-and-continue.** A flaky API call or missing env var logs a warning
  and returns - the scanner's exit code stays driven by findings, never by
  comment-posting failures.
- **Full-report artifact is always written** to
  `security-reports/report.md` (overridable with
  `--mr-comment-full-report PATH`). The MR comment links to this artifact so
  reviewers can click through from the dashboard view.

Short aliases (`--gh-comment` / `--gl-comment`) are equivalent to the long
forms and exist because CI YAML tends to be long enough already.

## GitHub Actions

```yaml
on:
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write       # required to POST/PATCH the comment
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install ansible-security-scanner
      - name: Ansible Security Scan (+ PR comment)
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: ansible-security-scanner --gh-comment --directory ansible/
      - name: Upload full report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ansible-security-full-report
          path: security-reports/report.md
```

## GitLab CI (works on self-hosted - uses `CI_SERVER_URL`)

```yaml
ansible-security-scan:
  stage: test
  image: python:3.12-slim
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - pip install ansible-security-scanner
    - ansible-security-scanner --gl-comment --directory ansible/
  artifacts:
    when: always
    paths:
      - security-reports/
    expire_in: 30 days
```

`CI_JOB_TOKEN` is exposed automatically by GitLab and is sufficient for
posting MR comments on most projects. Use a project access token
(`GITLAB_TOKEN`) if your instance restricts job-token MR access.

> **The `artifacts:` block above is required.** The "Full report" link in the
> MR comment resolves to
> `<CI_JOB_URL>/artifacts/file/security-reports/report.md`. Without an
> `artifacts:` declaration that uploads `security-reports/`, GitLab returns
> 404 for that URL because the file lives only on the runner's ephemeral
> disk and is discarded when the job ends. The file:line links in the
> comment also depend on the scan having run from the **repo root** (the
> default `before_script` working directory) - if you `cd` elsewhere
> before invoking the scanner, deep links will resolve against the wrong
> tree.

## Resolved-state example

When a scan finds zero findings **and** the previous scan on the same MR had
findings, the comment flips to a resolved banner:

> ### All security findings resolved
>
> **Security score:** 100 / 100 - review confidence: high
>
> **Resolved since last scan:** 3 findings (rules: `hardcoded_credentials`, `unpinned_container`, `missing_no_log`)

## Tuning

| Flag | Default | Purpose |
| --- | --- | --- |
| `--github-comment` / `--gh-comment` | off | Post/update a PR comment on GitHub. |
| `--gitlab-comment` / `--gl-comment` | off | Post/update an MR comment on GitLab. |
| `--mr-comment-full-report PATH` | `security-reports/report.md` | Where to write the full-report artifact the comment links to. |
| `--mr-comment-scope-changed-files` | on | Auto-scope the scan to the MR's changed YAML files. |
| `--no-mr-comment-scope-changed-files` | - | Opt out of scoping; scan the full `--directory`. |
| `--inline-comments` | off | Also post per-finding inline review threads (file-level for off-diff findings). |
| `--no-inline-comments` | - | Disable inline review threads (default). |

## Inline review threads (optional)

When `--inline-comments` is passed alongside `--gitlab-comment` /
`--github-comment`, the scanner posts a per-finding inline review
thread on each offending diff line, in addition to the summary
comment.

### Body shape

Two body shapes are emitted, depending on whether the thread is
anchored to a diff line:

- **Anchored threads** include the rule header, the full description,
  the full recommendation prose, a `<details>` block with the
  remediation example (when the rule ships one), a `<details>` block
  with compliance-framework links, and the resolution disclaimer.
  The platform renders the diff hunk itself above the comment
  (green/red line markers, surrounding context), so we do not
  duplicate it as a fenced YAML block.
- **File-level threads** (off-diff findings, or anchored posts the
  platform rejected) carry the same enriched body as anchored threads
  *plus* a fenced YAML snippet of the offending code, since there's
  no rendered diff above to provide context.

Both shapes end with the resolution-semantics disclaimer:

> *Resolving this thread does not unblock the pipeline. The scan
> re-runs on every push and will close fixed-finding threads
> automatically.*

GitLab and GitHub do not expose a way to suppress the per-thread
"Resolve thread" button on MR/PR diff discussions (the `resolvable`
attribute is a read-only response field, not a request parameter).
The disclaimer makes the button's actual semantics explicit:
resolving locally is bookkeeping only - the CI gate is driven by
re-running the scan, not by thread state.

### Anchor-first with file-level fallback

The scanner asks the platform to anchor the thread on
`(file_path, line_number)` for every finding whose file is in the MR's
changed-files list. If the platform rejects the anchor (line not in the
diff per the platform's view, file renamed in a way the position
payload can't express, etc.) the thread is automatically retried as a
file-level comment. Findings whose file isn't in the MR's diff at all
go straight to file-level.

The platform is the source of truth. The scanner does not maintain a
client-side cache of which lines are in the diff: that approach was
brittle (truncated `/changes` responses, rename detection, hunk-header
parsing edge cases, scan-directory vs repo-root path mismatches) and
caused on-diff findings to silently post as file-level when the
client-side hint disagreed with the platform. With the platform as
the only authority, the worst case is one wasted POST per off-diff
finding, which auto-falls-back transparently.

### Path normalization

Findings carry `file_path` relative to the scanner's `--directory`
argument; the MR/PR diff is always repo-root-relative. The scanner
rewrites finding paths to repo-root-relative before posting so the
two views line up. Without this normalization, every finding under a
non-root `--directory` would land in the file-level fallback path.

### Summary-comment changes

The summary comment in inline mode skips the per-finding code
snippets and the "Show recommended fix" expander (those live in the
inline threads). Locations, counts, severity dots, and the fix hint
remain.

### On re-runs

- threads whose finding still exists are skipped,
- threads whose finding has disappeared are resolved,
- new findings post new threads.

### APIs used

- **GitLab** [Discussions API][gl-discussions]:
  `POST /merge_requests/:iid/discussions` (with a `position` payload
  for line anchors), `PUT .../discussions/:id` to resolve. Changed
  files come from `GET /merge_requests/:iid/changes`.
- **GitHub** GraphQL `addPullRequestReviewThread` /
  `resolveReviewThread`. The v3 REST review-comment endpoint can't
  anchor file-level threads, so GraphQL is used for both shapes.
  Changed files come from `GET /repos/:owner/:repo/pulls/:n/files`.

### Operational notes

- Capped at 50 threads per run. HTTP failures are non-fatal and
  don't affect the scanner's exit code.
- The summary log line reports `posted=N (anchored=A file_level=F
  fallback=R) skipped=S resolved=X failed=Y capped=C`. A non-zero
  `fallback` count is normal and indicates the platform rejected
  some anchor positions; a non-zero `failed` count is worth
  investigating (5xx, network errors, or fallback also failed).
- 4xx responses on anchored posts trigger the file-level retry and
  are logged at INFO with the platform's response body so reviewers
  can see exactly *why* the anchor was rejected. 5xx / transport
  errors do not retry (those are usually transient).

[gl-discussions]: https://docs.gitlab.com/ee/api/discussions.html
