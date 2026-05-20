# Environment Variables

The scanner reads the following environment variables. Tokens are *only* read
from env vars - never from CLI flags - so they never land in shell history,
CI logs, or `--help` output.

## Authentication (MR/PR commenting)

| Variable | Used by | Purpose |
|---|---|---|
| `ANSIBLE_SEC_SCANNER_GITHUB_TOKEN` | `--gh-comment` | Highest-precedence GitHub token. Use when you want a scanner-specific token separate from the workflow's default `GITHUB_TOKEN`. |
| `GITHUB_TOKEN` | `--gh-comment` | The default token GitHub Actions injects into every workflow. Needs `pull-requests: write`. |
| `GH_TOKEN` | `--gh-comment` | Alternative name some workflows use; same semantics as `GITHUB_TOKEN`. |
| `ANSIBLE_SEC_SCANNER_GITLAB_TOKEN` | `--gl-comment` | Highest-precedence GitLab token. |
| `GITLAB_TOKEN` | `--gl-comment` | Personal access token or project access token with `api` scope. |
| `CI_JOB_TOKEN` | `--gl-comment` | The token GitLab CI injects automatically. Works for the project's own MRs without extra setup. |

## Platform detection (set automatically by GitHub Actions / GitLab CI)

The scanner detects which platform it's running on by reading these. You don't
set them manually; they're populated by your CI runner.

| Variable | Platform | What it tells the scanner |
|---|---|---|
| `GITHUB_ACTIONS`, `GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_SHA`, `GITHUB_SERVER_URL`, `GITHUB_EVENT_PATH`, `GITHUB_RUN_ID` | GitHub | This is a GitHub Actions PR run. `GITHUB_SERVER_URL` makes GitHub Enterprise transparent. |
| `CI_SERVER_URL`, `CI_PROJECT_ID`, `CI_PROJECT_PATH`, `CI_MERGE_REQUEST_IID`, `CI_COMMIT_SHA`, `CI_JOB_URL` | GitLab | This is a GitLab MR pipeline. `CI_SERVER_URL` makes self-hosted GitLab transparent. |

## Default overrides

These let you set defaults once (e.g. in a CI image, container, or shell
profile) instead of repeating flags on every invocation. **CLI flags always
win** - env vars only fill in defaults that the CLI didn't set.

| Variable | Equivalent CLI flag | Notes |
|---|---|---|
| `ANSIBLE_SEC_SCANNER_DIRECTORY` | `--directory` | Default scan root. |
| `ANSIBLE_SEC_SCANNER_FORMAT` | `--format` | One of `markdown`, `json`, `xml`, `yaml`, `csv`, `html`, `junit`, `sarif`, `gl-sast`, `cyclonedx`. |
| `ANSIBLE_SEC_SCANNER_OUTPUT` | `--output` | Output file path; format is inferred from the extension. |
| `ANSIBLE_SEC_SCANNER_ALLOWLIST` | `--allowlist` | Path to allowlist YAML. |
| `ANSIBLE_SEC_SCANNER_JOBS` | `--jobs` / `-j` | Worker thread count. Must be a positive integer. |
| `ANSIBLE_SEC_SCANNER_SEVERITY` | `--severity` | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. |
| `ANSIBLE_SEC_SCANNER_SELECT` | `--select` | Run ONLY the listed rules (comma-separated, fnmatch globs supported). |
| `ANSIBLE_SEC_SCANNER_IGNORE` | `--ignore` | Drop the listed rules (comma-separated, fnmatch globs supported). |
| `ANSIBLE_SEC_SCANNER_EXIT_ZERO` | `--exit-zero` | Set to `1` / `true` / `yes` to always exit 0. |

## `--changed-files` env-var lookup

`--changed-files` accepts either:

- a **literal list** of file paths (newline-, space-, or comma-separated), or
- a **`$VAR_NAME`** form that reads the named environment variable at runtime.

Only files ending in `.yml`, `.yaml`, `.j2`, or `.cfg` are kept - anything
else in the diff (Python, Markdown, JSON, lockfiles) is silently passed
through, so you can feed raw `git diff` output without pre-filtering.

### Real-world recipes

The flag is delimiter-agnostic, so the simplest pattern is to pipe whatever
your platform gives you straight in:

```bash
ansible-security-scanner \
  --directory ansible \
  --changed-files "$(git diff --name-only origin/main...HEAD)"
```

| Scenario | Command |
|---|---|
| **Pre-commit** (only staged files) | `git diff --cached --name-only --diff-filter=ACMR` |
| **Local feature branch vs `main`** | `git diff --name-only origin/main...HEAD` |
| **PR / MR vs the merge target** | `git diff --name-only "origin/$TARGET_BRANCH...HEAD"` |
| **Last commit only** (push hook) | `git diff --name-only HEAD~1 HEAD` |
| **Promotion `staging` -> `production`** | `git diff --name-only origin/staging...origin/production` |

Note the **three dots** (`A...B`): that's "everything reachable from `B` that
isn't on `A`'s side of the merge base" - i.e. the diff a reviewer sees on the
PR/MR, not the temporary state of the working tree. Use two dots (`A..B`)
only if you specifically want "B minus A as of right now".

### CI/CD variable form

Most CI providers expose changed-file lists as variables; the `$VAR` form
keeps long lists out of shell history and avoids re-shelling-out to git:

```bash
# GitLab CI - GitLab populates CI_MERGE_REQUEST_CHANGED_FILES
ansible-security-scanner --changed-files '$CI_MERGE_REQUEST_CHANGED_FILES'
```

The single-quote form is important - your shell would otherwise expand
`$VAR` before the scanner sees it.

| Platform | Variable | Notes |
|---|---|---|
| GitLab CI (MR pipelines) | `$CI_MERGE_REQUEST_CHANGED_FILES` | Newline-separated; GitLab-managed. |
| GitHub Actions | *(no native var)* | Use `git diff --name-only "${{ github.event.pull_request.base.sha }}...HEAD"`. |
| Bitbucket Pipelines | *(no native var)* | Same - diff against `$BITBUCKET_PR_DESTINATION_BRANCH`. |
| Jenkins (Multibranch) | `CHANGE_TARGET` | Diff against `origin/$CHANGE_TARGET...HEAD`. |
| Azure DevOps | `$(System.PullRequest.TargetBranch)` | Diff against that branch. |

For platforms without a native variable, set one yourself in a `before_script`
and pass it through:

```bash
export CHANGED_FILES="$(git diff --name-only "origin/$TARGET_BRANCH...HEAD")"
ansible-security-scanner --changed-files '$CHANGED_FILES'
```

### Interaction with MR-comment auto-scoping

When `--mr-comment` is enabled, the scanner already auto-scopes to the merge
request's changed files (via the platform API). Passing `--changed-files`
explicitly **wins** - use it when you want to scan a narrower or wider list
than what the platform reports, e.g. to add `group_vars/` files that the MR
author didn't touch but that affect the playbooks they did. To opt out of
auto-scoping entirely, pass `--no-mr-comment-scope-changed-files`.
