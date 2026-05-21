"""Platform detection and request-context dataclasses for MR/PR comments.

Pure env probing — no network I/O. Tokens read from environment variables
only; never logged, echoed, or persisted. Every code path that could
surface a token routes through :func:`_redact` first.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)


Platform = Literal["github", "gitlab"]


@dataclass
class PlatformContext:
    """Everything the commenter needs to talk to GitHub or GitLab.

    Populated by :func:`detect_platform` from CI environment variables.
    ``token`` is the only sensitive field — it must never be logged,
    echoed, or written to disk.
    """

    platform: Platform
    api_url: str
    project_ref: str
    mr_number: int
    commit_sha: str
    token: str = field(repr=False)
    run_url: str | None = None


@dataclass
class CommentResult:
    """Outcome of ``post_or_update_comment``.

    Exposes just enough for the CLI layer to log a coherent summary
    without needing to know about httpx ``Response`` objects.
    """

    posted: bool
    updated: bool
    comment_id: int | None
    comment_url: str | None
    findings_count: int
    previous_findings_count: int | None
    bytes_written: int
    error: str | None = None


def _redact(msg: str, *tokens: str) -> str:
    """Strip any provided token value from a log message.

    Used on error paths and debug logs so a stray ``logger.warning``
    with a full ``httpx`` request object never leaks a PAT to CI
    output. Empty / falsy tokens are no-ops.
    """
    out = msg
    for tok in tokens:
        if tok:
            out = out.replace(tok, "***REDACTED***")
    return out


def _first_env(*names: str, env: dict[str, str] | None = None) -> str | None:
    """Return the first non-empty environment variable from ``names``."""
    source = env if env is not None else os.environ
    for name in names:
        val = source.get(name)
        if val:
            return val
    return None


def detect_platform(
    want: Platform,
    env: dict[str, str] | None = None,
) -> PlatformContext | None:
    """Detect the MR/PR context from CI environment variables.

    Returns ``None`` (with a WARNING logged) if the requested platform
    isn't active or required env vars are missing. Never probes the
    network; never reads config files. The ``env`` parameter exists
    for testability; production callers always pass ``None``.
    """
    e = env if env is not None else dict(os.environ)

    if want == "github":
        return _detect_github(e)
    if want == "gitlab":
        return _detect_gitlab(e)
    logger.warning("Unknown MR-comment platform requested: %r", want)
    return None


def _detect_github(e: dict[str, str]) -> PlatformContext | None:
    """Pull a GitHub PR context out of GitHub Actions env vars.

    GitHub exposes ``GITHUB_REF=refs/pull/<n>/merge`` on pull-request
    workflows. We also accept ``GITHUB_EVENT_PATH`` (a JSON blob) as a
    fallback because re-run workflows sometimes lose the ref.
    """
    token = _first_env(
        "ANSIBLE_SEC_SCANNER_GITHUB_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        env=e,
    )
    if not token:
        logger.warning(
            "--github-comment: no GitHub token found in env "
            "(looked for ANSIBLE_SEC_SCANNER_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN). "
            "Skipping MR comment."
        )
        return None

    repo = e.get("GITHUB_REPOSITORY", "").strip()
    server_url = e.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    api_url = (e.get("GITHUB_API_URL") or "").rstrip("/")
    if not api_url:
        api_url = (
            "https://api.github.com"
            if server_url == "https://github.com"
            else f"{server_url}/api/v3"
        )

    pr_number, head_sha = _extract_github_pr_context(e)
    sha = head_sha or e.get("GITHUB_SHA", "").strip()

    if not repo or pr_number is None:
        logger.warning(
            "--github-comment: GitHub PR context incomplete "
            "(GITHUB_REPOSITORY=%r, PR number=%r). "
            "This flag must run inside a pull_request GitHub Actions workflow.",
            repo or "<unset>",
            pr_number,
        )
        return None

    run_url: str | None = None
    server = e.get("GITHUB_SERVER_URL")
    run_id = e.get("GITHUB_RUN_ID")
    if server and repo and run_id:
        run_url = f"{server.rstrip('/')}/{repo}/actions/runs/{run_id}"

    return PlatformContext(
        platform="github",
        api_url=api_url,
        project_ref=repo,
        mr_number=pr_number,
        commit_sha=sha,
        token=token,
        run_url=run_url,
    )


def _extract_github_pr_context(e: dict[str, str]) -> tuple[int | None, str | None]:
    """Parse the PR number and head-commit SHA from GitHub Actions env.

    The head SHA matters because ``GITHUB_SHA`` on a ``pull_request``
    workflow is GitHub's synthetic *merge commit*, garbage-collected
    after merge or close. ``pull_request.head.sha`` (the actual
    contributor-pushed commit) is durable for the life of the repo
    and keeps file:line deep-links alive.
    """
    pr_number: int | None = None
    head_sha: str | None = None

    ref = e.get("GITHUB_REF", "")
    m = re.match(r"^refs/pull/(\d+)/(?:merge|head)$", ref)
    if m:
        pr_number = int(m.group(1))

    event_path = e.get("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).is_file():
        try:
            payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "--github-comment: GITHUB_EVENT_PATH %s is unreadable: %s. "
                "Falling back to GITHUB_REF and GITHUB_SHA.",
                event_path,
                exc,
            )
            return pr_number, head_sha
        pr = payload.get("pull_request") or payload.get("issue") or {}
        if pr_number is None:
            num = pr.get("number")
            if isinstance(num, int) and num > 0:
                pr_number = num
        head = (pr.get("head") or {}).get("sha")
        if isinstance(head, str) and head.strip():
            head_sha = head.strip()
    return pr_number, head_sha


def _detect_gitlab(e: dict[str, str]) -> PlatformContext | None:
    """Pull a GitLab MR context out of GitLab CI env vars.

    Works against gitlab.com and self-hosted instances because GitLab
    Runner exports ``CI_API_V4_URL`` on every job. Falls back to
    deriving from ``CI_SERVER_URL`` for pre-12.7 runners.
    """
    token = _first_env(
        "ANSIBLE_SEC_SCANNER_GITLAB_TOKEN",
        "GITLAB_TOKEN",
        "CI_JOB_TOKEN",
        env=e,
    )
    if not token:
        logger.warning(
            "--gitlab-comment: no GitLab token found in env "
            "(looked for ANSIBLE_SEC_SCANNER_GITLAB_TOKEN, GITLAB_TOKEN, CI_JOB_TOKEN). "
            "Skipping MR comment."
        )
        return None

    api_url = (e.get("CI_API_V4_URL") or "").rstrip("/")
    server_url = (e.get("CI_SERVER_URL") or "").rstrip("/")
    if not api_url and server_url:
        api_url = f"{server_url}/api/v4"

    # On forked-MR pipelines, ``CI_PROJECT_ID`` is the source (fork);
    # the Notes API must POST to the *target* project, exposed as
    # ``CI_MERGE_REQUEST_PROJECT_ID``. Prefer the latter when present.
    project_id = (
        e.get("CI_MERGE_REQUEST_PROJECT_ID", "").strip() or e.get("CI_PROJECT_ID", "").strip()
    )
    mr_iid_str = e.get("CI_MERGE_REQUEST_IID", "").strip()
    # On merged-results / merge-train pipelines, ``CI_COMMIT_SHA`` is a
    # synthetic commit that GitLab garbage-collects after the MR closes,
    # which 404s file:line deep-links. ``CI_MERGE_REQUEST_SOURCE_BRANCH_SHA``
    # is the contributor-pushed head and stays reachable.
    sha = (
        e.get("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", "").strip()
        or e.get("CI_COMMIT_SHA", "").strip()
    )

    if not api_url or not project_id or not mr_iid_str:
        logger.warning(
            "--gitlab-comment: GitLab MR context incomplete "
            "(CI_API_V4_URL=%r, CI_SERVER_URL=%r, project_id=%r, "
            "CI_MERGE_REQUEST_IID=%r). "
            "This flag must run inside a merge_request_event pipeline.",
            e.get("CI_API_V4_URL", "<unset>"),
            server_url or "<unset>",
            project_id or "<unset>",
            mr_iid_str or "<unset>",
        )
        return None

    try:
        mr_iid = int(mr_iid_str)
    except ValueError:
        logger.warning(
            "--gitlab-comment: CI_MERGE_REQUEST_IID=%r is not an integer.",
            mr_iid_str,
        )
        return None

    run_url = e.get("CI_JOB_URL") or None

    return PlatformContext(
        platform="gitlab",
        api_url=api_url,
        project_ref=project_id,
        mr_number=mr_iid,
        commit_sha=sha,
        token=token,
        run_url=run_url,
    )


def _resolve_finding_paths(
    file_path: str,
    scan_root: Path | None,
) -> tuple[str, Path | None]:
    """Map a finding's ``file_path`` to a repo-root-relative display
    path and a disk-readable absolute path.

    Findings carry ``file_path`` relative to the scanner's ``--directory``
    argument. That layout is correct for the markdown report (rooted at
    ``--directory``) but breaks the MR/PR deep-link and on-disk snippet
    re-read, both of which expect repo-root-relative paths.

    When ``scan_root`` is provided we re-attach its repo-root-relative
    prefix and resolve the on-disk path. When ``scan_root`` is ``None``
    we keep today's behaviour so callers that don't yet thread the scan
    root through aren't regressed.
    """
    if not file_path:
        return file_path, None

    if scan_root is None:
        return file_path, Path(file_path)

    candidate = Path(file_path)
    if candidate.is_absolute():
        return file_path, candidate

    on_disk = (scan_root / candidate).resolve()
    try:
        repo_relative = on_disk.relative_to(Path.cwd().resolve())
        display = repo_relative.as_posix()
    except ValueError:
        display = file_path
    return display, on_disk


def _file_deep_link(ctx: PlatformContext, file_path: str, line_number: int) -> str | None:
    """Build a browser-friendly link to ``<file_path>:<line_number>`` on
    the platform's blob viewer, or ``None`` when we can't.

    Returns ``None`` when ``commit_sha`` is missing or when we can't
    derive the web-UI host. Callers fall back to the bare reference
    in that case so the comment never renders a broken link.
    """
    if not file_path or not ctx.commit_sha:
        return None
    anchor = f"#L{line_number}" if line_number else ""
    if ctx.platform == "github":
        server = "https://github.com"
        if ctx.api_url and ctx.api_url != "https://api.github.com":
            server = ctx.api_url.rsplit("/api/v3", 1)[0]
        return f"{server}/{ctx.project_ref}/blob/{ctx.commit_sha}/{file_path}{anchor}"
    project_path = os.environ.get("CI_PROJECT_PATH")
    server_url = os.environ.get("CI_SERVER_URL", "").rstrip("/")
    if not project_path or not server_url:
        return None
    return f"{server_url}/{project_path}/-/blob/{ctx.commit_sha}/{file_path}{anchor}"
