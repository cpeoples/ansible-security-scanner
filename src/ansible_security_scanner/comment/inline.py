"""Per-finding inline review threads (opt-in via ``--inline-comments``).

Posts each finding as an inline diff thread on the MR/PR, in addition
to the consolidated summary comment posted by default.

GitLab uses the Discussions API; GitHub uses GraphQL review threads
(``addPullRequestReviewThread`` / ``resolveReviewThread``). The REST
review-comment endpoint can't anchor file-level threads, which we
need for findings on lines the MR didn't touch.

Every body ends in ``<!-- ansible-security-scanner:inline:v1:<fp> -->``
so subsequent runs skip duplicates and resolve threads whose finding
has disappeared.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .context import PlatformContext, _redact
from .fingerprint import _finding_fingerprint
from .rendering import (
    _SEVERITY_EMOJI,
    _redact_snippet,
    _render_framework_coverage_inline,
    _render_remediation_block,
)

logger = logging.getLogger(__name__)

_INLINE_MARKER_PREFIX = "<!-- ansible-security-scanner:inline:v1:"
_INLINE_MARKER_SUFFIX = " -->"
_INLINE_MARKER_RE = re.compile(r"<!--\s*ansible-security-scanner:inline:v1:([0-9a-f]{16})\s*-->")

# Beyond this cap, the summary comment is a saner read than 50+ threads.
_MAX_INLINE_COMMENTS = 50

_RESOLUTION_DISCLAIMER = (
    "_Resolving this thread does not unblock the pipeline. The scan re-runs "
    "on every push and will close fixed-finding threads automatically._"
)


@dataclass
class InlinePostResult:
    posted: int = 0
    skipped: int = 0
    resolved: int = 0
    failed: int = 0
    capped: int = 0
    anchored: int = 0
    file_level: int = 0
    fallback: int = 0
    error: str | None = None
    thread_urls: list[str] = field(default_factory=list)

    def _record(self, *, posted: bool, anchored: bool, attempted_anchor: bool) -> None:
        if not posted:
            self.failed += 1
            return
        self.posted += 1
        if anchored:
            self.anchored += 1
        else:
            self.file_level += 1
            if attempted_anchor:
                self.fallback += 1


def _httpx() -> Any:
    # Routed through the parent package so ``patch.object(comment.httpx, ...)``
    # in tests swaps in a double for everything below.
    from . import httpx as _h  # noqa: PLC0415

    return _h


def _inline_marker(fingerprint: str) -> str:
    return f"{_INLINE_MARKER_PREFIX}{fingerprint}{_INLINE_MARKER_SUFFIX}"


def _decode_inline_marker(body: str) -> str | None:
    m = _INLINE_MARKER_RE.search(body or "")
    return m.group(1) if m else None


def _is_4xx(exc: Any) -> bool:
    """True if ``exc`` is an httpx HTTPStatusError with a 4xx status."""
    resp = getattr(exc, "response", None)
    code = getattr(resp, "status_code", None)
    return isinstance(code, int) and 400 <= code < 500


def _response_body(exc: Any, token: str, *, limit: int = 240) -> str:
    """Best-effort extract of the platform's response body for logging.

    Returns the (redacted, truncated) body text, falling back to
    ``str(exc)`` when no body is reachable.
    """
    resp = getattr(exc, "response", None)
    text = getattr(resp, "text", None) or str(exc)
    redacted = _redact(text, token)
    if len(redacted) > limit:
        return redacted[:limit] + "..."
    return redacted


def _log_summary(ctx: PlatformContext, result: InlinePostResult) -> None:
    logger.info(
        "Inline comments on %s: posted=%d (anchored=%d file_level=%d "
        "fallback=%d) skipped=%d resolved=%d failed=%d capped=%d.",
        ctx.platform,
        result.posted,
        result.anchored,
        result.file_level,
        result.fallback,
        result.skipped,
        result.resolved,
        result.failed,
        result.capped,
    )


def _render_inline_body(finding: Any, *, anchored: bool) -> str:
    """Render an inline-thread body for ``finding``.

    ``anchored=True`` skips the YAML code fence: the platform renders
    the diff hunk above the comment, so the snippet would duplicate it.

    ``anchored=False`` keeps the fenced snippet: file-level threads
    aren't attached to a hunk, so the snippet is the only context the
    reviewer gets.
    """
    severity = (getattr(finding, "severity", "") or "LOW").upper()
    emoji = _SEVERITY_EMOJI.get(severity, "\u26aa")
    rule_id = getattr(finding, "rule_id", "") or "unknown"
    title = (getattr(finding, "title", "") or rule_id).strip()
    description = (getattr(finding, "description", "") or "").strip()
    recommendation = (getattr(finding, "recommendation", "") or "").strip()

    parts: list[str] = [
        f"{emoji} **{severity}** \u00b7 `{rule_id}` \u2014 {title}",
    ]
    if description:
        parts.append(description)

    if not anchored:
        snippet = _redact_snippet(
            getattr(finding, "code_snippet", "") or "",
            pin=getattr(finding, "match_line", "") or "",
        )
        if snippet:
            parts.append(f"```yaml\n{snippet}\n```")

    if recommendation:
        parts.append(f"**Recommendation:** {recommendation}")

    remediation = _render_remediation_block(finding)
    if remediation:
        parts.append(remediation)

    frameworks = _render_framework_coverage_inline(finding)
    if frameworks:
        parts.append(frameworks)

    parts.append(_RESOLUTION_DISCLAIMER)
    parts.append(_inline_marker(_finding_fingerprint(finding)))
    return "\n\n".join(parts)


def _split_findings(
    findings: list[Any],
    changed_files: set[str] | None,
) -> tuple[list[Any], list[Any]]:
    """Partition findings into ``(anchor_candidates, file_level_only)``.

    A finding goes in the first bucket when its file is in
    ``changed_files`` (or when ``changed_files`` is ``None`` and we have
    no information either way). The platform is the source of truth for
    whether the specific *line* is anchorable; we don't second-guess.
    """
    if changed_files is None:
        return list(findings), []
    anchor_candidates: list[Any] = []
    file_level_only: list[Any] = []
    for f in findings:
        fp = getattr(f, "file_path", "") or ""
        if fp in changed_files:
            anchor_candidates.append(f)
        else:
            file_level_only.append(f)
    return anchor_candidates, file_level_only


def _normalize_path(file_path: str, scan_root: Path | None) -> str:
    """Rewrite ``file_path`` from ``--directory``-relative to repo-root-relative.

    Findings carry paths relative to the scanner's ``--directory``; the
    MR/PR diff returns paths relative to the repo root. When ``scan_root``
    is provided, prepend its repo-root-relative prefix so the two views
    line up. When ``scan_root`` is ``None`` or the rewrite isn't
    expressible (e.g. ``scan_root`` is outside the cwd), return the path
    unchanged.
    """
    if not file_path or scan_root is None:
        return file_path
    candidate = Path(file_path)
    if candidate.is_absolute():
        return file_path
    on_disk = (scan_root / candidate).resolve()
    try:
        return on_disk.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return file_path


def _normalize_findings(findings: list[Any], scan_root: Path | None) -> list[Any]:
    """Return findings with ``file_path`` rewritten to repo-root-relative."""
    if scan_root is None:
        return findings
    return [_rewrite_finding_path(f, scan_root) for f in findings]


def _rewrite_finding_path(finding: Any, scan_root: Path) -> Any:
    original = getattr(finding, "file_path", "") or ""
    normalized = _normalize_path(original, scan_root)
    if normalized == original:
        return finding
    try:
        return replace(finding, file_path=normalized)
    except TypeError:
        return finding


def post_inline_comments(
    findings: Iterable[Any],
    ctx: PlatformContext,
    *,
    changed_files: set[str] | None = None,
    scan_root: Path | None = None,
    timeout: float = 15.0,
) -> InlinePostResult:
    """Post, skip, or resolve per-finding inline threads on ``ctx``'s MR/PR.

    Findings whose file is in ``changed_files`` are tried as anchored
    threads; the platform decides whether the line is anchorable and we
    fall back to file-level on rejection. Findings outside the changed
    set go straight to file-level. ``scan_root`` (the scanner's
    ``--directory``) is used to rewrite ``file_path`` to repo-root-relative
    so it lines up with the platform's diff view.
    """
    findings = _normalize_findings(list(findings), scan_root)
    try:
        if ctx.platform == "github":
            return _github_post_inline(findings, ctx, changed_files, timeout=timeout)
        return _gitlab_post_inline(findings, ctx, changed_files, timeout=timeout)
    except Exception as exc:  # pragma: no cover
        msg = _redact(str(exc), ctx.token)
        logger.warning("Inline comments: %s post failed (%s).", ctx.platform, msg)
        return InlinePostResult(error=msg)


# GitLab Discussions API:
#   POST /projects/:id/merge_requests/:iid/discussions
#   GET  /projects/:id/merge_requests/:iid/discussions?per_page=100
#   PUT  /projects/:id/merge_requests/:iid/discussions/:disc_id  (resolve)


def _gitlab_post_inline(
    findings: list[Any],
    ctx: PlatformContext,
    changed_files: set[str] | None,
    *,
    timeout: float,
) -> InlinePostResult:
    httpx = _httpx()
    if httpx is None:
        return InlinePostResult(error="httpx is not installed")

    headers = {"PRIVATE-TOKEN": ctx.token}
    base = f"{ctx.api_url}/projects/{ctx.project_ref}/merge_requests/{ctx.mr_number}"
    result = InlinePostResult()

    with httpx.Client(timeout=timeout) as client:
        existing_index = _gitlab_existing_discussions(client, headers, base)
        diff_refs = _gitlab_diff_refs(client, headers, base)

        anchor_candidates, file_level_only = _split_findings(findings, changed_files)
        anchor_ids = {id(f) for f in anchor_candidates}
        wanted_fps: set[str] = set()
        posted = 0

        for finding in anchor_candidates + file_level_only:
            if posted >= _MAX_INLINE_COMMENTS:
                result.capped += 1
                continue
            fp = _finding_fingerprint(finding)
            wanted_fps.add(fp)
            if fp in existing_index:
                result.skipped += 1
                continue

            try_anchor = id(finding) in anchor_ids and diff_refs is not None
            posted_one, anchored = _gitlab_post_one(
                client, headers, base, finding, ctx.token, diff_refs, try_anchor=try_anchor
            )
            result._record(posted=posted_one, anchored=anchored, attempted_anchor=try_anchor)
            if posted_one:
                posted += 1

        for fp, disc_id in existing_index.items():
            if fp in wanted_fps:
                continue
            try:
                client.put(
                    f"{base}/discussions/{disc_id}",
                    headers=headers,
                    json={"resolved": True},
                )
                result.resolved += 1
            except httpx.HTTPError as exc:
                logger.info(
                    "Inline comments: GitLab resolve failed for fp=%s (%s).",
                    fp,
                    _redact(str(exc), ctx.token),
                )

    _log_summary(ctx, result)
    return result


def _gitlab_post_one(
    client: Any,
    headers: dict[str, str],
    base: str,
    finding: Any,
    token: str,
    diff_refs: dict[str, str] | None,
    *,
    try_anchor: bool,
) -> tuple[bool, bool]:
    """Post a single GitLab discussion. Returns ``(posted, anchored)``.

    Tries an anchored post first when ``try_anchor`` is set; on a 4xx
    response (typically "Note position is invalid"), retries with a
    file-level body. 5xx and network errors are not retried.
    """
    httpx = _httpx()
    file_path = getattr(finding, "file_path", "?")
    line_number = getattr(finding, "line_number", "?")

    if try_anchor and diff_refs is not None:
        payload = {
            "body": _render_inline_body(finding, anchored=True),
            "position": _gitlab_position(finding, diff_refs),
        }
        try:
            resp = client.post(f"{base}/discussions", headers=headers, json=payload)
            resp.raise_for_status()
            return True, True
        except httpx.HTTPError as exc:
            if not _is_4xx(exc):
                logger.warning(
                    "Inline comments: GitLab POST failed for %s:%s (%s).",
                    file_path,
                    line_number,
                    _response_body(exc, token),
                )
                return False, False
            logger.info(
                "Inline comments: GitLab rejected anchored post for %s:%s, "
                "retrying as file-level (%s).",
                file_path,
                line_number,
                _response_body(exc, token),
            )

    payload = {"body": _render_inline_body(finding, anchored=False)}
    try:
        resp = client.post(f"{base}/discussions", headers=headers, json=payload)
        resp.raise_for_status()
        return True, False
    except httpx.HTTPError as exc:
        logger.warning(
            "Inline comments: GitLab file-level POST failed for %s:%s (%s).",
            file_path,
            line_number,
            _response_body(exc, token),
        )
        return False, False


def _gitlab_existing_discussions(client: Any, headers: dict[str, str], base: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for page in range(1, 11):
        resp = client.get(
            f"{base}/discussions?per_page=100&page={page}",
            headers=headers,
        )
        resp.raise_for_status()
        chunk = resp.json() or []
        if not chunk:
            break
        for disc in chunk:
            disc_id = disc.get("id")
            if not disc_id:
                continue
            for note in disc.get("notes") or []:
                if note.get("system"):
                    continue
                fp = _decode_inline_marker(note.get("body") or "")
                if fp:
                    out[fp] = disc_id
                    break
        if len(chunk) < 100:
            break
    return out


def _gitlab_diff_refs(client: Any, headers: dict[str, str], base: str) -> dict[str, str] | None:
    resp = client.get(base, headers=headers)
    resp.raise_for_status()
    refs = (resp.json() or {}).get("diff_refs") or {}
    if not all(refs.get(k) for k in ("base_sha", "start_sha", "head_sha")):
        return None
    return {k: refs[k] for k in ("base_sha", "start_sha", "head_sha")}


def _gitlab_position(finding: Any, diff_refs: dict[str, str]) -> dict[str, Any]:
    # Both new_path and old_path are required; GitLab rejects positional
    # notes on renamed/modified files when old_path is omitted.
    fp = getattr(finding, "file_path", "") or ""
    ln = int(getattr(finding, "line_number", 0) or 0)
    return {
        "base_sha": diff_refs["base_sha"],
        "start_sha": diff_refs["start_sha"],
        "head_sha": diff_refs["head_sha"],
        "position_type": "text",
        "new_path": fp,
        "old_path": fp,
        "new_line": ln,
    }


# GitHub GraphQL: REST review-comments cannot anchor file-level threads,
# so we use addPullRequestReviewThread for both on-diff and off-diff.

_GH_GRAPHQL_QUERY_PR_ID = """
query PRId($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) { id }
  }
}
"""

_GH_GRAPHQL_QUERY_THREADS = """
query Threads($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $cursor) {
        nodes {
          id
          comments(first: 1) { nodes { body } }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

_GH_GRAPHQL_MUTATION_ADD_THREAD = """
mutation AddThread($input: AddPullRequestReviewThreadInput!) {
  addPullRequestReviewThread(input: $input) {
    thread { id url }
  }
}
"""

_GH_GRAPHQL_MUTATION_RESOLVE = """
mutation Resolve($threadId: ID!) {
  resolveReviewThread(input: { threadId: $threadId }) {
    thread { id }
  }
}
"""


def _github_post_inline(
    findings: list[Any],
    ctx: PlatformContext,
    changed_files: set[str] | None,
    *,
    timeout: float,
) -> InlinePostResult:
    httpx = _httpx()
    if httpx is None:
        return InlinePostResult(error="httpx is not installed")

    if "/" not in (ctx.project_ref or ""):
        return InlinePostResult(
            error=f"GitHub project_ref {ctx.project_ref!r} is not in 'owner/repo' form."
        )
    owner, name = ctx.project_ref.split("/", 1)
    graphql_url = ctx.api_url.replace("/api/v3", "").rstrip("/") + "/graphql"
    headers = {
        "Authorization": f"Bearer {ctx.token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }
    result = InlinePostResult()

    with httpx.Client(timeout=timeout) as client:
        pr_id = _github_pr_node_id(client, headers, graphql_url, owner, name, ctx.mr_number)
        if pr_id is None:
            return InlinePostResult(error="could not resolve GitHub PR node id")

        existing_index = _github_existing_threads(
            client, headers, graphql_url, owner, name, ctx.mr_number
        )
        anchor_candidates, file_level_only = _split_findings(findings, changed_files)
        anchor_ids = {id(f) for f in anchor_candidates}
        wanted_fps: set[str] = set()
        posted = 0

        for finding in anchor_candidates + file_level_only:
            if posted >= _MAX_INLINE_COMMENTS:
                result.capped += 1
                continue
            fp = _finding_fingerprint(finding)
            wanted_fps.add(fp)
            if fp in existing_index:
                result.skipped += 1
                continue

            try_anchor = id(finding) in anchor_ids
            posted_one, anchored, url = _github_post_one(
                client, headers, graphql_url, pr_id, finding, ctx.token, try_anchor=try_anchor
            )
            result._record(posted=posted_one, anchored=anchored, attempted_anchor=try_anchor)
            if posted_one:
                posted += 1
                if url:
                    result.thread_urls.append(url)

        for fp, thread_id in existing_index.items():
            if fp in wanted_fps:
                continue
            try:
                client.post(
                    graphql_url,
                    headers=headers,
                    json={
                        "query": _GH_GRAPHQL_MUTATION_RESOLVE,
                        "variables": {"threadId": thread_id},
                    },
                )
                result.resolved += 1
            except httpx.HTTPError as exc:
                logger.info(
                    "Inline comments: GitHub resolve failed for fp=%s (%s).",
                    fp,
                    _redact(str(exc), ctx.token),
                )

    _log_summary(ctx, result)
    return result


def _github_post_one(
    client: Any,
    headers: dict[str, str],
    graphql_url: str,
    pr_id: str,
    finding: Any,
    token: str,
    *,
    try_anchor: bool,
) -> tuple[bool, bool, str | None]:
    """Post a single GitHub review thread. Returns ``(posted, anchored, url)``.

    Tries an anchored ``addPullRequestReviewThread`` first when
    ``try_anchor`` is set; on a 4xx response or GraphQL ``errors``
    field (e.g. "pull_request_review_thread.line must be part of the
    diff"), retries with ``subjectType: FILE``.
    """
    if try_anchor:
        anchored_input = {
            "pullRequestId": pr_id,
            "body": _render_inline_body(finding, anchored=True),
            "path": getattr(finding, "file_path", "") or "",
            "line": int(getattr(finding, "line_number", 0) or 0),
            "side": "RIGHT",
        }
        ok, url, retry = _github_send_thread(client, headers, graphql_url, anchored_input, token)
        if ok:
            return True, True, url
        if not retry:
            return False, False, None
        logger.info(
            "Inline comments: GitHub rejected anchored thread for %s:%s, retrying as file-level.",
            getattr(finding, "file_path", "?"),
            getattr(finding, "line_number", "?"),
        )

    file_level_input = {
        "pullRequestId": pr_id,
        "body": _render_inline_body(finding, anchored=False),
        "path": getattr(finding, "file_path", "") or "",
        "subjectType": "FILE",
    }
    ok, url, _retry = _github_send_thread(client, headers, graphql_url, file_level_input, token)
    return ok, False, url


def _github_send_thread(
    client: Any,
    headers: dict[str, str],
    graphql_url: str,
    inp: dict[str, Any],
    token: str,
) -> tuple[bool, str | None, bool]:
    """Send one ``addPullRequestReviewThread`` mutation.

    Returns ``(posted, thread_url, retry_as_file_level)``. ``retry_as_file_level``
    is True only on 4xx HTTP or GraphQL errors that look like position
    rejections - those we retry; transport / 5xx / unknown errors we don't.
    """
    httpx = _httpx()
    try:
        resp = client.post(
            graphql_url,
            headers=headers,
            json={
                "query": _GH_GRAPHQL_MUTATION_ADD_THREAD,
                "variables": {"input": inp},
            },
        )
        resp.raise_for_status()
        data = resp.json() or {}
    except httpx.HTTPError as exc:
        retry = _is_4xx(exc) and inp.get("subjectType") != "FILE"
        if not retry:
            logger.warning(
                "Inline comments: GitHub addReviewThread failed for %s:%s (%s).",
                inp.get("path", "?"),
                inp.get("line", "?"),
                _response_body(exc, token),
            )
        return False, None, retry

    errors = data.get("errors")
    if errors:
        retry = inp.get("subjectType") != "FILE"
        if not retry:
            logger.warning(
                "Inline comments: GitHub addReviewThread errors for %s:%s (%s).",
                inp.get("path", "?"),
                inp.get("line", "?"),
                _redact(str(errors), token),
            )
        return False, None, retry

    thread = ((data.get("data") or {}).get("addPullRequestReviewThread") or {}).get("thread") or {}
    return True, thread.get("url"), False


def _github_pr_node_id(
    client: Any,
    headers: dict[str, str],
    graphql_url: str,
    owner: str,
    name: str,
    pr_number: int,
) -> str | None:
    resp = client.post(
        graphql_url,
        headers=headers,
        json={
            "query": _GH_GRAPHQL_QUERY_PR_ID,
            "variables": {"owner": owner, "name": name, "number": pr_number},
        },
    )
    resp.raise_for_status()
    pr = (((resp.json() or {}).get("data") or {}).get("repository") or {}).get("pullRequest") or {}
    pr_id = pr.get("id")
    return pr_id if isinstance(pr_id, str) else None


def _github_existing_threads(
    client: Any,
    headers: dict[str, str],
    graphql_url: str,
    owner: str,
    name: str,
    pr_number: int,
) -> dict[str, str]:
    out: dict[str, str] = {}
    cursor: str | None = None
    for _ in range(10):
        resp = client.post(
            graphql_url,
            headers=headers,
            json={
                "query": _GH_GRAPHQL_QUERY_THREADS,
                "variables": {
                    "owner": owner,
                    "name": name,
                    "number": pr_number,
                    "cursor": cursor,
                },
            },
        )
        resp.raise_for_status()
        rt = (
            (((resp.json() or {}).get("data") or {}).get("repository") or {}).get("pullRequest")
            or {}
        ).get("reviewThreads") or {}
        for node in rt.get("nodes") or []:
            tid = node.get("id")
            comments = (node.get("comments") or {}).get("nodes") or []
            if not (tid and comments):
                continue
            fp = _decode_inline_marker(comments[0].get("body") or "")
            if fp:
                out[fp] = tid
        page_info = rt.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
    return out
