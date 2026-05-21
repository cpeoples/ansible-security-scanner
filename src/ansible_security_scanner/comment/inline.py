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
from dataclasses import dataclass, field
from typing import Any

from .context import PlatformContext, _redact
from .fingerprint import _finding_fingerprint
from .rendering import _SEVERITY_EMOJI, _first_sentence, _redact_snippet

logger = logging.getLogger(__name__)

_INLINE_MARKER_PREFIX = "<!-- ansible-security-scanner:inline:v1:"
_INLINE_MARKER_SUFFIX = " -->"
_INLINE_MARKER_RE = re.compile(r"<!--\s*ansible-security-scanner:inline:v1:([0-9a-f]{16})\s*-->")

# Beyond this many threads the summary comment is the saner read.
_MAX_INLINE_COMMENTS = 50


@dataclass
class InlinePostResult:
    posted: int = 0
    skipped: int = 0
    resolved: int = 0
    failed: int = 0
    capped: int = 0
    error: str | None = None
    thread_urls: list[str] = field(default_factory=list)


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


def _render_inline_body(finding: Any) -> str:
    severity = (getattr(finding, "severity", "") or "LOW").upper()
    emoji = _SEVERITY_EMOJI.get(severity, "\u26aa")
    rule_id = getattr(finding, "rule_id", "") or "unknown"
    title = (getattr(finding, "title", "") or rule_id).strip()
    description = _first_sentence(getattr(finding, "description", "") or "")
    fix = _first_sentence(getattr(finding, "recommendation", "") or "")

    parts: list[str] = [
        f"{emoji} **{severity}** \u00b7 `{rule_id}` \u2014 {title}",
    ]
    if description:
        parts.append(description)

    snippet = _redact_snippet(
        getattr(finding, "code_snippet", "") or "",
        pin=getattr(finding, "match_line", "") or "",
    )
    if snippet:
        parts.append(f"```yaml\n{snippet}\n```")

    if fix:
        parts.append(f"\U0001f4a1 **Fix:** {fix}")

    parts.append(_inline_marker(_finding_fingerprint(finding)))
    return "\n\n".join(parts)


def _split_findings(
    findings: list[Any],
    changed_files: set[str] | None,
    diff_lines: dict[str, set[int]] | None,
) -> tuple[list[Any], list[Any]]:
    line_anchored: list[Any] = []
    file_level: list[Any] = []
    have_diff = changed_files is not None or diff_lines is not None
    for f in findings:
        fp = getattr(f, "file_path", "") or ""
        ln = int(getattr(f, "line_number", 0) or 0)
        in_changed = changed_files is None or fp in changed_files
        in_lines = diff_lines is None or ln in diff_lines.get(fp, set())
        if not have_diff or (in_changed and in_lines):
            line_anchored.append(f)
        else:
            file_level.append(f)
    return line_anchored, file_level


def post_inline_comments(
    findings: Iterable[Any],
    ctx: PlatformContext,
    *,
    changed_files: set[str] | None = None,
    diff_lines: dict[str, set[int]] | None = None,
    timeout: float = 15.0,
) -> InlinePostResult:
    """Post, skip, or resolve per-finding inline threads on ``ctx``'s MR/PR.

    Findings whose ``file_path``/``line_number`` are not in the diff
    metadata fall back to file-level threads.
    """
    findings = list(findings)
    try:
        if ctx.platform == "github":
            return _github_post_inline(findings, ctx, changed_files, diff_lines, timeout=timeout)
        return _gitlab_post_inline(findings, ctx, changed_files, diff_lines, timeout=timeout)
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
    diff_lines: dict[str, set[int]] | None,
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

        line_anchored, file_level = _split_findings(findings, changed_files, diff_lines)
        file_level_ids = {id(f) for f in file_level}
        wanted_fps: set[str] = set()
        posted = 0

        for finding in line_anchored + file_level:
            if posted >= _MAX_INLINE_COMMENTS:
                result.capped += 1
                continue
            fp = _finding_fingerprint(finding)
            wanted_fps.add(fp)
            if fp in existing_index:
                result.skipped += 1
                continue
            payload: dict[str, Any] = {"body": _render_inline_body(finding)}
            if id(finding) not in file_level_ids and diff_refs is not None:
                payload["position"] = _gitlab_position(finding, diff_refs)
            try:
                resp = client.post(f"{base}/discussions", headers=headers, json=payload)
                resp.raise_for_status()
                posted += 1
                result.posted += 1
            except httpx.HTTPError as exc:
                result.failed += 1
                logger.warning(
                    "Inline comments: GitLab POST failed for %s:%s (%s).",
                    getattr(finding, "file_path", "?"),
                    getattr(finding, "line_number", "?"),
                    _redact(str(exc), ctx.token),
                )

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

    return result


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
    diff_lines: dict[str, set[int]] | None,
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
        line_anchored, file_level = _split_findings(findings, changed_files, diff_lines)
        file_level_ids = {id(f) for f in file_level}
        wanted_fps: set[str] = set()
        posted = 0

        for finding in line_anchored + file_level:
            if posted >= _MAX_INLINE_COMMENTS:
                result.capped += 1
                continue
            fp = _finding_fingerprint(finding)
            wanted_fps.add(fp)
            if fp in existing_index:
                result.skipped += 1
                continue

            inp: dict[str, Any] = {
                "pullRequestId": pr_id,
                "body": _render_inline_body(finding),
                "path": getattr(finding, "file_path", "") or "",
            }
            if id(finding) in file_level_ids:
                inp["subjectType"] = "FILE"
            else:
                inp["line"] = int(getattr(finding, "line_number", 0) or 0)
                inp["side"] = "RIGHT"

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
                errors = data.get("errors")
            except httpx.HTTPError as exc:
                result.failed += 1
                logger.warning(
                    "Inline comments: GitHub addReviewThread failed for %s:%s (%s).",
                    getattr(finding, "file_path", "?"),
                    getattr(finding, "line_number", "?"),
                    _redact(str(exc), ctx.token),
                )
                continue
            if errors:
                result.failed += 1
                logger.warning(
                    "Inline comments: GitHub addReviewThread errors for %s:%s (%s).",
                    getattr(finding, "file_path", "?"),
                    getattr(finding, "line_number", "?"),
                    _redact(str(errors), ctx.token),
                )
                continue
            thread = ((data.get("data") or {}).get("addPullRequestReviewThread") or {}).get(
                "thread"
            ) or {}
            if thread.get("url"):
                result.thread_urls.append(thread["url"])
            posted += 1
            result.posted += 1

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

    return result


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
