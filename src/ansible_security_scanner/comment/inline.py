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

from .context import PlatformContext, _file_deep_link, _redact
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

_INLINE_HEADER_RE = re.compile(r"\*\*(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\*\*\s+\u00b7\s+(`[^`]+`)")

# Sentinel embedded in resolved-thread bodies so subsequent runs can
# tell "I closed this" from "this is still open". Kept separate from
# the fingerprint marker so the dedup index keeps working unchanged.
_INLINE_RESOLVED_SENTINEL = "<!-- ansible-security-scanner:inline:state:resolved -->"

# Beyond this cap, the summary comment is a saner read than 50+ threads.
_MAX_INLINE_COMMENTS = 50

_RESOLUTION_DISCLAIMER = (
    "_Resolving this thread does not unblock the pipeline. The scan re-runs "
    "on every push and will close fixed-finding threads automatically._"
)

_RESOLVED_DISCLAIMER_TEMPLATE = (
    "_Closed automatically by the scanner because this finding is no longer "
    "present in commit `{sha}`._"
)

# Inline-thread breadcrumb appears only when the run's resolved policy
# (`--select` or `--ignore`) is large enough that the missing context is
# non-obvious. For small hand-curated lists the summary comment is right
# there - no breadcrumb needed.
_INLINE_BREADCRUMB_THRESHOLD = 8
_INLINE_BREADCRUMB = (
    "_This run suppresses other rule classes; see the summary comment for the policy._"
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


@dataclass(frozen=True)
class _ThreadRecord:
    """Existing-thread index entry: thread id + first-note id + body.

    All three fields are needed so the resolve loop can edit the
    user-visible note before closing the thread. ``note_id`` is the
    first non-system note (GitLab) or first review-comment node id
    (GitHub) - the one whose body the reviewer sees at the top of the
    thread.
    """

    thread_id: str
    note_id: str
    body: str


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


def _render_inline_location(finding: Any, file_link: str | None) -> str | None:
    """Render a one-line ``<file>:<line>`` reference under the severity
    header.

    Anchored inline threads are attached to the diff hunk and the
    platform shows the file/line in the gutter, but we still want a
    machine-greppable, copy-pasteable reference inside the body so
    reviewers can quote the location into Slack/Linear/etc. without
    losing it. File-level threads (anchor failed) get the same line so
    reviewers know which line fired even though the platform didn't
    pin the comment.

    ``file_link`` is the deep-link to the blob viewer at the run's
    commit SHA; when present we render the path as a Markdown link so
    one click jumps to the offending line. When the link can't be
    built (no ``commit_sha`` / unknown CI server) we fall back to a
    plain ``code`` reference.
    """
    file_path = (getattr(finding, "file_path", "") or "").strip()
    line_number = getattr(finding, "line_number", 0) or 0
    if not file_path:
        return None
    if line_number > 0:
        label = f"{file_path}:{line_number}"
    else:
        label = file_path
    if file_link:
        return f"\U0001f4cd [`{label}`]({file_link})"
    return f"\U0001f4cd `{label}`"


def _render_inline_body(
    finding: Any,
    *,
    anchored: bool,
    breadcrumb: bool = False,
    file_link: str | None = None,
) -> str:
    """Render an inline-thread body for ``finding``.

    ``anchored=True`` skips the YAML code fence: the platform renders
    the diff hunk above the comment, so the snippet would duplicate it.

    ``anchored=False`` keeps the fenced snippet: file-level threads
    aren't attached to a hunk, so the snippet is the only context the
    reviewer gets.

    ``breadcrumb=True`` appends a one-line italic note pointing reviewers
    at the summary-comment policy block. Set when either the resolved
    ``--ignore`` or ``--select`` list exceeds
    ``_INLINE_BREADCRUMB_THRESHOLD``; below that the summary's flat
    list is small enough to spot at a glance.

    ``file_link`` is the platform-specific blob-viewer URL pinned to
    ``commit_sha#L<line>``. When present a ``<file>:<line>`` location
    line is rendered immediately under the severity header so reviewers
    have one-click navigation away from the diff context.
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
    location = _render_inline_location(finding, file_link)
    if location:
        parts.append(location)
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
    if breadcrumb:
        parts.append(_INLINE_BREADCRUMB)
    parts.append(_inline_marker(_finding_fingerprint(finding)))
    return "\n\n".join(parts)


def _short_sha(sha: str) -> str:
    return (sha or "").strip()[:7] or "unknown"


def _finding_file_link(ctx: PlatformContext, finding: Any) -> str | None:
    """Return the platform deep-link for ``finding`` or ``None``.

    Centralises the ``finding.file_path`` / ``finding.line_number``
    coercion so the two post_one paths can't drift on edge cases like
    ``None`` line numbers or missing ``file_path``.
    """
    return _file_deep_link(
        ctx,
        getattr(finding, "file_path", "") or "",
        int(getattr(finding, "line_number", 0) or 0),
    )


def _render_resolved_inline_body(original_body: str, commit_sha: str) -> str:
    """Rewrite ``original_body`` to its closed-state form.

    Replaces the leading severity header with a green ``RESOLVED`` line
    and swaps the open-state disclaimer for the closed variant.
    Preserves the body's marker (so dedup still works) and embeds an
    HTML sentinel so future runs can tell open from closed at a glance.
    """
    fingerprint = _decode_inline_marker(original_body)
    short = _short_sha(commit_sha)
    blocks = original_body.split("\n\n")

    rule_id = "this rule"
    header_idx: int | None = None
    for i, block in enumerate(blocks):
        match = _INLINE_HEADER_RE.search(block)
        if match:
            header_idx = i
            rule_id = match.group(1)
            break
    if header_idx is not None:
        blocks[header_idx] = (
            f"\u2705 **RESOLVED** \u00b7 {rule_id} \u2014 no longer found in `{short}`"
        )

    closed_disclaimer = _RESOLVED_DISCLAIMER_TEMPLATE.format(sha=short)
    rebuilt: list[str] = []
    for block in blocks:
        if block.strip() == _RESOLUTION_DISCLAIMER:
            rebuilt.append(closed_disclaimer)
        elif block.strip() == _INLINE_BREADCRUMB:
            continue
        else:
            rebuilt.append(block)

    if not any(block.strip() == closed_disclaimer for block in rebuilt):
        marker_idx = next(
            (i for i, b in enumerate(rebuilt) if _INLINE_MARKER_PREFIX in b),
            len(rebuilt),
        )
        rebuilt.insert(marker_idx, closed_disclaimer)

    body = "\n\n".join(rebuilt)
    if _INLINE_RESOLVED_SENTINEL not in body:
        if fingerprint:
            marker = _inline_marker(fingerprint)
            body = body.replace(marker, f"{_INLINE_RESOLVED_SENTINEL}\n\n{marker}", 1)
        else:
            body = f"{body.rstrip()}\n\n{_INLINE_RESOLVED_SENTINEL}"
    return body


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
    ignored_rule_ids: list[str] | None = None,
    selected_rule_ids: list[str] | None = None,
) -> InlinePostResult:
    """Post, skip, or resolve per-finding inline threads on ``ctx``'s MR/PR.

    Findings whose file is in ``changed_files`` are tried as anchored
    threads; the platform decides whether the line is anchorable and we
    fall back to file-level on rejection. Findings outside the changed
    set go straight to file-level. ``scan_root`` (the scanner's
    ``--directory``) is used to rewrite ``file_path`` to repo-root-relative
    so it lines up with the platform's diff view.

    ``selected_rule_ids`` and ``ignored_rule_ids`` are the resolved
    (post-glob) policy. When either list exceeds
    :data:`_INLINE_BREADCRUMB_THRESHOLD`, each inline body picks up a
    one-line pointer at the summary comment's policy block; otherwise
    the bodies are unchanged.
    """
    findings = _normalize_findings(list(findings), scan_root)
    breadcrumb = _policy_warrants_breadcrumb(ignored_rule_ids, selected_rule_ids)
    try:
        if ctx.platform == "github":
            return _github_post_inline(
                findings, ctx, changed_files, timeout=timeout, breadcrumb=breadcrumb
            )
        return _gitlab_post_inline(
            findings, ctx, changed_files, timeout=timeout, breadcrumb=breadcrumb
        )
    except Exception as exc:  # pragma: no cover
        msg = _redact(str(exc), ctx.token)
        logger.warning("Inline comments: %s post failed (%s).", ctx.platform, msg)
        return InlinePostResult(error=msg)


def _policy_warrants_breadcrumb(
    ignored_rule_ids: list[str] | None,
    selected_rule_ids: list[str] | None,
) -> bool:
    """True when the run's resolved policy is large enough that each
    inline thread should point reviewers at the summary's policy block.

    Symmetric across ``--select`` and ``--ignore``: a 30-rule whitelist
    hides as much context as a 30-rule blacklist, so both gate the
    breadcrumb at the same threshold.
    """
    return any(
        rules and len(rules) > _INLINE_BREADCRUMB_THRESHOLD
        for rules in (ignored_rule_ids, selected_rule_ids)
    )


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
    breadcrumb: bool = False,
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
                client,
                headers,
                base,
                finding,
                ctx,
                diff_refs,
                try_anchor=try_anchor,
                breadcrumb=breadcrumb,
            )
            result._record(posted=posted_one, anchored=anchored, attempted_anchor=try_anchor)
            if posted_one:
                posted += 1

        for fp, record in existing_index.items():
            if fp in wanted_fps:
                continue
            if _INLINE_RESOLVED_SENTINEL in record.body:
                continue
            new_body = _render_resolved_inline_body(record.body, ctx.commit_sha)
            try:
                if record.note_id:
                    client.put(
                        f"{base}/discussions/{record.thread_id}/notes/{record.note_id}",
                        headers=headers,
                        json={"body": new_body},
                    )
                client.put(
                    f"{base}/discussions/{record.thread_id}",
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
    ctx: PlatformContext,
    diff_refs: dict[str, str] | None,
    *,
    try_anchor: bool,
    breadcrumb: bool = False,
) -> tuple[bool, bool]:
    """Post a single GitLab discussion. Returns ``(posted, anchored)``.

    Tries an anchored post first when ``try_anchor`` is set; on a 4xx
    response (typically "Note position is invalid"), retries with a
    file-level body. 5xx and network errors are not retried.
    """
    httpx = _httpx()
    token = ctx.token
    file_path = getattr(finding, "file_path", "?")
    line_number = getattr(finding, "line_number", "?")
    file_link = _finding_file_link(ctx, finding)

    if try_anchor and diff_refs is not None:
        payload = {
            "body": _render_inline_body(
                finding, anchored=True, breadcrumb=breadcrumb, file_link=file_link
            ),
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

    payload = {
        "body": _render_inline_body(
            finding, anchored=False, breadcrumb=breadcrumb, file_link=file_link
        )
    }
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


def _gitlab_existing_discussions(
    client: Any, headers: dict[str, str], base: str
) -> dict[str, _ThreadRecord]:
    out: dict[str, _ThreadRecord] = {}
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
                body = note.get("body") or ""
                fp = _decode_inline_marker(body)
                if fp:
                    out[fp] = _ThreadRecord(
                        thread_id=str(disc_id),
                        note_id=str(note.get("id") or ""),
                        body=body,
                    )
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
          comments(first: 1) { nodes { id body } }
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

_GH_GRAPHQL_MUTATION_UPDATE_COMMENT = """
mutation Update($id: ID!, $body: String!) {
  updatePullRequestReviewComment(input: { pullRequestReviewCommentId: $id, body: $body }) {
    pullRequestReviewComment { id }
  }
}
"""


def _github_post_inline(
    findings: list[Any],
    ctx: PlatformContext,
    changed_files: set[str] | None,
    *,
    timeout: float,
    breadcrumb: bool = False,
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
                client,
                headers,
                graphql_url,
                pr_id,
                finding,
                ctx,
                try_anchor=try_anchor,
                breadcrumb=breadcrumb,
            )
            result._record(posted=posted_one, anchored=anchored, attempted_anchor=try_anchor)
            if posted_one:
                posted += 1
                if url:
                    result.thread_urls.append(url)

        for fp, record in existing_index.items():
            if fp in wanted_fps:
                continue
            if _INLINE_RESOLVED_SENTINEL in record.body:
                continue
            new_body = _render_resolved_inline_body(record.body, ctx.commit_sha)
            try:
                if record.note_id:
                    client.post(
                        graphql_url,
                        headers=headers,
                        json={
                            "query": _GH_GRAPHQL_MUTATION_UPDATE_COMMENT,
                            "variables": {"id": record.note_id, "body": new_body},
                        },
                    )
                client.post(
                    graphql_url,
                    headers=headers,
                    json={
                        "query": _GH_GRAPHQL_MUTATION_RESOLVE,
                        "variables": {"threadId": record.thread_id},
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
    ctx: PlatformContext,
    *,
    try_anchor: bool,
    breadcrumb: bool = False,
) -> tuple[bool, bool, str | None]:
    """Post a single GitHub review thread. Returns ``(posted, anchored, url)``.

    Tries an anchored ``addPullRequestReviewThread`` first when
    ``try_anchor`` is set; on a 4xx response or GraphQL ``errors``
    field (e.g. "pull_request_review_thread.line must be part of the
    diff"), retries with ``subjectType: FILE``.
    """
    token = ctx.token
    file_link = _finding_file_link(ctx, finding)
    if try_anchor:
        anchored_input = {
            "pullRequestId": pr_id,
            "body": _render_inline_body(
                finding, anchored=True, breadcrumb=breadcrumb, file_link=file_link
            ),
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
        "body": _render_inline_body(
            finding, anchored=False, breadcrumb=breadcrumb, file_link=file_link
        ),
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
) -> dict[str, _ThreadRecord]:
    out: dict[str, _ThreadRecord] = {}
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
            first = comments[0] or {}
            body = first.get("body") or ""
            fp = _decode_inline_marker(body)
            if fp:
                out[fp] = _ThreadRecord(
                    thread_id=str(tid),
                    note_id=str(first.get("id") or ""),
                    body=body,
                )
        page_info = rt.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
    return out
