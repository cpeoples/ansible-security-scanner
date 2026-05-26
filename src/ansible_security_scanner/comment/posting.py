"""HTTP I/O for MR/PR comment posting.

This module is the only place in the package that reaches across the
network. All ``httpx`` access goes through ``_pkg.httpx`` (the parent
package's bound name) so tests can ``patch.object(comment.httpx, ...)``
and have the patch take effect for the live code paths here.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from .context import CommentResult, PlatformContext, _redact
from .fingerprint import _decode_marker, _findings_count_from_body

logger = logging.getLogger(__name__)


def _httpx() -> Any:
    """Return the package-level ``httpx`` attribute.

    Routed through the parent package so ``patch.object(comment.httpx,
    ...)`` swaps in the test double for everything below.
    """
    from . import httpx as _h  # noqa: PLC0415 - late binding by design

    return _h


def fetch_changed_files(ctx: PlatformContext, *, timeout: float = 10.0) -> list[str] | None:
    """Return the list of files changed in this MR/PR, or ``None`` if
    the platform call fails.

    Used when the user passes ``--github-comment`` / ``--gitlab-comment``
    *without* ``--files`` or ``--directory`` - the scanner scopes the
    scan to the MR's diff so comments don't complain about pre-existing
    issues on unchanged files. On failure we log and return ``None``;
    callers fall back to a full repo scan rather than silently posting
    an empty comment.
    """
    httpx = _httpx()
    if httpx is None:
        logger.warning("httpx is not installed - cannot fetch changed files.")
        return None
    try:
        with httpx.Client(timeout=timeout) as client:
            if ctx.platform == "github":
                return _github_changed_files(client, ctx)
            return _gitlab_changed_files(client, ctx)
    except httpx.HTTPError as exc:
        logger.warning(
            _redact(
                f"Failed to fetch changed files from {ctx.platform}: {exc}",
                ctx.token,
            )
        )
        return None


def _github_changed_files(client: Any, ctx: PlatformContext) -> list[str]:
    """Page through the GitHub ``pulls/{n}/files`` endpoint.

    Capped at 10 pages of 100 files = 1000 files. If the cap is hit we
    log a warning so the user can decide whether to scan the full repo.
    """
    files: list[str] = []
    headers = {
        "Authorization": f"Bearer {ctx.token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    for page in range(1, 51):
        url = (
            f"{ctx.api_url}/repos/{ctx.project_ref}/pulls/{ctx.mr_number}"
            f"/files?per_page=100&page={page}"
        )
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        chunk = resp.json() or []
        if not chunk:
            break
        for entry in chunk:
            fp = entry.get("filename")
            status = entry.get("status")
            if fp and status != "removed":
                files.append(fp)
        if len(chunk) < 100:
            break
    else:
        logger.warning(
            "Hit the 10-page (1000-file) cap fetching GitHub PR files; "
            "scan will only cover the first 1000."
        )
    return files


def _gitlab_changed_files(client: Any, ctx: PlatformContext) -> list[str]:
    """Hit GitLab's ``merge_requests/{iid}/changes`` endpoint."""
    headers = {"PRIVATE-TOKEN": ctx.token}
    url = f"{ctx.api_url}/projects/{ctx.project_ref}/merge_requests/{ctx.mr_number}/changes"
    resp = client.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json() or {}
    out: list[str] = []
    for change in data.get("changes", []) or []:
        if change.get("deleted_file"):
            continue
        fp = change.get("new_path") or change.get("old_path")
        if fp:
            out.append(fp)
    return out


def fetch_diff_lines(
    ctx: PlatformContext,
    *,
    timeout: float = 15.0,
) -> dict[str, set[int]] | None:
    """Return ``{file_path: {added/context line numbers}}`` for the MR diff,
    or ``None`` when the platform call fails.

    Deprecated: inline-comment posting no longer consumes this hint -
    the platform itself is now the source of truth for whether a given
    ``(file, line)`` is anchorable. Kept for downstream callers but
    scheduled for removal once those migrate.
    """
    httpx = _httpx()
    if httpx is None:
        return None
    try:
        with httpx.Client(timeout=timeout) as client:
            if ctx.platform == "github":
                return _github_diff_lines(client, ctx)
            return _gitlab_diff_lines(client, ctx)
    except httpx.HTTPError as exc:
        logger.info(
            "Inline comments: could not fetch diff lines from %s: %s.",
            ctx.platform,
            _redact(str(exc), ctx.token),
        )
        return None


def _github_diff_lines(client: Any, ctx: PlatformContext) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    headers = {
        "Authorization": f"Bearer {ctx.token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    for page in range(1, 51):
        url = (
            f"{ctx.api_url}/repos/{ctx.project_ref}/pulls/{ctx.mr_number}"
            f"/files?per_page=100&page={page}"
        )
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        chunk = resp.json() or []
        if not chunk:
            break
        for entry in chunk:
            fp = entry.get("filename")
            patch = entry.get("patch") or ""
            if not fp or entry.get("status") == "removed" or not patch:
                continue
            out.setdefault(fp, set()).update(_added_lines_from_patch(patch))
        if len(chunk) < 100:
            break
    return out


def _gitlab_diff_lines(client: Any, ctx: PlatformContext) -> dict[str, set[int]]:
    """Build ``{file: {line numbers in MR diff}}`` from GitLab.

    Prefers the ``/versions`` endpoint (canonical, untruncated diffs)
    and falls back to ``/changes`` (which can be truncated on large
    MRs) only if ``/versions`` returns nothing usable.
    """
    headers = {"PRIVATE-TOKEN": ctx.token}
    base = f"{ctx.api_url}/projects/{ctx.project_ref}/merge_requests/{ctx.mr_number}"

    versions_resp = client.get(f"{base}/versions", headers=headers)
    versions_resp.raise_for_status()
    versions = versions_resp.json() or []
    if versions:
        version_id = versions[0].get("id")
        if version_id:
            detail = client.get(f"{base}/versions/{version_id}", headers=headers)
            detail.raise_for_status()
            out = _parse_gitlab_diffs((detail.json() or {}).get("diffs") or [])
            if out:
                return out

    changes_resp = client.get(f"{base}/changes", headers=headers)
    changes_resp.raise_for_status()
    return _parse_gitlab_diffs((changes_resp.json() or {}).get("changes") or [])


def _parse_gitlab_diffs(entries: list[dict[str, Any]]) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for entry in entries:
        if entry.get("deleted_file"):
            continue
        fp = entry.get("new_path") or entry.get("old_path")
        diff = entry.get("diff") or ""
        if not fp or not diff:
            continue
        out.setdefault(fp, set()).update(_added_lines_from_patch(diff))
    return out


_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _added_lines_from_patch(patch: str) -> set[int]:
    # Includes context lines so a finding adjacent to (but not on) a +
    # line still anchors to a hunk reviewers can see.
    lines: set[int] = set()
    new_ln = 0
    for raw in patch.splitlines():
        m = _HUNK_HEADER_RE.match(raw)
        if m:
            new_ln = int(m.group(1))
            continue
        if not raw or new_ln == 0 or raw[0] == "-":
            continue
        if raw[0] in "+ ":
            lines.add(new_ln)
            new_ln += 1
    return lines


def fetch_existing_marker(
    ctx: PlatformContext,
    *,
    timeout: float = 15.0,
) -> dict[str, Any] | None:
    """Locate the previous scanner comment on this MR/PR (if any) and
    return its decoded marker payload, or ``None`` if there isn't one.

    Read-only counterpart to :func:`post_or_update_comment`: callers
    fetch the previous payload before rendering so the body can include
    a delta line. Failures are non-fatal: a transient API hiccup skips
    the delta line, never the comment itself.
    """
    httpx = _httpx()
    if httpx is None:
        return None
    try:
        with httpx.Client(timeout=timeout) as client:
            if ctx.platform == "github":
                headers = {
                    "Authorization": f"Bearer {ctx.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                base = f"{ctx.api_url}/repos/{ctx.project_ref}"
                _, previous = _find_github_existing_comment(client, headers, base, ctx.mr_number)
                return previous
            headers = {"PRIVATE-TOKEN": ctx.token}
            base = f"{ctx.api_url}/projects/{ctx.project_ref}/merge_requests/{ctx.mr_number}"
            _, previous = _find_gitlab_existing_note(client, headers, base)
            return previous
    except httpx.HTTPError as exc:
        msg = _redact(str(exc), ctx.token)
        logger.info(
            "MR-comment: could not fetch previous comment marker on %s: %s. "
            "Delta header will be omitted from this scan's comment.",
            ctx.platform,
            msg,
        )
        return None


def post_or_update_comment(
    ctx: PlatformContext,
    body: str,
    *,
    timeout: float = 15.0,
) -> CommentResult:
    """Post a new comment or PATCH an existing one matching our marker.

    Idempotent: re-running on the same MR after a second commit edits
    the same comment instead of creating a thread of duplicates.
    Failures raise nothing - the CLI's "warn and continue" contract
    means we always return a :class:`CommentResult` (with ``error``
    set) so the scan's exit code stays driven by findings.
    """
    httpx = _httpx()
    if httpx is None:
        return CommentResult(
            posted=False,
            updated=False,
            comment_id=None,
            comment_url=None,
            findings_count=0,
            previous_findings_count=None,
            bytes_written=0,
            error="httpx is not installed",
        )

    try:
        with httpx.Client(timeout=timeout) as client:
            if ctx.platform == "github":
                return _github_post_or_update(client, ctx, body)
            return _gitlab_post_or_update(client, ctx, body)
    except httpx.HTTPError as exc:
        # We redact BEFORE formatting - httpx exceptions can embed the
        # request URL (no token) and occasionally request headers (with
        # token) depending on version. Redacting unconditionally is
        # cheaper than introspecting the exception type.
        msg = _redact(str(exc), ctx.token)
        logger.warning(
            "MR comment post to %s failed: %s. Continuing - scanner exit code is unaffected.",
            ctx.platform,
            msg,
        )
        return CommentResult(
            posted=False,
            updated=False,
            comment_id=None,
            comment_url=None,
            findings_count=0,
            previous_findings_count=None,
            bytes_written=0,
            error=msg,
        )


def _github_post_or_update(client: Any, ctx: PlatformContext, body: str) -> CommentResult:
    """GitHub PR-comment flow: list issue comments, find one with our
    marker, PATCH it if found, POST a new one otherwise.

    GitHub's issue-comments endpoint is used (not the review-comment
    one) because review comments are tied to a file+line and can't be
    used for summary comments spanning the whole PR.
    """
    headers = {
        "Authorization": f"Bearer {ctx.token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    base = f"{ctx.api_url}/repos/{ctx.project_ref}"

    existing_id, previous = _find_github_existing_comment(client, headers, base, ctx.mr_number)
    findings_count = _findings_count_from_body(body)

    if existing_id is not None:
        url = f"{base}/issues/comments/{existing_id}"
        resp = client.patch(url, headers=headers, json={"body": body})
        resp.raise_for_status()
        data = resp.json() or {}
        return CommentResult(
            posted=False,
            updated=True,
            comment_id=existing_id,
            comment_url=data.get("html_url"),
            findings_count=findings_count,
            previous_findings_count=(previous or {}).get("findings_count"),
            bytes_written=len(body.encode("utf-8")),
        )

    url = f"{base}/issues/{ctx.mr_number}/comments"
    resp = client.post(url, headers=headers, json={"body": body})
    resp.raise_for_status()
    data = resp.json() or {}
    return CommentResult(
        posted=True,
        updated=False,
        comment_id=data.get("id"),
        comment_url=data.get("html_url"),
        findings_count=findings_count,
        previous_findings_count=None,
        bytes_written=len(body.encode("utf-8")),
    )


def _find_github_existing_comment(
    client: Any, headers: dict[str, str], base: str, pr_number: int
) -> tuple[int | None, dict[str, Any] | None]:
    """Walk GitHub's issue-comments pages looking for one with our
    marker. Capped at 10 pages (1000 comments).
    """
    for page in range(1, 11):
        url = f"{base}/issues/{pr_number}/comments?per_page=100&page={page}"
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        comments = resp.json() or []
        if not comments:
            return None, None
        for c in comments:
            body = c.get("body") or ""
            decoded = _decode_marker(body)
            if decoded is not None:
                return c.get("id"), decoded
        if len(comments) < 100:
            return None, None
    return None, None


def _gitlab_post_or_update(client: Any, ctx: PlatformContext, body: str) -> CommentResult:
    """GitLab MR-note flow: equivalent to the GitHub path above but
    against the ``merge_requests/{iid}/notes`` endpoint.
    """
    headers = {"PRIVATE-TOKEN": ctx.token}
    base = f"{ctx.api_url}/projects/{ctx.project_ref}/merge_requests/{ctx.mr_number}"

    existing_id, previous = _find_gitlab_existing_note(client, headers, base)
    findings_count = _findings_count_from_body(body)

    if existing_id is not None:
        url = f"{base}/notes/{existing_id}"
        resp = client.put(url, headers=headers, json={"body": body})
        resp.raise_for_status()
        comment_url = _gitlab_note_url(ctx, existing_id)
        return CommentResult(
            posted=False,
            updated=True,
            comment_id=existing_id,
            comment_url=comment_url,
            findings_count=findings_count,
            previous_findings_count=(previous or {}).get("findings_count"),
            bytes_written=len(body.encode("utf-8")),
        )

    url = f"{base}/notes"
    resp = client.post(url, headers=headers, json={"body": body})
    resp.raise_for_status()
    data = resp.json() or {}
    note_id = data.get("id")
    return CommentResult(
        posted=True,
        updated=False,
        comment_id=note_id,
        comment_url=_gitlab_note_url(ctx, note_id) if note_id else None,
        findings_count=findings_count,
        previous_findings_count=None,
        bytes_written=len(body.encode("utf-8")),
    )


def _find_gitlab_existing_note(
    client: Any, headers: dict[str, str], base: str
) -> tuple[int | None, dict[str, Any] | None]:
    """Same marker-scan as the GitHub helper but for GitLab MR notes."""
    for page in range(1, 11):
        url = f"{base}/notes?per_page=100&page={page}&sort=desc&order_by=updated_at"
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        notes = resp.json() or []
        if not notes:
            return None, None
        for n in notes:
            if n.get("system"):
                continue
            body = n.get("body") or ""
            decoded = _decode_marker(body)
            if decoded is not None:
                return n.get("id"), decoded
        if len(notes) < 100:
            return None, None
    return None, None


def _gitlab_note_url(ctx: PlatformContext, note_id: int) -> str | None:
    """Rebuild a browser-friendly link to a GitLab note.

    GitLab's REST API doesn't return a ``web_url`` on note
    create/update; we derive one from ``CI_SERVER_URL`` +
    ``CI_PROJECT_PATH`` (when available).
    """
    project_path = os.environ.get("CI_PROJECT_PATH")
    server_url = os.environ.get("CI_SERVER_URL", "").rstrip("/")
    if not project_path or not server_url:
        return None
    return f"{server_url}/{project_path}/-/merge_requests/{ctx.mr_number}#note_{note_id}"
