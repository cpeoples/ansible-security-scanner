#!/usr/bin/env python3
"""
Merge-request / pull-request comment posting for the scanner.

Invoked from ``cli.main()`` when the user passes ``--gitlab-comment``
(``--gl-comment``) or ``--github-comment`` (``--gh-comment``). Platform
detection is purely env-based (see ``detect_platform``); tokens are
read from environment variables only - never from CLI flags, config
files, or logs.

The comment rendered here follows the "Dashboard + Drilldown" format:

- One-line severity header so reviewers see the shape at a glance.
- Findings grouped by rule id, each in a collapsed ``<details>`` block.
- Up to 5 occurrences shown per rule; the rest collapsed into "N more".
- Above ~100 findings, only the top 10 rules by count × severity are
  shown; other rules are summarised.
- Hard cap of ``_MAX_COMMENT_BYTES`` (well under GitHub's 65 536
  character hard cap) - if the rendered body would exceed the cap the
  renderer degrades further to a dashboard-only view.

A stable HTML marker is embedded at the end of every body so the next
scan can find and PATCH the same comment rather than spamming new
ones. The marker also carries the previous run's finding count + SHA
so the "resolved" banner can cite exactly how many findings were
cleaned up.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

try:
    import httpx
except ImportError:  # pragma: no cover - declared as a runtime dependency
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


# Comment-sizing limits, tuned to "what fits in an MR comment" rather
# than user preference. Users who want richer output should read the
# always-written full-report artifact (``security-reports/report.md``).

# GitHub's hard limit is 65 536 characters. Leave headroom for the
# marker, the footer, and any URL expansion GitHub does server-side.
_MAX_COMMENT_BYTES = 55_000

# Snippets per rule rendered as full fenced blocks. Beyond this we
# collapse remaining findings to a one-line reference list -- repeated
# near-identical snippets drown out signal.
_MAX_SNIPPETS_PER_RULE = 3

# Findings per rule rendered before the tail is dropped and replaced
# with a "see the full report" pointer. ~50 keeps a worst-case rule
# under ~6 KB of comment body, with room for the remediation block.
_MAX_FINDINGS_PER_RULE = 50

# Above this count, only the top-N rules are shown as ``<details>``;
# everything else becomes a summary line pointing at the full report.
_DASHBOARD_THRESHOLD = 100
_TOP_RULES_IN_DASHBOARD = 10

# Severity weights used when ranking "top rules". Matches the scanner's
# own severity-weighted scoring (see ``score_calculator.py``); keeps
# the comment's "top offenders" list aligned with the score surfaced
# in the header.
_SEVERITY_WEIGHT = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 1}

# Stable marker. Versioned so future changes to the embedded payload
# format (e.g. adding resolved-findings tracking) remain backward
# compatible with older comments already posted on long-lived MRs.
# The detection regex (``_MARKER_RE``) accepts any ``:v\d+`` so older
# v1 comments posted by previous scanner versions still resolve in
# ``_find_existing_comment_id`` and get PATCHed in place.
_MARKER_PREFIX = "<!-- ansible-security-scanner:mr-comment:v2"
_MARKER_SUFFIX = "-->"

# Public repo URL, embedded in the footer credit line. Defined at module
# scope (rather than inlined) so the URL has exactly one source of truth
# and is trivial to change if the repo ever moves.
_PROJECT_URL = "https://github.com/cpeoples/ansible-security-scanner"

# Default path where the full aggregate report is written alongside
# posting the comment. The parent ``security-reports/`` directory is
# already namespaced for the scanner, so we don't repeat "security" or
# qualify the filename with "mr-comment-" - a CI ``artifacts:`` glob
# of ``security-reports/**`` picks this up alongside any future
# sibling outputs (per-file reports, SARIF, etc.) with no rename.
_DEFAULT_FULL_REPORT_PATH = Path("security-reports") / "report.md"


Platform = Literal["github", "gitlab"]


@dataclass
class PlatformContext:
    """Everything the commenter needs to talk to GitHub or GitLab.

    Populated by ``detect_platform`` from CI environment variables; no
    network I/O happens during detection. ``token`` is the only
    sensitive field here - it must never be logged, echoed, or written
    to disk. Every code path that could surface a token value routes
    through ``_redact`` first.
    """

    platform: Platform
    api_url: str
    project_ref: str  # "owner/repo" for GitHub, "<project_id>" for GitLab
    mr_number: int  # PR number on GitHub, MR iid on GitLab
    commit_sha: str  # The SHA the scanner saw on disk
    token: str = field(repr=False)
    run_url: str | None = None  # Link to CI job / GH action run (footer)


@dataclass
class CommentResult:
    """Outcome of ``post_or_update_comment``. Exposes just enough for
    the CLI layer to log a coherent summary without needing to know
    about httpx Response objects.
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
    with the full httpx request object never leaks a PAT to CI output.
    Empty / falsy tokens are no-ops so callers don't need to guard
    around optional auth.
    """
    out = msg
    for tok in tokens:
        if tok:
            out = out.replace(tok, "***REDACTED***")
    return out


def _first_env(*names: str, env: dict[str, str] | None = None) -> str | None:
    """Return the first non-empty environment variable from ``names``.

    Used to walk fallback chains like "scanner-specific -> platform
    default -> CI-job-specific" without a pile of ``os.environ.get``
    calls at each call site. Accepts an explicit ``env`` mapping for
    tests (and for ``detect_platform``'s ``env=`` parameter, which
    otherwise would leak real process env into unit tests).
    """
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
    isn't active or if required env vars are missing. Never probes
    the network and never reads config files - this is the one choice
    the user already made clear: env-only.

    The ``env`` parameter exists for testability; production callers
    always pass ``None`` so ``os.environ`` is consulted.
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
    fallback because re-run workflows sometimes lose the ref. Both
    paths produce the same ``PlatformContext``; if neither is usable
    we log a specific warning so operators know which env var to set.
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
    # Prefer GitHub Actions' canonical predefined variable. It's always
    # exported and already accounts for github.com vs Enterprise (where
    # the API base is ``https://HOST/api/v3``); we synthesise the same
    # value as a fallback for non-Actions callers.
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
    """Parse the PR number AND the durable head-commit SHA from GitHub
    Actions env, preferring ``GITHUB_REF=refs/pull/<n>/merge`` for the
    number and the pull-request event payload for the head SHA.

    The head SHA matters because ``GITHUB_SHA`` on a ``pull_request``
    workflow is GitHub's synthetic *merge commit* -- reachable via
    ``refs/pull/<n>/merge`` while the PR is open, but garbage-collected
    after merge or close. ``pull_request.head.sha`` (the actual
    contributor-pushed commit) is durable for the life of the repo and
    keeps file:line deep-links alive after the PR is merged.
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

    Works transparently against gitlab.com AND self-hosted instances
    because GitLab Runner exports ``CI_API_V4_URL`` (the canonical,
    version-correct API root) on every job. We fall back to deriving
    it from ``CI_SERVER_URL`` for pre-12.7 runners that didn't export
    ``CI_API_V4_URL`` yet.
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
    # which 404s file:line deep-links posted in the comment.
    # ``CI_MERGE_REQUEST_SOURCE_BRANCH_SHA`` is the contributor-pushed
    # head and stays reachable for the life of the project, so prefer it
    # on MR pipelines and fall back to ``CI_COMMIT_SHA`` elsewhere.
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


# Marker payload size cap. The marker is a single embedded HTML
# comment used for cross-run state (locate the comment to PATCH,
# diff resolved rules, cite cleared rule IDs). It must stay small so
# it doesn't eat the comment-byte budget that powers the
# ``<details>`` drilldown -- we previously shipped every open rule_id
# verbatim, which on a 1000-rule MR bloated the marker to ~35 KB and
# pushed the renderer into the empty-``<details>`` fallback. v2 ships
# at most ``_MARKER_RULE_SAMPLE`` named ids plus a SHA-256 digest of
# the full sorted set so "did anything change" comparisons stay
# precise without paying per-rule bytes.
_MARKER_RULE_SAMPLE = 12

# Per-finding fingerprint cap. Each fingerprint is a 16-hex-char
# truncated SHA-256 of "rule_id|file_path|line_number" -- enough
# entropy to make collisions vanishingly unlikely on realistic
# scans without bloating the marker. The full set is also digested
# so the next run can detect "did anything change" in O(1) bytes
# even when the truncated list is capped.
_MARKER_FINGERPRINT_SAMPLE = 50
_FINGERPRINT_LEN = 16


def _finding_fingerprint(finding: Any) -> str:
    """Stable per-finding identity hash.

    Combines ``rule_id``, ``file_path``, and ``line_number`` -- the
    same triple the scanner uses to dedup across files -- so the
    same finding on the same line in two consecutive scans hashes
    to the same value. Truncated to ``_FINGERPRINT_LEN`` hex chars
    to keep the marker payload small.
    """
    rule_id = getattr(finding, "rule_id", "") or ""
    file_path = getattr(finding, "file_path", "") or ""
    line_number = getattr(finding, "line_number", 0) or 0
    raw = f"{rule_id}|{file_path}|{line_number}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:_FINGERPRINT_LEN]


def _encode_marker(
    findings_count: int,
    commit_sha: str,
    open_rule_ids: Iterable[str],
    *,
    finding_fingerprints: Iterable[str] | None = None,
    finding_rule_ids: Iterable[str] | None = None,
) -> str:
    """Serialise a small JSON payload into the trailing HTML marker.

    Embedded on a single line so naive regex searches (including the
    ``_find_existing_comment_id`` helper below) always match it. The
    payload lets the next scan:

    * tell whether this comment was posted by an older scanner version,
    * compute "findings resolved since last run" precisely (down to
      the per-finding level when ``finding_fingerprints`` is supplied),
    * cite the previous scan's SHA in the footer,
    * name the rule families that resolved (when ``finding_rule_ids``
      is supplied alongside the fingerprints).

    Schema (v2):

    * ``version`` -- schema version, bumped when fields change.
    * ``findings_count`` -- total finding count this run.
    * ``commit_sha`` -- head SHA the scan was run against.
    * ``open_rule_ids`` -- at most ``_MARKER_RULE_SAMPLE`` ids, used
      to cite cleared rules in the resolved banner.
    * ``open_rule_ids_total`` / ``open_rule_ids_digest`` -- full-set
      cardinality and SHA-256 digest of the sorted ids, so the next
      run can detect *any* change to the rule surface in O(1) bytes.
    * ``finding_fingerprints`` -- at most ``_MARKER_FINGERPRINT_SAMPLE``
      truncated fingerprints from ``_finding_fingerprint``. Optional.
    * ``finding_fingerprints_total`` / ``finding_fingerprints_digest``
      -- same shape as the rule-id pair, used by ``_compute_delta``
      to know when the truncated sample understates the real diff.
    * ``finding_rule_ids`` -- ``{fingerprint: rule_id}`` over the same
      sample as ``finding_fingerprints``. Inline-mapped (not a
      parallel list) so JSON corruption can't desync the two arrays.

    ``finding_rule_ids`` (the caller-supplied list) must be aligned by
    index with ``finding_fingerprints``. Mismatched lengths raise.
    """
    sorted_ids = sorted({r for r in open_rule_ids if r})
    digest = hashlib.sha256("\n".join(sorted_ids).encode("utf-8")).hexdigest()
    payload = {
        "version": 2,
        "findings_count": int(findings_count),
        "commit_sha": commit_sha or "",
        "open_rule_ids": sorted_ids[:_MARKER_RULE_SAMPLE],
        "open_rule_ids_total": len(sorted_ids),
        "open_rule_ids_digest": digest,
    }
    if finding_fingerprints is not None:
        fps_list = [f for f in finding_fingerprints if f]
        rules_list: list[str] | None = None if finding_rule_ids is None else list(finding_rule_ids)
        if rules_list is not None and len(rules_list) != len(fps_list):
            raise ValueError(
                "finding_rule_ids must be the same length as the "
                f"non-empty entries of finding_fingerprints (got "
                f"{len(rules_list)} vs {len(fps_list)})"
            )
        if rules_list is not None:
            pair_map: dict[str, str] = {}
            for fp, rid in zip(fps_list, rules_list):
                if fp and fp not in pair_map:
                    pair_map[fp] = rid or ""
            sorted_fps = sorted(pair_map.keys())
            sample_fps = sorted_fps[:_MARKER_FINGERPRINT_SAMPLE]
            payload["finding_rule_ids"] = {
                fp: pair_map[fp] for fp in sample_fps if pair_map.get(fp)
            }
        else:
            sorted_fps = sorted(set(fps_list))
            sample_fps = sorted_fps[:_MARKER_FINGERPRINT_SAMPLE]
        fp_digest = hashlib.sha256("\n".join(sorted_fps).encode("utf-8")).hexdigest()
        payload["finding_fingerprints"] = sample_fps
        payload["finding_fingerprints_total"] = len(sorted_fps)
        payload["finding_fingerprints_digest"] = fp_digest
    as_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return f"{_MARKER_PREFIX} {as_json} {_MARKER_SUFFIX}"


_MARKER_RE = re.compile(
    r"<!--\s*ansible-security-scanner:mr-comment:v\d+\s*(\{.*?\})\s*-->",
    re.DOTALL,
)


def _decode_marker(body: str) -> dict[str, Any] | None:
    """Pull the JSON payload out of an existing comment's marker, or
    ``None`` if no marker is present / parseable.

    Deliberately tolerant: a malformed marker (future version,
    hand-edited body, etc.) returns ``None`` and the caller treats
    this run as a fresh post - better than crashing mid-pipeline.
    """
    m = _MARKER_RE.search(body or "")
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return data


# Severity tiers, ordered most-actionable first. Drives both the
# severity header line at the top of the comment and the new
# tier-grouped section headings that group rule blocks under one
# section per severity.
_SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Maximum rule names listed in a tier section heading before
# truncating with "+N more". Picked so a single severity line stays
# under ~140 chars on a typical wide-rule scan.
_TIER_SUMMARY_RULE_NAMES = 4

# Friendly tier labels used in <summary> text. The emoji conveys
# severity at a glance; the word reinforces it for screen readers
# and search-in-page.
_TIER_LABEL = {
    "CRITICAL": "critical",
    "HIGH": "high-severity",
    "MEDIUM": "medium-severity",
    "LOW": "low-severity",
}


_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}


# Snippet redaction strikes a balance: show enough of the offending
# line for the reviewer to recognise it, never the literal secret value.
# Patterns target the textual *value* of common credential keys, not the
# keys themselves -- the key is what makes the snippet recognisable.

_SNIPPET_MAX_CHARS = 120
# Sized so a typical Ansible task block fits whole. Outliers fall back
# to the pinned-offender trim below.
_SNIPPET_MAX_LINES = 40

# When a single line exceeds ``_SNIPPET_MAX_CHARS`` we don't blindly
# keep the prefix - that hides exactly the part that often contains
# the offending flag (e.g. ``curl -d '<12KB JSON>' -k -u ...``).
# Instead we keep the start of the line (so reviewers always see
# what the line *begins* with) AND the region around the rightmost
# CLI flag (so the substring that made the rule fire stays visible).
# The two halves are joined by a single ``...`` ellipsis - same visual
# convention as a sentence-with-elision, no bracketing ellipses.
# The pattern matches typical CLI flag forms - ``-k``, ``-X``,
# ``--insecure``, ``--no-check-certs``, ``--validate-certs=false``.
# Anchored to a word boundary so we don't pick up dashes inside
# JSON/strings.
_SNIPPET_FLAG_RE = re.compile(r"(?<![\w-])(-[A-Za-z]\b|--[A-Za-z][\w-]*)")
_SNIPPET_PREFIX_KEEP = 60
_SNIPPET_FLAG_TAIL_KEEP = 50

# Match ``<key>: "value"`` / ``<key>=value`` for a small set of
# credential-looking keys. Captures the key + delimiter so we can
# replace only the value half. Single-line by design - snippets are
# already a single line of context per finding.
_SNIPPET_KV_REDACT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|"
    r"private[-_]?key|client[-_]?secret|auth[-_]?token|bearer|"
    r"x-api-key|aws_secret_access_key)"
    r"(\s*[:=]\s*['\"]?)"
    r"([^'\"\s,}]+)"
)
_SNIPPET_URL_CREDS_RE = re.compile(r"(?i)(https?://[^:\s]+:)([^@\s]+)(@)")
_SNIPPET_BEARER_RE = re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._\-]+)")

# A captured value that is *only* a Jinja2 reference (e.g.
# ``{{ vault_password }}``) is not a literal secret - it's a
# vault-backed lookup, which is the recommended pattern. Redacting
# it produces noise (``password: "*** vault_password }}"``) and
# obscures the legitimate context reviewers need to see. The KV
# regex stops at whitespace so the captured value for
# ``"{{ x }}"`` is just ``{{`` - look at the slice of the source
# starting at the value to make the determination.
_JINJA_VALUE_PREFIX_RE = re.compile(r"^\s*\{\{[^{}]*\}\}\s*['\"]?\s*$")


def _kv_redact_replacement(snippet: str, match: re.Match[str]) -> str:
    value_start = match.start(3)
    line_end = snippet.find("\n", value_start)
    tail = snippet[value_start : line_end if line_end != -1 else len(snippet)]
    if _JINJA_VALUE_PREFIX_RE.match(tail):
        return match.group(0)
    return f"{match.group(1)}{match.group(2)}***"


def _redact_snippet(snippet: str, *, pin: str = "") -> str:
    """Return a length-bounded, secret-redacted view of a finding's
    code snippet.

    The scanner's ``code_snippet`` is the full enclosing YAML task
    block. Short blocks render whole; longer blocks trim to head +
    pinned offender (when ``pin`` is supplied) + tail, with ``# ...``
    gap markers showing where lines were dropped.

    Redaction is intentionally conservative: we only mask the
    *value* portion of patterns that strongly imply a credential.
    Anything else passes through unchanged so the reviewer sees
    real context.
    """
    if not snippet:
        return ""
    raw_lines = [ln.rstrip() for ln in snippet.splitlines() if ln.strip()]
    if not raw_lines:
        return ""

    indent = min((len(ln) - len(ln.lstrip()) for ln in raw_lines), default=0)
    dedented = [ln[indent:] for ln in raw_lines]
    pin_dedented = pin.strip()
    if pin_dedented and indent and pin_dedented.startswith(" " * indent):
        pin_dedented = pin_dedented[indent:]
    trimmed = _trim_to_head_and_tail(dedented, _SNIPPET_MAX_LINES, pin=pin_dedented)

    redacted: list[str] = []
    for ln in trimmed:
        ln = _SNIPPET_KV_REDACT_RE.sub(lambda m, src=ln: _kv_redact_replacement(src, m), ln)
        ln = _SNIPPET_URL_CREDS_RE.sub(lambda m: f"{m.group(1)}***{m.group(3)}", ln)
        ln = _SNIPPET_BEARER_RE.sub(lambda m: f"{m.group(1)}***", ln)
        if len(ln) > _SNIPPET_MAX_CHARS:
            ln = _truncate_long_line(ln)
        redacted.append(ln)
    return "\n".join(redacted)


def _truncate_long_line(ln: str) -> str:
    """Truncate a single snippet line, keeping both the line's start
    AND the region around the rightmost CLI flag.

    For long shell tasks like
    ``curl -d '<12KB JSON>' -k -u "splunker:..."``
    the naive ``ln[:N]`` keeps the harmless ``curl -d`` prefix and
    drops the ``-k`` that made the rule fire. Reviewers then see a
    snippet that doesn't seem to match the rule's claim, which
    looks broken. We instead emit ``<prefix>...<flag-tail>`` so the
    line's beginning *and* the offending flag are both visible.
    The single middle ellipsis is a normal sentence-with-elision
    convention; it doesn't bracket the line on both sides.

    When no flag is present we fall back to the prefix-and-trailing-...
    behaviour. The full unaltered snippet always lives in the full
    Markdown report linked from the comment footer, so anyone who
    needs the elided middle can click through.
    """
    matches = list(_SNIPPET_FLAG_RE.finditer(ln))
    if not matches:
        return ln[: _SNIPPET_MAX_CHARS - 3].rstrip() + "..."

    # The tail must start at the EARLIEST flag past the prefix
    # window, not the rightmost one. Picking the rightmost flag
    # would silently drop intermediate flags - e.g. for
    # ``curl -d '<huge>' -k -u "..." -H "..."`` the rightmost flag
    # is ``-H``, but ``-k`` is the one that fired the rule. Keeping
    # everything from the first uncovered flag onward is also
    # cheaper than trying to score "which flag is the offender" at
    # render time without rule context.
    tail_anchor: int | None = None
    for m in matches:
        if m.start() >= _SNIPPET_PREFIX_KEEP:
            tail_anchor = m.start()
            break
    if tail_anchor is None:
        return ln[: _SNIPPET_MAX_CHARS - 3].rstrip() + "..."

    prefix = ln[:_SNIPPET_PREFIX_KEEP].rstrip()
    tail = ln[tail_anchor:].lstrip()
    if len(tail) > _SNIPPET_FLAG_TAIL_KEEP:
        tail = tail[: _SNIPPET_FLAG_TAIL_KEEP - 3].rstrip() + "..."
    return f"{prefix} ... {tail}"


def _trim_to_head_and_tail(
    lines: list[str],
    max_lines: int,
    *,
    pin: str = "",
) -> list[str]:
    """Cap ``lines`` to ``max_lines`` while preserving the first line
    (task header), the last line (task tail), and -- when ``pin`` is
    given -- the line containing the offender so the trigger never
    elides into a ``# ...`` gap.

    When ``lines`` already fits, returns it unchanged. Otherwise builds
    ``head + [optional pinned slice] + tail`` with ``# ...`` separators
    where lines are dropped, so reviewers always see the head, the
    offender, and the tail.
    """
    if len(lines) <= max_lines:
        return lines

    pin_idx: int | None = None
    if pin:
        for i, ln in enumerate(lines):
            if ln.strip() == pin:
                pin_idx = i
                break

    head_count = max(1, max_lines // 3)
    tail_count = max(1, max_lines // 3)
    head = lines[:head_count]
    tail = lines[-tail_count:]

    if pin_idx is None or pin_idx < head_count or pin_idx >= len(lines) - tail_count:
        return head + ["# ..."] + tail

    middle = ["# ..."] if pin_idx > head_count else []
    middle.append(lines[pin_idx])
    if pin_idx + 1 < len(lines) - tail_count:
        middle.append("# ...")
    return head + middle + tail


def _resolve_finding_paths(
    file_path: str,
    scan_root: Path | None,
) -> tuple[str, Path | None]:
    """Map a finding's ``file_path`` to a repo-root-relative display
    path and a disk-readable absolute path.

    Findings carry ``file_path`` relative to the scanner's
    ``--directory`` argument (e.g. ``demo.yml`` when the scan ran with
    ``--directory ansible/``). That layout is correct for the markdown
    report (which is rooted at ``--directory``) but breaks two
    consumers in the MR/PR comment:

    * the ``/blob/<sha>/<file_path>`` deep link 404s on the platform
      because the file actually lives at ``<directory>/<file_path>``
      under the repo root;
    * ``_decorate_snippet`` reads the source from disk for context +
      caret rendering and silently falls back to the undecorated
      snippet when the read fails.

    When ``scan_root`` is provided we re-attach its repo-root-relative
    prefix so the display path matches the layout the platform sees
    on disk, and we resolve the on-disk path for snippet decoration.
    When ``scan_root`` is ``None`` we keep today's behaviour (path
    rendered verbatim, snippet read from CWD) so callers that don't
    yet thread the scan root through aren't regressed.
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
    """Build a browser-friendly link to ``<file_path>:<line_number>``
    on the platform's blob viewer, or ``None`` when we can't.

    Returns ``None`` when ``commit_sha`` is missing (rendering an
    unanchored link that breaks on the next commit is worse than a
    plain ``file:line`` reference) or when we can't derive the
    web-UI host. Callers fall back to the bare reference in that
    case so the comment never renders a broken link.
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


_SENTENCE_END = re.compile(r"\. (?=[A-Z])")


def _first_sentence(text: str, *, max_chars: int = 220) -> str:
    """Return the first sentence of ``text``, capped at ``max_chars``.

    Sentence boundaries are ``. <space> <Capital>``; abbreviations
    (``e.g.``, ``Mr.``, ``U.S.``, ``Python 3.9``) are skipped via
    structural shapes in :func:`_looks_like_abbreviation` so we don't
    truncate mid-clause.
    """
    s = (text or "").strip()
    if not s:
        return ""
    for match in _SENTENCE_END.finditer(s):
        end = match.start()
        if end >= max_chars:
            break
        if _looks_like_abbreviation(s, end):
            continue
        return s[: end + 1].strip()
    if len(s) <= max_chars:
        return s
    return s[: max_chars - 3].rstrip() + "..."


def _looks_like_abbreviation(s: str, dot_index: int) -> bool:
    """True when the period at ``s[dot_index]`` ends an abbreviation.

    Recognises three shapes: dotted (``e.g.``, ``U.S.``), short tokens
    (``Mr.``, ``oz.``), and decimals (``3.9``).
    """
    if dot_index < 1:
        return False
    if dot_index >= 2 and s[dot_index - 2] == ".":
        return True
    if s[dot_index - 1].isdigit():
        return True
    word_start = dot_index
    while word_start > 0 and s[word_start - 1].isalpha():
        word_start -= 1
    token = s[word_start:dot_index]
    return 0 < len(token) < 4 and (word_start == 0 or not s[word_start - 1].isalnum())


def _group_by_rule(findings: list[Any]) -> dict[str, list[Any]]:
    """Bucket findings by ``rule_id`` while preserving insertion order.

    Insertion-order preservation matters because the renderer walks
    the groups in that order to build the comment; arbitrary ordering
    would make two identical scans produce different comment bodies
    and break the edit-in-place idempotency check on some platforms.
    """
    groups: dict[str, list[Any]] = {}
    for f in findings:
        groups.setdefault(getattr(f, "rule_id", "unknown"), []).append(f)
    return groups


def _rule_rank(group: list[Any]) -> tuple[int, int, int]:
    """Sort key for rule ordering in the rendered comment.

    Reviewers expect CRITICALs at the top of the page no matter how
    many other findings sit below them. The previous implementation
    summed severity weights across the group, which let a 6-HIGH rule
    (weight 48) outrank a 3-CRITICAL rule (weight 45). Rank instead
    by the *peak* severity in the group, then total weight, then
    count - this guarantees every CRITICAL group sorts above every
    non-CRITICAL group regardless of repetition.
    """
    peak = max(
        (_SEVERITY_WEIGHT.get((getattr(f, "severity", "") or "LOW").upper(), 1) for f in group),
        default=1,
    )
    weight_sum = sum(
        _SEVERITY_WEIGHT.get((getattr(f, "severity", "") or "LOW").upper(), 1) for f in group
    )
    return (peak, weight_sum, len(group))


def _severity_header(findings: list[Any], security_score: float | None) -> str:
    """Build the one-line severity counter that anchors the comment.

    Reviewers glance at this, nothing else, when deciding whether to
    block an MR. Keep it compact and always in the same shape
    regardless of how truncated the body is below.
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = (getattr(f, "severity", "") or "").upper()
        if sev in counts:
            counts[sev] += 1

    parts = [
        f"{_SEVERITY_EMOJI[sev]} {counts[sev]} {sev}"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if counts[sev]
    ]
    if not parts:
        parts = ["✅ 0 findings"]

    header = "### 🛡️ Security Scan - " + " · ".join(parts)
    if security_score is not None:
        header += f"\n\n**Security score:** {int(round(security_score))} / 100"
    return header


_GAP_MARKER_RE = re.compile(r"^\s*#\s*\.{3,}\s*$")

# Lines of context shown above + below the offender row in the
# decorated snippet (matches ruff/eslint/semgrep convention).
_SNIPPET_CONTEXT_LINES = 3

# Hard cap for the YAML-task-aware widener. Even if the task block is
# huge (long heredoc, many `vars:` entries), don't render more than
# this many lines or the comment becomes a wall of text.
_SNIPPET_MAX_TASK_LINES = 30

_TASK_HEADER_RE = re.compile(r"^\s*-\s+(?:name|hosts|block|rescue|always|import_|include_)\b")


def _indent_of(line: str) -> int:
    """Leading-space indent of ``line``, or ``-1`` for blank / comment lines."""
    stripped = line.lstrip()
    if not stripped or stripped.startswith("#"):
        return -1
    return len(line) - len(stripped)


def _expand_to_yaml_task(source_lines: list[str], line_number: int) -> tuple[int, int] | None:
    """Find the smallest enclosing Ansible task block around ``line_number``.

    Returns ``(start, end)`` 1-indexed inclusive line numbers when the
    offender lives inside a ``- name:`` / ``- block:`` / ``- include_*:``
    item. Returns ``None`` for plain config YAML or when the block
    exceeds ``_SNIPPET_MAX_TASK_LINES`` so callers fall back to the
    fixed-context window rather than rendering a wall of text.
    """
    if line_number <= 0 or line_number > len(source_lines):
        return None
    offender_indent = _indent_of(source_lines[line_number - 1])
    if offender_indent < 0:
        return None

    opener_idx: int | None = None
    opener_indent = 0
    for i in range(line_number - 2, -1, -1):
        indent = _indent_of(source_lines[i])
        if indent < 0 or indent >= offender_indent:
            continue
        if _TASK_HEADER_RE.match(source_lines[i]):
            opener_idx = i
            opener_indent = indent
            break
    if opener_idx is None:
        return None

    end_idx = len(source_lines) - 1
    for i in range(opener_idx + 1, len(source_lines)):
        indent = _indent_of(source_lines[i])
        if indent < 0:
            continue
        if indent <= opener_indent:
            end_idx = i - 1
            break

    if end_idx - opener_idx + 1 > _SNIPPET_MAX_TASK_LINES:
        return None
    return opener_idx + 1, end_idx + 1


# Rules that flag the *absence* of a key on a task. The finding is
# anchored at the task header for navigation, but the header itself
# isn't the offender, so we skip the ``>`` caret -- the remediation
# block carries the actionable guidance.
_STRUCTURAL_RULE_IDS = frozenset({"missing_no_log"})


def _decorate_snippet(
    snippet: str,
    *,
    file_path: str,
    line_number: int,
    show_caret: bool = True,
    source_path: Path | None = None,
) -> str:
    """Re-render ``snippet`` with file-line numbers and a caret on the
    offending row, ripgrep-style::

        76 |     ignore_errors: no
        77 |     uri:
     >  78 |       url: "http://{{ AMI_rawUrl }}:81/update_hec"
        79 |       method: POST
        80 |       headers:

    The (snippet-line -> file-line) mapping isn't reliable from the
    finding alone (snippets are built at many sites with different
    anchoring conventions), so we re-read the source file and locate
    the snippet inside it.

    Returns the original snippet unchanged when the source file isn't
    readable or the snippet can't be pinned (heavy redaction, deleted
    files, synthesised paths, etc.).
    """
    if not snippet or line_number <= 0 or not file_path:
        return snippet

    read_target = source_path if source_path is not None else Path(file_path)
    try:
        source_lines = read_target.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return snippet
    if not source_lines or line_number > len(source_lines):
        return snippet

    snippet_lines = snippet.splitlines()
    offender_idx_in_snippet = _locate_offender_in_snippet(snippet_lines, source_lines, line_number)
    if offender_idx_in_snippet is None:
        return snippet

    task_window = _expand_to_yaml_task(source_lines, line_number)
    if task_window is not None:
        start, end = task_window
    else:
        start = max(1, line_number - _SNIPPET_CONTEXT_LINES)
        end = min(len(source_lines), line_number + _SNIPPET_CONTEXT_LINES)
    window = list(enumerate(source_lines[start - 1 : end], start=start))
    width = len(str(end))

    rendered: list[str] = []
    for file_ln, content in window:
        marker = ">" if show_caret and file_ln == line_number else " "
        rendered.append(f"{marker} {file_ln:>{width}} | {_redact_snippet_line(content)}")
    return "\n".join(rendered)


def _redact_snippet_line(line: str) -> str:
    """Single-line variant of ``_redact_snippet``.

    ``_redact_snippet`` strips blank lines and dedents -- destructive
    when rendering a literal source-file window where indentation
    carries meaning. This helper applies just the secret-masking
    regexes and leaves whitespace untouched.
    """
    if not line:
        return line
    ln = _SNIPPET_KV_REDACT_RE.sub(lambda m, src=line: _kv_redact_replacement(src, m), line)
    ln = _SNIPPET_URL_CREDS_RE.sub(lambda m: f"{m.group(1)}***{m.group(3)}", ln)
    ln = _SNIPPET_BEARER_RE.sub(lambda m: f"{m.group(1)}***", ln)
    if len(ln) > _SNIPPET_MAX_CHARS:
        ln = _truncate_long_line(ln)
    return ln


def _locate_offender_in_snippet(
    snippet_lines: list[str],
    source_lines: list[str],
    line_number: int,
) -> int | None:
    """Find the snippet-line index corresponding to file-line
    ``line_number``, or ``None`` when the snippet can't be pinned.

    Two passes: exact line equality, then stripped equality (handles
    snippets where leading whitespace was normalised).
    """
    if line_number <= 0 or line_number > len(source_lines):
        return None
    target = source_lines[line_number - 1]

    for i, ln in enumerate(snippet_lines):
        if ln == target:
            return i

    target_stripped = target.strip()
    if not target_stripped:
        return None
    for i, ln in enumerate(snippet_lines):
        if ln.strip() == target_stripped:
            return i

    return None


def _render_finding_item(
    anchor: str,
    snippet: str,
    *,
    file_path: str = "",
    line_number: int = 0,
    show_caret: bool = True,
    source_path: Path | None = None,
) -> str:
    """Render one finding row in a rule block.

    The scanner emits a synthetic ``# ...`` gap-marker line inside
    ``code_snippet`` when the offending key isn't adjacent to the
    task header (e.g. ``uri:`` on one line, ``validate_certs: no``
    several lines later). The marker is a scanner annotation, not
    real file content, so we never want it inside a ``yaml`` fence.

    When a gap marker is present we split the snippet on it and emit
    the two halves as separate fenced blocks with an italic
    ``(intermediate lines elided)`` separator between them. When
    there's no gap marker the snippet renders as a single fence.

    The file:line anchor is rendered as a plain paragraph (no list
    bullet) so the following fenced code block sits at the document
    root rather than inside a list-item continuation. GitHub and
    GitLab both indent fenced code under a preceding ``- `` bullet
    inside a ``<details>`` element, which produces a wall of indented
    snippets when a rule has many findings -- even after the blank
    line that should terminate the list.
    """
    if not snippet:
        return anchor

    decorated = _decorate_snippet(
        snippet,
        file_path=file_path,
        line_number=line_number,
        show_caret=show_caret,
        source_path=source_path,
    )
    if decorated != snippet:
        # Decorated render replaces the gap-marker pathway below.
        return f"{anchor}\n\n" + _fence(decorated)

    lines = snippet.splitlines()
    gap_idx = next((i for i, ln in enumerate(lines) if _GAP_MARKER_RE.match(ln)), -1)
    if gap_idx == -1:
        return f"{anchor}\n\n" + _fence("\n".join(lines))

    before = "\n".join(lines[:gap_idx]).rstrip()
    after = "\n".join(lines[gap_idx + 1 :]).lstrip("\n")
    parts: list[str] = [anchor]
    if before:
        parts.append(_fence(before))
    parts.append("*(intermediate lines elided)*")
    if after:
        parts.append(_fence(after))
    return "\n\n".join(parts)


def _fence(body: str) -> str:
    """Build a ``yaml`` code fence at column 0.

    Earlier versions indented every line by two spaces so the fence
    visually nested under its bullet, but that turns the whole block
    into a list-item continuation in stricter CommonMark renderers
    (e.g. GitLab) and leaks the list context into whatever block
    follows. Emitting at column 0 with a blank line before the fence
    closes the list and renders identically on GitHub and GitLab.
    """
    return f"```yaml\n{body}\n```"


# Match the `**Vulnerable Code:** ... <fence>` chunk emitted by the
# remediation generators. We strip it from the rendered remediation
# because the same code is already shown above (per-finding, with
# proper redaction). Showing it again wastes comment bytes and risks
# leaking secrets into a section the redacter doesn't run over.
# The label sometimes carries an emoji prefix ("❌ Vulnerable Code")
# from the richer generators, so the regex tolerates any leading
# non-word characters between the bold markers.
_VULNERABLE_CODE_BLOCK_RE = re.compile(
    r"\*\*[^\w*]*Vulnerable Code:\*\*\s*\n```[a-zA-Z0-9_-]*\n.*?```\s*\n",
    re.DOTALL,
)


def _redact_remediation(raw: str) -> str:
    """Run the same redaction primitives over every line of a
    remediation example.

    The pre-formatted ``remediation_example`` from
    ``RemediationGenerator`` embeds the original (unredacted) finding
    snippet in its "Vulnerable Code" + "Secret Parameters Found"
    sections. Without redaction those literal secrets would leak into
    the MR comment - the very thing the snippet redacter was built
    to prevent. The single-line redactors are safe to run inside code
    fences because they only mutate ``key: value`` / ``URL userinfo``
    / ``Bearer ...`` patterns, none of which produce false positives
    on Markdown narrative text.
    """
    out: list[str] = []
    for line in raw.splitlines():
        ln = _SNIPPET_KV_REDACT_RE.sub(lambda m, src=line: _kv_redact_replacement(src, m), line)
        ln = _SNIPPET_URL_CREDS_RE.sub(lambda m: f"{m.group(1)}***{m.group(3)}", ln)
        ln = _SNIPPET_BEARER_RE.sub(lambda m: f"{m.group(1)}***", ln)
        ln = _BACKTICK_LITERAL_REDACT_RE.sub(_backtick_literal_replacement, ln)
        out.append(ln)
    return "\n".join(out)


# Match ``**field**: `<value>` -> `<replacement>`` rows the rich
# generators emit for "Secret Parameters Found" sections. The value
# half is a back-tick-delimited literal which the KV redactor can't
# see because it stops at quotes/whitespace, not back-ticks.
_BACKTICK_LITERAL_REDACT_RE = re.compile(
    r"(?i)\*\*(?P<key>password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|"
    r"private[-_]?key|client[-_]?secret|auth[-_]?token|bearer|aws_secret_access_key|"
    r"pass)\*\*:\s*`(?P<value>[^`]+)`"
)


def _backtick_literal_replacement(match: re.Match[str]) -> str:
    value = match.group("value")
    if _JINJA_VALUE_PREFIX_RE.match(value):
        return match.group(0)
    return f"**{match.group('key')}**: `***`"


def _ensure_fence_blank_lines(md: str) -> str:
    """Guarantee a blank line on both sides of every fenced code block.

    GitHub-Flavored Markdown is strict about code-fence delimiters
    inside an HTML ``<details>`` element: a ``**Label:**\\n```yaml``
    sequence with no blank line is parsed as inline text, so the code
    block silently disappears from the rendered comment. The raw text
    we receive from ``RemediationGenerator`` runs labels and fences
    together (which renders fine at the document root); inserting
    blank lines around every fence makes both contexts identical.
    """
    lines = md.splitlines()
    out: list[str] = []
    in_fence = False
    for i, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            if not in_fence and out and out[-1].strip():
                out.append("")
            out.append(line)
            if in_fence and i + 1 < len(lines) and lines[i + 1].strip():
                out.append("")
            in_fence = not in_fence
        else:
            out.append(line)
    return "\n".join(out)


def _render_remediation_block(finding: Any) -> str:
    """Render the structured remediation example for a rule group as
    a collapsed ``<details>`` block.

    Findings carry a pre-formatted ``remediation_example`` string from
    ``RemediationGenerator`` containing a ``Secure Fix:`` code block
    and a ``Why this matters:`` rationale. Displaying it inline gives
    reviewers a copy-pasteable corrected snippet right alongside the
    offending one - same reason the markdown report does it. Wrapped
    in a nested collapsed ``<details>`` so the comment stays scannable
    and only opens when a reviewer wants the full fix.

    Returns an empty string when no remediation is present so the
    caller can append unconditionally.
    """
    raw = (getattr(finding, "remediation_example", "") or "").strip()
    if not raw:
        return ""

    cleaned = _VULNERABLE_CODE_BLOCK_RE.sub("", raw, count=1).strip()
    if not cleaned:
        return ""

    cleaned = _redact_remediation(cleaned)
    cleaned = _ensure_fence_blank_lines(cleaned)

    return f"<details><summary>🛠️ Show recommended fix</summary>\n\n{cleaned}\n\n</details>"


def _render_rule_block(
    rule_id: str,
    group: list[Any],
    ctx: PlatformContext,
    *,
    show_details: bool,
    with_severity_emoji: bool = True,
    full_report_link: str | None = None,
    scan_root: Path | None = None,
) -> str:
    """Render one ``<details>`` block for a rule group.

    ``show_details=False`` drops the per-finding file:line list and
    collapses the block into just the header row - used in dashboard
    mode (>100 findings) so the comment body still fits.

    ``with_severity_emoji=False`` omits the leading ``🔴/🟠/🟡/🟢`` from
    the rule's summary line. Used inside the tier-grouped layout
    where the parent tier's <details> already conveys severity, so
    every per-rule row would otherwise repeat the same colored dot
    redundantly.

    When ``show_details=True`` each finding renders as a deep-linked
    file:line followed by a redacted snippet of the offending line,
    and the block ends with a one-line remediation hint pulled from
    the rule's own ``recommendation`` field. Snippet/recommendation
    lookups silently degrade to plain text when the data is missing.
    """
    severity = (getattr(group[0], "severity", "LOW") or "LOW").upper()
    title = (getattr(group[0], "title", "") or rule_id).strip()
    files = {getattr(f, "file_path", "?") for f in group}
    if with_severity_emoji:
        prefix = _SEVERITY_EMOJI.get(severity, "⚪") + " "
    else:
        prefix = ""
    summary = (
        f"<summary>{prefix}<code>{rule_id}</code> · {title} - "
        f"{len(group)} finding{'s' if len(group) != 1 else ''} "
        f"in {len(files)} file{'s' if len(files) != 1 else ''}</summary>"
    )

    if not show_details:
        return f"<details>{summary}</details>"

    # First N findings render with their full code snippet so the
    # reviewer sees the offending pattern in context. Findings
    # beyond the snippet cap collapse to a compact comma-separated
    # reference list of file:line links -- same triage value
    # (location), a fraction of the vertical space.
    snippet_findings = group[:_MAX_SNIPPETS_PER_RULE]
    extra_findings = group[_MAX_SNIPPETS_PER_RULE:_MAX_FINDINGS_PER_RULE]

    blocks: list[str] = []
    for f in snippet_findings:
        fp = getattr(f, "file_path", "?")
        ln = getattr(f, "line_number", 0)
        rule_id = getattr(f, "rule_id", "") or ""
        display_path, source_path = _resolve_finding_paths(fp, scan_root)
        link = _file_deep_link(ctx, display_path, ln)
        anchor = f"[`{display_path}:{ln}`]({link})" if link else f"`{display_path}:{ln}`"
        snippet = _redact_snippet(
            getattr(f, "code_snippet", "") or "",
            pin=getattr(f, "match_line", "") or "",
        )
        blocks.append(
            _render_finding_item(
                anchor,
                snippet,
                file_path=display_path,
                line_number=ln,
                show_caret=rule_id not in _STRUCTURAL_RULE_IDS,
                source_path=source_path,
            )
        )

    if extra_findings:
        more_links: list[str] = []
        for f in extra_findings:
            fp = getattr(f, "file_path", "?")
            ln = getattr(f, "line_number", 0)
            display_path, _ = _resolve_finding_paths(fp, scan_root)
            link = _file_deep_link(ctx, display_path, ln)
            more_links.append(
                f"[`{display_path}:{ln}`]({link})" if link else f"`{display_path}:{ln}`"
            )
        blocks.append("**Also at:** " + ", ".join(more_links))

    truncated = len(group) - _MAX_FINDINGS_PER_RULE
    if truncated > 0:
        # Tail dropped; name the affected files and point at the full report.
        files_in_tail = sorted(
            {
                _resolve_finding_paths(getattr(f, "file_path", "?"), scan_root)[0]
                for f in group[_MAX_FINDINGS_PER_RULE:]
                if getattr(f, "file_path", "")
            }
        )
        file_hint = ""
        if files_in_tail:
            shown = ", ".join(f"`{p}`" for p in files_in_tail[:3])
            if len(files_in_tail) > 3:
                shown += f" (+{len(files_in_tail) - 3} more)"
            file_hint = f" in {shown}"
        plural = "s" if truncated != 1 else ""
        report_pointer = (
            f"see the full report (`{full_report_link}`) for every location."
            if full_report_link
            else "see the full report artifact linked in the footer below."
        )
        blocks.append(f"…and **{truncated} more finding{plural}**{file_hint} — {report_pointer}")

    body = "\n\n".join(blocks)
    fix_hint = _first_sentence(getattr(group[0], "recommendation", "") or "")
    if fix_hint:
        body += f"\n\n💡 **Fix:** {fix_hint}"

    remediation_block = _render_remediation_block(group[0])
    if remediation_block:
        body += "\n\n" + remediation_block

    return "<details>" + summary + "\n\n" + body + "\n\n</details>"


def _render_footer(ctx: PlatformContext, full_report_link: str | None) -> str:
    """Build the small metadata footer: commit SHA, scanner credit
    (linked back to the project), and a link to wherever the full
    report can be reviewed.

    ``full_report_link`` is either:

    * an absolute URL (already-resolved artifact link, used verbatim);
    * a workspace-relative path - we don't render it as a clickable
      file link because the scanner has no way to know the CI
      runner's web-UI artifact base. Instead we resolve it against
      the run/job URL we already have:

      - GitLab CI: ``<CI_JOB_URL>/artifacts/file/<path>`` is the
        canonical browseable URL for any file in the job's artifact
        bundle; one click opens the rendered Markdown.
      - GitHub Actions: GitHub doesn't expose a deterministic
        per-file artifact URL (artifact IDs are minted server-side
        post-upload), so we link to the run's artifact list page
        and instruct the reviewer to download.
      - Outside CI (no run_url): show the path as-is so a developer
        running the scanner locally sees where it landed on disk.
    """
    from . import __version__ as scanner_version  # lazy to avoid import cycles

    bits: list[str] = []
    report_bit, run_link_already_used = _format_full_report_bit(ctx, full_report_link)
    if report_bit:
        bits.append(report_bit)
    if ctx.commit_sha:
        bits.append(f"commit `{ctx.commit_sha[:12]}`")
    bits.append(
        f"Scanned with [ansible-security-scanner]({_PROJECT_URL}){_format_version(scanner_version)}"
    )
    if ctx.run_url and not run_link_already_used:
        bits.append(f"[run logs]({ctx.run_url})")
    return "<sub>" + " · ".join(bits) + "</sub>"


def _format_version(scanner_version: str) -> str:
    """Format the scanner-version suffix shown next to the credit link.

    Returns an empty string for dev/local builds (anything carrying a
    PEP 440 ``+local`` segment or a ``.devN`` marker, e.g.
    ``0.1.dev1+gce3b15a21.d20260430``) so a reviewer never sees a raw
    commit hash or local-build timestamp in a public MR/PR comment.
    Tagged releases render as `` v1.2.3``.
    """
    v = (scanner_version or "").strip()
    if not v or "+" in v or ".dev" in v:
        return ""
    return f" v{v.lstrip('v')}"


def _format_full_report_bit(
    ctx: PlatformContext,
    full_report_link: str | None,
) -> tuple[str | None, bool]:
    """Render the "Full report" footer fragment for the current
    platform / link shape.

    Returns ``(fragment, run_link_already_used)`` so the caller knows
    whether to also emit a separate ``[run logs]`` entry. Splitting
    this out of ``_render_footer`` keeps the platform-specific URL
    construction in one place and lets us unit-test each branch
    without re-rendering the whole footer.
    """
    if not full_report_link:
        return None, False

    if full_report_link.startswith(("http://", "https://")):
        return f"📎 [Full report]({full_report_link})", False

    if ctx.run_url:
        if ctx.platform == "gitlab":
            # CI_JOB_URL + /artifacts/file/<path> is GitLab's stable
            # browseable URL for any file in a job's artifact bundle.
            artifact_url = (
                f"{ctx.run_url.rstrip('/')}/artifacts/file/{full_report_link.lstrip('/')}"
            )
            return f"📎 [Full report]({artifact_url})", True
        # GitHub: anchor at the artifacts list on the run page. The
        # artifact ID isn't predictable, so we send the reviewer to
        # the page where it's listed for download.
        artifacts_url = f"{ctx.run_url.rstrip('/')}#artifacts"
        return (
            f"📎 Full report: `{full_report_link}` "
            f"(download from [run artifacts]({artifacts_url}))",
            True,
        )

    return f"📎 Full report: `{full_report_link}`", False


@dataclass
class _Delta:
    """Compact result of comparing two consecutive scans of the same MR.

    Populated by ``_compute_delta`` from the previous run's marker
    payload + the current run's findings. Counts are exact when both
    scans wrote fingerprints; older v2 markers without fingerprints
    fall back to rule-id deltas.

    ``approximate=True`` signals that the previous truncated fingerprint
    sample understated the real diff -- the renderer flags the line so
    reviewers don't read exact counts that are actually lower bounds.

    ``resolved_rule_ids`` / ``new_rule_ids`` are family-level: a rule
    appears in ``resolved_rule_ids`` only when *every* finding for it
    disappeared (otherwise the receipts would lie about ongoing
    findings the reviewer can still see in the body).
    """

    resolved: int
    new: int
    still_open: int
    approximate: bool
    resolved_rule_ids: tuple[str, ...] = ()
    new_rule_ids: tuple[str, ...] = ()


def _compute_delta(
    previous: dict[str, Any] | None,
    current_findings: list[Any],
) -> _Delta | None:
    """Return resolved/new/still-open counts comparing the previous
    marker payload against the current scan's findings.

    Returns ``None`` when there's no comparable previous run.

    Precise mode (preferred): both runs carry fingerprints; set-diff
    them. Each fingerprint is a 16-char SHA-256 prefix of
    ``rule_id|file_path|line_number``. Counts are per-finding;
    rule-id receipts are family-level (see ``_Delta``).

    Fallback mode: no fingerprints in the previous marker. Set-diff
    rule ids, ``approximate=True`` so the renderer says "rules" not
    "findings".
    """
    if not previous:
        return None

    current_fps = {_finding_fingerprint(f) for f in current_findings}
    prev_fps_sample: list[str] = list(previous.get("finding_fingerprints") or [])
    prev_fps_total = previous.get("finding_fingerprints_total")
    raw_rule_map = previous.get("finding_rule_ids")
    prev_rule_map: dict[str, str] = raw_rule_map if isinstance(raw_rule_map, dict) else {}

    if prev_fps_sample or isinstance(prev_fps_total, int):
        prev_fps_set = set(prev_fps_sample)
        resolved_fps = prev_fps_set - current_fps
        new_fps = current_fps - prev_fps_set
        resolved = len(resolved_fps)
        new = len(new_fps)
        still_open = len(current_fps & prev_fps_set)
        # ``open_rule_ids`` survives marker truncation, so union it with
        # the rule-mapping values for full family coverage.
        prev_rule_families: set[str] = set(prev_rule_map.values()) | set(
            previous.get("open_rule_ids") or []
        )
        current_rule_families: set[str] = {
            getattr(f, "rule_id", "") or "" for f in current_findings
        }
        current_rule_families.discard("")
        resolved_rule_ids: tuple[str, ...] = tuple(
            sorted(prev_rule_families - current_rule_families)
        )
        new_rule_ids: tuple[str, ...] = tuple(sorted(current_rule_families - prev_rule_families))
        approximate = bool(isinstance(prev_fps_total, int) and prev_fps_total > len(prev_fps_set))
        if resolved == 0 and new == 0:
            return _Delta(0, 0, still_open, approximate, resolved_rule_ids, new_rule_ids)
        return _Delta(resolved, new, still_open, approximate, resolved_rule_ids, new_rule_ids)

    # Rule-id-only fallback.
    prev_rule_ids = set(previous.get("open_rule_ids") or [])
    if not prev_rule_ids and not previous.get("findings_count"):
        return None
    current_rule_ids = {
        getattr(f, "rule_id", "") for f in current_findings if getattr(f, "rule_id", "")
    }
    resolved_rule_set = prev_rule_ids - current_rule_ids
    new_rule_set = current_rule_ids - prev_rule_ids
    still_rules = len(current_rule_ids & prev_rule_ids)
    if not resolved_rule_set and not new_rule_set:
        return None
    return _Delta(
        len(resolved_rule_set),
        len(new_rule_set),
        still_rules,
        approximate=True,
        resolved_rule_ids=tuple(sorted(resolved_rule_set)),
        new_rule_ids=tuple(sorted(new_rule_set)),
    )


def _render_delta_line(delta: _Delta | None) -> str:
    """Render a one-line trajectory summary for the comment header.

    Returns ``""`` when nothing meaningfully changed.

    Tone follows the trajectory:

    * pure progress (resolved >0, new ==0)  -> "📈 Progress: 2 resolved · 3 still open"
    * pure regression (new >0, resolved ==0) -> "⚠️ 2 new findings since last scan · 5 still open"
    * mixed (both >0)                        -> "📊 2 resolved · 1 new · 3 still open since last scan"

    Receipts continuations follow on the next line when populated:

        Resolved rules: `rule_a`, `rule_b`, …
        New rules:      `rule_c`, `rule_d`, …

    Each line is capped at ``_RESOLVED_RULES_HEADLINE_CAP`` rule names
    with an "(+N more)" overflow so a giant cleanup PR doesn't push
    the rest of the comment off the screen.

    ``delta.approximate=True`` softens "findings" to "rules" since the
    fallback is rule-level, not per-line.
    """
    if delta is None:
        return ""
    if delta.resolved == 0 and delta.new == 0:
        return ""

    unit = "rule" if delta.approximate else "finding"

    def _plural(n: int, word: str) -> str:
        return f"{n} {word}{'s' if n != 1 else ''}"

    if delta.new == 0 and delta.resolved > 0:
        line = f"📈 **Progress:** {_plural(delta.resolved, unit)} resolved"
        if delta.still_open:
            line += f" · {delta.still_open} still open"
    elif delta.resolved == 0 and delta.new > 0:
        line = f"⚠️ **{_plural(delta.new, 'new ' + unit)}** since last scan"
        if delta.still_open:
            line += f" · {delta.still_open} still open"
    else:
        line = (
            f"📊 {delta.resolved} resolved · {delta.new} new · "
            f"{delta.still_open} still open since last scan"
        )

    if delta.resolved_rule_ids:
        line += "  \n" + _format_rule_ids_suffix("Resolved rules", delta.resolved_rule_ids)
    if delta.new_rule_ids:
        line += "  \n" + _format_rule_ids_suffix("New rules", delta.new_rule_ids)

    return line


# Cap on rule names spelled out in receipts lines before we collapse
# the rest into "(+N more)". 8 covers realistic PRs without truncation
# while keeping pathological cleanup PRs from dominating the header.
_RESOLVED_RULES_HEADLINE_CAP = 8


def _format_rule_ids_suffix(label: str, rule_ids: tuple[str, ...]) -> str:
    """Format a ``<label>: \\`rule_a\\`, \\`rule_b\\`, …`` continuation
    following the delta headline. Backticks render as inline code so
    reviewers can grep for the rule in their IDE.

    Caller appends two trailing spaces + ``\\n`` to produce a Markdown
    ``<br>`` so the continuation hugs the headline.
    """
    head = list(rule_ids[:_RESOLVED_RULES_HEADLINE_CAP])
    overflow = len(rule_ids) - len(head)
    rendered = ", ".join(f"`{r}`" for r in head)
    if overflow > 0:
        rendered += f" (+{overflow} more)"
    return f"{label}: {rendered}"


def _render_resolved_banner(
    previous_findings_count: int | None,
    previous_open_rule_ids: list[str],
    ctx: PlatformContext,
) -> str:
    """Render the zero-findings resolved state.

    Matches the "green ✓ with diff" UX picked earlier: celebrate the
    cleanup AND tell the reviewer exactly how many findings
    disappeared since the last scanned commit. The confidence number
    is the scanner's own security_score - no new metric introduced.
    """
    if previous_findings_count and previous_findings_count > 0:
        cleaned = previous_findings_count
        rules = ", ".join(f"`{r}`" for r in previous_open_rule_ids[:6])
        if len(previous_open_rule_ids) > 6:
            rules += f", and {len(previous_open_rule_ids) - 6} more"
        rules_line = f"\n\n**Resolved since last scan:** {cleaned} finding"
        rules_line += "s" if cleaned != 1 else ""
        if rules:
            rules_line += f" (rules: {rules})"
        return (
            "### ✅ All security findings resolved\n\n"
            "**Security score:** 100 / 100 · review confidence: high" + rules_line
        )

    return (
        "### ✅ No security findings\n\n"
        "**Security score:** 100 / 100 · 0 findings on changed files."
    )


def _tier_summary_line(severity: str, ranked_for_tier: list[tuple[str, list[Any]]]) -> str:
    """Build the single-line section heading for a severity tier.

    Reads as e.g. ``🔴 1 critical · curl_pipe_to_shell`` or
    ``🟡 7 medium-severity · 4 rules · world_writable_files,
    get_url_no_checksum, +5 more``. Listing the first few rule
    names lets reviewers scan a tier without expanding every rule.
    """
    finding_count = sum(len(group) for _, group in ranked_for_tier)
    rule_count = len(ranked_for_tier)
    rule_word = "rule" if rule_count == 1 else "rules"

    emoji = _SEVERITY_EMOJI.get(severity, "⚪")
    label = _TIER_LABEL.get(severity, severity.lower())

    head = f"{emoji} **{finding_count} {label}**"
    if rule_count != finding_count:
        head += f" · {rule_count} {rule_word}"

    shown = [rid for rid, _ in ranked_for_tier[:_TIER_SUMMARY_RULE_NAMES]]
    extra = rule_count - len(shown)
    names = ", ".join(f"`{rid}`" for rid in shown)
    if extra > 0:
        names += f", +{extra} more"
    if names:
        return f"{head} · {names}"
    return head


def _render_tier_section(
    severity: str,
    ranked_for_tier: list[tuple[str, list[Any]]],
    ctx: PlatformContext,
    *,
    show_details: bool,
    full_report_link: str | None = None,
    scan_root: Path | None = None,
) -> str:
    """Render one severity-tier section.

    Each tier is a markdown section heading followed by its rule
    blocks. We deliberately do NOT wrap the tier in a ``<details>``
    element: nesting ``<details>`` blocks that contain fenced code
    breaks GitHub and GitLab Markdown rendering (the renderer drops
    out of HTML mode at the first code fence, leaking subsequent
    ``<summary>`` tags as raw text). Section headings give reviewers
    the same severity grouping without the nesting hazard.

    The per-rule blocks themselves omit their leading severity emoji
    because the section heading already conveys severity.

    Empty tiers are filtered out by the caller (``_render_tiered_body``)
    so this helper never has to handle the zero-rule case.
    """
    rule_blocks = [
        _render_rule_block(
            rid,
            group,
            ctx,
            show_details=show_details,
            with_severity_emoji=False,
            full_report_link=full_report_link,
            scan_root=scan_root,
        )
        for rid, group in ranked_for_tier
    ]
    heading = "#### " + _tier_summary_line(severity, ranked_for_tier)
    return heading + "\n\n" + "\n\n".join(rule_blocks)


def _group_ranked_by_severity(
    ranked: list[tuple[str, list[Any]]],
) -> dict[str, list[tuple[str, list[Any]]]]:
    """Bucket ``ranked`` (rule_id, group) pairs into severity tiers
    while preserving each tier's rank ordering.

    The input ranking (severity-weighted count) already places the
    most-actionable rules first; preserving it inside each tier means
    a reviewer who expands HIGH sees the noisiest HIGH rule at the
    top, not the alphabetically-first one.
    """
    buckets: dict[str, list[tuple[str, list[Any]]]] = {sev: [] for sev in _SEVERITY_ORDER}
    for rid, group in ranked:
        sev = (getattr(group[0], "severity", "LOW") or "LOW").upper()
        buckets.setdefault(sev, buckets["LOW"]).append((rid, group))
    return buckets


def _render_tiered_body(
    ranked: list[tuple[str, list[Any]]],
    ctx: PlatformContext,
    *,
    show_details: bool,
    full_report_link: str | None = None,
    scan_root: Path | None = None,
) -> list[str]:
    """Render the full set of rule blocks as one ``<details>`` per
    non-empty severity tier, in tier order. Returns the list of
    section strings so the caller can splice them between the
    severity header and the footer.

    A horizontal rule (``---``) separates consecutive tier sections;
    the first tier isn't prefixed since the section heading already
    announces the start of the body.
    """
    buckets = _group_ranked_by_severity(ranked)
    sections: list[str] = []
    for sev in _SEVERITY_ORDER:
        rules_in_tier = buckets.get(sev) or []
        if not rules_in_tier:
            continue
        if sections:
            sections.append("---")
        sections.append(
            _render_tier_section(
                sev,
                rules_in_tier,
                ctx,
                show_details=show_details,
                full_report_link=full_report_link,
                scan_root=scan_root,
            )
        )
    return sections


def render_comment_body(
    findings: list[Any],
    ctx: PlatformContext,
    *,
    security_score: float | None = None,
    previous: dict[str, Any] | None = None,
    full_report_link: str | None = None,
    scan_root: Path | None = None,
) -> str:
    """Produce the final Markdown body for the MR/PR comment.

    Applies the "Dashboard + Drilldown" degradation ladder:

    * 0 findings -> resolved banner (cites previously-open rules).
    * 1-100 findings -> header + per-rule ``<details>`` blocks.
    * 101+ findings OR rendered body > ``_MAX_COMMENT_BYTES`` ->
      dashboard-only view: header + top-N rule summaries + a
      prominent link to the full-report artifact.

    Every output includes the stable marker so subsequent scans can
    locate and PATCH this exact comment rather than appending a new
    one.
    """
    open_rule_ids = sorted(
        {getattr(f, "rule_id", "") for f in findings if getattr(f, "rule_id", "")}
    )
    finding_fingerprints = [_finding_fingerprint(f) for f in findings]
    # Aligned with ``finding_fingerprints`` so the next scan can name
    # the resolved rule families in its delta header.
    finding_rule_ids = [getattr(f, "rule_id", "") or "" for f in findings]
    delta_line = _render_delta_line(_compute_delta(previous, findings))

    if not findings:
        prev_count = None
        prev_open = []
        if previous:
            prev_count = previous.get("findings_count")
            prev_open = previous.get("open_rule_ids") or []
        body = _render_resolved_banner(prev_count, list(prev_open), ctx)
        footer = _render_footer(ctx, full_report_link)
        marker = _encode_marker(0, ctx.commit_sha, open_rule_ids)
        return "\n\n".join([body, "---", footer, marker]) + "\n"

    groups = _group_by_rule(findings)
    ranked = sorted(groups.items(), key=lambda kv: _rule_rank(kv[1]), reverse=True)
    total = len(findings)

    header = _severity_header(findings, security_score)
    if delta_line:
        header += f"\n\n{delta_line}"
    header += (
        f"\n\n**Changed files scanned:** {len({getattr(f, 'file_path', '?') for f in findings})}"
        f" · **Findings:** {total}"
    )

    # First pass: render every rule in full, grouped under one
    # <details> per severity tier. CRITICAL/HIGH open by default,
    # MEDIUM/LOW collapsed so the comment stays scannable on PRs
    # with long-tail advisory findings.
    full_sections = _render_tiered_body(
        ranked, ctx, show_details=True, full_report_link=full_report_link, scan_root=scan_root
    )
    body = _render_drilldown(
        header,
        full_sections,
        ctx,
        full_report_link,
        open_rule_ids,
        total,
        finding_fingerprints=finding_fingerprints,
        finding_rule_ids=finding_rule_ids,
    )
    if len(body.encode("utf-8")) <= _MAX_COMMENT_BYTES and total < _DASHBOARD_THRESHOLD:
        return body

    # Second pass: above the dashboard threshold OR body too large.
    # Show the top N rules grouped by tier; collapse the tail into a
    # single summary line that cites the full report.
    top = ranked[:_TOP_RULES_IN_DASHBOARD]
    tail = ranked[_TOP_RULES_IN_DASHBOARD:]

    top_sections = _render_tiered_body(
        top, ctx, show_details=True, full_report_link=full_report_link, scan_root=scan_root
    )
    tail_count = sum(len(g) for _, g in tail)
    if tail:
        tail_summary = (
            f"\n\n**+ {len(tail)} more rule{'s' if len(tail) != 1 else ''} "
            f"({tail_count} finding{'s' if tail_count != 1 else ''})** - "
            "see the full report linked below for details.\n"
        )
    else:
        tail_summary = ""

    body = _render_drilldown(
        header,
        top_sections,
        ctx,
        full_report_link,
        open_rule_ids,
        total,
        trailing=tail_summary,
        finding_fingerprints=finding_fingerprints,
        finding_rule_ids=finding_rule_ids,
    )
    if len(body.encode("utf-8")) <= _MAX_COMMENT_BYTES:
        return body

    # Third pass (last resort): collapse every block to a header-only
    # row, still grouped by tier. Preserves the one-line summary for
    # every top rule even in worst-case inputs. If this still exceeds
    # the budget the platform will reject it and we fall through to
    # warn-and-continue.
    compact_sections = _render_tiered_body(
        top, ctx, show_details=False, full_report_link=full_report_link, scan_root=scan_root
    )
    return _render_drilldown(
        header,
        compact_sections,
        ctx,
        full_report_link,
        open_rule_ids,
        total,
        trailing=tail_summary,
        finding_fingerprints=finding_fingerprints,
        finding_rule_ids=finding_rule_ids,
    )


def _render_drilldown(
    header: str,
    blocks: list[str],
    ctx: PlatformContext,
    full_report_link: str | None,
    open_rule_ids: list[str],
    findings_count: int,
    *,
    trailing: str = "",
    finding_fingerprints: list[str] | None = None,
    finding_rule_ids: list[str] | None = None,
) -> str:
    """Assemble header + rule blocks + footer + marker into the final
    comment body. Split out so the size-check passes above can
    re-assemble with different block sets without duplicating the
    structural glue.
    """
    footer = _render_footer(ctx, full_report_link)
    marker = _encode_marker(
        findings_count=findings_count,
        commit_sha=ctx.commit_sha,
        open_rule_ids=open_rule_ids,
        finding_fingerprints=finding_fingerprints,
        finding_rule_ids=finding_rule_ids,
    )
    parts: list[str] = [header]
    if blocks:
        # Mirrors the ``---`` between tiers; separates header from the body.
        parts.append("---")
    parts.extend(blocks)
    if trailing:
        parts.append(trailing)
    parts.append("---")
    parts.append(footer)
    parts.append(marker)
    return "\n\n".join(parts) + "\n"


def fetch_changed_files(ctx: PlatformContext, *, timeout: float = 10.0) -> list[str] | None:
    """Return the list of files changed in this MR/PR, or ``None`` if
    the platform call fails.

    Used when the user passes ``--github-comment`` / ``--gitlab-comment``
    *without* ``--files`` or ``--directory`` - the scanner scopes the
    scan to the MR's diff so comments don't complain about pre-existing
    issues on unchanged files. On failure we log and return ``None``;
    callers fall back to a full repo scan (with a warning) rather than
    silently posting an empty comment.
    """
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

    Defensive against very large PRs (the scanner has no business
    commenting on a 4000-file refactor) by capping at 10 pages of 100
    files = 1000 files. If the cap is hit we log a warning so the
    user can decide whether to scan the full repo instead.
    """
    files: list[str] = []
    headers = {
        "Authorization": f"Bearer {ctx.token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    for page in range(1, 11):
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
    """Hit GitLab's ``merge_requests/{iid}/changes`` endpoint.

    GitLab returns the full diff in one response (no pagination needed
    for the changed-files list itself) so this is simpler than the
    GitHub path.
    """
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


def fetch_existing_marker(
    ctx: PlatformContext,
    *,
    timeout: float = 15.0,
) -> dict[str, Any] | None:
    """Locate the previous scanner comment on this MR/PR (if any) and
    return its decoded marker payload, or ``None`` if there isn't one.

    Read-only counterpart to ``post_or_update_comment``: callers fetch
    the previous payload before rendering so the body can include a
    delta line; ``post_or_update_comment`` then re-discovers the same
    comment when it writes (the write-side discovery decides
    POST-vs-PATCH). Two discoveries because the body must be fully
    rendered (and size-checked) before the write path is reached.

    Failures are non-fatal: a transient API hiccup skips the delta
    line, never the comment itself.
    """
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

    Idempotent: re-running on the same MR after a second commit
    edits the same comment instead of creating a thread of duplicates.
    Failures raise nothing - the CLI's "warn and continue" contract
    means we always return a ``CommentResult`` (with ``error`` set)
    so the scan's exit code stays driven by findings, never by a
    transient API hiccup.
    """
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
        # request URL (no token) and occasionally request headers
        # (with token) depending on version. Redacting unconditionally
        # is cheaper than introspecting the exception type.
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
    marker. Capped at 10 pages (1000 comments) which is far beyond
    any realistic PR - if someone hits that they have bigger
    problems than scanner comment upkeep.
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
        data = resp.json() or {}
        # GitLab doesn't return an HTML URL on note PUTs; we reconstruct.
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
    """Same marker-scan as the GitHub helper but for GitLab MR notes.

    GitLab supports ``?per_page=100`` and link-header pagination; we
    honour the former and cap at 10 pages for the same reason.
    """
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
    ``CI_PROJECT_PATH`` (when available) so the CLI can print a
    clickable link. Falls back to ``None`` when we can't build a
    safe URL rather than emitting a broken one.
    """
    project_path = os.environ.get("CI_PROJECT_PATH")
    server_url = os.environ.get("CI_SERVER_URL", "").rstrip("/")
    if not project_path or not server_url:
        return None
    return f"{server_url}/{project_path}/-/merge_requests/{ctx.mr_number}#note_{note_id}"


def _findings_count_from_body(body: str) -> int:
    """Read back the findings count we just encoded into the marker.

    Cheaper and less error-prone than threading the count through
    every caller - the marker is already authoritative and the
    caller already rendered it correctly.
    """
    decoded = _decode_marker(body)
    if not decoded:
        return 0
    try:
        return int(decoded.get("findings_count") or 0)
    except (TypeError, ValueError):
        return 0


def write_full_report_artifact(
    rendered_markdown: str,
    *,
    path: Path | None = None,
) -> Path:
    """Persist the scanner's full Markdown report next to the MR
    comment so reviewers can click through from the comment.

    Always written - even on a resolved (0-findings) run - so CI
    artifact-upload rules don't have to special-case missing files.
    Returns the final path so the CLI can log it.
    """
    target = path or _DEFAULT_FULL_REPORT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(rendered_markdown, encoding="utf-8")
    return target
