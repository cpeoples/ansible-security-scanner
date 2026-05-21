"""Merge-request / pull-request comment posting for the scanner.

Invoked from ``cli.main()`` when the user passes ``--gitlab-comment``
(``--gl-comment``) or ``--github-comment`` (``--gh-comment``). Platform
detection is purely env-based (see :func:`detect_platform`); tokens are
read from environment variables only - never from CLI flags, config
files, or logs.

The comment rendered here follows the "Dashboard + Drilldown" format:

- One-line severity header so reviewers see the shape at a glance.
- Findings grouped by rule id, each in a collapsed ``<details>`` block.
- Up to 5 occurrences shown per rule; the rest collapsed into "N more".
- Above ~100 findings, only the top 10 rules by count x severity are
  shown; other rules are summarised.
- Hard cap of ``_MAX_COMMENT_BYTES`` (well under GitHub's 65 536
  character hard cap) - if the rendered body would exceed the cap the
  renderer degrades further to a dashboard-only view.

A stable HTML marker is embedded at the end of every body so the next
scan can find and PATCH the same comment rather than spamming new ones.
The marker also carries the previous run's finding count + SHA so the
"resolved" banner can cite exactly how many findings were cleaned up.

This module is the public package surface for the comment subsystem;
implementation lives in the four sibling modules:

* :mod:`.context`     - dataclasses, env detection, path helpers
* :mod:`.fingerprint` - markers, fingerprints, run-to-run deltas
* :mod:`.rendering`   - Markdown body, snippets, redaction, footers
* :mod:`.posting`     - GitHub / GitLab REST I/O
"""

# ruff: noqa: F401
# ``__init__`` re-exports the historical flat ``comment.X`` surface so
# external imports (cli.py, tests/test_comment.py) stay working after
# the package split. Every name below is intentionally re-exported.

from __future__ import annotations

from pathlib import Path

try:
    import httpx
except ImportError:  # pragma: no cover - declared as a runtime dependency
    httpx = None  # type: ignore[assignment]

from .context import (  # noqa: E402
    CommentResult,
    Platform,
    PlatformContext,
    _detect_github,
    _detect_gitlab,
    _extract_github_pr_context,
    _file_deep_link,
    _first_env,
    _redact,
    _resolve_finding_paths,
    detect_platform,
)
from .fingerprint import (  # noqa: E402
    _FINGERPRINT_LEN,
    _MARKER_FINGERPRINT_SAMPLE,
    _MARKER_PREFIX,
    _MARKER_RE,
    _MARKER_RULE_SAMPLE,
    _MARKER_SUFFIX,
    _RESOLVED_RULES_HEADLINE_CAP,
    _compute_delta,
    _decode_marker,
    _Delta,
    _encode_marker,
    _finding_fingerprint,
    _findings_count_from_body,
    _format_rule_ids_suffix,
    _render_delta_line,
)
from .inline import (  # noqa: E402
    InlinePostResult,
    post_inline_comments,
)
from .posting import (  # noqa: E402
    _find_github_existing_comment,
    _find_gitlab_existing_note,
    _github_changed_files,
    _github_post_or_update,
    _gitlab_changed_files,
    _gitlab_note_url,
    _gitlab_post_or_update,
    fetch_changed_files,
    fetch_diff_lines,
    fetch_existing_marker,
    post_or_update_comment,
)
from .rendering import (  # noqa: E402
    _BACKTICK_LITERAL_REDACT_RE,
    _DASHBOARD_THRESHOLD,
    _DEFAULT_FULL_REPORT_PATH,
    _GAP_MARKER_RE,
    _JINJA_VALUE_PREFIX_RE,
    _MAX_COMMENT_BYTES,
    _MAX_FINDINGS_PER_RULE,
    _MAX_SNIPPETS_PER_RULE,
    _PROJECT_URL,
    _SENTENCE_END,
    _SEVERITY_EMOJI,
    _SEVERITY_ORDER,
    _SEVERITY_WEIGHT,
    _SNIPPET_BEARER_RE,
    _SNIPPET_CONTEXT_LINES,
    _SNIPPET_FLAG_RE,
    _SNIPPET_FLAG_TAIL_KEEP,
    _SNIPPET_KV_REDACT_RE,
    _SNIPPET_MAX_CHARS,
    _SNIPPET_MAX_LINES,
    _SNIPPET_MAX_TASK_LINES,
    _SNIPPET_PREFIX_KEEP,
    _SNIPPET_URL_CREDS_RE,
    _STRUCTURAL_RULE_IDS,
    _TASK_HEADER_RE,
    _TIER_LABEL,
    _TIER_SUMMARY_RULE_NAMES,
    _TOP_RULES_IN_DASHBOARD,
    _VULNERABLE_CODE_BLOCK_RE,
    _backtick_literal_replacement,
    _decorate_snippet,
    _ensure_fence_blank_lines,
    _expand_to_yaml_task,
    _fence,
    _first_sentence,
    _format_full_report_bit,
    _format_version,
    _group_by_rule,
    _group_ranked_by_severity,
    _indent_of,
    _kv_redact_replacement,
    _locate_offender_in_snippet,
    _looks_like_abbreviation,
    _redact_remediation,
    _redact_snippet,
    _redact_snippet_line,
    _render_drilldown,
    _render_finding_item,
    _render_footer,
    _render_remediation_block,
    _render_resolved_banner,
    _render_rule_block,
    _render_tier_section,
    _render_tiered_body,
    _rule_rank,
    _severity_header,
    _tier_summary_line,
    _trim_to_head_and_tail,
    _truncate_long_line,
    render_comment_body,
    write_full_report_artifact,
)

__all__ = [
    "CommentResult",
    "InlinePostResult",
    "Path",
    "Platform",
    "PlatformContext",
    "detect_platform",
    "fetch_changed_files",
    "fetch_diff_lines",
    "fetch_existing_marker",
    "httpx",
    "post_inline_comments",
    "post_or_update_comment",
    "render_comment_body",
    "write_full_report_artifact",
]
