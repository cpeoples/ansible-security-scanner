"""Snippet-level secret redaction shared across renderers.

The scanner widens ``code_snippet`` to the full enclosing YAML task block
so every report (markdown, SARIF, JSON, terminal, MR/PR comments) shows
the offending task in context. That widening can drag a sibling
``password:`` / ``token:`` line into the snippet, so we mask common
credential shapes at finding-emission time. Renderers may layer extra
redaction on top, but every ``SecurityFinding.code_snippet`` is already
safe by default.
"""

from __future__ import annotations

import re

_KV_REDACT_RE = re.compile(
    r"""(?ix)
    ^(\s*-?\s*)
    (
        (?:[A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|auth|credential)s?)
    )
    (\s*[:=]\s*)
    (?!\{\{)
    (['\"]?)([^\s'\"#]+)\4
    """,
    re.MULTILINE | re.VERBOSE,
)

_URL_CREDS_RE = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)"
    r"(?P<userinfo>[^/@\s:]+:[^/@\s]+)@"
)

_BEARER_RE = re.compile(r"(?i)(Bearer|Basic)\s+([A-Za-z0-9._\-+/=]{8,})")


def redact_secrets(snippet: str) -> str:
    """Mask common credential shapes in ``snippet`` with ``***``.

    Handles ``key: value`` / ``key=value`` pairs for password-like keys,
    URL userinfo (``https://user:pass@host``), and ``Bearer <token>``
    headers. Jinja templates (``{{ ... }}``) are left untouched so
    legitimate variable references stay readable.
    """
    if not snippet:
        return snippet

    redacted = _KV_REDACT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}***", snippet)
    redacted = _URL_CREDS_RE.sub(lambda m: f"{m.group('scheme')}***@", redacted)
    redacted = _BEARER_RE.sub(lambda m: f"{m.group(1)} ***", redacted)
    return redacted
