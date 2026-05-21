"""Markdown body rendering for MR/PR comments.

Pure functions: takes findings + a :class:`PlatformContext`, returns a
Markdown string. No network I/O. The "Dashboard + Drilldown" degradation
ladder lives here:

* 0 findings -> resolved banner.
* 1-100 findings -> header + per-rule ``<details>`` blocks grouped by tier.
* 101+ findings or body > ``_MAX_COMMENT_BYTES`` -> dashboard-only view.

Snippet redaction (the credential-masking primitives) also lives here so
both the per-finding fenced blocks and the remediation example get the
same treatment.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..link_resolver import (
    resolve_atlas,
    resolve_cis,
    resolve_cwe,
    resolve_hipaa,
    resolve_mitre,
    resolve_nist,
    resolve_pci,
    resolve_soc2,
    resolve_stig,
)
from .context import PlatformContext, _file_deep_link, _resolve_finding_paths
from .fingerprint import (
    _compute_delta,
    _encode_marker,
    _finding_fingerprint,
    _render_delta_line,
)

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
# with a "see the full report" pointer.
_MAX_FINDINGS_PER_RULE = 50

# Above this count, only the top-N rules are shown as ``<details>``;
# everything else becomes a summary line pointing at the full report.
_DASHBOARD_THRESHOLD = 100
_TOP_RULES_IN_DASHBOARD = 10
# Render rule blocks as ``<details open>`` when total findings are at or
# below this count, or when there's only one rule group.
_AUTO_EXPAND_FINDING_THRESHOLD = 3

# Suppression-transparency thresholds. ``_IGNORE_FLAT_LIMIT`` is the
# largest ignore list we render as a comma-separated blockquote; above
# it we group by category. ``_IGNORE_HARD_CAP`` bounds the number of
# rule names we'll print in the grouped form before collapsing the
# tail into a top-categories summary - guards against pathologically
# broad globs (``*`` against ~1k rules) blowing up the comment.
_IGNORE_FLAT_LIMIT = 8
_IGNORE_HARD_CAP = 60
_IGNORE_TOP_CATEGORIES = 5

# Severity weights used when ranking "top rules". Matches the scanner's
# own severity-weighted scoring; keeps the comment's "top offenders"
# list aligned with the score surfaced in the header.
_SEVERITY_WEIGHT = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 1}

# Public repo URL, embedded in the footer credit line.
_PROJECT_URL = "https://github.com/cpeoples/ansible-security-scanner"

# Default path where the full aggregate report is written alongside
# posting the comment.
_DEFAULT_FULL_REPORT_PATH = Path("security-reports") / "report.md"

# Severity tiers, ordered most-actionable first.
_SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Maximum rule names listed in a tier section heading before truncating.
_TIER_SUMMARY_RULE_NAMES = 4

# Friendly tier labels used in <summary> text.
_TIER_LABEL = {
    "CRITICAL": "critical",
    "HIGH": "high-severity",
    "MEDIUM": "medium-severity",
    "LOW": "low-severity",
}

_SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",
    "HIGH": "\U0001f7e0",
    "MEDIUM": "\U0001f7e1",
    "LOW": "\U0001f7e2",
}


# --- Snippet redaction --------------------------------------------------------
#
# Snippet redaction strikes a balance: show enough of the offending line
# for the reviewer to recognise it, never the literal secret value.
# Patterns target the textual *value* of common credential keys, not the
# keys themselves -- the key is what makes the snippet recognisable.

_SNIPPET_MAX_CHARS = 120
# Sized so a typical Ansible task block fits whole. Outliers fall back
# to the pinned-offender trim below.
_SNIPPET_MAX_LINES = 40

# When a single line exceeds ``_SNIPPET_MAX_CHARS`` we keep the start of
# the line AND the region around the rightmost CLI flag so the offending
# substring stays visible.
_SNIPPET_FLAG_RE = re.compile(r"(?<![\w-])(-[A-Za-z]\b|--[A-Za-z][\w-]*)")
_SNIPPET_PREFIX_KEEP = 60
_SNIPPET_FLAG_TAIL_KEEP = 50

# Match ``<key>: "value"`` / ``<key>=value`` for a small set of
# credential-looking keys.
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
# ``{{ vault_password }}``) is not a literal secret - it's a vault-backed
# lookup, which is the recommended pattern. Redacting it produces noise
# and obscures the legitimate context reviewers need to see.
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

    Redaction is intentionally conservative: we only mask the *value*
    portion of patterns that strongly imply a credential.
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
    and the region around the rightmost CLI flag.

    For long shell tasks the naive ``ln[:N]`` keeps the harmless prefix
    and drops the flag that made the rule fire. We instead emit
    ``<prefix>...<flag-tail>`` so the line's beginning *and* the
    offending flag are both visible.
    """
    matches = list(_SNIPPET_FLAG_RE.finditer(ln))
    if not matches:
        return ln[: _SNIPPET_MAX_CHARS - 3].rstrip() + "..."

    # The tail must start at the EARLIEST flag past the prefix window,
    # not the rightmost one. Picking the rightmost flag would silently
    # drop intermediate flags. Keeping everything from the first
    # uncovered flag onward is also cheaper than scoring "which flag is
    # the offender" without rule context.
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


# --- Task-window expansion ----------------------------------------------------

_GAP_MARKER_RE = re.compile(r"^\s*#\s*\.{3,}\s*$")

# Lines of context shown above + below the offender row in the
# decorated snippet (matches ruff/eslint/semgrep convention).
_SNIPPET_CONTEXT_LINES = 3

# Hard cap for the YAML-task-aware widener. Even if the task block is
# huge (long heredoc, many `vars:` entries), don't render more than
# this many lines or the comment becomes a wall of text.
_SNIPPET_MAX_TASK_LINES = 30

_TASK_HEADER_RE = re.compile(r"^\s*-\s+(?:name|hosts|block|rescue|always|import_|include_)\b")

# Rules that flag the *absence* of a key on a task. The finding is
# anchored at the task header for navigation, but the header itself
# isn't the offender, so we skip the ``>`` caret.
_STRUCTURAL_RULE_IDS = frozenset({"missing_no_log"})


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
    exceeds ``_SNIPPET_MAX_TASK_LINES``.
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


def _decorate_snippet(
    snippet: str,
    *,
    file_path: str,
    line_number: int,
    show_caret: bool = True,
    source_path: Path | None = None,
) -> str:
    """Re-render ``snippet`` with file-line numbers and a caret on the
    offending row, ripgrep-style.

    Returns the original snippet unchanged when the source file isn't
    readable or the snippet can't be pinned.
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


# --- Sentence + grouping helpers ---------------------------------------------

_SENTENCE_END = re.compile(r"\. (?=[A-Z])")


def _first_sentence(text: str, *, max_chars: int = 220) -> str:
    """Return the first sentence of ``text``, capped at ``max_chars``.

    Sentence boundaries are ``. <space> <Capital>``; abbreviations
    (``e.g.``, ``Mr.``, ``U.S.``, ``Python 3.9``) are skipped via
    structural shapes in :func:`_looks_like_abbreviation`.
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
    would make two identical scans produce different comment bodies.
    """
    groups: dict[str, list[Any]] = {}
    for f in findings:
        groups.setdefault(getattr(f, "rule_id", "unknown"), []).append(f)
    return groups


def _rule_rank(group: list[Any]) -> tuple[int, int, int]:
    """Sort key for rule ordering in the rendered comment.

    Reviewers expect CRITICALs at the top no matter how many other
    findings sit below them. Rank by the *peak* severity in the group,
    then total weight, then count.
    """
    peak = max(
        (_SEVERITY_WEIGHT.get((getattr(f, "severity", "") or "LOW").upper(), 1) for f in group),
        default=1,
    )
    weight_sum = sum(
        _SEVERITY_WEIGHT.get((getattr(f, "severity", "") or "LOW").upper(), 1) for f in group
    )
    return (peak, weight_sum, len(group))


def _severity_header(
    findings: list[Any],
    security_score: float | None,
    *,
    active_policy: bool = False,
) -> str:
    """Build the one-line severity counter that anchors the comment.

    ``active_policy`` appends ``(active policy)`` to the score line when
    either ``--select`` or ``--ignore`` is in effect, signalling that
    the score reflects the configured policy rather than a clean
    codebase.
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
        parts = ["\u2705 0 findings"]

    header = "### \U0001f6e1\ufe0f Security Scan - " + " \u00b7 ".join(parts)
    if security_score is not None:
        score_line = f"\n\n**Security score:** {int(round(security_score))} / 100"
        if active_policy:
            score_line += " *(active policy)*"
        header += score_line
    return header


def _pluralize(n: int, singular: str, plural: str | None = None) -> str:
    """Format ``"1 rule"`` / ``"3 rules"``-style counts."""
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _render_policy_note(
    *,
    selected_rule_ids: list[str],
    ignored_rule_ids: list[str],
    category_for_rule: dict[str, str],
) -> str:
    """Render the always-on suppression-transparency note.

    Returns ``""`` when neither ``--select`` nor ``--ignore`` is in
    effect. Otherwise emits one note that summarises the *active* run
    policy:

    * ``--select`` was used (with or without ``--ignore``) - voices
      the note as *"scan limited to N rule(s) via --select"* and lists
      the active set, since that's the actionable surface; an ignore
      list inside a select universe is appended in parentheses.
    * Only ``--ignore`` was used - voices the note as *"N rule(s)
      suppressed via --ignore"* and lists the suppressed set.

    The list-shape (flat blockquote vs grouped ``<details>`` vs
    capped categories) follows :data:`_IGNORE_FLAT_LIMIT` and
    :data:`_IGNORE_HARD_CAP` regardless of which voice fires; the
    rendering machinery is reused.
    """
    if selected_rule_ids:
        head = f"Scan limited to {_pluralize(len(selected_rule_ids), 'rule')} via `--select`"
        if ignored_rule_ids:
            head += f" (and {len(ignored_rule_ids)} further suppressed via `--ignore`)"
        return _render_rule_disclosure(head, selected_rule_ids, category_for_rule)

    if ignored_rule_ids:
        head = f"{_pluralize(len(ignored_rule_ids), 'rule')} suppressed via `--ignore`"
        return _render_rule_disclosure(head, ignored_rule_ids, category_for_rule)

    return ""


def _render_rule_disclosure(
    head: str,
    rule_ids: list[str],
    category_for_rule: dict[str, str],
) -> str:
    """Render a "Note: <head>" disclosure listing ``rule_ids``.

    Three shapes by list size:

    * ``<= _IGNORE_FLAT_LIMIT`` - blockquote, flat comma-separated list.
    * ``<= _IGNORE_HARD_CAP`` - collapsed ``<details>`` grouped by
      category, all rules listed under their category.
    * ``> _IGNORE_HARD_CAP`` - collapsed ``<details>`` showing the
      top ``_IGNORE_TOP_CATEGORIES`` categories with rule counts.

    Rules without a known YAML category fall into an ``other`` bucket.
    """
    if len(rule_ids) <= _IGNORE_FLAT_LIMIT:
        listed = ", ".join(f"`{rid}`" for rid in rule_ids)
        return f"> **Note:** {head}: {listed}."

    by_category: dict[str, list[str]] = {}
    for rid in rule_ids:
        by_category.setdefault(category_for_rule.get(rid, "other"), []).append(rid)
    ordered = sorted(by_category.items(), key=lambda kv: (-len(kv[1]), kv[0]))

    summary = (
        f"<summary><strong>Note:</strong> {head} across "
        f"{_pluralize(len(ordered), 'category', 'categories')} "
        "(click to expand)</summary>"
    )

    if len(rule_ids) > _IGNORE_HARD_CAP:
        top = ordered[:_IGNORE_TOP_CATEGORIES]
        lines = [f"- **{_humanize_category(cat)}** \u2014 {len(rids)} rules" for cat, rids in top]
        tail = len(ordered) - len(top)
        if tail > 0:
            lines.append(f"- *...and {_pluralize(tail, 'more category', 'more categories')}*")
        lines.append("")
        lines.append("*Rule list capped for readability; see your CI config for the full policy.*")
        body = "\n".join(lines)
    else:
        body = "\n".join(
            f"- **{_humanize_category(cat)}** ({len(rids)}): "
            + ", ".join(f"`{rid}`" for rid in sorted(rids))
            for cat, rids in ordered
        )

    return f"<details>\n{summary}\n\n{body}\n</details>"


def _humanize_category(category_key: str) -> str:
    """Render a snake_case category key as a Title Cased label."""
    return category_key.replace("_", " ").title()


def _fence(body: str) -> str:
    """Build a ``yaml`` code fence at column 0.

    Earlier versions indented every line by two spaces so the fence
    visually nested under its bullet, but that turns the whole block
    into a list-item continuation in stricter CommonMark renderers and
    leaks the list context into whatever block follows.
    """
    return f"```yaml\n{body}\n```"


def _render_finding_item(
    anchor: str,
    snippet: str,
    *,
    file_path: str = "",
    line_number: int = 0,
    show_caret: bool = True,
    source_path: Path | None = None,
) -> str:
    """Render one finding row in a rule block."""
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


# --- Remediation block --------------------------------------------------------

# Match the `**Vulnerable Code:** ... <fence>` chunk emitted by the
# remediation generators. We strip it because the same code is already
# shown above (per-finding, with proper redaction). The label sometimes
# carries an emoji prefix from richer generators, so the regex tolerates
# any leading non-word characters between the bold markers.
_VULNERABLE_CODE_BLOCK_RE = re.compile(
    r"\*\*[^\w*]*Vulnerable Code:\*\*\s*\n```[a-zA-Z0-9_-]*\n.*?```\s*\n",
    re.DOTALL,
)

# Match ``**field**: `<value>` -> `<replacement>`` rows the rich
# generators emit for "Secret Parameters Found" sections. The value half
# is back-tick-delimited which the KV redactor can't see (it stops at
# quotes/whitespace, not back-ticks).
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


def _redact_remediation(raw: str) -> str:
    """Run the same redaction primitives over every line of a
    remediation example.

    The pre-formatted ``remediation_example`` from
    :class:`RemediationGenerator` embeds the original (unredacted)
    finding snippet in its "Vulnerable Code" + "Secret Parameters
    Found" sections. Without redaction those literal secrets would
    leak into the MR comment.
    """
    out: list[str] = []
    for line in raw.splitlines():
        ln = _SNIPPET_KV_REDACT_RE.sub(lambda m, src=line: _kv_redact_replacement(src, m), line)
        ln = _SNIPPET_URL_CREDS_RE.sub(lambda m: f"{m.group(1)}***{m.group(3)}", ln)
        ln = _SNIPPET_BEARER_RE.sub(lambda m: f"{m.group(1)}***", ln)
        ln = _BACKTICK_LITERAL_REDACT_RE.sub(_backtick_literal_replacement, ln)
        out.append(ln)
    return "\n".join(out)


def _ensure_fence_blank_lines(md: str) -> str:
    """Guarantee a blank line on both sides of every fenced code block.

    GitHub-Flavored Markdown is strict about code-fence delimiters
    inside an HTML ``<details>`` element: a ``**Label:**\\n```yaml``
    sequence with no blank line is parsed as inline text, so the code
    block silently disappears.
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


def _render_framework_coverage_inline(finding: Any) -> str:
    """Render compliance-framework links as a collapsed ``<details>`` block.

    Returns ``""`` when the finding carries no framework metadata.
    """
    sources: list[tuple[str, list[str], Any]] = [
        ("CWE", getattr(finding, "cwe", []) or [], resolve_cwe),
        ("MITRE ATT&CK", getattr(finding, "mitre_attack", []) or [], resolve_mitre),
        ("MITRE ATLAS", getattr(finding, "mitre_atlas", []) or [], resolve_atlas),
        ("CIS Controls", getattr(finding, "cis_controls", []) or [], resolve_cis),
        ("NIST 800-53", getattr(finding, "nist_controls", []) or [], resolve_nist),
        ("PCI-DSS v4", getattr(finding, "pci_dss", []) or [], resolve_pci),
        ("HIPAA", getattr(finding, "hipaa", []) or [], resolve_hipaa),
        ("SOC 2 TSC", getattr(finding, "soc2", []) or [], resolve_soc2),
        ("DISA STIG", getattr(finding, "stig", []) or [], resolve_stig),
    ]

    rows: list[str] = []
    for label, ids, resolver in sources:
        if not ids:
            continue
        rendered: list[str] = []
        for raw in ids:
            ref = resolver(raw)
            if ref:
                rendered.append(f"[{ref.id}]({ref.url})")
            else:
                rendered.append(f"`{raw}`")
        rows.append(f"- **{label}:** " + ", ".join(rendered))

    if not rows:
        return ""

    body = "\n".join(rows)
    return f"<details><summary>Compliance frameworks</summary>\n\n{body}\n\n</details>"


def _render_remediation_block(finding: Any) -> str:
    """Render the structured remediation example as a collapsed
    ``<details>`` block. Returns ``""`` when no remediation is present.
    """
    raw = (getattr(finding, "remediation_example", "") or "").strip()
    if not raw:
        return ""

    cleaned = _VULNERABLE_CODE_BLOCK_RE.sub("", raw, count=1).strip()
    if not cleaned:
        return ""

    cleaned = _redact_remediation(cleaned)
    cleaned = _ensure_fence_blank_lines(cleaned)

    return f"<details><summary>\U0001f6e0\ufe0f Show recommended fix</summary>\n\n{cleaned}\n\n</details>"


def _render_rule_block(
    rule_id: str,
    group: list[Any],
    ctx: PlatformContext,
    *,
    show_details: bool,
    with_severity_emoji: bool = True,
    full_report_link: str | None = None,
    scan_root: Path | None = None,
    inline_mode: bool = False,
    expanded: bool = False,
) -> str:
    """Render one ``<details>`` block for a rule group.

    ``show_details=False`` drops the per-finding file:line list and
    collapses the block into just the header row (dashboard mode).

    ``with_severity_emoji=False`` omits the leading colored dot when
    used inside a tier-grouped layout where severity is conveyed by
    the parent section heading.

    ``inline_mode=True`` skips the per-finding code snippets and the
    remediation expander. Used when ``--inline-comments`` posts the
    same code as inline review threads.

    ``expanded=True`` renders ``<details open>`` so the block opens
    without a click.
    """
    severity = (getattr(group[0], "severity", "LOW") or "LOW").upper()
    title = (getattr(group[0], "title", "") or rule_id).strip()
    files = {getattr(f, "file_path", "?") for f in group}
    if with_severity_emoji:
        prefix = _SEVERITY_EMOJI.get(severity, "\u26aa") + " "
    else:
        prefix = ""
    summary = (
        f"<summary>{prefix}<code>{rule_id}</code> \u00b7 {title} - "
        f"{len(group)} finding{'s' if len(group) != 1 else ''} "
        f"in {len(files)} file{'s' if len(files) != 1 else ''}</summary>"
    )
    open_tag = "<details open>" if expanded else "<details>"

    if not show_details:
        return f"{open_tag}{summary}</details>"

    def _anchor(f: Any) -> tuple[str, str, Path | None, int]:
        fp = getattr(f, "file_path", "?")
        ln = getattr(f, "line_number", 0)
        display_path, source_path = _resolve_finding_paths(fp, scan_root)
        link = _file_deep_link(ctx, display_path, ln)
        text = f"[`{display_path}:{ln}`]({link})" if link else f"`{display_path}:{ln}`"
        return text, display_path, source_path, ln

    blocks: list[str] = []
    if inline_mode:
        location_links = [_anchor(f)[0] for f in group[:_MAX_FINDINGS_PER_RULE]]
        if location_links:
            blocks.append("**Locations:** " + ", ".join(location_links))
    else:
        snippet_findings = group[:_MAX_SNIPPETS_PER_RULE]
        extra_findings = group[_MAX_SNIPPETS_PER_RULE:_MAX_FINDINGS_PER_RULE]

        for f in snippet_findings:
            anchor, display_path, source_path, ln = _anchor(f)
            rid = getattr(f, "rule_id", "") or ""
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
                    show_caret=rid not in _STRUCTURAL_RULE_IDS,
                    source_path=source_path,
                )
            )

        if extra_findings:
            blocks.append("**Also at:** " + ", ".join(_anchor(f)[0] for f in extra_findings))

    truncated = len(group) - _MAX_FINDINGS_PER_RULE
    if truncated > 0:
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
        blocks.append(
            f"\u2026and **{truncated} more finding{plural}**{file_hint} \u2014 {report_pointer}"
        )

    body = "\n\n".join(blocks)
    fix_hint = _first_sentence(getattr(group[0], "recommendation", "") or "")
    if fix_hint:
        body += f"\n\n\U0001f4a1 **Fix:** {fix_hint}"

    if not inline_mode:
        remediation_block = _render_remediation_block(group[0])
        if remediation_block:
            body += "\n\n" + remediation_block

    return open_tag + summary + "\n\n" + body + "\n\n</details>"


# --- Footer + resolved banner ------------------------------------------------


def _render_footer(ctx: PlatformContext, full_report_link: str | None) -> str:
    """Build the small metadata footer: commit SHA, scanner credit
    (linked back to the project), and a link to the full report.
    """
    from .. import __version__ as scanner_version

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
    return "<sub>" + " \u00b7 ".join(bits) + "</sub>"


def _format_version(scanner_version: str) -> str:
    """Format the scanner-version suffix shown next to the credit link.

    Returns an empty string for dev/local builds (anything carrying a
    PEP 440 ``+local`` segment or a ``.devN`` marker) so a reviewer
    never sees a raw commit hash or local-build timestamp in a public
    MR/PR comment.
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
    whether to also emit a separate ``[run logs]`` entry.
    """
    if not full_report_link:
        return None, False

    if full_report_link.startswith(("http://", "https://")):
        return f"\U0001f4ce [Full report]({full_report_link})", False

    if ctx.run_url:
        if ctx.platform == "gitlab":
            artifact_url = (
                f"{ctx.run_url.rstrip('/')}/artifacts/file/{full_report_link.lstrip('/')}"
            )
            return f"\U0001f4ce [Full report]({artifact_url})", True
        artifacts_url = f"{ctx.run_url.rstrip('/')}#artifacts"
        return (
            f"\U0001f4ce Full report: `{full_report_link}` "
            f"(download from [run artifacts]({artifacts_url}))",
            True,
        )

    return f"\U0001f4ce Full report: `{full_report_link}`", False


def _render_resolved_banner(
    previous_findings_count: int | None,
    previous_open_rule_ids: list[str],
    ctx: PlatformContext,
    *,
    active_policy: bool = False,
) -> str:
    """Render the zero-findings resolved state."""
    qualifier = " *(active policy)*" if active_policy else ""
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
            "### \u2705 All security findings resolved\n\n"
            f"**Security score:** 100 / 100{qualifier} \u00b7 review confidence: high" + rules_line
        )

    return (
        "### \u2705 No security findings\n\n"
        f"**Security score:** 100 / 100{qualifier} \u00b7 0 findings on changed files."
    )


# --- Tier rendering ----------------------------------------------------------


def _tier_summary_line(severity: str, ranked_for_tier: list[tuple[str, list[Any]]]) -> str:
    """Build the single-line section heading for a severity tier."""
    finding_count = sum(len(group) for _, group in ranked_for_tier)
    rule_count = len(ranked_for_tier)
    rule_word = "rule" if rule_count == 1 else "rules"

    emoji = _SEVERITY_EMOJI.get(severity, "\u26aa")
    label = _TIER_LABEL.get(severity, severity.lower())

    head = f"{emoji} **{finding_count} {label}**"
    if rule_count != finding_count:
        head += f" \u00b7 {rule_count} {rule_word}"

    shown = [rid for rid, _ in ranked_for_tier[:_TIER_SUMMARY_RULE_NAMES]]
    extra = rule_count - len(shown)
    names = ", ".join(f"`{rid}`" for rid in shown)
    if extra > 0:
        names += f", +{extra} more"
    if names:
        return f"{head} \u00b7 {names}"
    return head


def _render_tier_section(
    severity: str,
    ranked_for_tier: list[tuple[str, list[Any]]],
    ctx: PlatformContext,
    *,
    show_details: bool,
    full_report_link: str | None = None,
    scan_root: Path | None = None,
    inline_mode: bool = False,
    expanded: bool = False,
) -> str:
    """Render one severity-tier section.

    Each tier is a markdown section heading followed by its rule
    blocks. We deliberately do NOT wrap the tier in a ``<details>``
    element: nesting ``<details>`` blocks that contain fenced code
    breaks GitHub and GitLab Markdown rendering.
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
            inline_mode=inline_mode,
            expanded=expanded,
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
    inline_mode: bool = False,
    expanded: bool = False,
) -> list[str]:
    """Render the full set of rule blocks as one section per non-empty
    severity tier, in tier order. Returns the list of section strings
    so the caller can splice them between the severity header and
    footer.
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
                inline_mode=inline_mode,
                expanded=expanded,
            )
        )
    return sections


# --- Top-level body ----------------------------------------------------------


def render_comment_body(
    findings: list[Any],
    ctx: PlatformContext,
    *,
    security_score: float | None = None,
    previous: dict[str, Any] | None = None,
    full_report_link: str | None = None,
    scan_root: Path | None = None,
    inline_mode: bool = False,
    ignored_rule_ids: list[str] | None = None,
    selected_rule_ids: list[str] | None = None,
    category_for_rule: dict[str, str] | None = None,
) -> str:
    """Produce the final Markdown body for the MR/PR comment.

    Applies the "Dashboard + Drilldown" degradation ladder:

    * 0 findings -> resolved banner (cites previously-open rules).
    * 1-100 findings -> header + per-rule ``<details>`` blocks.
    * 101+ findings or rendered body > ``_MAX_COMMENT_BYTES`` ->
      dashboard-only view: header + top-N rule summaries + a
      prominent link to the full-report artifact.

    ``selected_rule_ids`` and ``ignored_rule_ids`` (both resolved
    post-glob) drive the always-on policy-transparency note: a footer
    block listing whichever set is most informative for the run
    (active set when ``--select`` is in effect, suppressed set
    otherwise). The score line picks up an *(active policy)* qualifier
    whenever either is set. Both surfaces are silent when the
    arguments are empty / ``None``.

    Every output includes the stable marker so subsequent scans can
    locate and PATCH this exact comment.
    """
    ignored_rule_ids = ignored_rule_ids or []
    selected_rule_ids = selected_rule_ids or []
    category_for_rule = category_for_rule or {}
    active_policy = bool(ignored_rule_ids or selected_rule_ids)
    policy_note = _render_policy_note(
        selected_rule_ids=selected_rule_ids,
        ignored_rule_ids=ignored_rule_ids,
        category_for_rule=category_for_rule,
    )

    open_rule_ids = sorted(
        {getattr(f, "rule_id", "") for f in findings if getattr(f, "rule_id", "")}
    )
    finding_fingerprints = [_finding_fingerprint(f) for f in findings]
    finding_rule_ids = [getattr(f, "rule_id", "") or "" for f in findings]
    delta_line = _render_delta_line(_compute_delta(previous, findings))

    if not findings:
        prev_count = None
        prev_open: list[str] = []
        if previous:
            prev_count = previous.get("findings_count")
            prev_open = previous.get("open_rule_ids") or []
        body = _render_resolved_banner(
            prev_count, list(prev_open), ctx, active_policy=active_policy
        )
        footer = _render_footer(ctx, full_report_link)
        marker = _encode_marker(0, ctx.commit_sha, open_rule_ids)
        parts = [body, "---"]
        if policy_note:
            parts.extend([policy_note, "---"])
        parts.extend([footer, marker])
        return "\n\n".join(parts) + "\n"

    groups = _group_by_rule(findings)
    ranked = sorted(groups.items(), key=lambda kv: _rule_rank(kv[1]), reverse=True)
    total = len(findings)
    expanded = total <= _AUTO_EXPAND_FINDING_THRESHOLD or len(groups) == 1

    header = _severity_header(findings, security_score, active_policy=active_policy)
    if delta_line:
        header += f"\n\n{delta_line}"
    header += (
        f"\n\n**Changed files scanned:** {len({getattr(f, 'file_path', '?') for f in findings})}"
        f" \u00b7 **Findings:** {total}"
    )

    full_sections = _render_tiered_body(
        ranked,
        ctx,
        show_details=True,
        full_report_link=full_report_link,
        scan_root=scan_root,
        inline_mode=inline_mode,
        expanded=expanded,
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
        policy_note=policy_note,
    )
    if len(body.encode("utf-8")) <= _MAX_COMMENT_BYTES and total < _DASHBOARD_THRESHOLD:
        return body

    top = ranked[:_TOP_RULES_IN_DASHBOARD]
    tail = ranked[_TOP_RULES_IN_DASHBOARD:]

    top_sections = _render_tiered_body(
        top,
        ctx,
        show_details=True,
        full_report_link=full_report_link,
        scan_root=scan_root,
        inline_mode=inline_mode,
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
        policy_note=policy_note,
    )
    if len(body.encode("utf-8")) <= _MAX_COMMENT_BYTES:
        return body

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
        policy_note=policy_note,
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
    policy_note: str = "",
) -> str:
    """Assemble header + rule blocks + footer + marker into the final
    comment body.
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
        parts.append("---")
    parts.extend(blocks)
    if trailing:
        parts.append(trailing)
    if policy_note:
        parts.append("---")
        parts.append(policy_note)
    parts.append("---")
    parts.append(footer)
    parts.append(marker)
    return "\n\n".join(parts) + "\n"


def write_full_report_artifact(
    rendered_markdown: str,
    *,
    path: Path | None = None,
) -> Path:
    """Persist the scanner's full Markdown report next to the MR
    comment so reviewers can click through from the comment.

    Always written - even on a resolved (0-findings) run - so CI
    artifact-upload rules don't have to special-case missing files.
    """
    target = path or _DEFAULT_FULL_REPORT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(rendered_markdown, encoding="utf-8")
    return target
