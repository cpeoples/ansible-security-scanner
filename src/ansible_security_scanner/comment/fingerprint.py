"""Comment-marker payload, per-finding fingerprints, and run-to-run deltas.

Every comment body ends with a stable HTML marker carrying a small JSON
payload. Subsequent scans locate that marker (via :data:`_MARKER_RE`),
PATCH the same comment in place, and read the previous payload to
compute resolved/new findings (the "delta line").
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

# Stable marker. Versioned so future changes to the embedded payload
# format remain backward compatible with older comments already posted
# on long-lived MRs. The detection regex (``_MARKER_RE``) accepts any
# ``:v\d+`` so older v1 comments still resolve in
# ``_find_existing_comment_id`` and get PATCHed in place.
_MARKER_PREFIX = "<!-- ansible-security-scanner:mr-comment:v2"
_MARKER_SUFFIX = "-->"

# Marker payload size cap. The marker is a single embedded HTML comment
# used for cross-run state (locate the comment to PATCH, diff resolved
# rules, cite cleared rule IDs). It must stay small so it doesn't eat
# the comment-byte budget; we previously shipped every open rule_id
# verbatim, which on a 1000-rule MR bloated the marker to ~35 KB. v2
# ships at most ``_MARKER_RULE_SAMPLE`` named ids plus a SHA-256 digest
# of the full sorted set so "did anything change" comparisons stay
# precise without paying per-rule bytes.
_MARKER_RULE_SAMPLE = 12

# Per-finding fingerprint cap. Each fingerprint is a 16-hex-char
# truncated SHA-256 of "rule_id|file_path|line_number" — enough entropy
# to make collisions vanishingly unlikely on realistic scans without
# bloating the marker. The full set is also digested so the next run
# can detect "did anything change" in O(1) bytes even when the
# truncated list is capped.
_MARKER_FINGERPRINT_SAMPLE = 50
_FINGERPRINT_LEN = 16

_MARKER_RE = re.compile(
    r"<!--\s*ansible-security-scanner:mr-comment:v\d+\s*(\{.*?\})\s*-->",
    re.DOTALL,
)

# Cap on rule names spelled out in receipts lines before we collapse
# the rest into "(+N more)". 8 covers realistic PRs without truncation
# while keeping pathological cleanup PRs from dominating the header.
_RESOLVED_RULES_HEADLINE_CAP = 8


def _finding_fingerprint(finding: Any) -> str:
    """Stable per-finding identity hash.

    Combines ``rule_id``, ``file_path``, and ``line_number`` — the same
    triple the scanner uses to dedup across files — so the same finding
    on the same line in two consecutive scans hashes to the same value.
    Truncated to ``_FINGERPRINT_LEN`` hex chars to keep marker payload
    small.
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

    Embedded on a single line so naive regex searches always match it.
    The payload lets the next scan tell whether this comment was posted
    by an older scanner version, compute "findings resolved since last
    run" precisely (down to the per-finding level when
    ``finding_fingerprints`` is supplied), cite the previous scan's SHA
    in the footer, and name the rule families that resolved.

    Schema (v2):

    * ``version`` — schema version, bumped when fields change.
    * ``findings_count`` — total finding count this run.
    * ``commit_sha`` — head SHA the scan was run against.
    * ``open_rule_ids`` — at most ``_MARKER_RULE_SAMPLE`` ids, used to
      cite cleared rules in the resolved banner.
    * ``open_rule_ids_total`` / ``open_rule_ids_digest`` — full-set
      cardinality and SHA-256 digest of the sorted ids, so the next
      run can detect *any* change to the rule surface in O(1) bytes.
    * ``finding_fingerprints`` — at most ``_MARKER_FINGERPRINT_SAMPLE``
      truncated fingerprints. Optional.
    * ``finding_fingerprints_total`` / ``finding_fingerprints_digest``
      — same shape as the rule-id pair, used by ``_compute_delta`` to
      know when the truncated sample understates the real diff.
    * ``finding_rule_ids`` — ``{fingerprint: rule_id}`` over the same
      sample as ``finding_fingerprints``. Inline-mapped (not a parallel
      list) so JSON corruption can't desync the two arrays.

    ``finding_rule_ids`` (the caller-supplied list) must be aligned by
    index with ``finding_fingerprints``. Mismatched lengths raise.
    """
    sorted_ids = sorted({r for r in open_rule_ids if r})
    digest = hashlib.sha256("\n".join(sorted_ids).encode("utf-8")).hexdigest()
    payload: dict[str, Any] = {
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
            for fp, rid in zip(fps_list, rules_list, strict=True):
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


def _decode_marker(body: str) -> dict[str, Any] | None:
    """Pull the JSON payload out of an existing comment's marker.

    Returns ``None`` when no marker is present or parseable. Deliberately
    tolerant: a malformed marker (future version, hand-edited body)
    returns ``None`` and the caller treats this run as a fresh post —
    better than crashing mid-pipeline.
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


def _findings_count_from_body(body: str) -> int:
    """Read back the findings count we just encoded into the marker."""
    decoded = _decode_marker(body)
    if not decoded:
        return 0
    try:
        return int(decoded.get("findings_count") or 0)
    except (TypeError, ValueError):
        return 0


@dataclass
class _Delta:
    """Compact result of comparing two consecutive scans of the same MR.

    Counts are exact when both scans wrote fingerprints; older v2 markers
    without fingerprints fall back to rule-id deltas.

    ``approximate=True`` signals that the previous truncated fingerprint
    sample understated the real diff — the renderer flags the line so
    reviewers don't read exact counts that are actually lower bounds.

    ``resolved_rule_ids`` / ``new_rule_ids`` are family-level: a rule
    appears in ``resolved_rule_ids`` only when *every* finding for it
    disappeared.
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

    Precise mode (preferred): both runs carry fingerprints; set-diff
    them. Each fingerprint is a 16-char SHA-256 prefix of
    ``rule_id|file_path|line_number``.

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


def _format_rule_ids_suffix(label: str, rule_ids: tuple[str, ...]) -> str:
    """Format a ``<label>: \\`rule_a\\`, \\`rule_b\\`, …`` continuation
    following the delta headline.

    Caller appends two trailing spaces + ``\\n`` to produce a Markdown
    ``<br>`` so the continuation hugs the headline.
    """
    head = list(rule_ids[:_RESOLVED_RULES_HEADLINE_CAP])
    overflow = len(rule_ids) - len(head)
    rendered = ", ".join(f"`{r}`" for r in head)
    if overflow > 0:
        rendered += f" (+{overflow} more)"
    return f"{label}: {rendered}"


def _render_delta_line(delta: _Delta | None) -> str:
    """Render a one-line trajectory summary for the comment header.

    Returns ``""`` when nothing meaningfully changed.

    Tone follows the trajectory:

    * pure progress (resolved >0, new ==0)  → "📈 Progress: 2 resolved · 3 still open"
    * pure regression (new >0, resolved ==0) → "⚠️ 2 new findings since last scan · 5 still open"
    * mixed (both >0)                        → "📊 2 resolved · 1 new · 3 still open since last scan"

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
