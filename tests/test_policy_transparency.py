"""Tests for v0.1.8 policy-transparency rendering.

Exercises the always-on note that surfaces ``--select`` / ``--ignore``
policy in MR/PR comments, the *(active policy)* score qualifier, and
the inline-thread breadcrumb that fires when the resolved policy
exceeds eight rules.

Findings are stub-built rather than scanned end-to-end so we isolate
the renderer and inline body shape from pattern-pack churn.
"""

from __future__ import annotations

from dataclasses import dataclass

from ansible_security_scanner import comment
from ansible_security_scanner.comment.inline import (
    _INLINE_BREADCRUMB,
    _RESOLUTION_DISCLAIMER,
    _render_inline_body,
)
from ansible_security_scanner.comment.rendering import _render_policy_note


def _ignore_note(ignored_rule_ids, category_for_rule):
    """Tiny shim so ignore-only renderer tests stay readable."""
    return _render_policy_note(
        selected_rule_ids=[],
        ignored_rule_ids=ignored_rule_ids,
        category_for_rule=category_for_rule,
    )


@dataclass
class _F:
    rule_id: str
    severity: str
    file_path: str
    line_number: int
    title: str
    description: str = ""
    recommendation: str = ""
    code_snippet: str = ""
    remediation_example: str = ""


def _ctx() -> comment.PlatformContext:
    return comment.PlatformContext(
        platform="github",
        api_url="https://api.github.com",
        project_ref="octocat/repo",
        mr_number=1,
        commit_sha="0" * 40,
        token="SECRET",
    )


# ---- _ignore_note shape ---------------------------------------------


def test_ignore_note_empty_ignores_returns_empty_string():
    assert _ignore_note([], {}) == ""


def test_ignore_note_flat_form_under_threshold():
    note = _ignore_note(
        ["a_rule", "b_rule", "c_rule"],
        {"a_rule": "cat_x", "b_rule": "cat_x", "c_rule": "cat_y"},
    )
    assert note.startswith("> **Note:**")
    assert "3 rules suppressed via `--ignore`" in note
    assert "`a_rule`" in note and "`b_rule`" in note and "`c_rule`" in note
    assert "<details>" not in note


def test_ignore_note_singular_word_for_one_rule():
    note = _ignore_note(["only_rule"], {"only_rule": "cat_x"})
    assert "1 rule suppressed" in note
    assert "1 rules" not in note


def test_ignore_note_grouped_form_above_threshold():
    rules = [f"rule_{i:02d}" for i in range(12)]
    cats = {r: ("alpha" if i % 2 == 0 else "beta") for i, r in enumerate(rules)}
    note = _ignore_note(rules, cats)
    assert note.startswith("<details>")
    assert "12 rules suppressed" in note
    assert "**Alpha**" in note and "**Beta**" in note
    assert "rule_00" in note and "rule_11" in note


def test_ignore_note_unknown_category_falls_into_other_bucket():
    rules = [f"r{i}" for i in range(10)]
    note = _ignore_note(rules, {})
    assert "**Other**" in note


def test_ignore_note_hard_cap_collapses_tail():
    rules = [f"rule_{i:03d}" for i in range(80)]
    cats: dict[str, str] = {}
    for i, r in enumerate(rules):
        cats[r] = f"cat_{i % 8}"
    note = _ignore_note(rules, cats)
    assert "80 rules suppressed" in note
    assert "Rule list capped for readability" in note
    assert "rule_000" not in note  # collapsed; not all listed


# ---- render_comment_body integration ---------------------------------------


def _findings(n: int = 1) -> list[_F]:
    return [
        _F(
            rule_id=f"rule_{i}",
            severity="HIGH",
            file_path=f"file_{i}.yml",
            line_number=10,
            title=f"title {i}",
        )
        for i in range(n)
    ]


def test_summary_score_picks_up_active_policy_qualifier():
    body = comment.render_comment_body(
        _findings(1),
        _ctx(),
        security_score=87,
        ignored_rule_ids=["a", "b"],
        category_for_rule={"a": "cat", "b": "cat"},
    )
    assert "**Security score:** 87 / 100 *(active policy)*" in body
    assert "Note:" in body and "2 rules suppressed" in body


def test_summary_score_unqualified_when_no_ignore():
    body = comment.render_comment_body(_findings(1), _ctx(), security_score=87)
    assert "**Security score:** 87 / 100" in body
    assert "*(active policy)*" not in body
    assert "Note:" not in body


def test_resolved_banner_picks_up_active_policy_qualifier():
    body = comment.render_comment_body(
        [],
        _ctx(),
        ignored_rule_ids=["only"],
        category_for_rule={"only": "cat"},
    )
    assert "100 / 100 *(active policy)*" in body
    assert "1 rule suppressed via `--ignore`" in body


def test_resolved_banner_clean_when_no_ignore():
    body = comment.render_comment_body([], _ctx())
    assert "100 / 100" in body
    assert "*(active policy)*" not in body
    assert "Note:" not in body


# ---- --select voice --------------------------------------------------------


def test_select_voice_lists_active_set():
    body = comment.render_comment_body(
        _findings(1),
        _ctx(),
        security_score=87,
        selected_rule_ids=["rule_a", "rule_b"],
        category_for_rule={"rule_a": "cat", "rule_b": "cat"},
    )
    assert "Scan limited to 2 rules via `--select`" in body
    assert "`rule_a`" in body and "`rule_b`" in body
    assert "*(active policy)*" in body


def test_select_singular_word_for_one_rule():
    body = comment.render_comment_body(
        _findings(1),
        _ctx(),
        selected_rule_ids=["only_rule"],
        category_for_rule={"only_rule": "cat"},
    )
    assert "Scan limited to 1 rule via `--select`" in body
    assert "1 rules" not in body


def test_select_with_ignore_mentions_both_in_head():
    body = comment.render_comment_body(
        _findings(1),
        _ctx(),
        selected_rule_ids=["a", "b", "c"],
        ignored_rule_ids=["x"],
        category_for_rule={"a": "cat", "b": "cat", "c": "cat", "x": "cat"},
    )
    assert "Scan limited to 3 rules via `--select`" in body
    assert "1 further suppressed via `--ignore`" in body


def test_ignore_only_does_not_mention_select():
    body = comment.render_comment_body(
        _findings(1),
        _ctx(),
        ignored_rule_ids=["x", "y"],
        category_for_rule={"x": "cat", "y": "cat"},
    )
    assert "via `--select`" not in body
    assert "2 rules suppressed via `--ignore`" in body


# ---- inline-body breadcrumb -------------------------------------------------


def _inline_finding() -> _F:
    return _F(
        rule_id="example_rule",
        severity="HIGH",
        file_path="x.yml",
        line_number=12,
        title="Example",
        description="An example finding.",
        recommendation="Do the thing.",
    )


def test_inline_breadcrumb_off_by_default():
    body = _render_inline_body(_inline_finding(), anchored=True)
    assert _RESOLUTION_DISCLAIMER in body
    assert _INLINE_BREADCRUMB not in body


def test_inline_breadcrumb_appears_when_requested():
    body = _render_inline_body(_inline_finding(), anchored=True, breadcrumb=True)
    assert _RESOLUTION_DISCLAIMER in body
    assert _INLINE_BREADCRUMB in body
    assert body.index(_RESOLUTION_DISCLAIMER) < body.index(_INLINE_BREADCRUMB)


def test_inline_breadcrumb_present_in_file_level_body_too():
    body = _render_inline_body(_inline_finding(), anchored=False, breadcrumb=True)
    assert _INLINE_BREADCRUMB in body
