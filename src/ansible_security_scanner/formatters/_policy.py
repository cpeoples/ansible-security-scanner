#!/usr/bin/env python3
"""
Shared helpers for rendering ``--select`` / ``--ignore`` policy disclosure.

The Markdown, HTML, and any future score-bearing formatter all need to
voice the same decision: was the score produced under a constrained rule
set, and if so, which set is the actionable one to surface? The voicing
mirrors :mod:`ansible_security_scanner.comment.rendering` so the report
file and the MR/PR comment read the same.
"""

from __future__ import annotations

from dataclasses import dataclass


def pluralize_rules(n: int) -> str:
    """``"1 rule"`` / ``"3 rules"``-style count for policy disclosure.

    Kept local to the formatters package rather than reaching into the
    ``comment.rendering`` private helper; the rule names that drive
    these counts are the only thing the two surfaces share.
    """
    return f"{n} {'rule' if n == 1 else 'rules'}"


@dataclass(frozen=True)
class PolicyVoicing:
    """The structured pieces a formatter needs to render a policy block.

    ``head_template`` carries the prose with ``{select}`` / ``{ignore}``
    placeholders so each formatter can substitute its own emphasis
    syntax (Markdown backticks, HTML ``<code>``, etc.) without
    re-implementing the branching.
    """

    head_template: str
    rule_ids: tuple[str, ...]


def voice(selected_rule_ids: list[str], ignored_rule_ids: list[str]) -> PolicyVoicing | None:
    """Pick the right voicing for a run's resolved policy.

    Mirrors the comment-rendering precedent: ``--select`` voicing wins
    and lists the active set (the actionable surface), with an optional
    parenthetical for an ``--ignore`` filter applied on top.
    ``--ignore``-only voicing lists the suppressed set. Returns
    ``None`` when neither flag is in effect so callers can short-circuit.
    """
    if selected_rule_ids:
        head = f"Scan limited to {pluralize_rules(len(selected_rule_ids))} via {{select}}"
        if ignored_rule_ids:
            head += f" (and {len(ignored_rule_ids)} further suppressed via {{ignore}})"
        return PolicyVoicing(head_template=head, rule_ids=tuple(selected_rule_ids))

    if ignored_rule_ids:
        head = f"{pluralize_rules(len(ignored_rule_ids))} suppressed via {{ignore}}"
        return PolicyVoicing(head_template=head, rule_ids=tuple(ignored_rule_ids))

    return None
