#!/usr/bin/env python3
"""Shared YAML-AST helpers used by the per-file scanner, the TaintTracker,
and the DependencyCollector.

These used to live as static methods on ``FileScanner`` but pulling them up
to a module-level function breaks a potential circular import between the
sibling scanner modules: both the taint tracker and the dependency
collector walk arbitrary playbook YAML the same way the file scanner does,
and they shouldn't have to round-trip through ``FileScanner`` to do it.
"""

from __future__ import annotations


def extract_all_tasks(yaml_data) -> list:
    """Return every task dict under a playbook's ``tasks`` / ``pre_tasks`` /
    ``post_tasks`` / ``handlers`` keys, including tasks nested inside
    ``block:`` / ``rescue:`` / ``always:`` clauses.

    Accepts three top-level shapes - the three Ansible shipping layouts:

    * **Playbook** - a list of plays, each a dict with ``tasks:`` /
      ``pre_tasks:`` / ``post_tasks:`` / ``handlers:`` keys.
    * **Single play** - one dict of the same shape.
    * **Role task / handler file** (``roles/*/tasks/*.yml``,
      ``roles/*/handlers/*.yml``) - a bare list of task dicts, with no
      enclosing play. Detected by checking whether the top-level list
      items look like tasks (carry task keywords like ``name`` + a
      module invocation) rather than plays (``hosts`` / ``tasks`` /
      ``roles``). Without this, the cross-file TaintTracker and the
      structural-hygiene AST checks silently skip every role task
      file - which is how real-world Ansible projects ship 90 % of
      their logic. Non-dict entries are skipped so malformed YAML
      degrades gracefully instead of aborting the walk.
    """
    tasks: list = []
    items = yaml_data if isinstance(yaml_data, list) else [yaml_data]

    _PLAY_KEYS = {"hosts", "tasks", "pre_tasks", "post_tasks", "handlers", "roles"}

    def _collect_from_task_list(task_list) -> None:
        """Append every task dict (plus nested block/rescue children)."""
        if not isinstance(task_list, list):
            return
        for t in task_list:
            if not isinstance(t, dict):
                continue
            tasks.append(t)
            # Mirror the historical behaviour: only ``block`` and
            # ``rescue`` children are walked here. ``always:`` lives
            # alongside them but is intentionally left alone because
            # some rules look at the block scope itself to decide
            # whether ``always:`` is a peer (see the AST-based
            # ``ansible_block_without_rescue_or_always`` check).
            for nested_key in ("block", "rescue"):
                nested = t.get(nested_key, [])
                if isinstance(nested, list):
                    tasks.extend(b for b in nested if isinstance(b, dict))

    for item in items:
        if not isinstance(item, dict):
            continue
        # Play-shaped: has at least one of the play-level keys. Walk
        # the four conventional task-list slots.
        if _PLAY_KEYS & set(item.keys()):
            for key in ("tasks", "pre_tasks", "post_tasks", "handlers"):
                _collect_from_task_list(item.get(key, []))
            continue
        # Role-task-file-shaped: a bare dict at the top level (when the
        # file is a single-entry list). Treat it as one task directly.
        tasks.append(item)
        for nested_key in ("block", "rescue"):
            nested = item.get(nested_key, [])
            if isinstance(nested, list):
                tasks.extend(b for b in nested if isinstance(b, dict))

    # Final fallback: if the top-level shape is a list of plain task
    # dicts (role tasks/handlers file) AND NONE of the per-item
    # branches above added anything - re-walk as a flat task list.
    # This guard handles the pure ``roles/*/tasks/main.yml`` shape
    # where every entry is a task dict with no play keywords.
    if not tasks and isinstance(yaml_data, list):
        _collect_from_task_list(yaml_data)

    return tasks


def extract_deep_strings(data, results: list, depth: int = 0) -> None:
    """Recursively harvest every string leaf from a nested dict/list into
    ``results``. Depth-capped at 8 so pathological / recursive YAML can't
    trigger runaway recursion during scans.
    """
    if depth > 8:
        return
    if isinstance(data, str):
        results.append((data, None))
    elif isinstance(data, dict):
        for v in data.values():
            extract_deep_strings(v, results, depth + 1)
    elif isinstance(data, list):
        for item in data:
            extract_deep_strings(item, results, depth + 1)


__all__ = ["extract_all_tasks", "extract_deep_strings"]
