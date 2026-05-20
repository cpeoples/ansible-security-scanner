"""
Structural classification of YAML files into Ansible-scannable vs not.

The audit tool (and, eventually, the scanner's file-walking front-end)
use this to decide which files contain **playbook-semantic content** that
the playbook-oriented rules should evaluate, and which are inert
metadata/data files that happen to be YAML (vars, requirements, Galaxy
meta, raw Kubernetes manifests, inventory, molecule configs, ...).

Classification is purely **structural** - we inspect the parsed YAML
AST, never the filename, directory, or file extension. This means a
playbook named ``requirements.yml`` or ``vars.yml`` will still be
correctly classified as ``playbook`` if its contents are a list of
plays, and a file named ``playbook.yml`` containing only vars dicts
will be classified as ``vars``.

The classifier is conservative: anything that could plausibly carry
playbook or task content is classified as ``playbook`` or ``tasks_list``
(scannable). We only exclude files whose AST cannot hold Ansible tasks
at all (top-level dict with no task-capable keys, or top-level list
where no item contains any play/task directive). That avoids false
negatives - the guiding principle is "if unsure, scan it".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# Keys that, when present on a top-level list item, identify the item as
# a **play** (turning the list into a playbook). ``hosts`` is the
# canonical play marker; the ``*_playbook`` / ``*_role`` / ``add_host``
# directives are list items that Ansible accepts at the playbook level.
# Source: https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_reuse.html
PLAY_KEYS = frozenset(
    {
        "hosts",
        "import_playbook",
        "include_playbook",
        # Rarely seen at the top level but legal
        "add_host",
    }
)

# Keys that identify a top-level list item as a **task**. ``block`` /
# ``rescue`` / ``always`` are structural task containers; ``include_tasks``
# / ``import_tasks`` / ``include_role`` / ``import_role`` are task-level
# delegators; ``action`` is the legacy bare-task form. A task dict can
# also be identified purely by having a module-looking key (``shell``,
# ``ansible.builtin.copy``, ``community.general.x``, ``mycollection.mod``)
# plus any of the task-flow keys (``when``, ``loop``, ``name``, ``vars``,
# ``register``, ``tags``, ``notify``).
TASK_CONTAINER_KEYS = frozenset(
    {
        "block",
        "rescue",
        "always",
        "include_tasks",
        "import_tasks",
        "include_role",
        "import_role",
        "action",
        "local_action",
    }
)
TASK_FLOW_KEYS = frozenset(
    {
        "name",
        "when",
        "loop",
        "with_items",
        "with_dict",
        "with_fileglob",
        "with_sequence",
        "register",
        "tags",
        "notify",
        "listen",
        "vars",
        "delegate_to",
        "run_once",
        "ignore_errors",
        "changed_when",
        "failed_when",
        "until",
        "retries",
        "delay",
        "no_log",
        "become",
        "become_user",
        "check_mode",
    }
)


def _looks_like_module_name(key: str) -> bool:
    """Heuristic: ``key`` looks like an Ansible module invocation.

    Accepts collection-qualified names (``namespace.collection.module``),
    legacy short names (``shell``, ``copy``, ``yum``), and allows digits /
    underscores. Rejects top-level YAML keys that are obviously values
    (e.g. ``apiVersion``, ``kind`` - those belong to k8s manifests).
    """
    if not isinstance(key, str) or not key:
        return False
    if key in TASK_CONTAINER_KEYS or key in TASK_FLOW_KEYS:
        return False
    # A module name is all lowercase letters, digits, underscores, and
    # optionally dots for the collection-qualified form. Reject
    # CamelCase / PascalCase (those are K8s / CloudFormation keys) and
    # keys with spaces / punctuation.
    if not all(c.islower() or c.isdigit() or c in "._" for c in key):
        return False
    # At least one alpha so pure numbers aren't modules.
    return any(c.isalpha() for c in key)


def _is_task_dict(item: Any) -> bool:
    """True if ``item`` looks like an Ansible task definition."""
    if not isinstance(item, dict):
        return False
    keys = set(item.keys())
    if keys & TASK_CONTAINER_KEYS:
        return True
    # A task with a module invocation: at least one module-looking key
    # PLUS at least one task-flow key, OR a single module-looking key
    # whose value is a dict/string (that's the classic ``- name: X\n
    # shell: Y`` form).
    module_like = [k for k in keys if _looks_like_module_name(k)]
    if module_like and (keys & TASK_FLOW_KEYS):
        return True
    # Bare task: a single key that looks like a module, value is a scalar
    # or dict. This catches terse role tasks like ``- debug: var=foo``.
    return len(module_like) == 1 and not (keys - set(module_like))


def _is_play_dict(item: Any) -> bool:
    """True if ``item`` looks like an Ansible play."""
    if not isinstance(item, dict):
        return False
    return bool(set(item.keys()) & PLAY_KEYS)


def classify_yaml(data: Any) -> str:
    """Classify a parsed YAML AST into an Ansible file kind.

    Returns one of:
      * ``playbook``       - top-level list with at least one play
      * ``tasks_list``     - top-level list with at least one task
      * ``empty``          - empty file or ``null``
      * ``not_ansible``    - parseable YAML, but not playbook content
                             (vars, requirements, k8s manifest, etc.)
    """
    if data is None:
        return "empty"

    if isinstance(data, list):
        for item in data:
            if _is_play_dict(item):
                return "playbook"
        for item in data:
            if _is_task_dict(item):
                return "tasks_list"
        return "not_ansible"

    # Top-level mapping is never a playbook; it's vars / requirements /
    # k8s manifest / Galaxy collection meta / inventory.
    if isinstance(data, dict):
        return "not_ansible"

    return "not_ansible"


def classify_file(path: Path) -> str:
    """Classify ``path`` by parsing it and running :func:`classify_yaml`.

    Returns ``"parse_error"`` if YAML parsing fails. Does NOT use the
    filename or directory - pure structural detection.
    """
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (yaml.YAMLError, OSError, UnicodeDecodeError):
        return "parse_error"
    return classify_yaml(data)


SCANNABLE_KINDS = frozenset({"playbook", "tasks_list"})


def is_scannable(path: Path) -> bool:
    """True if ``path`` contains Ansible playbook or task content that
    the playbook-oriented scanner rules should evaluate."""
    return classify_file(path) in SCANNABLE_KINDS
