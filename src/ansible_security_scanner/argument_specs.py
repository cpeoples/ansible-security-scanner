"""
``meta/argument_specs.yml`` awareness for the scanner.

Ansible roles can declare and validate their inputs in
``<role>/meta/argument_specs.yml`` (see
https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_reuse_roles.html#specification-format).
When a variable is declared there with a type / required / regex / choices
constraint, Ansible itself enforces the contract before the role runs.

A line-based regex scanner cannot tell that a downstream
``{{ user_input }}`` reference is already constrained, so without this
hint it produces noise on every well-validated role variable.

This module:

  * Walks up from any scanned file to find an enclosing role root
    (a directory containing ``meta/argument_specs.yml``).
  * Loads each role's argument-specs once and caches the set of
    declared option names across all entry points.
  * Provides ``is_validated_variable(file_path, var_name)`` for the
    file scanner to consult before emitting noisy variable-related
    findings.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_ROLE_DIR_MARKERS = ("tasks", "handlers", "defaults", "vars", "meta", "templates", "files")
_SPEC_FILENAMES = ("argument_specs.yml", "argument_specs.yaml")


class ArgumentSpecsRegistry:
    """Cache of role-root -> validated variable names."""

    def __init__(self) -> None:
        self._role_to_vars: dict[Path, set[str]] = {}
        self._file_to_role: dict[Path, Path | None] = {}
        self._lock = threading.Lock()

    def role_root_for(self, file_path: Path) -> Path | None:
        """Return the role root directory for ``file_path``, or ``None``.

        A role root is the closest ancestor whose ``meta/`` subdirectory
        contains ``argument_specs.yml`` / ``argument_specs.yaml``.
        """
        try:
            resolved = file_path.resolve()
        except OSError:
            resolved = file_path

        with self._lock:
            # Cache may store ``None`` to mean "no role root for this file",
            # so check membership separately from the value.
            cached = self._file_to_role.get(resolved)
            if cached is not None or resolved in self._file_to_role:
                return cached

        role_root: Path | None = None
        for ancestor in [resolved, *resolved.parents]:
            meta_dir = ancestor / "meta"
            if not meta_dir.is_dir():
                continue
            if any((meta_dir / name).is_file() for name in _SPEC_FILENAMES):
                # Only treat this directory as a role root if it actually
                # looks like one - i.e. it carries at least one canonical
                # role subdirectory besides ``meta/``.
                siblings = {p.name for p in ancestor.iterdir() if p.is_dir()}
                if siblings & set(_ROLE_DIR_MARKERS):
                    role_root = ancestor
                    break

        with self._lock:
            self._file_to_role[resolved] = role_root
        return role_root

    def validated_vars_for(self, file_path: Path) -> set[str]:
        """Return the set of variable names validated by argument_specs."""
        role_root = self.role_root_for(file_path)
        if role_root is None:
            return set()

        with self._lock:
            cached = self._role_to_vars.get(role_root)
        if cached is not None:
            return cached

        names = self._load_role_specs(role_root)

        with self._lock:
            self._role_to_vars[role_root] = names
        return names

    def is_validated_variable(self, file_path: Path, var_name: str) -> bool:
        if not var_name:
            return False
        return var_name in self.validated_vars_for(file_path)

    @staticmethod
    def _load_role_specs(role_root: Path) -> set[str]:
        spec_path: Path | None = None
        for name in _SPEC_FILENAMES:
            candidate = role_root / "meta" / name
            if candidate.is_file():
                spec_path = candidate
                break
        if spec_path is None:
            return set()

        try:
            with spec_path.open(encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError) as exc:
            logger.debug("Could not parse %s: %s", spec_path, exc)
            return set()

        return _collect_option_names(data)


def _collect_option_names(spec: Any) -> set[str]:
    """Walk an ``argument_specs:`` document and return every option name.

    Schema::

        argument_specs:
          <entry_point>:
            options:
              <name>:
                type: str
                options:    # nested sub-args (rare)
                  <child>: ...
          <other_entry>:
            options: ...
    """
    names: set[str] = set()
    entries = spec.get("argument_specs") if isinstance(spec, dict) else None
    if not isinstance(entries, dict):
        return names
    for entry in entries.values():
        if isinstance(entry, dict):
            _collect_options(entry.get("options"), names)
    return names


def _collect_options(options: Any, sink: set[str]) -> None:
    if not isinstance(options, dict):
        return
    for key, value in options.items():
        if isinstance(key, str):
            sink.add(key)
        if isinstance(value, dict):
            _collect_options(value.get("options"), sink)


_default_registry = ArgumentSpecsRegistry()


def get_default_registry() -> ArgumentSpecsRegistry:
    return _default_registry
