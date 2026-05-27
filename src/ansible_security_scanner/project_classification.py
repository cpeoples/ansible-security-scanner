"""Project-level classification for findings.

Some Ansible projects are *security-hardening* roles whose purpose is
to manipulate exactly the surfaces our scanner flags as risky:
``/etc/pam.d/`` files, GRUB config, kernel module loading, sudoers
files, login banners, and so on. The CIS / STIG / dev-sec hardening
roles are the canonical examples - their entire job is to tighten
those surfaces, so the surface-touching rules are working-as-designed
rather than findings to act on.

This module classifies a scanned directory once at scan-start and
exposes a single boolean: ``is_security_hardening_project``. The
file scanner uses that to demote a curated list of system-modification
rules from MEDIUM/HIGH down a step, reducing noise without erasing
the audit trail.

Detection signal: any of ``meta/main.yml``, ``galaxy.yml``, or
``collection.yml`` at the project root listing ``cis``, ``stig``,
``hardening``, ``benchmark``, ``lockdown``, or ``compliance`` in its
galaxy tags / collection tags. Exactly the marker every published
hardening role uses.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml

_HARDENING_TAGS: frozenset[str] = frozenset(
    {
        "cis",
        "stig",
        "hardening",
        "benchmark",
        "lockdown",
        "compliance",
        "complianceascode",
        "ansible-lockdown",
    }
)

# Rules that hardening roles legitimately trigger by design. Demoted
# (not suppressed) inside a hardening project so an auditor still sees
# the touch-points but the security score doesn't double-count them
# as risk.
DEMOTE_IN_HARDENING_PROJECT: frozenset[str] = frozenset(
    {
        "pam_module_manipulation",
        "grub_bootloader_modification",
        "shadow_file_access",
        "kernel_module_load",
        "kernel_module_loading",
        "crontab_modification",
        "selinux_disable",
        "apparmor_disable",
        "firewall_disable",
        "firewalld_flush_or_disable",
        "iptables_nat_redirect",
        "ssh_config_manipulation",
        "ssh_authorized_keys_write",
        "sudo_nopasswd",
        "init_script_creation",
        "motd_banner_injection",
        "dpkg_apt_hooks_persistence",
        "ansible_block_without_rescue_or_always",
        "shadow_copy_or_passwd_export",
        "world_writable_files",
    }
)


def _read_yaml(path: Path) -> dict | None:
    try:
        with path.open(encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return None


def _tags_from(data: dict | None, *paths: tuple[str, ...]) -> Iterable[str]:
    if not isinstance(data, dict):
        return ()
    for path in paths:
        cursor: object = data
        for key in path:
            if not isinstance(cursor, dict):
                cursor = None
                break
            cursor = cursor.get(key)
        if isinstance(cursor, list):
            yield from (str(t).lower() for t in cursor if isinstance(t, (str, bytes)))


def is_security_hardening_project(directory: Path) -> bool:
    """Return ``True`` when ``directory`` is a CIS / STIG / hardening role.

    Reads only the top-level metadata files (``meta/main.yml``,
    ``galaxy.yml``, ``collection.yml``); cheap one-shot check at
    scan-start.
    """
    candidates = (
        (directory / "meta" / "main.yml", (("galaxy_info", "galaxy_tags"),)),
        (directory / "galaxy.yml", (("tags",),)),
        (directory / "collection.yml", (("tags",),)),
    )
    for path, key_paths in candidates:
        if not path.is_file():
            continue
        data = _read_yaml(path)
        for tag in _tags_from(data, *key_paths):
            if tag in _HARDENING_TAGS:
                return True
    return False
