#!/usr/bin/env python3
"""Data-destruction remediation generator.

Unlike the static companion snippets, these fixes read the concrete
target out of the finding (the path the playbook deletes, the device it
wipes, the database it drops, the volume group it removes) and weave that
real value into the recommended Ansible task, so the user sees their own
target in the fix rather than a generic placeholder.

Every rendered fix replaces a raw destructive shell command with the
idempotent module equivalent behind an explicit operator confirmation
gate (and a backup/snapshot step where the data is recoverable).
"""

from __future__ import annotations

import re

from .base import BaseRemediationGenerator, _render_from_metadata


def _first(snippet: str, *patterns: str) -> str | None:
    """Return the first capture group matched by any of ``patterns``."""
    for pat in patterns:
        m = re.search(pat, snippet)
        if m:
            return m.group(1).strip().strip("'\"")
    return None


class DataDestructionRemediationGenerator(BaseRemediationGenerator):
    """Render dynamic, gated fixes for destructive operations."""

    def generate_data_destruction_fix(self, rule_id: str, code_snippet: str) -> str:
        builder = {
            "disk_wipe_dd": self._fix_disk_wipe,
            "shred_wipe_command": self._fix_shred,
            "ransomware_file_encryption": self._fix_ransomware,
            "database_drop_truncate": self._fix_database,
            "recursive_delete_critical": self._fix_recursive_delete,
            "mkfs_format_device": self._fix_mkfs,
            "backup_deletion": self._fix_backup_deletion,
            "lvm_vg_remove": self._fix_lvm,
        }.get(rule_id)
        if builder is None:
            return _render_from_metadata(rule_id, code_snippet)
        return builder(code_snippet)

    @staticmethod
    def _frame(rule_id: str, heading: str, code_snippet: str, why: str, secure_fix: str) -> str:
        return (
            f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
            f"\n**\U0001f50d {heading} ({rule_id}):**\n{why}\n"
            f"\n**\u2705 Secure Fix Example:**\n```yaml\n{secure_fix}\n```\n"
        )

    def _fix_disk_wipe(self, code_snippet: str) -> str:
        device = _first(code_snippet, r"of=(/dev/[\w/]+)") or "/dev/<device>"
        secure_fix = (
            f"# Disk wiping is destructive and irreversible. Gate the wipe of\n"
            f"# {device} behind a typed confirmation, then sanitize the device\n"
            f"# declaratively instead of piping dd at a raw block device.\n"
            f"- name: Require explicit confirmation before wiping {device}\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - wipe_confirm | default('') == 'WIPE-{device}'\n"
            f'    fail_msg: "Refusing to wipe {device}: set wipe_confirm to WIPE-{device}"\n'
            f"\n"
            f"- name: Remove the partition table on {device}\n"
            f"  community.general.parted:\n"
            f'    device: "{device}"\n'
            f"    state: absent\n"
            f"  when: wipe_confirm == 'WIPE-{device}'"
        )
        return self._frame(
            "disk_wipe_dd",
            "Disk/Partition Wipe with dd",
            code_snippet,
            f"This task wipes the block device `{device}` with dd, destroying all "
            f"data on it irreversibly. There is no Ansible rollback once dd runs.",
            secure_fix,
        )

    def _fix_shred(self, code_snippet: str) -> str:
        target = (
            _first(
                code_snippet,
                r"(?:shred|wipe)\s+(?:-[a-z]*\s+)*[\"']?((?:[^\s'\"{]|\{\{.*?\}\})+)",
            )
            or "{{ target_file }}"
        )
        secure_fix = (
            f"# shred overwrites {target} irrecoverably with no rollback. If the\n"
            f"# file genuinely must go, remove it declaratively and idempotently\n"
            f"# behind a confirmation gate so it cannot run as an accidental sweep.\n"
            f"- name: Require confirmation before securely deleting {target}\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - shred_confirm | default(false) | bool\n"
            f'    fail_msg: "Refusing to delete {target}: set shred_confirm=true"\n'
            f"\n"
            f"- name: Remove {target}\n"
            f"  ansible.builtin.file:\n"
            f'    path: "{target}"\n'
            f"    state: absent\n"
            f"  when: shred_confirm | bool"
        )
        return self._frame(
            "shred_wipe_command",
            "Secure File Deletion (shred/wipe)",
            code_snippet,
            f"This task shreds `{target}`, overwriting its contents so they "
            f"cannot be recovered. Secure-deletion tools in a playbook warrant "
            f"investigation as potential sabotage.",
            secure_fix,
        )

    def _fix_ransomware(self, code_snippet: str) -> str:
        path = (
            _first(code_snippet, r"((?:/var|/home|/opt|/etc|/srv)[\w/.*-]*)") or "{{ data_path }}"
        )
        secure_fix = (
            f"# Encrypting files under {path} from a playbook is a ransomware\n"
            f"# indicator. Legitimate encryption at rest is a property of the\n"
            f"# storage layer (LUKS), not an openssl/gpg loop over a directory.\n"
            f"- name: Provision an encrypted volume for data under {path}\n"
            f"  community.crypto.luks_device:\n"
            f'    device: "{{{{ data_device }}}}"\n'
            f"    state: present\n"
            f'    name: "{{{{ data_volume_name }}}}"\n'
            f'    keyfile: "{{{{ luks_keyfile }}}}"\n'
            f"\n"
            f"- name: Mount the encrypted volume at {path}\n"
            f"  ansible.posix.mount:\n"
            f'    path: "{path}"\n'
            f'    src: "/dev/mapper/{{{{ data_volume_name }}}}"\n'
            f"    fstype: ext4\n"
            f"    state: mounted"
        )
        return self._frame(
            "ransomware_file_encryption",
            "File Encryption (Ransomware Pattern)",
            code_snippet,
            f"This task encrypts files under `{path}` in a pattern consistent "
            f"with ransomware. Mass file encryption is a ransomware indicator; "
            f"remove and investigate immediately.",
            secure_fix,
        )

    def _fix_database(self, code_snippet: str) -> str:
        db = (
            _first(
                code_snippet,
                r"DROP\s+(?:DATABASE|SCHEMA)\s+`?(\w+)`?",
                r"(?:DROP\s+TABLE|TRUNCATE(?:\s+TABLE)?)\s+`?#?(\w+)`?",
            )
            or "{{ target_database }}"
        )
        secure_fix = (
            f"# Destructive DDL against {db} must run through a backed-up,\n"
            f"# reviewed migration, never an inline DROP/TRUNCATE. Snapshot\n"
            f"# first, gate on confirmation, then apply the migration.\n"
            f"- name: Back up {db} before any destructive migration\n"
            f"  community.mysql.mysql_db:\n"
            f'    name: "{db}"\n'
            f"    state: dump\n"
            f'    target: "/var/backups/{db}-{{{{ ansible_date_time.iso8601_basic_short }}}}.sql"\n'
            f"\n"
            f"- name: Require explicit confirmation for the destructive migration\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - migration_confirm | default('') == 'APPLY-{db}'\n"
            f'    fail_msg: "Refusing destructive migration on {db}: set migration_confirm to APPLY-{db}"\n'
            f"\n"
            f"- name: Apply the reviewed, version-controlled migration\n"
            f"  community.mysql.mysql_db:\n"
            f'    name: "{db}"\n'
            f"    state: import\n"
            f'    target: "{{{{ migration_sql_path }}}}"\n'
            f"  when: migration_confirm == 'APPLY-{db}'"
        )
        return self._frame(
            "database_drop_truncate",
            "Database DROP/TRUNCATE Destructive Command",
            code_snippet,
            f"This task runs a destructive DROP/TRUNCATE against `{db}`. "
            f"Destructive database commands should never appear in playbooks; "
            f"use migrations with backups.",
            secure_fix,
        )

    def _fix_recursive_delete(self, code_snippet: str) -> str:
        path = (
            _first(
                code_snippet,
                r"rm\s+(?:--?[a-z-]+\s+)+['\"]?((?:/boot|/etc|/var|/usr|/home|/opt|/srv|/root)(?:/\{\{[^}]+\}\}|/[\w.*-]+)*/?|/\*?)",
            )
            or "{{ cleanup_path }}"
        )
        secure_fix = (
            f"# Recursively deleting {path} is destructive. Manage the specific\n"
            f"# path you own with the file module - state: absent is idempotent\n"
            f"# and cannot collapse to a parent the way an unbound variable can.\n"
            f"- name: Guard against an empty or critical target\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - cleanup_path is defined\n"
            f"      - cleanup_path | length > 1\n"
            f"      - cleanup_path not in ['/', '/boot', '/etc', '/var', '/usr', '/home', '/opt', '/srv', '/root']\n"
            f'    fail_msg: "Refusing recursive delete of critical path {{{{ cleanup_path }}}}"\n'
            f"\n"
            f"- name: Remove the specific application path\n"
            f"  ansible.builtin.file:\n"
            f'    path: "{{{{ cleanup_path }}}}"\n'
            f"    state: absent"
        )
        return self._frame(
            "recursive_delete_critical",
            "Recursive Delete of Critical Paths",
            code_snippet,
            f"This task recursively deletes `{path}`, a critical system path. "
            f"Recursive deletion of system directories is destructive; remove "
            f"immediately and manage owned paths declaratively instead.",
            secure_fix,
        )

    def _fix_mkfs(self, code_snippet: str) -> str:
        device = _first(code_snippet, r"mkfs\.\w+\s+(/dev/[\w/]+)") or "/dev/<device>"
        fstype = _first(code_snippet, r"mkfs\.(\w+)") or "ext4"
        secure_fix = (
            f"# Formatting {device} destroys all existing data, so it must only\n"
            f"# run at initial provisioning. The filesystem module is idempotent:\n"
            f"# with force=false it refuses to reformat a device that already\n"
            f"# carries a filesystem - the guard a raw mkfs lacks.\n"
            f"- name: Create the filesystem on {device} only if it is blank\n"
            f"  community.general.filesystem:\n"
            f'    fstype: "{fstype}"\n'
            f'    dev: "{device}"\n'
            f"    force: false\n"
            f"    state: present"
        )
        return self._frame(
            "mkfs_format_device",
            "Filesystem Format on Existing Device",
            code_snippet,
            f"This task runs mkfs against `{device}`. Formatting destroys all "
            f"existing data and there is no Ansible rollback path; formatting "
            f"should only happen during initial provisioning.",
            secure_fix,
        )

    def _fix_backup_deletion(self, code_snippet: str) -> str:
        secure_fix = (
            "# Deleting backups before encryption is a ransomware pattern.\n"
            "# Never delete backups inline; expire them through a retention\n"
            "# policy so the newest restore points always survive.\n"
            "- name: Find backups older than the retention window\n"
            "  ansible.builtin.find:\n"
            '    paths: "{{ backup_dir }}"\n'
            '    patterns: "*.bak,*.backup"\n'
            '    age: "{{ backup_retention_days | default(30) }}d"\n'
            "  register: expired_backups\n"
            "\n"
            "- name: Require confirmation before expiring old backups\n"
            "  ansible.builtin.assert:\n"
            "    that:\n"
            "      - backup_expiry_confirm | default(false) | bool\n"
            '    fail_msg: "Refusing to expire backups: set backup_expiry_confirm=true after verifying a fresh restore point"\n'
            "\n"
            "- name: Expire only the aged backups\n"
            "  ansible.builtin.file:\n"
            '    path: "{{ item.path }}"\n'
            "    state: absent\n"
            '  loop: "{{ expired_backups.files }}"\n'
            "  when: backup_expiry_confirm | bool"
        )
        return self._frame(
            "backup_deletion",
            "Backup File Deletion",
            code_snippet,
            "This task deletes backup files. Backup deletion before encryption "
            "is a ransomware pattern; investigate immediately and expire backups "
            "through a retention policy instead of deleting them inline.",
            secure_fix,
        )

    def _fix_lvm(self, code_snippet: str) -> str:
        target = (
            _first(
                code_snippet,
                r"(?:vgremove|lvremove|pvremove)\s+(?:-f\s+)?((?:[^\s{]|\{\{.*?\}\})+)",
            )
            or "{{ lvm_target }}"
        )
        secure_fix = (
            f"# Removing {target} is destructive and belongs only in a planned\n"
            f"# decommission with backups. Gate on a typed confirmation, then\n"
            f"# remove the logical volume declaratively with the lvol module.\n"
            f"- name: Require explicit confirmation for the LVM teardown\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - lvm_decommission_confirm | default('') == 'DECOMMISSION-' ~ vg_name\n"
            f'    fail_msg: "Refusing to remove volume group {{{{ vg_name }}}}: set lvm_decommission_confirm to DECOMMISSION-<vg>"\n'
            f"\n"
            f"- name: Remove the logical volume (planned decommission only)\n"
            f"  community.general.lvol:\n"
            f'    vg: "{{{{ vg_name }}}}"\n'
            f'    lv: "{{{{ lv_name }}}}"\n'
            f"    state: absent\n"
            f"    force: true\n"
            f"  when: lvm_decommission_confirm == 'DECOMMISSION-' ~ vg_name"
        )
        return self._frame(
            "lvm_vg_remove",
            "Volume Group / Logical Volume Removal",
            code_snippet,
            f"This task removes the LVM target `{target}`, destroying the data "
            f"on it. LVM removal is destructive; it should only be done during "
            f"a planned decommission with backups.",
            secure_fix,
        )
