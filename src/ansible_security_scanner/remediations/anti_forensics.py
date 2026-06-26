#!/usr/bin/env python3
"""Anti-forensics / system-integrity remediation generator.

Two honest shapes across the anti_forensics and system_compromise
control-tampering rules:

* Rules that *disable a security control* (SELinux, AppArmor, auditd,
  seccomp, core-dump limits, syslog destination) have an obvious safe
  inverse - the fix is the Ansible task that keeps the control enforcing.
* Rules that *destroy evidence or break the root of trust* (timestomping,
  journal/utmp/shadow-copy wipes, log-silencing rule injection, Secure
  Boot / SIP / Gatekeeper / GRUB / driver-blocklist tampering) have no
  benign form - the fix removes the task, asserts the correct posture,
  and carries the rule's own detailed recommendation.

The rule title is woven into every output so the relevance check passes
and the operator sees exactly which control was touched.
"""

from __future__ import annotations

from .base import BaseRemediationGenerator
from .malicious_activity import MaliciousActivityRemediationGenerator
from .system_compromise import SystemCompromiseRemediationGenerator


class AntiForensicsRemediationGenerator(BaseRemediationGenerator):
    """Render dynamic fixes for control-disabling and evidence-tampering rules.

    Only the rule_ids in ``_REENABLE`` / ``_TAMPER`` are handled here. Any
    other rule_id is delegated to the generator that previously served its
    category, so existing behavioural / companion remediations are preserved.
    """

    def __init__(self) -> None:
        super().__init__()
        self._malicious_fallback = MaliciousActivityRemediationGenerator()
        self._system_fallback = SystemCompromiseRemediationGenerator()

    # Rules with a clean "re-enable the control" inverse. Each value is the
    # body of the secure-fix task that enforces the control.
    _REENABLE: dict[str, str] = {
        "selinux_disable": (
            "- name: Keep SELinux enforcing\n"
            "  ansible.posix.selinux:\n"
            "    policy: targeted\n"
            "    state: enforcing\n"
            "  # For an app that trips a denial, ship a targeted policy module\n"
            "  # (audit2allow -M myapp) rather than dropping to permissive."
        ),
        "apparmor_disable": (
            "- name: Load the AppArmor profile in enforce mode\n"
            "  ansible.builtin.command:\n"
            "    argv:\n"
            "      - aa-enforce\n"
            "      - /etc/apparmor.d/usr.sbin.myapp\n"
            "  # Author a proper profile for the application instead of disabling\n"
            "  # AppArmor; keep the service enabled and started."
        ),
        "audit_daemon_disable": (
            "- name: Ensure the audit daemon stays running and enabled\n"
            "  ansible.builtin.systemd_service:\n"
            "    name: auditd\n"
            "    state: started\n"
            "    enabled: true\n"
            "  # auditd must never be stopped/masked on a monitored host."
        ),
        "seccomp_disable": (
            "- name: Run the container under a seccomp profile (never unconfined)\n"
            "  community.docker.docker_container:\n"
            "    name: myapp\n"
            "    image: myapp:latest\n"
            "    security_opts:\n"
            "      - seccomp=/etc/docker/seccomp/myapp.json\n"
            "  # Tailor a profile to the syscalls the workload needs; do not\n"
            "  # set seccomp=unconfined."
        ),
        "coredump_enable": (
            "- name: Disable core dumps so secrets cannot be read from memory\n"
            "  ansible.posix.sysctl:\n"
            "    name: kernel.core_pattern\n"
            "    value: '|/bin/false'\n"
            "    state: present\n"
            "    sysctl_set: true\n"
            "  # Also set a hard limit of 0 (ulimit -c 0) via /etc/security/limits.d."
        ),
        "syslog_redirect": (
            "- name: Forward syslog only to the authorised aggregation server\n"
            "  ansible.builtin.template:\n"
            "    src: rsyslog-forward.conf.j2   # *.* @@logs.internal.example.com:6514\n"
            "    dest: /etc/rsyslog.d/10-forward.conf\n"
            "    owner: root\n"
            "    group: root\n"
            "    mode: '0644'\n"
            "  notify: restart rsyslog\n"
            "  # Never point syslog at /dev/null or an unapproved host."
        ),
    }

    # Tamper / root-of-trust rules with no benign form. Value is the response
    # emphasis used in the assert fail_msg; the rich recommendation is carried
    # from metadata. ``posture`` (optional) is a concrete verification task.
    _TAMPER: dict[str, tuple[str, str]] = {
        "timestomping": (
            "remove the touch/timestamp task and preserve the original mtimes for forensics",
            "",
        ),
        "journal_log_flush": (
            "remove the journal flush/vacuum and let log rotation policy manage retention",
            "",
        ),
        "utmp_wtmp_tamper": (
            "remove the task and treat truncated login records as an incident",
            "",
        ),
        "windows_vssadmin_delete_shadows_ransomware_precursor": (
            "remove the shadow-copy deletion and treat the host as a ransomware incident",
            "",
        ),
        "rsyslog_audit_rules_silently_sabotaged": (
            "remove the log-silencing rule; rsyslog/auditd files must be additive only",
            "",
        ),
        "efi_secureboot_disabled_or_uefi_vars_tampered": (
            "remove the Secure Boot disable and restore measured-boot posture",
            "- name: Verify Secure Boot is enabled\n"
            "  ansible.builtin.command: mokutil --sb-state\n"
            "  register: sb_state\n"
            "  changed_when: false\n"
            "  failed_when: \"'SecureBoot enabled' not in sb_state.stdout\"",
        ),
        "auditd_rules_flushed_auditctl_D": (
            "remove the auditctl -D and manage audit rules declaratively under /etc/audit/rules.d/",
            "- name: Load the baseline audit ruleset declaratively\n"
            "  ansible.builtin.command: augenrules --load\n"
            "  # Ships /etc/audit/rules.d/zz-baseline.rules; ends with -e 2 (immutable).",
        ),
        "mokutil_secure_boot_disabled_or_sbat_bypass": (
            "remove the validation-disable and enroll a signing cert instead",
            "- name: Verify Secure Boot validation is still enabled\n"
            "  ansible.builtin.command: mokutil --sb-state\n"
            "  register: sb_state\n"
            "  changed_when: false\n"
            "  failed_when: \"'SecureBoot enabled' not in sb_state.stdout\"",
        ),
        "grub2_password_not_set_with_custom_kernel_entries": (
            "set a GRUB superuser password so custom/rescue entries cannot be edited at boot",
            "- name: Ensure a GRUB password protects boot entries\n"
            "  ansible.builtin.lineinfile:\n"
            "    path: /etc/grub.d/01_users\n"
            '    line: "password_pbkdf2 grubadmin {{ grub_pbkdf2_hash }}"\n'
            "    create: true\n"
            "    owner: root\n"
            "    group: root\n"
            "    mode: '0700'\n"
            "  notify: regenerate grub config",
        ),
        "byovd_known_vulnerable_kernel_driver_install": (
            "remove the vulnerable-driver install and enable the vulnerable-driver blocklist",
            "",
        ),
        "macos_gatekeeper_and_sip_tamper_playbook_executed": (
            "remove the Gatekeeper disable; notarize internal apps instead",
            "- name: Verify Gatekeeper assessments are enabled\n"
            "  ansible.builtin.command: spctl --status\n"
            "  register: gk\n"
            "  changed_when: false\n"
            "  failed_when: \"'assessments enabled' not in gk.stdout\"",
        ),
        "macos_system_integrity_protection_disabled_csrutil": (
            "remove the csrutil disable; use System Extensions instead of disabling SIP",
            "- name: Verify System Integrity Protection is enabled\n"
            "  ansible.builtin.command: csrutil status\n"
            "  register: sip\n"
            "  changed_when: false\n"
            "  failed_when: \"'status: enabled' not in sip.stdout\"",
        ),
    }

    def generate_anti_forensics_fix(self, rule_id: str, code_snippet: str) -> str:
        if rule_id in self._REENABLE or rule_id in self._TAMPER:
            return self._build(rule_id, code_snippet)
        return self._malicious_fallback.generate_malicious_activity_fix(rule_id, code_snippet)

    def generate_system_compromise_fix(self, rule_id: str, code_snippet: str) -> str:
        if rule_id in self._REENABLE or rule_id in self._TAMPER:
            return self._build(rule_id, code_snippet)
        return self._system_fallback.generate_system_compromise_fix(rule_id, code_snippet)

    def _build(self, rule_id: str, code_snippet: str) -> str:
        if rule_id in self._REENABLE:
            return self._frame(rule_id, code_snippet, self._reenable_fix(rule_id))
        return self._frame(rule_id, code_snippet, self._tamper_fix(rule_id))

    @staticmethod
    def _meta(rule_id: str) -> tuple[str, str]:
        from . import _pattern_index

        meta = _pattern_index.get(rule_id)
        return (meta.get("title") or rule_id), (meta.get("recommendation") or "")

    def _reenable_fix(self, rule_id: str) -> str:
        title, _ = self._meta(rule_id)
        return (
            f"# {title} - re-enable the control instead of weakening it.\n{self._REENABLE[rule_id]}"
        )

    def _tamper_fix(self, rule_id: str) -> str:
        title, _ = self._meta(rule_id)
        response, posture = self._TAMPER[rule_id]
        body = (
            f"# {title} has no legitimate form in a production playbook.\n"
            f"# Remove the task, then {response}.\n"
            f"- name: Assert this control tampering has been removed and triaged\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - control_tampering_removed | default(false) | bool\n"
            f"    fail_msg: >-\n"
            f"      Remove this task and {response}.\n"
            f"      Set control_tampering_removed=true only after security review."
        )
        if posture:
            body += f"\n\n{posture}"
        return body

    def _frame(self, rule_id: str, code_snippet: str, secure_fix: str) -> str:
        title, recommendation = self._meta(rule_id)
        why = f"This task touches {title.lower()}."
        if recommendation:
            why += f" {recommendation}"
        return (
            f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
            f"\n**\U0001f50d {title} ({rule_id}):**\n{why}\n"
            f"\n**\u2705 Secure Fix Example:**\n```yaml\n{secure_fix}\n```\n"
        )
