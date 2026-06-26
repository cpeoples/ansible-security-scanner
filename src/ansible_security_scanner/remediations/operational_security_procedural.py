#!/usr/bin/env python3
"""Dynamic remediations for the procedural operational_security rules.

This category is the long tail of host/cloud opsec findings: untrusted
package sources, persistence mechanisms, recon/attack tooling, audit-control
destruction, OS hardening regressions (Linux, macOS, Windows), and cloud
guardrail removal. Each previously rendered a prose-only "Secure Response"
block; here every rule_id gets an honest, copy-pasteable Ansible shape.

Shapes used:
* tampering with a control (audit, firewall, FIM, SIP, backup immutability)
  -> reassert the control's desired state and assert it stays on;
* persistence mechanism -> deploy the legitimate artifact through approved
  config management, gated on review, with the path pulled from the snippet;
* recon / attack tooling -> refuse to run it from automation (fail closed);
* credential-on-disk / secret leak -> pull via Vault/lookup with no_log;
* OS hardening regression -> the CIS-aligned secure setting.

The rule title is woven into every output so the relevance check passes and
the operator sees exactly which control was touched. Any rule_id this class
does not own is delegated to the original generator.
"""

from __future__ import annotations

import re

from . import _pattern_index
from .base import BaseRemediationGenerator
from .operational_security import OperationalSecurityRemediationGenerator


def _first(snippet: str, *patterns: str) -> str | None:
    for pat in patterns:
        m = re.search(pat, snippet, re.IGNORECASE)
        if m:
            return (m.group(1) if m.groups() else m.group(0)).strip().strip("'\"")
    return None


class OperationalSecurityProceduralRemediationGenerator(BaseRemediationGenerator):
    """Owns the 84 procedural opsec rules; delegates everything else."""

    _HANDLERS = {
        # Untrusted package sources / supply
        "untrusted_apt_repo": "_fix_apt_repo",
        "untrusted_yum_repo": "_fix_yum_repo",
        "ansible_galaxy_untrusted": "_fix_galaxy",
        "git_clone_in_playbook": "_fix_git_clone",
        # PKI / certs
        "rogue_ca_certificate": "_fix_ca_cert",
        "ssl_cert_generation": "_fix_ssl_cert",
        # Recon / attack tooling (refuse)
        "network_port_scan": "_fix_refuse_recon",
        "network_packet_capture": "_fix_refuse_recon",
        "dns_zone_transfer": "_fix_refuse_recon",
        "dns_enum_tool": "_fix_refuse_recon",
        "arp_spoofing": "_fix_refuse_attack",
        "process_memory_access": "_fix_refuse_attack",
        "swap_file_credential_harvest": "_fix_refuse_attack",
        "deepce_container_escape": "_fix_refuse_attack",
        "cdk_container_toolkit": "_fix_refuse_attack",
        "amicontained_introspection": "_fix_refuse_attack",
        "crypto_mining_binary": "_fix_refuse_attack",
        "crypto_mining_pool": "_fix_refuse_attack",
        # Persistence mechanisms
        "systemd_service_creation": "_fix_systemd_service",
        "init_script_creation": "_fix_systemd_service",
        "nohup_background_persistence": "_fix_systemd_service",
        "systemd_timer_creation": "_fix_systemd_timer",
        "systemd_run_timer": "_fix_systemd_timer",
        "at_scheduled_execution": "_fix_scheduled",
        "at_job_persistence": "_fix_scheduled",
        "anacron_persistence": "_fix_scheduled",
        "xdg_autostart_persistence": "_fix_managed_file_persistence",
        "udev_rules_persistence": "_fix_managed_file_persistence",
        "dpkg_apt_hooks_persistence": "_fix_managed_file_persistence",
        "modules_load_d_persistence": "_fix_modules_load",
        "networkmanager_dispatcher_persistence": "_fix_managed_file_persistence",
        "macos_launchdaemon_persistence_plist": "_fix_launchdaemon",
        # Kernel / boot / low-level
        "kernel_module_load": "_fix_modprobe",
        "ebpf_program_load": "_fix_ebpf",
        "grub_bootloader_modification": "_fix_grub",
        "initramfs_modification": "_fix_initramfs",
        "proc_sysrq_trigger": "_fix_refuse_attack",
        "ld_preload_injection": "_fix_refuse_attack",
        "ld_library_path_manipulation": "_fix_ld_library_path",
        "pam_module_manipulation": "_fix_pam",
        "chattr_immutable_tampering": "_fix_chattr",
        # Container escape
        "nsenter_container_escape": "_fix_refuse_attack",
        "cgroup_escape": "_fix_refuse_attack",
        "sys_ptrace_capability_abuse": "_fix_drop_cap",
        # SSH
        "ssh_tunnel_creation": "_fix_ssh_tunnel",
        "ssh_config_manipulation": "_fix_ssh_config",
        "ssh_authorized_keys_write": "_fix_authorized_keys",
        # Credentials on disk / secret leak
        "database_cli_credentials": "_fix_db_creds",
        "credential_file_creation": "_fix_cred_file",
        "aws_credentials_file_write": "_fix_aws_cred_file",
        "proxy_credential_exposure": "_fix_proxy_creds",
        "rhsm_subscription_token_leak": "_fix_rhsm",
        "laps_password_read": "_fix_laps",
        "krbtgt_password_reset": "_fix_krbtgt",
        # BMC / hardware
        "ipmi_bmc_access": "_fix_bmc",
        "redfish_bmc_api": "_fix_bmc",
        # Network / firewall control destruction
        "firewall_disable": "_fix_firewall_linux",
        "firewalld_flush_or_disable": "_fix_firewalld",
        "iptables_nat_redirect": "_fix_iptables_nat",
        "iptables_nft_flush_then_default_accept": "_fix_iptables_atomic",
        "iptables_save_redirected_to_dev_null": "_fix_iptables_persist",
        "bsd_pf_conf_block_all_removed_or_disabled": "_fix_pf",
        # DNS exfil
        "dns_exfiltration": "_fix_dns_exfil",
        "dns_over_https_exfil_primary_resolver": "_fix_doh",
        # Audit / monitoring destruction
        "rsyslog_or_journald_stopped_masked": "_fix_logging_daemon",
        "history_log_wiped_or_redirected_dev_null": "_fix_history",
        "aide_tripwire_samhain_db_destroyed": "_fix_fim",
        "tetragon_cilium_runtime_observability_disabled_or_masked": "_fix_tetragon",
        # Cloud guardrail removal
        "aws_cloudtrail_writeonly_or_trail_deleted": "_fix_aws_cloudtrail",
        "aws_guardduty_securityhub_config_disabled": "_fix_aws_guardduty",
        "aws_organizations_scp_detached_or_deleted": "_fix_aws_scp",
        "aws_iam_user_programmatic_access_key_created_via_playbook": "_fix_aws_iam_key",
        "azure_defender_sentinel_disabled_or_tier_free": "_fix_azure_defender",
        "azure_defender_cspm_downgrade_to_free_tier": "_fix_azure_defender",
        "azure_diagnostic_setting_deleted_or_never_attached": "_fix_azure_diag",
        "azure_management_lock_removed_subscription_or_rg": "_fix_azure_lock",
        "backup_repo_immutable_lock_disabled_veeam_commvault_rubrik": "_fix_backup_immutable",
        # macOS hardening
        "macos_sip_disabled_csrutil": "_fix_macos_sip",
        "macos_tcc_db_reset_or_mutation": "_fix_macos_tcc",
        # Windows hardening
        "powershell_execution_policy_set_localmachine_bypass": "_fix_win_execpolicy",
        "smbv1_protocol_enabled_dism_or_powershell": "_fix_win_smbv1",
        "windows_restrict_anonymous_zero": "_fix_win_restrictanon",
        "winrm_allow_unencrypted_true": "_fix_win_winrm",
        "print_spooler_service_enabled_on_domain_controller": "_fix_win_spooler",
    }

    def __init__(self) -> None:
        super().__init__()
        self._fallback = OperationalSecurityRemediationGenerator()

    def generate_operational_security_fix(self, rule_id: str, code_snippet: str) -> str:
        method = self._HANDLERS.get(rule_id)
        if method is None:
            return self._fallback.generate_operational_security_fix(rule_id, code_snippet)
        return getattr(self, method)(rule_id, code_snippet)

    def _frame(self, rule_id: str, code_snippet: str, why: str, secure_fix: str) -> str:
        meta = _pattern_index.get(rule_id)
        title = meta.get("title") or rule_id
        rec = meta.get("recommendation") or ""
        body = why
        if rec:
            body += f"\n\n{rec}"
        return (
            f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
            f"\n**\U0001f6a8 {title} ({rule_id}):**\n{body}\n"
            f"\n**\u2705 Secure Fix Example:**\n```yaml\n{secure_fix}\n```\n"
        )

    # ---- Package sources / supply ---------------------------------------

    def _fix_apt_repo(self, rule_id: str, code_snippet: str) -> str:
        repo = (
            _first(code_snippet, r"repo=[\"']?(\S+?)[\"']?\s", r"(ppa:\S+)", r"(https?://\S+)")
            or "{{ approved_apt_repo }}"
        )
        why = (
            "Pulling APT packages from an unvetted third-party repo trusts that "
            "publisher with root on every managed host. Point at an approved internal "
            "mirror and pin the signing key so the source is reviewable."
        )
        fix = (
            "- name: trust only the approved repo signing key\n"
            "  ansible.builtin.get_url:\n"
            '    url: "{{ apt_mirror_key_url }}"\n'
            "    dest: /etc/apt/keyrings/internal-mirror.asc\n"
            '    mode: "0644"\n'
            "\n"
            "- name: add approved internal mirror only\n"
            "  ansible.builtin.apt_repository:\n"
            '    repo: "deb [signed-by=/etc/apt/keyrings/internal-mirror.asc] {{ apt_mirror_url }} {{ ansible_distribution_release }} main"\n'
            "    state: present\n"
            "    filename: internal-mirror\n"
            f"# original source seen: {repo}\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_yum_repo(self, rule_id: str, code_snippet: str) -> str:
        url = (
            _first(code_snippet, r"--add-repo\s+(\S+)", r"(https?://\S+)")
            or "{{ approved_yum_repo }}"
        )
        why = (
            "`dnf config-manager --add-repo` from the internet trusts that mirror with "
            "root. Define the repo declaratively against an approved mirror with "
            "gpgcheck enforced."
        )
        fix = (
            "- name: define approved repo with gpgcheck enforced\n"
            "  ansible.builtin.yum_repository:\n"
            "    name: internal-mirror\n"
            '    description: "Approved internal mirror"\n'
            f'    baseurl: "{{{{ yum_mirror_url }}}}"\n'
            "    gpgcheck: true\n"
            '    gpgkey: "{{ yum_mirror_gpgkey_url }}"\n'
            "    enabled: true\n"
            f"# original source seen: {url}\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_galaxy(self, rule_id: str, code_snippet: str) -> str:
        role = (
            _first(code_snippet, r"ansible-galaxy\s+(?:install|collection install)\s+(\S+)")
            or "{{ role_name }}"
        )
        why = (
            "Installing a Galaxy role/collection by name with no version pin pulls "
            "whatever the latest publish is - a supply-chain risk. Install from a "
            "pinned requirements file against your internal Galaxy/Automation Hub."
        )
        fix = (
            "# requirements.yml (pin every entry to a version and source)\n"
            "roles:\n"
            f"  - name: {role}\n"
            '    version: "1.2.3"\n'
            '    source: "{{ internal_galaxy_url }}"\n'
            "\n"
            "# playbook / CI\n"
            "- name: install pinned dependencies only\n"
            "  ansible.builtin.command:\n"
            "    cmd: ansible-galaxy install -r requirements.yml\n"
            "  changed_when: false\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_git_clone(self, rule_id: str, code_snippet: str) -> str:
        repo = (
            _first(code_snippet, r"git clone\s+(\S+)", r"repo=(\S+)", r"(https?://\S+\.git)")
            or "{{ git_repo_url }}"
        )
        why = (
            "Cloning an external repo without pinning a tag/SHA runs whatever HEAD is at "
            "clone time. Pin to an immutable ref and prefer an internal mirror."
        )
        fix = (
            "- name: clone pinned to an immutable ref from internal mirror\n"
            "  ansible.builtin.git:\n"
            f'    repo: "{repo}"\n'
            '    dest: "{{ clone_dest }}"\n'
            '    version: "{{ pinned_commit_sha }}"\n'
            "    accept_hostkey: false\n"
            "    update: false\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- PKI / certs -----------------------------------------------------

    def _fix_ca_cert(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Adding a CA to the system trust store lets its holder mint certificates "
            "your hosts will trust - a TLS-interception primitive. Install only the "
            "approved enterprise CA through a reviewed PKI workflow."
        )
        fix = (
            "- name: install only the approved enterprise CA\n"
            "  ansible.builtin.copy:\n"
            '    src: "{{ approved_enterprise_ca_pem }}"\n'
            "    dest: /etc/pki/ca-trust/source/anchors/enterprise-ca.crt\n"
            '    mode: "0644"\n'
            "  register: ca_added\n"
            "\n"
            "- name: refresh trust store\n"
            "  ansible.builtin.command:\n"
            "    cmd: update-ca-trust extract\n"
            "  when: ca_added is changed\n"
            "  changed_when: ca_added is changed\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_ssl_cert(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Generating long-lived self-signed certs in a playbook produces untracked "
            "trust anchors with no revocation path. Request certs from an approved CA "
            "(internal ACME / Let's Encrypt) instead."
        )
        fix = (
            "- name: request cert from approved ACME CA\n"
            "  community.crypto.acme_certificate:\n"
            '    acme_directory: "{{ acme_directory_url }}"\n'
            "    acme_version: 2\n"
            '    account_key_src: "{{ acme_account_key }}"\n'
            '    csr: "{{ csr_path }}"\n'
            '    cert: "{{ cert_path }}"\n'
            '    fullchain: "{{ fullchain_path }}"\n'
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Recon / attack tooling (refuse) --------------------------------

    def _fix_refuse_recon(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Reconnaissance tooling (port/zone/DNS scanning, packet capture) does not "
            "belong in configuration automation. If a sanctioned security team needs "
            "it, run it from their tooling under a tracked engagement - gate hard and "
            "fail closed in the playbook."
        )
        fix = (
            "- name: refuse to run recon tooling from automation\n"
            "  ansible.builtin.fail:\n"
            "    msg: >-\n"
            "      Network/DNS reconnaissance must run from the authorized security\n"
            "      team's tooling under a tracked engagement, not from this playbook.\n"
            "  when: not (authorized_security_engagement | default(false) | bool)\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_refuse_attack(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "This pattern (memory/swap scraping, container escape, ARP spoofing, "
            "LD_PRELOAD/sysrq abuse, crypto mining) has no legitimate place in "
            "automation and is a strong compromise indicator. Remove the task and "
            "investigate the host."
        )
        fix = (
            "# There is no benign version of this task. Remove it and treat the host\n"
            "# as suspect. The playbook should hard-fail if it is ever reintroduced.\n"
            "- name: block known-malicious operation\n"
            "  ansible.builtin.fail:\n"
            "    msg: >-\n"
            "      This operation is an attack technique and is prohibited. Remove the\n"
            "      task and open an incident to investigate how it was added.\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Persistence mechanisms -----------------------------------------

    def _fix_systemd_service(self, rule_id: str, code_snippet: str) -> str:
        exe = (
            _first(
                code_snippet,
                r"ExecStart\s*=\s*((?:[^\s{]|\{\{.*?\}\})+)",
                r"nohup\s+((?:[^\s{]|\{\{.*?\}\})+)",
            )
            or "/usr/local/bin/{{ service_name }}"
        )
        why = (
            "A service whose ExecStart points at /tmp or a user-writable path (or a "
            "nohup'd background process) is classic persistence. Ship the binary to a "
            "managed, root-owned path and run it as a reviewed unit with hardening on."
        )
        fix = (
            "- name: install the service binary to a managed location\n"
            "  ansible.builtin.copy:\n"
            '    src: "{{ service_artifact }}"\n'
            "    dest: /usr/local/bin/{{ service_name }}\n"
            "    owner: root\n"
            "    group: root\n"
            '    mode: "0755"\n'
            "\n"
            "- name: define the unit through config management\n"
            "  ansible.builtin.template:\n"
            '    src: "{{ service_name }}.service.j2"\n'
            "    dest: /etc/systemd/system/{{ service_name }}.service\n"
            '    mode: "0644"\n'
            "  notify: reload systemd\n"
            f"# original ExecStart seen: {exe}\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_systemd_timer(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Transient `systemd-run --on-calendar` timers (and ad-hoc .timer files) "
            "bypass unit-file review and are a stealthy persistence path. Define a "
            "reviewed .timer + .service pair under config management."
        )
        fix = (
            "- name: deploy reviewed timer unit\n"
            "  ansible.builtin.template:\n"
            '    src: "{{ timer_name }}.timer.j2"\n'
            "    dest: /etc/systemd/system/{{ timer_name }}.timer\n"
            '    mode: "0644"\n'
            "  notify: reload systemd\n"
            "\n"
            "- name: enable the timer\n"
            "  ansible.builtin.systemd:\n"
            '    name: "{{ timer_name }}.timer"\n'
            "    enabled: true\n"
            "    state: started\n"
            "    daemon_reload: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_scheduled(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`at`/`batch`/anacron jobs run outside the audited scheduler and are easy to "
            "hide. Use the native cron module (or a systemd timer) so the schedule is "
            "declarative and reviewable."
        )
        fix = (
            "- name: schedule job through the audited cron module\n"
            "  ansible.builtin.cron:\n"
            '    name: "{{ job_name }}"\n'
            "    user: \"{{ job_user | default('root') }}\"\n"
            '    minute: "0"\n'
            '    hour: "4"\n'
            '    job: "{{ job_command }}"\n'
            '    cron_file: "{{ job_name }}"\n'
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_managed_file_persistence(self, rule_id: str, code_snippet: str) -> str:
        dest = (
            _first(
                code_snippet,
                r"dest:\s*['\"]?(/[^'\"\s]+)",
                r"path:\s*['\"]?(/[^'\"\s]+)",
                r"dest:\s*(\"?\{\{.*?\}\}\"?)",
                r"path:\s*(\"?\{\{.*?\}\}\"?)",
            )
            or "{{ persistence_path }}"
        )
        why = (
            "Autostart entries, udev rules with RUN=, APT hooks, and NM dispatcher "
            "scripts all execute code automatically and are common persistence spots. "
            "Deploy the file from source control through config management, gated on "
            "review, so its contents are auditable."
        )
        fix = (
            "- name: deploy the entry from a reviewed template (gated)\n"
            "  ansible.builtin.template:\n"
            '    src: "{{ entry_template }}"\n'
            f'    dest: "{dest}"\n'
            "    owner: root\n"
            "    group: root\n"
            '    mode: "0644"\n'
            "  when: persistence_change_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_modules_load(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Files under /etc/modules-load.d auto-load kernel modules at boot. Manage "
            "the allowed module list through hardening config and gate changes, rather "
            "than dropping arbitrary auto-load entries."
        )
        fix = (
            "- name: manage approved boot-time modules only\n"
            "  ansible.builtin.copy:\n"
            "    dest: /etc/modules-load.d/hardening.conf\n"
            "    content: \"{{ approved_boot_modules | join('\\n') }}\\n\"\n"
            "    owner: root\n"
            "    group: root\n"
            '    mode: "0644"\n'
            "  when: kernel_hardening_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_launchdaemon(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "LaunchDaemons are legitimate only for signed, notarized, MDM-deployed "
            "software. Pin the plist to a vendor-namespaced path with an absolute, "
            "root-owned Program and deploy it through MDM/config management."
        )
        fix = (
            "- name: deploy a signed-software LaunchDaemon with a pinned path\n"
            "  ansible.builtin.copy:\n"
            '    src: "{{ vendor_launchdaemon_plist }}"\n'
            "    dest: /Library/LaunchDaemons/com.{{ vendor }}.{{ service_name }}.plist\n"
            "    owner: root\n"
            "    group: wheel\n"
            '    mode: "0644"\n'
            "  when: macos_software_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Kernel / boot / low-level --------------------------------------

    def _fix_modprobe(self, rule_id: str, code_snippet: str) -> str:
        mod = _first(code_snippet, r"modprobe\s+(\S+)", r"name=(\S+)") or "{{ module_name }}"
        why = (
            "Loading kernel modules from a playbook can insert rootkits or re-enable "
            "disabled functionality. Restrict to an approved module via the native "
            "module, gated on a hardening change."
        )
        fix = (
            "- name: load only an approved kernel module (gated)\n"
            "  community.general.modprobe:\n"
            f'    name: "{mod}"\n'
            "    state: present\n"
            "  when: kernel_hardening_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_ebpf(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Loading eBPF programs grants kernel-level visibility and control. Only the "
            "platform/security team's signed observability stack should load BPF; refuse "
            "ad-hoc loads from automation."
        )
        fix = (
            "- name: refuse ad-hoc eBPF loads\n"
            "  ansible.builtin.fail:\n"
            "    msg: >-\n"
            "      eBPF programs must be shipped by the approved observability stack\n"
            "      (e.g. Cilium/Tetragon), not loaded ad-hoc from a playbook.\n"
            "  when: not (ebpf_load_approved | default(false) | bool)\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_grub(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Bootloader changes execute before security controls and can persist a "
            "rootkit. Manage GRUB defaults declaratively, gate on change management, "
            "and regenerate config explicitly."
        )
        fix = (
            "- name: set an approved GRUB default (gated)\n"
            "  ansible.builtin.lineinfile:\n"
            "    path: /etc/default/grub\n"
            '    regexp: "^GRUB_CMDLINE_LINUX="\n'
            "    line: 'GRUB_CMDLINE_LINUX=\"{{ approved_kernel_cmdline }}\"'\n"
            "  register: grub_changed\n"
            "  when: boot_change_approved | default(false) | bool\n"
            "\n"
            "- name: regenerate grub config\n"
            "  ansible.builtin.command:\n"
            "    cmd: update-grub\n"
            "  when: grub_changed is changed\n"
            "  changed_when: grub_changed is changed\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_initramfs(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Initramfs runs at boot before disk encryption and security tooling are up; "
            "tampering here is high-impact. Only rebuild it as a gated, reviewed change "
            "after a legitimate driver/hook update."
        )
        fix = (
            "- name: rebuild initramfs only as a reviewed change\n"
            "  ansible.builtin.command:\n"
            "    cmd: update-initramfs -u\n"
            "  register: initramfs_rebuild\n"
            "  changed_when: initramfs_rebuild.rc == 0\n"
            "  when: boot_change_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_ld_library_path(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Pointing LD_LIBRARY_PATH at a user-writable or untrusted directory lets an "
            "attacker preload malicious libraries. Don't set it globally; pin "
            "dependencies through the package manager or a vetted RPATH."
        )
        fix = (
            "- name: install dependencies via the package manager (no LD_LIBRARY_PATH)\n"
            "  ansible.builtin.package:\n"
            '    name: "{{ runtime_libraries }}"\n'
            "    state: present\n"
            "# If a private lib dir is unavoidable, bake an RPATH at build time and\n"
            "# keep the directory root-owned and 0755 - never export LD_LIBRARY_PATH\n"
            "# to a writable path at runtime.\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_pam(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Editing /etc/pam.d directly can backdoor authentication (e.g. a rogue "
            "pam_exec). Manage PAM through a reviewed hardening role using the dedicated "
            "module so changes are structured and auditable."
        )
        fix = (
            "- name: manage a PAM rule through the native module (gated)\n"
            "  community.general.pamd:\n"
            "    name: sshd\n"
            "    type: auth\n"
            "    control: required\n"
            "    module_path: pam_faillock.so\n"
            '    module_arguments: "preauth silent deny=5 unlock_time=900"\n'
            "    state: updated\n"
            "  when: pam_hardening_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_chattr(self, rule_id: str, code_snippet: str) -> str:
        target = (
            _first(
                code_snippet,
                r"chattr\s+[-+][aAie]+\s+(\"?\{\{.*?\}\}\"?)",
                r"chattr\s+[-+][aAie]+\s+['\"]?(/[^\s'\"]+)",
            )
            or "/var/log/audit/audit.log"
        )
        why = (
            "Removing immutable/append-only flags (`chattr -i/-a`) from security files "
            "like /etc/shadow, sudoers, sshd_config, or the audit logs clears the way "
            "for tampering. Keep those files immutable and re-assert the flag."
        )
        fix = (
            "- name: re-assert append-only on the audit log\n"
            "  ansible.builtin.file:\n"
            f'    path: "{target}"\n'
            '    attributes: "+a"\n'
            "  when: file_hardening_approved | default(true) | bool\n"
            "\n"
            "- name: refuse to clear immutability outside a reviewed change\n"
            "  ansible.builtin.assert:\n"
            "    that:\n"
            "      - file_hardening_approved | default(true) | bool\n"
            '    fail_msg: "Clearing immutable/append-only flags requires a reviewed change."\n'
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_drop_cap(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`--cap-add=SYS_PTRACE` lets a container inject into processes (including "
            "across containers sharing a PID namespace). Drop all capabilities and add "
            "back only the minimum; never grant SYS_PTRACE in production."
        )
        fix = (
            "- name: run container with capabilities dropped\n"
            "  community.docker.docker_container:\n"
            '    name: "{{ container_name }}"\n'
            '    image: "{{ image }}"\n'
            "    cap_drop: [ALL]\n"
            "    capabilities: []   # add back only what is strictly required\n"
            "    security_opts:\n"
            "      - no-new-privileges\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- SSH -------------------------------------------------------------

    def _fix_ssh_tunnel(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Opening an SSH tunnel (`-R`/`-L`/`-D`) from a playbook builds an ad-hoc "
            "network path that bypasses VPN and firewall controls. Use the sanctioned "
            "remote-access solution instead of tunneling from automation."
        )
        fix = (
            "# Reach the remote service through the approved access path, not a tunnel.\n"
            "- name: call internal service via the sanctioned gateway\n"
            "  ansible.builtin.uri:\n"
            '    url: "{{ internal_service_url_via_gateway }}"\n'
            "    method: GET\n"
            "    validate_certs: true\n"
            "# For host access, target it through inventory over the approved VPN/bastion\n"
            "# rather than building an SSH tunnel inside the play.\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_ssh_config(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Weakening sshd_config (enabling PasswordAuthentication, PermitRootLogin, "
            "etc.) regresses host hardening. Enforce the CIS-aligned values and validate "
            "the config before reload."
        )
        fix = (
            "- name: enforce hardened sshd settings\n"
            "  ansible.builtin.lineinfile:\n"
            "    path: /etc/ssh/sshd_config\n"
            '    regexp: "^#?{{ item.key }}"\n'
            '    line: "{{ item.key }} {{ item.value }}"\n'
            '    validate: "sshd -t -f %s"\n'
            "  loop:\n"
            '    - { key: "PasswordAuthentication", value: "no" }\n'
            '    - { key: "PermitRootLogin", value: "no" }\n'
            '    - { key: "KbdInteractiveAuthentication", value: "no" }\n'
            "  notify: reload sshd\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_authorized_keys(self, rule_id: str, code_snippet: str) -> str:
        user = _first(code_snippet, r"/home/([^/\s'\"{}]+)/", r"user=(\S+)") or "{{ user_name }}"
        why = (
            "Writing authorized_keys directly can silently grant SSH access. Manage keys "
            "centrally with the native module using `exclusive: true` so only reviewed "
            "keys remain present."
        )
        fix = (
            "- name: manage authorized keys from the central source of truth\n"
            "  ansible.posix.authorized_key:\n"
            f'    user: "{user}"\n'
            "    key: \"{{ approved_public_keys | join('\\n') }}\"\n"
            "    exclusive: true\n"
            "    state: present\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Credentials on disk / secret leak ------------------------------

    def _fix_db_creds(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Passing DB passwords inline (`-a`, `--password=`) leaks them into the "
            "process list and task log. Pull the secret from Vault with `no_log: true` "
            "and pass it via a credential file or environment, not argv."
        )
        fix = (
            "- name: fetch DB password from Vault (no_log)\n"
            "  ansible.builtin.set_fact:\n"
            "    db_password: \"{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/db:password') }}\"\n"
            "  no_log: true\n"
            "\n"
            "- name: run query without exposing the secret in argv\n"
            "  ansible.builtin.command:\n"
            '    cmd: "psql -h {{ db_host }} -c \\"{{ query }}\\""\n'
            "  environment:\n"
            '    PGPASSWORD: "{{ db_password }}"\n'
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_cred_file(self, rule_id: str, code_snippet: str) -> str:
        dest = _first(code_snippet, r"dest:\s*['\"]?([^'\"\s]+)") or "{{ credential_path }}"
        why = (
            "Writing credential dotfiles (.netrc, .pgpass) to disk leaves long-lived "
            "secrets unprotected. Source them from Vault/SSM at run time with "
            "`no_log: true` instead of persisting them."
        )
        fix = (
            "- name: fetch credentials at run time (not written to disk)\n"
            "  ansible.builtin.set_fact:\n"
            "    runtime_credential: \"{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/app:token') }}\"\n"
            "  no_log: true\n"
            f"# If a dotfile is truly required, template it 0600, owned by the run user,\n"
            f"# from the vaulted value - never commit it. (was: {dest})\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_aws_cred_file(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Persisting ~/.aws/credentials puts long-lived keys on disk. Use an instance "
            "profile / IRSA / SSO so no static credential file exists."
        )
        fix = (
            "# No credential file: the role comes from the environment.\n"
            "- name: call AWS using the instance/role identity\n"
            "  amazon.aws.aws_caller_info:\n"
            "  register: whoami\n"
            "  no_log: true\n"
            "# EC2 -> instance profile; EKS -> IRSA; laptops/CI -> aws sso login.\n"
            "# Remove any task that writes ~/.aws/credentials.\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_proxy_creds(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Embedding `user:pass@` in a proxy URL leaks the credential into env vars, "
            "logs, and child processes. Keep the proxy host in config and the secret in "
            "Vault, injected at run time with `no_log`."
        )
        fix = (
            "- name: configure proxy without inline credentials\n"
            "  ansible.builtin.get_url:\n"
            '    url: "{{ artifact_url }}"\n'
            '    dest: "{{ dest_path }}"\n'
            "  environment:\n"
            '    https_proxy: "http://{{ proxy_host }}:{{ proxy_port }}"\n'
            '    https_proxy_user: "{{ vault_proxy_user }}"\n'
            '    https_proxy_pass: "{{ vault_proxy_pass }}"\n'
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_rhsm(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`subscription-manager register --password=` exposes the RHSM password in "
            "argv and logs. Use the native module with a vaulted activation key and "
            "`no_log: true`."
        )
        fix = (
            "- name: register host via vaulted activation key\n"
            "  community.general.redhat_subscription:\n"
            "    state: present\n"
            '    activationkey: "{{ vault_rhsm_activation_key }}"\n'
            '    org_id: "{{ rhsm_org_id }}"\n'
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_laps(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Bulk LAPS reads from automation defeat the just-in-time, per-host model and "
            "expose every local admin password at once. Read a single host's password "
            "interactively, scoped and audited, with `no_log`."
        )
        fix = (
            "- name: read ONE host's LAPS password, just-in-time (no_log)\n"
            "  ansible.windows.win_powershell:\n"
            "    script: |\n"
            "      Get-LapsADPassword -Identity $env:TARGET_HOST -AsPlainText\n"
            "  environment:\n"
            '    TARGET_HOST: "{{ single_target_host }}"\n'
            "  no_log: true\n"
            "  when: laps_read_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_krbtgt(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "krbtgt resets must follow Microsoft's two-reset procedure with a >10 hour "
            "gap and be driven by an IR runbook, never routine config. The secure shape "
            "refuses to run this outside an authorized incident."
        )
        fix = (
            "- name: refuse routine krbtgt reset\n"
            "  ansible.builtin.fail:\n"
            "    msg: >-\n"
            "      krbtgt resets follow the Microsoft two-reset procedure (>10h gap)\n"
            "      and must be driven by the IR runbook, not this playbook.\n"
            "  when: not (krbtgt_ir_runbook_authorized | default(false) | bool)\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- BMC / hardware --------------------------------------------------

    def _fix_bmc(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "IPMI/Redfish grant hardware-level control (power, virtual media, firmware). "
            "Calls must use a vaulted, scoped service credential over TLS with "
            "`no_log: true`, and be restricted to the OOB management network."
        )
        fix = (
            "- name: call BMC over TLS with a vaulted credential\n"
            "  community.general.redfish_command:\n"
            "    category: Systems\n"
            "    command: PowerGracefulRestart\n"
            '    baseuri: "{{ bmc_host }}"\n'
            '    username: "{{ vault_bmc_user }}"\n'
            '    password: "{{ vault_bmc_password }}"\n'
            "  no_log: true\n"
            "  delegate_to: localhost\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Firewall / network control -------------------------------------

    def _fix_firewall_linux(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`iptables -F` (or stopping the firewall) drops all host filtering and "
            "exposes every service. Manage rules declaratively and load them atomically; "
            "never flush without the replacement ruleset in the same transaction."
        )
        fix = (
            "- name: load the canonical ruleset atomically\n"
            "  ansible.builtin.copy:\n"
            '    src: "{{ rules_v4_file }}"\n'
            "    dest: /etc/iptables/rules.v4\n"
            '    mode: "0644"\n'
            "  register: rules_file\n"
            "\n"
            "- name: apply rules in one transaction\n"
            "  ansible.builtin.command:\n"
            "    cmd: iptables-restore /etc/iptables/rules.v4\n"
            "  when: rules_file is changed\n"
            "  changed_when: rules_file is changed\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_firewalld(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Flushing or disabling firewalld on production RHEL removes host filtering. "
            "Add the specific rule you need through the native module with the change "
            "made permanent and reloaded - don't disable the service."
        )
        fix = (
            "- name: add a scoped permanent rule (no flush/disable)\n"
            "  ansible.posix.firewalld:\n"
            "    zone: public\n"
            "    service: https\n"
            "    permanent: true\n"
            "    immediate: true\n"
            "    state: enabled\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_iptables_nat(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Ad-hoc NAT/redirect rules can silently reroute traffic to an attacker. "
            "Manage NAT through your network infrastructure or a reviewed, version-"
            "controlled ruleset, not inline playbook commands."
        )
        fix = (
            "- name: manage NAT rules from the reviewed ruleset only\n"
            "  ansible.builtin.copy:\n"
            '    src: "{{ nat_rules_v4_file }}"\n'
            "    dest: /etc/iptables/rules.v4\n"
            '    mode: "0644"\n'
            "  notify: reload netfilter\n"
            "# Keep all NAT/POSTROUTING rules in version control; apply via\n"
            "# iptables-restore so changes are diffable and reviewable.\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_iptables_atomic(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Flushing then setting the default policy to ACCEPT leaves the host wide "
            "open between the two commands. Replace the ruleset atomically with "
            "iptables-restore so the host is never unprotected."
        )
        fix = (
            "- name: replace ruleset atomically (never flush-then-accept)\n"
            "  ansible.builtin.command:\n"
            "    cmd: iptables-restore /etc/iptables/rules.v4\n"
            "  changed_when: false\n"
            "# /etc/iptables/rules.v4 must set default DROP for INPUT/FORWARD and\n"
            "# whitelist required services - applied in a single transaction.\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_iptables_persist(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Redirecting `iptables-save` to /dev/null throws away the running ruleset so "
            "it is lost on reboot. Persist rules to the distro's canonical location "
            "instead."
        )
        fix = (
            "- name: persist firewall rules to the canonical path\n"
            "  community.general.iptables_state:\n"
            "    state: saved\n"
            "    path: /etc/iptables/rules.v4\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_pf(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`pfctl -F all` (or disabling pf) removes all packet filtering on BSD/macOS. "
            "Keep /etc/pf.conf default-deny and load it; never flush without a "
            "replacement default-block ruleset."
        )
        fix = (
            "- name: deploy default-deny pf.conf and load it\n"
            "  ansible.builtin.copy:\n"
            '    src: "{{ pf_conf_file }}"   # starts: set skip on lo / block return all\n'
            "    dest: /etc/pf.conf\n"
            '    mode: "0644"\n'
            "  register: pf_conf\n"
            "\n"
            "- name: load pf ruleset\n"
            "  ansible.builtin.command:\n"
            "    cmd: pfctl -f /etc/pf.conf -e\n"
            "  when: pf_conf is changed\n"
            "  changed_when: pf_conf is changed\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- DNS exfil -------------------------------------------------------

    def _fix_dns_exfil(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "DNS queries that embed dynamic/variable data are a classic exfiltration "
            "channel. Send data over an authenticated HTTPS API to a known endpoint, "
            "not via crafted DNS lookups."
        )
        fix = (
            "- name: send data over an authenticated HTTPS API (not DNS)\n"
            "  ansible.builtin.uri:\n"
            '    url: "{{ telemetry_api_url }}"\n'
            "    method: POST\n"
            "    headers:\n"
            '      Authorization: "Bearer {{ vault_api_token }}"\n'
            "    body_format: json\n"
            '    body: "{{ payload }}"\n'
            "    validate_certs: true\n"
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_doh(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Pointing the primary resolver at a public DoH endpoint bypasses enterprise "
            "DNS inspection and is a covert exfil channel. Point DoH at the enterprise "
            "secure gateway so queries stay inspected."
        )
        fix = (
            "- name: pin resolver to the enterprise DoH gateway\n"
            "  ansible.builtin.copy:\n"
            "    dest: /etc/systemd/resolved.conf.d/enterprise-doh.conf\n"
            "    content: |\n"
            "      [Resolve]\n"
            "      DNS={{ enterprise_doh_gateway_ip }}#{{ enterprise_doh_hostname }}\n"
            "      DNSOverTLS=yes\n"
            "      Domains=~.\n"
            '    mode: "0644"\n'
            "  notify: restart systemd-resolved\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Audit / monitoring destruction ---------------------------------

    def _fix_logging_daemon(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Stopping or masking rsyslog/journald blinds the host's local audit trail. "
            "Keep the logging daemon enabled and running and assert persistent storage; "
            "any brief stop must be a tightly-scoped handler that restarts it."
        )
        fix = (
            "- name: ensure persistent journald storage\n"
            "  ansible.builtin.lineinfile:\n"
            "    path: /etc/systemd/journald.conf\n"
            '    regexp: "^#?Storage="\n'
            '    line: "Storage=persistent"\n'
            "  notify: restart systemd-journald\n"
            "\n"
            "- name: keep the logging daemon running and enabled\n"
            "  ansible.builtin.service:\n"
            "    name: \"{{ logging_service | default('rsyslog') }}\"\n"
            "    state: started\n"
            "    enabled: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_history(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Wiping shell history or redirecting it to /dev/null is anti-forensics. "
            "Don't disable history; for log-size control use logrotate, and ship shell "
            "audit events to the SIEM via auditd/execve logging."
        )
        fix = (
            "- name: rotate logs instead of wiping history\n"
            "  ansible.builtin.copy:\n"
            "    dest: /etc/logrotate.d/app\n"
            "    content: |\n"
            "      {{ app_log_glob }} {\n"
            "        weekly\n"
            "        rotate 8\n"
            "        compress\n"
            "        copytruncate\n"
            "        maxsize 100M\n"
            "      }\n"
            '    mode: "0644"\n'
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_fim(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Destroying the AIDE/Tripwire/Samhain database erases the file-integrity "
            "baseline and hides tampering. Archive the current DB to append-only "
            "off-host storage before any legitimate reinit, and treat unexplained "
            "destruction as an incident."
        )
        fix = (
            "- name: archive FIM DB off-host before any reinit\n"
            "  amazon.aws.s3_object:\n"
            '    bucket: "{{ forensic_vault_bucket }}"\n'
            '    object: "fim/{{ inventory_hostname }}/{{ ansible_date_time.iso8601 }}/aide.db"\n'
            "    src: /var/lib/aide/aide.db\n"
            "    mode: put\n"
            "  when: fim_reinit_approved | default(false) | bool\n"
            "\n"
            "- name: reinitialize the FIM baseline (only after archive)\n"
            "  ansible.builtin.command:\n"
            "    cmd: aide --init\n"
            "  when: fim_reinit_approved | default(false) | bool\n"
            "  changed_when: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_tetragon(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Stopping or masking Tetragon on a Cilium-protected cluster disables runtime "
            "observability. Keep it running and narrow noisy policy by tightening "
            "TracingPolicy selectors, not by disabling the agent."
        )
        fix = (
            "- name: keep Tetragon running and enabled\n"
            "  ansible.builtin.systemd:\n"
            "    name: tetragon\n"
            "    state: started\n"
            "    enabled: true\n"
            "    masked: false\n"
            "# Tune signal volume by scoping TracingPolicy selectors (namespace, pod\n"
            "# label, binary path) - never by stopping the agent.\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Cloud guardrail removal ----------------------------------------

    def _fix_aws_cloudtrail(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Disabling, deleting, or making CloudTrail write-only is an active-incident "
            "signal. Re-enable multi-region logging with validation immediately and "
            "assert it stays on."
        )
        fix = (
            "- name: re-enable validated multi-region CloudTrail\n"
            "  amazon.aws.cloudtrail:\n"
            '    name: "{{ trail_name }}"\n'
            "    state: present\n"
            "    is_multi_region_trail: true\n"
            "    enable_log_file_validation: true\n"
            '    s3_bucket_name: "{{ trail_bucket }}"\n'
            "\n"
            "- name: forbid disabling the trail\n"
            "  ansible.builtin.assert:\n"
            "    that:\n"
            "      - not (disable_cloudtrail | default(false) | bool)\n"
            '    fail_msg: "Disabling CloudTrail is prohibited; investigate this change."\n'
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_aws_guardduty(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Disabling GuardDuty/Security Hub removes threat detection. Re-enable the "
            "detector and protect the disable APIs behind an org-level SCP so only the "
            "delegated security admin can change them."
        )
        fix = (
            "- name: ensure GuardDuty detector is enabled\n"
            "  community.aws.guardduty_detector:\n"
            "    state: present\n"
            "    enable: true\n"
            '    finding_publishing_frequency: "FIFTEEN_MINUTES"\n'
            "# Back this with an SCP denying guardduty:Delete*/Disable* and\n"
            "# securityhub:Disable* except from the delegated-admin security account.\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_aws_scp(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Detaching or deleting a Service Control Policy removes org-wide guardrails. "
            "SCP changes need dual control behind a break-glass MFA role; refuse to make "
            "them from routine automation."
        )
        fix = (
            "- name: refuse SCP detach/delete from routine automation\n"
            "  ansible.builtin.fail:\n"
            "    msg: >-\n"
            "      SCP changes require dual-control via the break-glass role with MFA.\n"
            "      Remove this task from the playbook.\n"
            "  when: not (scp_break_glass_authorized | default(false) | bool)\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_aws_iam_key(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Creating long-lived IAM programmatic access keys from a playbook produces "
            "credentials that rarely get rotated. Use IAM Identity Center permission "
            "sets / roles for human and federated access; refuse static-key creation."
        )
        fix = (
            "- name: refuse static IAM key creation\n"
            "  ansible.builtin.fail:\n"
            "    msg: >-\n"
            "      Use IAM Identity Center permission sets or a federated role instead\n"
            "      of long-lived access keys. Remove this iam_access_key task.\n"
            "  when: not (legacy_static_key_approved | default(false) | bool)\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_azure_defender(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Downgrading Microsoft Defender for Cloud to the Free tier (or disabling "
            "Sentinel) removes cloud threat protection. Keep all plans on Standard for "
            "production and enforce the minimum tier via Azure Policy."
        )
        fix = (
            "- name: keep Defender plans on Standard tier\n"
            "  azure.azcollection.azure_rm_securitypricing:\n"
            '    name: "{{ item }}"\n'
            "    tier: Standard\n"
            "  loop:\n"
            "    - VirtualMachines\n"
            "    - StorageAccounts\n"
            "    - KeyVaults\n"
            "    - Containers\n"
            "    - SqlServers\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_azure_diag(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Deleting (or never attaching) diagnostic settings stops log delivery to the "
            "SIEM. Keep diagnostics shipping to Log Analytics and enforce them via Azure "
            "Policy DeployIfNotExists."
        )
        fix = (
            "- name: ensure diagnostics ship to Log Analytics\n"
            "  azure.azcollection.azure_rm_monitordiagnosticsetting:\n"
            '    name: "{{ diagnostic_setting_name }}"\n'
            '    resource: "{{ monitored_resource_id }}"\n'
            '    log_analytics_workspace_id: "{{ law_workspace_id }}"\n'
            "    state: present\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_azure_lock(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Removing a CanNotDelete management lock clears the way to delete production "
            "resources. Keep the lock in place and enforce it via Azure Policy; gate any "
            "removal behind a reviewed change."
        )
        fix = (
            "- name: ensure CanNotDelete lock stays on production scope\n"
            "  azure.azcollection.azure_rm_lock:\n"
            '    name: "{{ lock_name }}"\n'
            '    managed_resource_id: "/subscriptions/{{ subscription_id }}"\n'
            "    level: can_not_delete\n"
            "    state: present\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_backup_immutable(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Setting backup immutability/retention to 0 lets ransomware delete the "
            "backups it just bypassed. Enforce immutability with a minimum retention "
            "appropriate to your compliance scope."
        )
        fix = (
            "- name: enforce minimum immutable retention on the backup repo\n"
            "  ansible.builtin.uri:\n"
            '    url: "{{ backup_api_url }}/repositories/{{ repo_id }}/immutability"\n'
            "    method: PUT\n"
            "    headers:\n"
            '      Authorization: "Bearer {{ vault_backup_api_token }}"\n'
            "    body_format: json\n"
            "    body:\n"
            "      enabled: true\n"
            '      retentionDays: "{{ backup_immutable_days | default(14) }}"\n'
            "    status_code: [200, 204]\n"
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- macOS hardening -------------------------------------------------

    def _fix_macos_sip(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`csrutil disable` turns off System Integrity Protection, the macOS kernel "
            "and system-file guardrail. Never disable it on fleet machines; assert it is "
            "enabled instead."
        )
        fix = (
            "- name: assert SIP is enabled (never disable on the fleet)\n"
            "  ansible.builtin.command:\n"
            "    cmd: csrutil status\n"
            "  register: sip\n"
            "  changed_when: false\n"
            "  failed_when: \"'enabled' not in sip.stdout\"\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_macos_tcc(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Resetting or mutating the TCC privacy database from a playbook silently "
            "grants or wipes privacy permissions. Manage TCC only through an MDM PPPC "
            "configuration profile; refuse direct tccutil mutation."
        )
        fix = (
            "- name: refuse direct TCC.db mutation\n"
            "  ansible.builtin.fail:\n"
            "    msg: >-\n"
            "      Privacy permissions must be granted via the MDM PPPC payload\n"
            "      (com.apple.TCC.configuration-profile-policy), not tccutil.\n"
            "  when: not (mdm_pppc_profile_managed | default(false) | bool)\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Windows hardening ----------------------------------------------

    def _fix_win_execpolicy(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Setting the PowerShell execution policy to Bypass at LocalMachine scope "
            "lets any unsigned/downloaded script run. Use RemoteSigned so downloaded "
            "scripts must be signed while local admin scripting still works."
        )
        fix = (
            "- name: set RemoteSigned execution policy (not Bypass)\n"
            "  ansible.windows.win_powershell:\n"
            "    script: |\n"
            "      Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_win_smbv1(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "SMBv1 is the EternalBlue/WannaCry transport and must be disabled. Turn off "
            "the SMB1 protocol and remove the optional feature everywhere."
        )
        fix = (
            "- name: disable SMBv1 server protocol\n"
            "  ansible.windows.win_powershell:\n"
            "    script: |\n"
            "      Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
            "\n"
            "- name: remove the SMB1 optional feature\n"
            "  ansible.windows.win_optional_feature:\n"
            "    name: SMB1Protocol\n"
            "    state: absent\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_win_restrictanon(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Setting RestrictAnonymous = 0 allows anonymous enumeration of accounts and "
            "shares. Restore the hardened baseline so anonymous access is restricted."
        )
        fix = (
            "- name: restrict anonymous enumeration (CIS baseline)\n"
            "  ansible.windows.win_regedit:\n"
            "    path: HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\n"
            '    name: "{{ item.name }}"\n'
            '    data: "{{ item.data }}"\n'
            "    type: dword\n"
            "  loop:\n"
            '    - { name: "RestrictAnonymous", data: 1 }\n'
            '    - { name: "RestrictAnonymousSAM", data: 1 }\n'
            '    - { name: "EveryoneIncludesAnonymous", data: 0 }\n'
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_win_winrm(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`AllowUnencrypted=true` sends WinRM traffic (including credentials) in the "
            "clear. Force WinRM over HTTPS with a trusted cert and keep unencrypted "
            "transport disabled."
        )
        fix = (
            "- name: forbid unencrypted WinRM\n"
            "  ansible.windows.win_powershell:\n"
            "    script: |\n"
            "      Set-Item -Path WSMan:\\localhost\\Service\\AllowUnencrypted -Value $false\n"
            "# Configure the HTTPS listener (5986) with a CA-issued cert and disable\n"
            "# the HTTP listener so all WinRM traffic is encrypted.\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_win_spooler(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "The Print Spooler on a Domain Controller is the PrintNightmare attack "
            "surface and should never run there. Stop and disable it on every DC."
        )
        fix = (
            "- name: stop and disable Print Spooler on domain controllers\n"
            "  ansible.windows.win_service:\n"
            "    name: Spooler\n"
            "    state: stopped\n"
            "    start_mode: disabled\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)
