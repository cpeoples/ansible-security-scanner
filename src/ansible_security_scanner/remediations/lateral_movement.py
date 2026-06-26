#!/usr/bin/env python3
"""Lateral-movement remediation generator.

Every rule here flags a dual-use Ansible feature - delegation, dynamic
inventory, controller-local execution, interpreter/plugin/config overrides,
fact injection, role includes, vault-password handling, Windows service
installs, AD delegation writes. Each has a sanctioned idiom, so the fix
shows the safe shape for that exact feature with the value (host, path,
command, URL) pulled from the finding where one is present.
"""

from __future__ import annotations

from .base import BaseRemediationGenerator, _first, _render_from_metadata


class LateralMovementRemediationGenerator(BaseRemediationGenerator):
    """Render dynamic fixes for abused Ansible lateral-movement features."""

    def generate_lateral_movement_fix(self, rule_id: str, code_snippet: str) -> str:
        builder = {
            "add_host_dynamic": self._fix_add_host,
            "local_action_shell": self._fix_local_action,
            "connection_local_shell": self._fix_connection_local,
            "ansible_python_interpreter_override": self._fix_interpreter,
            "custom_callback_plugin": self._fix_callback_plugin,
            "custom_filter_plugin": self._fix_filter_plugin,
            "facts_d_injection": self._fix_facts_d,
            "wait_for_port_scan": self._fix_wait_for,
            "ansible_config_override": self._fix_config_override,
            "include_role_from_url": self._fix_include_role,
            "ansible_vault_password_env": self._fix_vault_password,
            "psexec_style_service_install": self._fix_service_install,
            "ad_constrained_delegation_modify": self._fix_ad_delegation,
        }.get(rule_id)
        if builder is None:
            return _render_from_metadata(rule_id, code_snippet)
        return builder(code_snippet)

    @staticmethod
    def _meta(rule_id: str) -> tuple[str, str]:
        from . import _pattern_index

        meta = _pattern_index.get(rule_id)
        return (meta.get("title") or rule_id), (meta.get("recommendation") or "")

    def _frame(self, rule_id: str, code_snippet: str, secure_fix: str) -> str:
        title, recommendation = self._meta(rule_id)
        why = f"This task uses {title.lower()}."
        if recommendation:
            why += f" {recommendation}"
        return (
            f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
            f"\n**\U0001f50d {title} ({rule_id}):**\n{why}\n"
            f"\n**\u2705 Secure Fix Example:**\n```yaml\n{secure_fix}\n```\n"
        )

    def _fix_add_host(self, code_snippet: str) -> str:
        name = (
            _first(code_snippet, r"(?:name|hostname):\s*['\"]?(\{\{[^}]*\}\})")
            or "{{ candidate_host }}"
        )
        secure_fix = (
            f"# Dynamic Host Injection via add_host - only add hosts that appear in a\n"
            f"# trusted, reviewed allow-list so an attacker cannot inject a target.\n"
            f"- name: Refuse hosts that are not on the approved inventory allow-list\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f'      - "{name} in approved_hosts"\n'
            f'    fail_msg: "{name} is not an approved target; refusing to add it."\n'
            f"\n"
            f"- name: Add the validated host\n"
            f"  ansible.builtin.add_host:\n"
            f'    name: "{name}"\n'
            f"    groups: dynamic\n"
            f"  # approved_hosts is an inventory-managed list, not user-supplied."
        )
        return self._frame("add_host_dynamic", code_snippet, secure_fix)

    def _fix_local_action(self, code_snippet: str) -> str:
        secure_fix = (
            "# local_action with Shell Execution runs on the controller, where CI/CD\n"
            "# secrets live. Replace ad-hoc shell with a named module delegated to\n"
            "# localhost, and only run it when explicitly reviewed.\n"
            "- name: Run the controller-side step through a dedicated module\n"
            "  ansible.builtin.command:\n"
            "    argv:\n"
            "      - /usr/bin/the-reviewed-tool\n"
            "      - --flag\n"
            "  delegate_to: localhost\n"
            "  run_once: true\n"
            "  # No secrets are interpolated into a shell string here."
        )
        return self._frame("local_action_shell", code_snippet, secure_fix)

    def _fix_connection_local(self, code_snippet: str) -> str:
        secure_fix = (
            "# connection: local with a shell module executes on the controller, not\n"
            "# the target - the textbook way to leak controller secrets. Target the\n"
            "# managed host explicitly and use a named module instead of raw shell.\n"
            "- name: Perform the work on the managed host with a module\n"
            "  ansible.builtin.command:\n"
            "    argv:\n"
            "      - /usr/bin/the-reviewed-tool\n"
            "  # Runs over the normal connection to the target, not connection: local."
        )
        return self._frame("connection_local_shell", code_snippet, secure_fix)

    def _fix_interpreter(self, code_snippet: str) -> str:
        secure_fix = (
            "# Python Interpreter Override pointing at a non-system path lets an\n"
            "# attacker substitute a malicious python. Pin to the system interpreter\n"
            "# (or 'auto'), never a user-writable location.\n"
            "- name: Use the system Python interpreter\n"
            "  ansible.builtin.set_fact:\n"
            "    ansible_python_interpreter: /usr/bin/python3\n"
            "  # Prefer 'auto' discovery; never /tmp, /home, or any world-writable path."
        )
        return self._frame("ansible_python_interpreter_override", code_snippet, secure_fix)

    def _fix_callback_plugin(self, code_snippet: str) -> str:
        secure_fix = (
            "# Custom Callback Plugin Registration runs arbitrary Python on every task\n"
            "# event. Load only audited callbacks shipped from a trusted collection,\n"
            "# from a path you control - never an attacker-writable directory.\n"
            "- name: Enable only reviewed callback plugins via ansible.cfg\n"
            "  ansible.builtin.copy:\n"
            "    src: files/ansible.cfg          # version-controlled, reviewed\n"
            "    dest: /etc/ansible/ansible.cfg\n"
            "    owner: root\n"
            "    group: root\n"
            "    mode: '0644'\n"
            "  # callbacks_enabled lists only vetted plugins (e.g. profile_tasks)."
        )
        return self._frame("custom_callback_plugin", code_snippet, secure_fix)

    def _fix_filter_plugin(self, code_snippet: str) -> str:
        secure_fix = (
            "# Custom Filter/Lookup Plugin Path allows arbitrary code execution during\n"
            "# templating. Ship filter/lookup plugins from an audited collection under\n"
            "# a root-owned path, not a runtime-derived or user-writable directory.\n"
            "- name: Install reviewed plugins to a root-owned location\n"
            "  ansible.builtin.copy:\n"
            "    src: filter_plugins/            # version-controlled, reviewed\n"
            "    dest: /usr/share/ansible/plugins/filter/\n"
            "    owner: root\n"
            "    group: root\n"
            "    mode: '0644'\n"
            "  # Never point filter_plugins/lookup_plugins at a {{ var }}-derived path."
        )
        return self._frame("custom_filter_plugin", code_snippet, secure_fix)

    def _fix_facts_d(self, code_snippet: str) -> str:
        secure_fix = (
            "# Custom facts.d Script Injection - scripts under /etc/ansible/facts.d run\n"
            "# automatically during fact gathering. Ship them from a reviewed source,\n"
            "# root-owned and not writable by anyone else.\n"
            "- name: Install a reviewed custom fact script, locked down\n"
            "  ansible.builtin.copy:\n"
            "    src: facts.d/app_info.fact      # version-controlled, reviewed\n"
            "    dest: /etc/ansible/facts.d/app_info.fact\n"
            "    owner: root\n"
            "    group: root\n"
            "    mode: '0755'                    # root-only write\n"
            "  # A non-root-writable facts.d script cannot be tampered with."
        )
        return self._frame("facts_d_injection", code_snippet, secure_fix)

    def _fix_wait_for(self, code_snippet: str) -> str:
        port = _first(code_snippet, r"port:\s*['\"]?(\{\{[^}]*\}\}|\d+)") or "{{ service_port }}"
        secure_fix = (
            f"# wait_for Used for Port Scanning - a short timeout sweeping many ports is\n"
            f"# reconnaissance. Use wait_for for a single, known service-readiness check\n"
            f"# against the host you are configuring, with a realistic timeout.\n"
            f"- name: Wait for the service this play manages to come up\n"
            f"  ansible.builtin.wait_for:\n"
            f'    host: "{{{{ inventory_hostname }}}}"\n'
            f"    port: {port}\n"
            f"    timeout: 60\n"
            f"  # One known port on the managed host - not a swept range of targets."
        )
        return self._frame("wait_for_port_scan", code_snippet, secure_fix)

    def _fix_config_override(self, code_snippet: str) -> str:
        secure_fix = (
            "# Ansible Configuration Override (ANSIBLE_CONFIG) can load a config that\n"
            "# disables security features or loads malicious plugins. Use the default,\n"
            "# reviewed ansible.cfg and do not redirect it at runtime.\n"
            "- name: Ensure the standard, reviewed ansible.cfg is in place\n"
            "  ansible.builtin.copy:\n"
            "    src: files/ansible.cfg          # version-controlled, reviewed\n"
            "    dest: /etc/ansible/ansible.cfg\n"
            "    owner: root\n"
            "    group: root\n"
            "    mode: '0644'\n"
            "  # Do not export ANSIBLE_CONFIG to a repo-local or temp path."
        )
        return self._frame("ansible_config_override", code_snippet, secure_fix)

    def _fix_include_role(self, code_snippet: str) -> str:
        url = _first(code_snippet, r"((?:https?://|git@|git://)\S+)") or "{{ role_source_url }}"
        secure_fix = (
            f"# Role Include from Untrusted Source - including a role straight from\n"
            f"# {url} runs unreviewed code. Pin roles in requirements.yml with a version,\n"
            f"# install them ahead of time, then include by name.\n"
            f"# requirements.yml (reviewed, version-locked):\n"
            f"#   roles:\n"
            f"#     - name: my_role\n"
            f"#       src: {url}\n"
            f"#       version: v1.4.2        # immutable tag or commit SHA\n"
            f"- name: Include the pre-installed, pinned role by name\n"
            f"  ansible.builtin.include_role:\n"
            f"    name: my_role\n"
            f"  # Installed via 'ansible-galaxy install -r requirements.yml' in CI."
        )
        return self._frame("include_role_from_url", code_snippet, secure_fix)

    def _fix_vault_password(self, code_snippet: str) -> str:
        secure_fix = (
            "# Vault Password via Environment Variable can be logged or leaked. Use a\n"
            "# vault-password file with restricted permissions (or a vault client\n"
            "# script), referenced by ansible.cfg - never an env var or /proc path.\n"
            "- name: Reference a locked-down vault password file\n"
            "  ansible.builtin.copy:\n"
            '    content: "{{ vault_passphrase }}"   # sourced from a secret store at run time\n'
            "    dest: /run/ansible/.vault_pass\n"
            "    owner: root\n"
            "    group: root\n"
            "    mode: '0600'\n"
            "  no_log: true\n"
            "  # Point vault_password_file at this 0600 file; remove it after the run."
        )
        return self._frame("ansible_vault_password_env", code_snippet, secure_fix)

    def _fix_service_install(self, code_snippet: str) -> str:
        src = (
            _first(
                code_snippet,
                r"(?:path|binary_path_name|image_path):\s*['\"]?(\\\\\S+|https?://\S+)",
            )
            or r"\\fileserver\share\app.exe"
        )
        secure_fix = (
            f"# PsExec-Style Remote Service Install - letting the service manager resolve\n"
            f"# a remote UNC/URL ({src}) at start time is the PsExec lateral-movement\n"
            f"# primitive. Copy the binary locally with a checksum, then point the\n"
            f"# service at the verified local path.\n"
            f"- name: Stage the binary locally with checksum verification\n"
            f"  ansible.windows.win_copy:\n"
            f"    src: files/app.exe              # reviewed, version-controlled\n"
            f"    dest: C:\\Program Files\\App\\app.exe\n"
            f"\n"
            f"- name: Install the service pointing at the local, verified binary\n"
            f"  ansible.windows.win_service:\n"
            f"    name: App\n"
            f"    path: C:\\Program Files\\App\\app.exe\n"
            f"    state: present\n"
            f"  # Never let the SCM resolve a remote path at service start."
        )
        return self._frame("psexec_style_service_install", code_snippet, secure_fix)

    def _fix_ad_delegation(self, code_snippet: str) -> str:
        secure_fix = (
            "# AD Constrained/Unconstrained Delegation Modification controls Kerberos\n"
            "# delegation; writes enable S4U abuse. These attributes must only change\n"
            "# through Tier-0 automation run by domain admins, gated and audited.\n"
            "- name: Gate any delegation-attribute change behind Tier-0 review\n"
            "  ansible.builtin.assert:\n"
            "    that:\n"
            "      - tier0_delegation_change_approved | default(false) | bool\n"
            "    fail_msg: >-\n"
            "      Delegation attribute writes require domain-admin sign-off and a\n"
            "      Resource-Based Constrained Delegation abuse review before running.\n"
            "  # Set tier0_delegation_change_approved=true only after security review."
        )
        return self._frame("ad_constrained_delegation_modify", code_snippet, secure_fix)
