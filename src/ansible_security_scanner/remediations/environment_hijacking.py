#!/usr/bin/env python3
"""Environment-hijacking remediation generator.

Each rule flags a tampered resolver, search path, or login script. The
fix shows the sanctioned Ansible idiom for managing that exact resource -
trusted nameservers, system-only PATH, a virtualenv instead of
PYTHONPATH - with the value pulled from the finding where one is present.
"""

from __future__ import annotations

from .base import BaseRemediationGenerator, _first, _render_from_metadata


class EnvironmentHijackingRemediationGenerator(BaseRemediationGenerator):
    """Render dynamic fixes for environment / resolver / path tampering."""

    def generate_environment_hijacking_fix(self, rule_id: str, code_snippet: str) -> str:
        builder = {
            "etc_hosts_manipulation": self._fix_hosts,
            "resolv_conf_manipulation": self._fix_resolv,
            "ntp_server_manipulation": self._fix_ntp,
            "path_env_prepend": self._fix_path,
            "pythonpath_manipulation": self._fix_pythonpath,
            "alternatives_manipulation": self._fix_alternatives,
            "ld_config_manipulation": self._fix_ldconfig,
            "motd_banner_injection": self._fix_motd,
            "library_path_injection": self._fix_libpath,
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

    def _fix_hosts(self, code_snippet: str) -> str:
        entry = _first(code_snippet, r"line:\s*['\"]?([^'\"}\n]+)") or "10.0.0.1 host.example.com"
        secure_fix = (
            f"# Detected /etc/hosts entry: {entry}\n"
            f"# Static host overrides belong in reviewed inventory, not ad-hoc\n"
            f"# playbook edits. Manage the file from a single source of truth so\n"
            f"# every entry is auditable, and prefer central DNS for resolution.\n"
            f"- name: Manage /etc/hosts from a reviewed template\n"
            f"  ansible.builtin.template:\n"
            f"    src: hosts.j2\n"
            f"    dest: /etc/hosts\n"
            f"    owner: root\n"
            f"    group: root\n"
            f"    mode: '0644'\n"
            f"    backup: true\n"
            f"  # hosts.j2 renders only approved entries from group_vars,\n"
            f"  # e.g. {{{{ approved_host_aliases }}}}, reviewed in version control."
        )
        return self._frame(
            "etc_hosts_manipulation",
            "/etc/hosts DNS Hijacking",
            code_snippet,
            "This task edits /etc/hosts, which can redirect domain resolution to "
            "attacker-controlled IPs. Host file changes should use centralized DNS; "
            "review all entries for domain hijacking.",
            secure_fix,
        )

    def _fix_resolv(self, code_snippet: str) -> str:
        secure_fix = (
            "# resolv.conf must point only at trusted corporate or well-known\n"
            "# resolvers. On systemd-resolved hosts, resolv.conf is generated -\n"
            "# set the nameservers declaratively rather than hand-editing it.\n"
            "- name: Pin DNS to trusted resolvers\n"
            "  ansible.builtin.template:\n"
            "    src: resolved.conf.j2\n"
            "    dest: /etc/systemd/resolved.conf\n"
            "    mode: '0644'\n"
            "    backup: true\n"
            "  notify: restart systemd-resolved\n"
            "  # resolved.conf.j2 sets DNS={{ trusted_dns_servers | join(' ') }}\n"
            "  # from reviewed group_vars (e.g. corporate or 1.1.1.1 / 8.8.8.8)."
        )
        return self._frame(
            "resolv_conf_manipulation",
            "DNS Resolver Manipulation",
            code_snippet,
            "This task points DNS resolution at a new nameserver. DNS resolver "
            "changes must point to trusted corporate or well-known DNS servers.",
            secure_fix,
        )

    def _fix_ntp(self, code_snippet: str) -> str:
        conf = (
            _first(code_snippet, r"(/etc/(?:ntp\.conf|chrony\.conf|systemd/timesyncd\.conf))")
            or "/etc/chrony.conf"
        )
        secure_fix = (
            f"# Detected time config: {conf}\n"
            f"# NTP must only reference authorized time servers - drift or a\n"
            f"# rogue server enables time-based auth bypass. Render the config\n"
            f"# from a reviewed list of trusted servers.\n"
            f"- name: Configure NTP against trusted time servers\n"
            f"  ansible.builtin.template:\n"
            f"    src: chrony.conf.j2\n"
            f"    dest: {conf}\n"
            f"    mode: '0644'\n"
            f"    backup: true\n"
            f"  notify: restart chrony\n"
            f"  # chrony.conf.j2 emits 'server <host> iburst' for each entry in\n"
            f"  # {{{{ trusted_ntp_servers }}}} (reviewed in version control)."
        )
        return self._frame(
            "ntp_server_manipulation",
            "NTP Server Manipulation",
            code_snippet,
            f"This task changes NTP configuration ({conf}), which can enable "
            f"time-based authentication bypass. NTP should only point to trusted, "
            f"authorized time servers.",
            secure_fix,
        )

    def _fix_path(self, code_snippet: str) -> str:
        secure_fix = (
            "# Prepending an untrusted directory to PATH lets a planted binary\n"
            "# shadow real system commands. Never prepend writable/temp dirs;\n"
            "# set a fixed, system-only PATH for the task that needs it.\n"
            "- name: Run with a trusted, system-only PATH\n"
            "  ansible.builtin.command: my_tool --run\n"
            "  environment:\n"
            "    PATH: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "  # Install tools to a system bindir via the package or copy module\n"
            "  # instead of pointing PATH at /tmp, /var/tmp, or /dev/shm."
        )
        return self._frame(
            "path_env_prepend",
            "PATH Environment Variable Manipulation",
            code_snippet,
            "This task prepends a directory to PATH, allowing malicious binaries "
            "to shadow legitimate system commands. Never prepend untrusted "
            "directories to PATH; only use system paths.",
            secure_fix,
        )

    def _fix_pythonpath(self, code_snippet: str) -> str:
        secure_fix = (
            "# A planted module on PYTHONPATH is imported first, giving the\n"
            "# attacker code execution. Don't set PYTHONPATH in playbooks - use\n"
            "# an isolated virtualenv so dependencies resolve from a known prefix.\n"
            "- name: Create an isolated virtualenv\n"
            "  ansible.builtin.pip:\n"
            "    name:\n"
            "      - mypackage\n"
            "    virtualenv: /opt/app/venv\n"
            "    virtualenv_command: python3 -m venv\n"
            "\n"
            "- name: Run inside the virtualenv (no PYTHONPATH override)\n"
            "  ansible.builtin.command: /opt/app/venv/bin/python -m myapp"
        )
        return self._frame(
            "pythonpath_manipulation",
            "PYTHONPATH Manipulation",
            code_snippet,
            "This task sets PYTHONPATH, so Python imports the planted module "
            "first, giving the attacker code execution as the playbook user. "
            "PYTHONPATH should not be modified in playbooks; use virtual "
            "environments instead.",
            secure_fix,
        )

    def _fix_alternatives(self, code_snippet: str) -> str:
        link = _first(code_snippet, r"(/usr/s?bin/[\w.-]+)") or "/usr/bin/python"
        secure_fix = (
            f"# Detected alternatives target: {link}\n"
            f"# update-alternatives can silently swap a system binary for an\n"
            f"# attacker's. Install the real tool from a trusted repo via the\n"
            f"# package module; only manage alternatives to a vetted, packaged path.\n"
            f"- name: Install the legitimate package from a trusted repository\n"
            f"  ansible.builtin.package:\n"
            f"    name: python3\n"
            f"    state: present\n"
            f"\n"
            f"- name: Point the alternative at the packaged binary only\n"
            f"  community.general.alternatives:\n"
            f"    name: python\n"
            f"    link: {link}\n"
            f"    path: /usr/bin/python3\n"
            f"  # path must be a vetted, package-managed binary - never /tmp."
        )
        return self._frame(
            "alternatives_manipulation",
            "System Alternatives Manipulation",
            code_snippet,
            f"This task uses update-alternatives to repoint `{link}`, which can "
            f"replace a system binary with an attacker-controlled version. "
            f"Alternatives changes should be reviewed; only use packages from "
            f"trusted repositories.",
            secure_fix,
        )

    def _fix_ldconfig(self, code_snippet: str) -> str:
        secure_fix = (
            "# Adding an untrusted path to the dynamic linker config makes every\n"
            "# program load a malicious .so first. Never add writable/temp dirs;\n"
            "# manage ld.so.conf.d from a reviewed template of vetted prefixes.\n"
            "- name: Manage the linker search path from reviewed config\n"
            "  ansible.builtin.template:\n"
            "    src: app-libs.conf.j2\n"
            "    dest: /etc/ld.so.conf.d/app-libs.conf\n"
            "    owner: root\n"
            "    group: root\n"
            "    mode: '0644'\n"
            "  notify: run ldconfig\n"
            "  # app-libs.conf.j2 lists only vetted, package-owned lib dirs\n"
            "  # (e.g. /opt/app/lib) - never /tmp, /var/tmp, /dev/shm, or /home."
        )
        return self._frame(
            "ld_config_manipulation",
            "Dynamic Linker Configuration Tampering",
            code_snippet,
            "This task modifies the dynamic linker configuration, which can "
            "inject malicious shared libraries into every process. Never add "
            "untrusted paths to the dynamic linker configuration.",
            secure_fix,
        )

    def _fix_motd(self, code_snippet: str) -> str:
        dest = (
            _first(code_snippet, r"(?:dest|path):\s*['\"]?(/etc/[\w./-]+)")
            or "/etc/profile.d/login.sh"
        )
        secure_fix = (
            f"# Detected login-script target: {dest}\n"
            f"# Code in a login/profile script runs for every user at login.\n"
            f"# Ship only reviewed, static content - never a shell payload - and\n"
            f"# render it from a template held in version control.\n"
            f"- name: Manage the login script from reviewed, static content\n"
            f"  ansible.builtin.template:\n"
            f"    src: login-banner.j2\n"
            f"    dest: {dest}\n"
            f"    owner: root\n"
            f"    group: root\n"
            f"    mode: '0644'\n"
            f"    validate: 'bash -n %s'\n"
            f"  # login-banner.j2 contains only static configuration, no command/raw."
        )
        return self._frame(
            "motd_banner_injection",
            "MOTD/Profile Script Injection",
            code_snippet,
            f"This task writes to a login script ({dest}) that executes on every "
            f"user login. Login scripts should only contain legitimate system "
            f"configuration.",
            secure_fix,
        )

    def _fix_libpath(self, code_snippet: str) -> str:
        var = (
            _first(
                code_snippet, r"\b(CLASSPATH|GEM_PATH|GEM_HOME|NODE_PATH|RUBYLIB|PERL5LIB|GOPATH)\b"
            )
            or "CLASSPATH"
        )
        secure_fix = (
            f"# Detected library-path variable: {var}\n"
            f"# Pointing {var} at a writable/temp dir lets a planted library load\n"
            f"# first. Resolve dependencies from a system-managed location and set\n"
            f"# the variable (if needed) to a vetted prefix only.\n"
            f"- name: Run with {var} pinned to a trusted prefix\n"
            f"  ansible.builtin.command: run_app\n"
            f"  environment:\n"
            f"    {var}: /opt/app/lib\n"
            f"  # Install dependencies via the package manager into /opt/app/lib;\n"
            f"  # never reference /tmp, /var/tmp, or /dev/shm."
        )
        return self._frame(
            "library_path_injection",
            "Library Search Path Injection",
            code_snippet,
            f"This task modifies `{var}` to load code from an untrusted path. "
            f"Language library paths should only reference trusted, "
            f"system-managed directories.",
            secure_fix,
        )
