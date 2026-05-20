#!/usr/bin/env python3
"""Remediations for become / delegate / connection misuse patterns."""

from .base import BaseRemediationGenerator


class BecomeDelegateMisuseRemediationGenerator(BaseRemediationGenerator):
    _FIX_MAP = {
        "become_flags_nopasswd_inline": "_fix_become_flags",
        "become_user_root_explicit": "_fix_become_user_root",
        "become_with_password_plaintext": "_fix_become_plaintext_pw",
        "become_without_explicit_become_method_for_windows": "_fix_become_windows",
        "connection_local_with_privilege_sensitive_module": "_fix_connection_local",
        "delegate_to_dynamic_host": "_fix_delegate_dynamic",
        "delegate_to_localhost_run_as_remote": "_fix_delegate_localhost",
        "raw_module_with_become": "_fix_raw_become",
    }

    def generate_become_delegate_misuse_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._fix_generic)

    def _fix_become_no_doc(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Silent privilege escalation:**
`become: true` alone uses the default `become_method` (sudo) and default `become_user` (root). Audit logs record "sudo" for every such task, making it hard to distinguish legitimate upgrades from abuse.

**✅ Secure Fix - Make the escalation explicit:**
```yaml
- name: reload nginx config (privileged)
  ansible.builtin.systemd:
    name: nginx
    state: reloaded
  become: true
  become_method: sudo
  become_user: root       # explicit - so code review can see it
```

**✅ Narrow the blast radius with task-level become (not play-level):**
```yaml
- hosts: web
  tasks:
    - name: put config (does NOT need root)
      ansible.builtin.template:
        src: nginx.conf.j2
        dest: /etc/nginx/nginx.conf
      # no become here - let a pre-chown'd directory receive the file

    - name: reload nginx (needs root)
      ansible.builtin.systemd: {{ name: nginx, state: reloaded }}
      become: true
      become_method: sudo
      become_user: root
```

**🔐 Hardening:**
- Task-level become beats play-level.
- Always set both `become_method` and `become_user` explicitly for reviewable auditability.
- Configure sudoers with a narrow command allow-list rather than blanket NOPASSWD.
"""

    def _fix_become_plaintext_pw(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Sudo password in plaintext in version control:**
Every commit, branch, PR, and fork now holds the sudo password for your fleet. This is a direct path to privilege escalation for anyone with repo read access.

**✅ Secure Fix 1 - Ansible Vault:**
```bash
ansible-vault encrypt inventory/group_vars/all/vault.yml
```
```yaml
# inventory/group_vars/all/vault.yml  (encrypted)
vault_sudo_pw: "super-long-random-string"

# inventory/group_vars/all/vars.yml  (plaintext, references vault)
ansible_become_password: "{{{{ vault_sudo_pw }}}}"
```

**✅ Secure Fix 2 - Passwordless sudo for narrow commands:**
```
# /etc/sudoers.d/ansible-nginx
ansible ALL=(root) NOPASSWD: /bin/systemctl reload nginx, /bin/systemctl restart nginx
```
```yaml
- name: reload nginx (passwordless sudo for this one command)
  ansible.builtin.systemd: {{ name: nginx, state: reloaded }}
  become: true
```

**✅ Secure Fix 3 - Prompt at runtime for interactive plays:**
```bash
ansible-playbook site.yml --ask-become-pass
```

**🔐 Hardening:**
- Add a pre-commit hook that greps for `ansible_become_password` literal values.
- Rotate any previously-committed password IMMEDIATELY and audit who had repo read access.
- Prefer narrow NOPASSWD sudoers entries over storing passwords anywhere.
"""

    def _fix_become_flags(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 become_flags disables sudo authentication:**
`-n`, `-k`, `!authenticate`, or `--preserve-env` combined with NOPASSWD short-circuits sudo's normal auth flow and lets any user in the ansible group escalate without further challenge.

**✅ Secure Fix - Keep become_flags default, narrow sudoers instead:**
```yaml
- name: run privileged task
  ansible.builtin.systemd:
    name: nginx
    state: reloaded
  become: true
  become_method: sudo
  # no become_flags
```

```
# /etc/sudoers.d/ansible-ops
ansible ALL=(root) NOPASSWD: /bin/systemctl reload nginx, /bin/systemctl restart nginx
Defaults:ansible env_reset, !visiblepw, logfile=/var/log/sudo-ansible.log
```

**🔐 Hardening:**
- CI check: `rg -n 'become_flags:.*(NOPASSWD|--preserve-env|!authenticate)' .`
- Log all sudo via `Defaults logfile=/var/log/sudo.log` and ship to your SIEM.
"""

    def _fix_become_user_root(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Explicit become_user: root violates least privilege:**
Running as root when a service user would do (nginx, postgres, app) expands the blast radius of any bug in the downstream module.

**✅ Secure Fix - Use the narrowest user:**
```yaml
- name: drop app binary as the app user
  ansible.builtin.copy:
    src: app
    dest: /opt/app/app
    owner: app
    mode: '0750'
  become: true
  become_user: app

- name: only use root for tasks that truly need it
  ansible.builtin.package: {{ name: nginx, state: present }}
  become: true
  become_user: root
```

**🔐 Hardening:**
- Audit rule: `become_user: root` should carry a code-review comment.
- Prefer service-specific sudoers entries over blanket root escalation.
"""

    def _fix_delegate_localhost(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 delegate_to: localhost silently shifts credential context:**
Ansible runs the task on the controller using controller credentials, not the target's - a subtle mistake when the module otherwise changes remote state (uri, copy, shell). Easy to overlook in review.

**✅ Secure Fix - Use connection: local for controller-side tasks:**
```yaml
- name: fetch secret from controller-side vault (run once, on controller)
  ansible.builtin.uri:
    url: https://vault.example.com/v1/secret/data/app
    headers: {{ "X-Vault-Token": "{{{{ vault_token }}}}" }}
    return_content: true
  register: secret
  connection: local
  run_once: true          # do not fan out across hosts
  delegate_to: localhost
  no_log: true            # secret contents
```

**✅ For legitimate jump-host delegation, be explicit:**
```yaml
- name: create DNS record on a dedicated controller host
  community.general.nsupdate:
    server: "{{{{ dns_primary }}}}"
    zone: example.com.
    record: "{{{{ inventory_hostname }}}}"
    value: "{{{{ ansible_host }}}}"
  delegate_to: dns-controller.example.com
  run_once: true
```

**🔐 Hardening:**
- Pair `delegate_to: localhost` with `run_once: true` and `no_log: true` when handling secrets.
- Keep secrets on the controller, out of remote task contexts.
"""

    def _fix_delegate_dynamic(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Dynamic delegate_to target:**
If the variable interpolated into delegate_to comes from inventory facts, a lookup, or untrusted input, an attacker can steer Ansible to run the task against an attacker-chosen host with the controller's credentials and keys.

**✅ Secure Fix - Validate the target against an allow-list:**
```yaml
- name: assert the delegation target is in the known inventory group
  ansible.builtin.assert:
    that:
      - delegation_target in groups['controllers']
    fail_msg: "Refusing to delegate to unknown host {{{{ delegation_target }}}}"

- name: safe delegation after assertion
  ansible.builtin.command: /usr/local/bin/update-record
  delegate_to: "{{{{ delegation_target }}}}"
```

**✅ Prefer static delegation when possible:**
```yaml
delegate_to: dns-controller.example.com   # static, reviewable
```

**🔐 Hardening:**
- Grep CI: scan for `delegate_to:` followed by Jinja interpolation markers.
- Never derive delegate_to from register / lookup / hostvars untrusted values.
"""

    def _fix_connection_local(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 connection: local + state-changing module:**
The task runs on the controller, not the intended target. Files are written, users are created, services are restarted on the Ansible host itself - often noticed only after the controller is polluted.

**✅ Secure Fix - Scope connection: local to controller-only tasks:**
```yaml
- name: render template on controller for later inspection
  ansible.builtin.template:
    src: report.j2
    dest: "/tmp/report-{{{{ inventory_hostname }}}}.txt"
  connection: local
  delegate_to: localhost
  run_once: true

- name: apply remote changes with the default ssh connection
  ansible.builtin.systemd:
    name: nginx
    state: reloaded
  # no connection: local - runs on the target as intended
```

**🔐 Hardening:**
- Reserve `connection: local` for API calls, templating, and controller-side fact gathering.
- Never use it with `ansible.builtin.user`, `group`, `file`, `service`, `systemd`, or `cron`.
"""

    def _fix_become_windows(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Windows play needs become_method: runas:**
On Windows, `become_method: sudo` is silently ignored, so tasks that require elevation fail quietly or run as the unelevated WinRM user. Missing `become_method: runas` often hides privilege bugs in CI.

**✅ Secure Fix:**
```yaml
- hosts: windows
  vars:
    ansible_connection: winrm
    ansible_winrm_transport: kerberos
  tasks:
    - name: install IIS (needs elevation)
      ansible.windows.win_feature:
        name: Web-Server
        state: present
      become: true
      become_method: runas
      become_user: Administrator
```

**🔐 Hardening:**
- Never mix sudo-style `become_method` on Windows plays.
- Use `become_flags: logon_type=interactive logon_flags=with_profile` only when needed for profile access.
"""

    def _fix_raw_become(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 ansible.builtin.raw + become: true:**
`raw` has no module framework - no argument types, no idempotency, no sanitisation. Elevating it to root means any variable interpolation runs as root with the user's own shell quoting (or lack thereof).

**✅ Secure Fix - Prefer a real module:**
```yaml
- name: install package (idempotent, typed)
  ansible.builtin.package:
    name: curl
    state: present
  become: true
  become_method: sudo
  become_user: root
```

**✅ If raw is unavoidable (pre-Python bootstrap), drop become:**
```yaml
- name: one-shot bootstrap - install python so Ansible can take over
  ansible.builtin.raw: "dnf -y install python3"
  # No become here: rely on the SSH user having a narrow NOPASSWD sudoers entry
  #   %ansible ALL=(root) NOPASSWD: /usr/bin/dnf -y install python3
```

**🔐 Hardening:**
- Use `raw` only on hosts without Python.
- Combine with narrow sudoers entries instead of `become`.
- Add a CI grep: `rg -n 'ansible.builtin.raw' -A 5 | grep -i 'become:\\s*true'`.
"""

    def _fix_generic(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 become/delegate/connection misuse detected.**

**✅ Secure Defaults:**
- Task-level `become` > play-level `become`.
- Always set `become_method` and `become_user` explicitly.
- Use `connection: local` only for controller-side tasks.
- Never derive `delegate_to` or `become_password` from untrusted variables.

**🔐 Hardening:**
- Narrow sudoers entries (NOPASSWD + command list) beat playbook-side passwords.
- Log all sudo invocations centrally.
- Gate delegation targets behind assertions.
"""
