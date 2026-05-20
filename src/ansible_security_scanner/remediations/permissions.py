#!/usr/bin/env python3
"""
Permissions remediation generator for Ansible Security Scanner
"""

from .base import BaseRemediationGenerator


class PermissionsRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for unsafe permissions"""

    def generate_context_aware_permissions_fix(self, code_snippet: str, rule_id: str = "") -> str:
        """Generate context-aware fix for unsafe permissions"""

        # Rule-ID-specific fixes for ansible.cfg hardening.
        # These go first because the generic code_snippet heuristics below
        # won't recognise `allow_world_readable_tmpfiles = True` as anything
        # special - they'd fall through to the generic path.
        cfg_fixes = self._ANSIBLE_CFG_FIXES
        if rule_id in cfg_fixes:
            return cfg_fixes[rule_id](self, code_snippet)

        if "/etc/passwd" in code_snippet or "/etc/shadow" in code_snippet:
            return self._generate_system_file_permissions_fix(code_snippet)
        if ".ssh/" in code_snippet or "id_rsa" in code_snippet:
            return self._generate_ssh_permissions_fix(code_snippet)
        if "/var/log" in code_snippet:
            return self._generate_log_permissions_fix(code_snippet)
        if "sudoers" in code_snippet:
            return self._generate_sudoers_permissions_fix(code_snippet)
        return self._generate_generic_permissions_fix(code_snippet)

    def _generate_system_file_permissions_fix(self, code_snippet: str) -> str:
        """Generate fix for system file permissions"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Dangerous System File Permissions:**
This sets unsafe permissions on critical system files that could compromise system security.

**✅ Secure Fix (Proper system file permissions):**
```yaml
# Set secure permissions for system files:
- name: Secure system files
  file:
    path: "{{{{ item.path }}}}"
    mode: "{{{{ item.mode }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
  loop:
    - {{ path: "/etc/passwd", mode: "0644", owner: "root", group: "root" }}
    - {{ path: "/etc/shadow", mode: "0600", owner: "root", group: "root" }}
    - {{ path: "/etc/group", mode: "0644", owner: "root", group: "root" }}
  become: yes
```

**🔐 System File Security Best Practices:**
- Never make system files world-writable
- Use restrictive permissions for sensitive files
- Regular audit of file permissions
- Implement file integrity monitoring
"""

        return template

    def _generate_ssh_permissions_fix(self, code_snippet: str) -> str:
        """Generate fix for SSH permissions"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Dangerous SSH File Permissions:**
This sets unsafe permissions on SSH files that could compromise authentication security.

**✅ Secure Fix (Proper SSH permissions):**
```yaml
# Set secure permissions for SSH files:
- name: Secure SSH directory
  file:
    path: "{{{{ ansible_env.HOME }}}}/.ssh"
    mode: '0700'
    owner: "{{{{ ansible_user }}}}"
    group: "{{{{ ansible_user }}}}"
    state: directory

- name: Secure SSH private keys
  file:
    path: "{{{{ ansible_env.HOME }}}}/.ssh/id_rsa"
    mode: '0600'
    owner: "{{{{ ansible_user }}}}"
    group: "{{{{ ansible_user }}}}"
  when: ansible_env.HOME + '/.ssh/id_rsa' is exists

- name: Secure SSH public keys
  file:
    path: "{{{{ ansible_env.HOME }}}}/.ssh/id_rsa.pub"
    mode: '0644'
    owner: "{{{{ ansible_user }}}}"
    group: "{{{{ ansible_user }}}}"
  when: ansible_env.HOME + '/.ssh/id_rsa.pub' is exists

- name: Secure authorized_keys
  file:
    path: "{{{{ ansible_env.HOME }}}}/.ssh/authorized_keys"
    mode: '0600'
    owner: "{{{{ ansible_user }}}}"
    group: "{{{{ ansible_user }}}}"
  when: ansible_env.HOME + '/.ssh/authorized_keys' is exists
```

**🔐 SSH Security Best Practices:**
- SSH directory should be 0700
- Private keys should be 0600
- Public keys can be 0644
- authorized_keys should be 0600
"""

        return template

    def _generate_log_permissions_fix(self, code_snippet: str) -> str:
        """Generate fix for log file permissions"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Dangerous Log File Permissions:**
This sets unsafe permissions on log files that could allow unauthorized access or tampering.

**✅ Secure Fix (Proper log permissions):**
```yaml
# Set secure permissions for log files:
- name: Secure log directory
  file:
    path: /var/log
    mode: '0755'
    owner: root
    group: root
    state: directory
  become: yes

- name: Secure individual log files
  file:
    path: "{{{{ item }}}}"
    mode: '0640'
    owner: root
    group: adm
  loop:
    - /var/log/auth.log
    - /var/log/secure
    - /var/log/messages
  become: yes
  when: item is exists
```

**🔐 Log Security Best Practices:**
- Log files should not be world-readable
- Use appropriate group ownership (adm, log)
- Implement log rotation with secure permissions
- Monitor log file integrity
"""

        return template

    def _generate_sudoers_permissions_fix(self, code_snippet: str) -> str:
        """Generate fix for sudoers file permissions"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Dangerous Sudoers File Permissions:**
This sets unsafe permissions on sudoers files that could allow privilege escalation.

**✅ Secure Fix (Proper sudoers permissions):**
```yaml
# Set secure permissions for sudoers files:
- name: Secure main sudoers file
  file:
    path: /etc/sudoers
    mode: '0440'
    owner: root
    group: root
  become: yes

- name: Secure sudoers.d directory
  file:
    path: /etc/sudoers.d
    mode: '0755'
    owner: root
    group: root
    state: directory
  become: yes

- name: Secure sudoers.d files
  file:
    path: "{{{{ item }}}}"
    mode: '0440'
    owner: root
    group: root
  with_fileglob:
    - "/etc/sudoers.d/*"
  become: yes
```

**🔐 Sudoers Security Best Practices:**
- Sudoers files should be 0440 (read-only)
- Always use visudo to edit sudoers
- Follow principle of least privilege
- Regular audit of sudo permissions
"""

        return template

    def _generate_generic_permissions_fix(self, code_snippet: str) -> str:
        """Generate generic permissions fix"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Unsafe File Permissions:**
This sets potentially unsafe file permissions that could compromise security.

**✅ Secure Fix (Proper file permissions):**
```yaml
# Set appropriate file permissions based on file type:
- name: Set secure file permissions
  file:
    path: "{{{{ target_file }}}}"
    mode: '0644'  # or 0600 for sensitive files
    owner: "{{{{ appropriate_owner }}}}"
    group: "{{{{ appropriate_group }}}}"
  become: yes
```

**🔐 File Permission Best Practices:**
- Use least-privilege permissions
- Regular audit of file permissions
- Use appropriate ownership
- Monitor for permission changes
"""

        return template

    # ansible.cfg hardening
    # Rule-ID-specific remediation templates. Each method returns a full
    # contextual markdown block; dispatch happens via _ANSIBLE_CFG_FIXES.

    def _fix_ansible_cfg_allow_world_readable_tmpfiles(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable ansible.cfg setting:**
```ini
{code_snippet}
```

**🚨 Why this is dangerous:**
`allow_world_readable_tmpfiles = True` relaxes the 0600 permission on per-task
temp files Ansible writes on remote hosts. Task arguments (including secrets
passed via `-e`, `vars:`, or `vars_files:`) can briefly land in a world-
readable file - any local user on the target host can cat them before the
task finishes.

**✅ Secure fix:**
```ini
[defaults]
# remove the line entirely; default is False
```
Or, if you genuinely must set it (e.g. you run as a non-root user with
`become: yes` to a different non-root user):
```ini
[defaults]
allow_world_readable_tmpfiles = False
```

**🔐 Related hardening:**
- Always pair secrets with `no_log: true` on the task
- Use ansible-vault for secret vars instead of `-e` on the command line
- Prefer `become_user: root` over become_user to another non-privileged account
"""

    def _fix_ansible_cfg_pipelining_without_requiretty(self, code_snippet: str) -> str:
        return f"""
**⚠️  ansible.cfg setting that needs a sudoers check:**
```ini
{code_snippet}
```

**🚨 Why this warrants review:**
`pipelining = True` streams module arguments over the SSH connection rather
than writing a temp file on disk. That's faster AND more secure - but only
if `Defaults !requiretty` is set in /etc/sudoers on every managed host.
Without that, pipelining silently breaks `become` and may cause security
tasks to skip or fail open.

**✅ Secure workflow:**
```ini
[defaults]
pipelining = True
```
...combined with a pre-check in your playbook:
```yaml
- name: ensure sudoers allows pipelining (no requiretty)
  ansible.builtin.lineinfile:
    path: /etc/sudoers
    regexp: '^Defaults\\s+requiretty'
    state: absent
    validate: 'visudo -cf %s'
  become: yes
```

**🔐 Notes:**
- If you cannot disable requiretty fleet-wide, set pipelining = False.
- Pipelining + allow_world_readable_tmpfiles is NEVER the right combo.
"""

    def _fix_ansible_cfg_retry_files_enabled_true(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable ansible.cfg setting:**
```ini
{code_snippet}
```

**🚨 Why this is dangerous:**
`retry_files_enabled = True` writes `<playbook>.retry` files after failed
runs, containing the inventory hostnames of every host that failed. On
shared controller machines these linger with default 0644 perms and leak
your inventory structure to any other local user.

**✅ Secure fix:**
```ini
[defaults]
retry_files_enabled = False
# OR, if you want retries, lock the path down:
retry_files_save_path = ~/.ansible/retry  # 0700, owned by the ansible user
```

**🔐 Hardening checklist:**
- Ensure ~/.ansible/retry exists with mode 0700 before first run
- Add `.retry` to .gitignore so accidentally-generated files never leave the host
"""

    def _fix_ansible_cfg_log_path_world_readable(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable ansible.cfg setting:**
```ini
{code_snippet}
```

**🚨 Why this is dangerous:**
The Ansible log captures task names, inventory hostnames, and - unless every
task uses `no_log: true` - module arguments including secrets. A log_path
in /tmp, /var/tmp, or any default-0644 location is a credential leak.

**✅ Secure fix:**
```ini
[defaults]
log_path = ~/.ansible/log/ansible.log
```
```yaml
- name: ensure log directory has restrictive perms
  ansible.builtin.file:
    path: ~/.ansible/log
    state: directory
    mode: '0700'
    owner: "{{{{ lookup('env', 'USER') }}}}"
```

**🔐 Defense-in-depth:**
- Always pair `no_log: true` with tasks that touch secrets
- Consider shipping logs to a locked-down syslog collector instead of local disk
- Rotate logs with logrotate using `create 0600` mode
"""

    def _fix_ansible_cfg_display_skipped_hosts_false(self, code_snippet: str) -> str:
        return f"""
**⚠️  ansible.cfg setting that reduces security signal:**
```ini
{code_snippet}
```

**🚨 Why this matters:**
`display_skipped_hosts = False` hides which hosts skipped a task. For
security-relevant playbooks (patching, firewall rules, user hardening)
a skipped task usually means a host was NOT hardened - you want that
visible in CI logs, not suppressed.

**✅ Secure fix:**
```ini
[defaults]
# leave this unset (default True) for prod/security playbooks
# display_skipped_hosts = True
```

**🔐 Alternative:**
If log noise is the real problem, silence only successful/changed output
and keep skipped visible:
```ini
[defaults]
display_ok_hosts = False
display_skipped_hosts = True
```
"""

    def _fix_ansible_cfg_nocows_disabled_in_prod(self, code_snippet: str) -> str:
        return f"""
**⚠️  ansible.cfg setting that hides a security signal:**
```ini
{code_snippet}
```

**🚨 Why this matters:**
`command_warnings = False` silences Ansible's warning when you use the
`command`/`shell` module for something a dedicated module could do better
(`shell: apt install x` -> use `ansible.builtin.apt` instead). Those
warnings are a security smell indicator - silencing them hides the
anti-pattern from reviewers.

**✅ Secure fix:**
```ini
[defaults]
# remove the line entirely; default is True
```

**🔐 Follow-up:**
Run your playbooks with `-vv` once after re-enabling warnings and convert
every `command_warnings` hit to a proper module call.
"""

    def _fix_ansible_cfg_private_key_file_world_readable_path(self, code_snippet: str) -> str:
        return f"""
**🚨 CRITICAL ansible.cfg finding:**
```ini
{code_snippet}
```

**🚨 Why this is CRITICAL:**
An SSH private key stored in /tmp, /var/tmp, ~/Downloads, ~/Desktop, or
any shared / world-readable directory is effectively public. Anyone with
local access, anyone with a stale backup, or anyone who runs `find /tmp
-name "id_*"` has your key.

**✅ Secure fix:**
```ini
[defaults]
private_key_file = ~/.ssh/id_ed25519
```
```bash
# one-time hardening of key perms
chmod 0600 ~/.ssh/id_ed25519
chmod 0700 ~/.ssh
```

**🔐 Stronger options (in increasing security):**
1. Use ssh-agent, don't reference private_key_file at all
2. Use a hardware token (YubiKey, 1Password SSH agent)
3. Use short-lived SSH certificates signed by a CA (teleport, smallstep)
"""

    def _fix_ansible_cfg_callback_whitelist_unpinned(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable ansible.cfg setting:**
```ini
{code_snippet}
```

**🚨 Why this is dangerous:**
`callback_whitelist = *` (or any wildcard) loads every callback plugin on
the plugin path - including any plugin an attacker planted there (e.g. a
tampered `slack` callback that exfiltrates task output to an attacker-
controlled webhook). This is a supply-chain time bomb.

**✅ Secure fix:**
```ini
[defaults]
callbacks_enabled = timer, profile_tasks, ansible.posix.profile_roles
callback_plugins = /etc/ansible/plugins/callback  # 0755, owned by root
```

**🔐 Hardening checklist:**
- Enumerate callbacks explicitly; never wildcard
- Pin callback_plugins to a root-owned, 0755 directory outside ~/.ansible
- Audit ~/.ansible/plugins/callback for any unexpected files before each release
"""

    def _fix_ansible_cfg_any_errors_fatal_false_in_prod(self, code_snippet: str) -> str:
        return f"""
**⚠️  ansible.cfg setting that can mask partial-fleet security failure:**
```ini
{code_snippet}
```

**🚨 Why this matters:**
With `any_errors_fatal = False`, a task failure on one host doesn't stop
the run on other hosts. For hardening playbooks (patching, firewall rules,
user/group changes) that means you can end up with a fleet in an
inconsistent, partially-hardened state - and the failure may be silent.

**✅ Secure fix:**
```ini
[defaults]
any_errors_fatal = True
```
Or per-play (more granular):
```yaml
- hosts: all
  any_errors_fatal: true
  max_fail_percentage: 0  # fail if a SINGLE host fails
  tasks:
    - ...
```

**🔐 For rolling security updates:**
Use `serial:` batches plus `max_fail_percentage:` to gate the rollout:
```yaml
- hosts: all
  serial: "20%"
  max_fail_percentage: 10
```
"""

    def _fix_ansible_cfg_roles_path_writable_location(self, code_snippet: str) -> str:
        return f"""
**🚨 HIGH ansible.cfg finding:**
```ini
{code_snippet}
```

**🚨 Why this is dangerous:**
`roles_path` or `collections_paths` pointing to /tmp, /var/tmp, or another
world-writable directory lets any local user on the Ansible controller
plant a malicious role/collection the next playbook run will execute as
the Ansible user - often root on targets via `become`.

**✅ Secure fix:**
```ini
[defaults]
roles_path = /etc/ansible/roles:~/.ansible/roles
collections_paths = /etc/ansible/collections:~/.ansible/collections
```
```bash
sudo mkdir -p /etc/ansible/roles /etc/ansible/collections
sudo chown root:ansible /etc/ansible/roles /etc/ansible/collections
sudo chmod 0755 /etc/ansible/roles /etc/ansible/collections
```

**🔐 Hardening checklist:**
- Never include /tmp, /var/tmp, or any relative `..` paths
- Audit each roles_path/collections_path directory for unexpected files
- Pin collection/role versions in requirements.yml (see also: galaxy supply-chain rules)
"""

    # Dispatch map: rule_id -> bound method. Built once at class-load time.
    _ANSIBLE_CFG_FIXES = {
        "ansible_cfg_allow_world_readable_tmpfiles": lambda self, s: (
            self._fix_ansible_cfg_allow_world_readable_tmpfiles(s)
        ),
        "ansible_cfg_pipelining_without_requiretty": lambda self, s: (
            self._fix_ansible_cfg_pipelining_without_requiretty(s)
        ),
        "ansible_cfg_retry_files_enabled_true": lambda self, s: (
            self._fix_ansible_cfg_retry_files_enabled_true(s)
        ),
        "ansible_cfg_log_path_world_readable": lambda self, s: (
            self._fix_ansible_cfg_log_path_world_readable(s)
        ),
        "ansible_cfg_display_skipped_hosts_false": lambda self, s: (
            self._fix_ansible_cfg_display_skipped_hosts_false(s)
        ),
        "ansible_cfg_nocows_disabled_in_prod": lambda self, s: (
            self._fix_ansible_cfg_nocows_disabled_in_prod(s)
        ),
        "ansible_cfg_private_key_file_world_readable_path": lambda self, s: (
            self._fix_ansible_cfg_private_key_file_world_readable_path(s)
        ),
        "ansible_cfg_callback_whitelist_unpinned": lambda self, s: (
            self._fix_ansible_cfg_callback_whitelist_unpinned(s)
        ),
        "ansible_cfg_any_errors_fatal_false_in_prod": lambda self, s: (
            self._fix_ansible_cfg_any_errors_fatal_false_in_prod(s)
        ),
        "ansible_cfg_roles_path_writable_location": lambda self, s: (
            self._fix_ansible_cfg_roles_path_writable_location(s)
        ),
        # Inventory / group_vars / host_vars
        "inventory_ansible_ssh_pass_literal": lambda self, s: self._fix_inventory_ssh_pass_literal(
            s
        ),
        "inventory_ansible_become_pass_literal": lambda self, s: (
            self._fix_inventory_become_pass_literal(s)
        ),
        "inventory_ansible_connection_paramiko_without_host_key": lambda self, s: (
            self._fix_inventory_paramiko_connection(s)
        ),
        "inventory_become_method_sudo_no_password": lambda self, s: (
            self._fix_inventory_become_flags_nopasswd(s)
        ),
        "inventory_winrm_ignore_cert_validation": lambda self, s: (
            self._fix_inventory_winrm_cert_ignore(s)
        ),
        "inventory_group_vars_all_contains_plaintext_secret": lambda self, s: (
            self._fix_inventory_group_vars_plaintext_secret(s)
        ),
        "inventory_host_pattern_all_hosts": lambda self, s: self._fix_inventory_host_pattern_all(s),
        # Dangerous Task Hygiene (symlink TOCTOU, unsafe writes, etc.)
        "file_follow_true_with_become": lambda self, s: self._fix_file_follow_true_with_become(s),
        "copy_unsafe_writes_true": lambda self, s: self._fix_copy_unsafe_writes_true(s),
        "template_mode_executable_to_system_path": lambda self, s: (
            self._fix_template_mode_executable_to_system_path(s)
        ),
        "lineinfile_no_backup_on_sensitive_file": lambda self, s: (
            self._fix_lineinfile_no_backup_on_sensitive_file(s)
        ),
    }

    # Inventory / group_vars / host_vars remediation
    def _fix_inventory_ssh_pass_literal(self, code_snippet: str) -> str:
        return f"""
**🚨 CRITICAL inventory finding:**
```ini
{code_snippet}
```

**🚨 Why this is CRITICAL:**
`ansible_ssh_pass=<literal>` in inventory puts every host's SSH password
in plaintext in version control. Anyone who clones the repo - past or
future employee, leaked CI artifact, mirror - has those credentials.

**✅ Secure fix:**
```yaml
# group_vars/webservers/vault.yml  (ansible-vault encrypted)
ansible_ssh_pass: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  66386439653431...
```
Or, ideally, remove the password entirely:
```yaml
# group_vars/webservers/main.yml
ansible_user: deploy
# auth is via ssh keys loaded into ssh-agent on the controller
```

**🔐 Hardening checklist:**
- Generate a per-host ssh key pair, push public keys with Ansible, then
  disable password auth on the target (`PasswordAuthentication no`).
- If you must keep a password (kickstart / first-boot flow), vault-encrypt
  it and rotate after first successful key push.
"""

    def _fix_inventory_become_pass_literal(self, code_snippet: str) -> str:
        return f"""
**🚨 CRITICAL inventory finding:**
```ini
{code_snippet}
```

**🚨 Why this is CRITICAL:**
Committing `ansible_become_pass=<literal>` hands every clone of the repo
the sudo password for every listed host. Combined with an SSH-key leak,
this is total compromise.

**✅ Secure fix:**
```yaml
# group_vars/all/vault.yml (vault-encrypted)
ansible_become_pass: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  33363264643061...
```
Or prompt at runtime and never store it:
```bash
ansible-playbook site.yml --ask-become-pass
```

**🔐 Better:** configure passwordless sudo for the ansible user on a
dedicated sudoers.d file, version-controlled alongside the playbook:
```
# /etc/sudoers.d/ansible-deploy (mode 0440)
deploy ALL=(root) NOPASSWD: /usr/bin/ansible-update
```
"""

    def _fix_inventory_paramiko_connection(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable inventory setting:**
```ini
{code_snippet}
```

**🚨 Why this is dangerous:**
`ansible_connection=paramiko` with default settings trusts the remote host
key on first connection (TOFU). On a fresh controller that first connection
may be intercepted - MITM, get the connection, and you're MITMing the
whole fleet forever.

**✅ Secure fix:**
```yaml
# group_vars/all/main.yml
ansible_connection: ssh  # uses system ssh, honours known_hosts
```
```yaml
# And pre-populate known_hosts before the first run:
- name: seed known_hosts
  ansible.builtin.known_hosts:
    name: "{{{{ item }}}}"
    key: "{{{{ lookup('pipe', 'ssh-keyscan -t ed25519 ' ~ item) }}}}"
    path: /etc/ssh/ssh_known_hosts
  loop: "{{{{ groups['all'] }}}}"
  delegate_to: localhost
  run_once: true
```

**🔐 If paramiko is non-negotiable:**
```yaml
ansible_connection: paramiko
ansible_paramiko_host_key_checking: true
ansible_paramiko_host_key_auto_add: false
```
"""

    def _fix_inventory_become_flags_nopasswd(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable inventory setting:**
```ini
{code_snippet}
```

**🚨 Why this is dangerous:**
`ansible_become_flags` containing `-n` makes sudo non-interactive - if the
target sudoers doesn't have NOPASSWD, the task fails silently; if it does,
NOPASSWD was smuggled in through inventory rather than being explicitly
reviewed. Either outcome is a security-review gap.

**✅ Secure fix:**
```yaml
# Drop -n. Let Ansible handle sudo prompting explicitly.
ansible_become_flags: ""
```
If the target truly needs NOPASSWD, document it in a role:
```yaml
- name: grant NOPASSWD sudo for the ansible user (reviewed + version-controlled)
  ansible.builtin.copy:
    content: "deploy ALL=(root) NOPASSWD: /usr/bin/apt-get"
    dest: /etc/sudoers.d/ansible-deploy
    mode: '0440'
    validate: 'visudo -cf %s'
```

**🔐 Hardening checklist:**
- Grant NOPASSWD ONLY for specific commands, never ALL=ALL.
- Review /etc/sudoers.d/ansible-* entries in every audit.
"""

    def _fix_inventory_winrm_cert_ignore(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable inventory setting:**
```ini
{code_snippet}
```

**🚨 Why this is dangerous:**
`ansible_winrm_server_cert_validation=ignore` disables TLS certificate
validation on the WinRM handshake. Any attacker on the controller-to-
Windows path can MITM and replay credentials (NTLM/CredSSP).

**✅ Secure fix:**
```yaml
# group_vars/windows/main.yml
ansible_winrm_server_cert_validation: validate
ansible_winrm_ca_trust_path: /etc/ssl/certs/corp-winrm-ca.pem
```
```bash
# And ensure each Windows host serves a cert from corp-winrm-ca:
Set-WSManInstance -ResourceURI winrm/config/listener \\
  -SelectorSet @{{Address="*";Transport="HTTPS"}} \\
  -ValueSet @{{CertificateThumbprint="<thumbprint>"}}
```

**🔐 Defense-in-depth:**
- Prefer Kerberos (ansible_winrm_transport=kerberos) over NTLM.
- Enable CredSSP ONLY on trusted network segments, never over the public internet.
"""

    def _fix_inventory_group_vars_plaintext_secret(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable group_vars / host_vars finding:**
```yaml
{code_snippet}
```

**🚨 Why this is dangerous:**
A variable with a secret-shaped name (*_password, *_token, *_secret, *_api_key,
*_private_key) is assigned a literal value in group_vars/all - that secret
now applies to every host in the inventory, in plaintext, in version control.

**✅ Secure fix:**
```yaml
# group_vars/all/vault.yml  (encrypt with: ansible-vault encrypt file.yml)
db_password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  66386439653431...
api_token: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  ...
```

**🔐 Stronger alternatives:**
1. **Secret manager lookup** (runtime-only, never on disk):
   ```yaml
   db_password: "{{{{ lookup('community.hashi_vault.hashi_vault', 'secret=kv/data/db:password') }}}}"
   ```
2. **1Password / AWS Secrets Manager lookup plugins** for dev-vs-prod splits.
3. **Per-environment vault files** - vault/prod.yml uses a different vault-id
   than vault/dev.yml so a prod password leak doesn't impact dev.
"""

    def _fix_inventory_host_pattern_all(self, code_snippet: str) -> str:
        return f"""
**⚠️  Broad-scope privileged play:**
```yaml
{code_snippet}
```

**🚨 Why this matters:**
A play with `hosts: all` + `become: true` applies privileged changes to
EVERY host in inventory at once. A typo, a bad YAML anchor, or a merged
PR with a wider role than intended can silently re-configure every host
in the fleet in one apply.

**✅ Secure fix:**
```yaml
- hosts: webservers    # narrow the pattern
  become: true
  serial: "25%"        # apply in batches, limit blast radius
  max_fail_percentage: 10
  tasks:
    - ...
```

**🔐 Additional guardrails:**
- Use group intersections: `hosts: webservers:&prod:!canary-excluded`
- Pre-flight with `--check --diff` against a small subset.
- Tag high-risk plays (`tags: [privileged, hardening]`) and require
  `--tags` to run them in CI.
"""

    def _fix_file_follow_true_with_become(self, code_snippet: str) -> str:
        return f"""
**🚨 Symlink TOCTOU: file + follow: yes + become:**
```yaml
{code_snippet}
```

**🚨 Why this is dangerous:**
`follow: yes` makes the `file:` module resolve the path and operate on the
symlink's TARGET instead of the symlink itself. Combined with `become: true`,
an unprivileged local user on the managed host can replace the path (if it's
in a world-writable location like /tmp, /var/tmp, /dev/shm, or even a user-
owned directory) with a symlink pointing at /etc/shadow, /root/.ssh/authorized_keys,
or any sensitive file - at the exact moment Ansible runs the task, the chmod/
chown lands on the attacker-chosen target, as root.

**✅ Secure fix - default follow behavior + stat guard:**
```yaml
- name: ensure logfile permissions (no symlink follow)
  ansible.builtin.file:
    path: /var/log/myapp/app.log
    mode: '0640'
    owner: myapp
    group: adm
    follow: no          # <-- default, but be explicit
  become: true

# If you MUST resolve a symlink target, validate it first:
- name: get real path of target
  ansible.builtin.stat:
    path: /var/log/myapp/app.log
  register: target_stat

- name: refuse to run if path resolves outside trusted tree
  ansible.builtin.fail:
    msg: "refusing: target resolves to {{{{ target_stat.stat.lnk_source | default(target_stat.stat.path) }}}}"
  when:
    - target_stat.stat.islnk | default(false)
    - not (target_stat.stat.lnk_source | default('')) is match('^/var/log/myapp/')
```

**🔐 Hardening checklist:**
- Never combine `follow: yes` + `become: true` on a path in /tmp, /var/tmp,
  /dev/shm, /home/*, or any user-owned directory.
- Prefer creating files in role-owned trees (/opt/myrole/, /var/lib/myrole/)
  where non-root users cannot plant symlinks.
- For log files specifically, use `ansible.posix.acl:` with explicit, named
  ACEs instead of chmod+chown.
"""

    def _fix_copy_unsafe_writes_true(self, code_snippet: str) -> str:
        return f"""
**🚨 copy/template with unsafe_writes: true:**
```yaml
{code_snippet}
```

**🚨 Why this is dangerous:**
Ansible's default write strategy is atomic: write to a tempfile in the same
directory, then `rename()` it into place. `unsafe_writes: true` disables that
and uses a direct `open(O_TRUNC)` on the destination. Two failure modes:

1. **Race with a local writer**: if the parent directory is world-writable, an
   unprivileged user can `open()` the destination between the truncate and the
   write, landing their own content in a root-owned file.
2. **Partial-read by a reader**: any process reading the file during the write
   gets a half-truncated file, which for config files means a missing `]`, a
   missing trailing newline, etc. - surprisingly easy to weaponize into DoS.

**✅ Secure fix - leave the default in place:**
```yaml
- name: deploy config (atomic, default behavior)
  ansible.builtin.copy:
    src: etc/app.conf
    dest: /etc/app.conf
    owner: root
    group: root
    mode: '0644'
    # unsafe_writes omitted - defaults to false
    backup: yes
```

**🔐 If you genuinely hit a real unsafe_writes use case:**
This only exists for bind-mounted destinations, FUSE filesystems without
rename support, or OverlayFS in certain container modes. Isolate the workaround:
```yaml
- name: write to a normal path first
  ansible.builtin.copy:
    src: etc/app.conf
    dest: /tmp/app.conf.stage
    mode: '0644'

- name: bind-mount from stage into container (the part that can't rename)
  ansible.builtin.command: mount --bind /tmp/app.conf.stage /var/lib/container/etc/app.conf
```

**🔐 Never enable `unsafe_writes: true` for:**
- Anything in /etc/, /root/, /boot/, or /usr/
- Any file matching *.conf, *.cfg, authorized_keys, sudoers, shadow, passwd
- Any destination on a world-writable parent directory
"""

    def _fix_template_mode_executable_to_system_path(self, code_snippet: str) -> str:
        return f"""
**🚨 template -> executable file in system path:**
```yaml
{code_snippet}
```

**🚨 Why this is dangerous:**
A `template:` writing to /etc/, /usr/bin/, /usr/local/bin/, /usr/sbin/, /opt/,
or /root/ with an executable mode (0755, 0775, 0777, or any 4xxx / x-bit form)
is the classic webshell / persistence-hook pattern. It reads like a config
deploy in review, but PATH-lookup, cron, or systemd invokes it as root.
Worse: any Jinja variable in the template that comes from facts, inventory,
or group_vars is now an arbitrary-code-execution sink.

**✅ Secure fix - separate config from scripts:**
```yaml
# Config goes in /etc with 0644 (non-executable):
- name: render app config
  ansible.builtin.template:
    src: app.conf.j2
    dest: /etc/myapp/app.conf
    mode: '0644'         # <-- not executable
    owner: root
    group: root

# Scripts ship from files/ (reviewed as scripts, not templated):
- name: deploy pre-vetted helper script
  ansible.builtin.copy:
    src: files/helper.sh    # <-- pre-rendered, version-controlled, reviewed
    dest: /usr/local/libexec/myapp/helper.sh
    mode: '0755'
    owner: root
    group: root

# Then wire it in via a systemd unit / cron / PATH entry:
- name: install systemd unit for helper
  ansible.builtin.copy:
    src: files/myapp-helper.service
    dest: /etc/systemd/system/myapp-helper.service
    mode: '0644'
```

**🔐 Hardening checklist:**
- Templates to /etc/, /usr/, /opt/, /root/ -> mode must be 0644 or stricter.
- If you must template an executable, render it to a role-owned directory
  (/opt/myrole/bin/) and invoke it explicitly from a systemd unit - never
  let PATH lookup or cron find it by proximity.
- Audit every Jinja variable referenced in an executable template: each one
  is an RCE sink if tainted.
"""

    def _fix_lineinfile_no_backup_on_sensitive_file(self, code_snippet: str) -> str:
        return f"""
**⚠️  Editing a sensitive file with backup: no:**
```yaml
{code_snippet}
```

**🚨 Why this matters:**
A `lineinfile:` or `blockinfile:` edit on /etc/sudoers, /etc/ssh/sshd_config,
/etc/passwd, /etc/shadow, /etc/pam.d/*, /etc/crontab, /etc/cron.d/*, or
/etc/security/* with `backup: no` means a typo locks the admin out of the
system with no on-host rollback. Sudoers syntax errors brick sudo until
console access. sshd_config errors brick SSH after the next `systemctl reload
sshd`. Recovery requires console / IPMI / cloud-provider rescue - slow and
expensive, especially across a fleet.

**✅ Secure fix - backup + validate:**
```yaml
- name: grant passwordless sudo for deploy user
  ansible.builtin.lineinfile:
    path: /etc/sudoers.d/deploy
    line: "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl"
    mode: '0440'
    owner: root
    group: root
    backup: yes                         # <-- rollback file on disk
    validate: 'visudo -cf %s'           # <-- fail-before-commit check

- name: enable PubkeyAuthentication
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: '^#?\\s*PubkeyAuthentication'
    line: 'PubkeyAuthentication yes'
    backup: yes
    validate: '/usr/sbin/sshd -t -f %s' # <-- sshd syntax check
  notify: reload sshd
```

**🔐 Per-file validate commands you should know:**
- `/etc/sudoers*` -> `visudo -cf %s`
- `/etc/ssh/sshd_config` -> `/usr/sbin/sshd -t -f %s`
- `/etc/nginx/*` -> `nginx -t -c %s`
- `/etc/httpd/httpd.conf` -> `/usr/sbin/httpd -f %s -t`
- `/etc/cron.d/*` -> `crontab -c -u root -T %s` (if cronie)
- `/etc/nftables.conf` -> `nft -c -f %s`

**🔐 Defense-in-depth:**
- Prefer `ansible.builtin.template:` over `lineinfile:` for whole-file
  management where possible - whole-file diffs are easier to review.
- For fleet-wide edits, stage the change on one canary host, SSH in manually
  to verify, THEN roll out.
"""
