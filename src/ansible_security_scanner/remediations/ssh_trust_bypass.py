#!/usr/bin/env python3
"""
SSH trust-bypass remediation generator.

Covers rules from patterns/ssh_trust_bypass.yml:
  - ssh_stricthostkey_disabled
  - ssh_userknownhosts_devnull
  - ansible_host_key_checking_false
  - ansible_cfg_host_key_checking_false
  - ssh_keyscan_auto_accept
  - ssh_args_disable_host_key
  - ssh_proxycommand_skips_verification
  - winrm_cert_validation_ignore
"""

from .base import BaseRemediationGenerator


class SshTrustBypassRemediationGenerator(BaseRemediationGenerator):
    """Generates remediations for SSH / WinRM trust-bypass patterns."""

    _FIX_MAP = {
        "ansible_cfg_host_key_checking_false": "_generate_ansible_cfg_hostkey_fix",
        "ansible_host_key_checking_false": "_generate_ansible_hostkey_fix",
        "ssh_args_disable_host_key": "_generate_ssh_args_fix",
        "ssh_keyscan_auto_accept": "_generate_keyscan_fix",
        "ssh_proxycommand_skips_verification": "_generate_proxycommand_fix",
        "ssh_stricthostkey_disabled": "_generate_stricthostkey_fix",
        "ssh_userknownhosts_devnull": "_generate_userknownhosts_fix",
        "winrm_cert_validation_ignore": "_generate_winrm_cert_fix",
    }

    def generate_ssh_trust_bypass_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_fix)

    # per-rule fixes

    def _generate_stricthostkey_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 StrictHostKeyChecking=no disables MitM protection:**
With StrictHostKeyChecking=no, the SSH client accepts any public key the target presents on the first connection and silently accepts key changes on subsequent connections. Anyone who can intercept traffic between the controller and the target can impersonate the target and capture credentials, commands, and secrets exchanged over the session.

**✅ Secure Fix 1 - Pre-seed known_hosts from a vetted source:**
```yaml
- name: ship a vetted known_hosts file to the controller user
  hosts: localhost
  gather_facts: false
  tasks:
    - name: copy bundled known_hosts (reviewed in version control)
      ansible.builtin.copy:
        src: known_hosts
        dest: "{{{{ lookup('env','HOME') }}}}/.ssh/known_hosts"
        mode: '0600'
```

**✅ Secure Fix 2 - Use SSH certificates instead of raw host keys:**
```yaml
- name: trust a CA that signs target host keys
  ansible.builtin.lineinfile:
    path: "{{{{ lookup('env','HOME') }}}}/.ssh/known_hosts"
    line: "@cert-authority *.example.com {{{{ target_ca_public_key }}}}"
    create: yes
    mode: '0600'
```

**✅ Secure Fix 3 - If you MUST bootstrap unknown hosts, pin fingerprints:**
```yaml
- name: validate target fingerprint before adding
  ansible.builtin.shell: |
    ssh-keygen -lf <(ssh-keyscan -T 5 -t ed25519 {{{{ inventory_hostname }}}}) | awk '{{{{print $2}}}}'
  register: live_fp
  changed_when: false
  failed_when: live_fp.stdout != expected_fingerprints[inventory_hostname]
```

**🔐 Hardening:**
- Never set `StrictHostKeyChecking=no` for long-lived hosts.
- In CI, pin the known_hosts file in the pipeline artefact and fail the job if ssh-keyscan output differs from the pinned copy.
- Treat any play that disables host-key checking as a one-shot bootstrap play that runs once per host lifetime.
"""

    def _generate_userknownhosts_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 UserKnownHostsFile=/dev/null forgets every host key:**
Every SSH connection becomes trust-on-first-use, with no record of prior keys. A network-adjacent attacker only needs to succeed on one connection to impersonate the target forever - the controller literally has no memory of the real key.

**✅ Secure Fix 1 - Use a real known_hosts file:**
```yaml
- name: use per-user known_hosts (default)
  ansible.builtin.copy:
    dest: "{{{{ lookup('env','HOME') }}}}/.ssh/known_hosts"
    content: |
      {{{{ production_known_hosts_bundle }}}}
    mode: '0600'
```

**✅ Secure Fix 2 - Use a role-shipped known_hosts bundle:**
```yaml
- name: install curated known_hosts for this inventory
  ansible.builtin.copy:
    src: "{{{{ role_path }}}}/files/known_hosts_production"
    dest: /etc/ssh/ssh_known_hosts
    owner: root
    group: root
    mode: '0644'
```

**✅ Secure Fix 3 - Point at a per-environment file via config:**
```ini
# ~/.ssh/config
Host *.prod.example.com
    UserKnownHostsFile ~/.ssh/known_hosts.prod
    StrictHostKeyChecking yes
```

**🔐 Hardening:**
- Remove all `/dev/null` references from ssh args, ansible.cfg, and inventory vars.
- Monitor for host-key changes: diff the production known_hosts file nightly against the pipeline-committed copy.
- Rotate host keys on a schedule and republish the known_hosts bundle as part of the rotation runbook.
"""

    def _generate_ansible_hostkey_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 ansible_host_key_checking=false disables the entire trust layer:**
This single inventory variable turns off host-key verification for every SSH connection Ansible makes within its scope. A malicious host in group_vars/host_vars (or an attacker with write access to the inventory) can completely disable the trust boundary for dozens of hosts at once.

**✅ Secure Fix 1 - Keep host_key_checking on everywhere:**
```yaml
# inventory/group_vars/all.yml
ansible_host_key_checking: true   # default; leave it here explicitly so nobody silently flips it
```

**✅ Secure Fix 2 - Bootstrap play that opts into TOFU once:**
```yaml
- name: one-time bootstrap (populates known_hosts, runs once per host)
  hosts: new_hosts
  gather_facts: false
  vars:
    ansible_host_key_checking: false   # scoped to THIS play only
  tasks:
    - name: collect live fingerprints into controller known_hosts
      ansible.builtin.known_hosts:
        name: "{{{{ inventory_hostname }}}}"
        key: "{{{{ lookup('pipe', 'ssh-keyscan -T 5 ' + inventory_hostname) }}}}"
        state: present

- name: all subsequent plays enforce host-key checking
  hosts: all
  tasks:
    - ansible.builtin.ping:
```

**✅ Secure Fix 3 - Enforce via env var in CI only for bootstrap stages:**
```bash
# CI: bootstrap stage
ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook bootstrap.yml

# CI: all subsequent stages (default)
ansible-playbook deploy.yml
```

**🔐 Hardening:**
- Forbid `ansible_host_key_checking: false` in group_vars/host_vars via a pre-commit grep.
- Audit with: `rg -n 'ansible_host_key_checking\\s*[:=]\\s*(?:false|no|0|off)' .`
- Prefer signed host certificates (`@cert-authority` in known_hosts) so hosts can be rotated without reseeding.
"""

    def _generate_ansible_cfg_hostkey_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```ini
{code_snippet}
```

**🚨 ansible.cfg host_key_checking=False is global:**
Every playbook that runs with this config file disables host-key checking. This is the single worst place to disable it - it catches bootstrap plays, deployment plays, and break-glass plays alike.

**✅ Secure Fix - Remove the line from ansible.cfg:**
```ini
# ansible.cfg
[defaults]
inventory = ./inventory
stdout_callback = default
# host_key_checking is left at its default value of True - do NOT add it here.
```

**✅ Secure Fix - Scope the bypass via env var for bootstrap only:**
```bash
# One-shot bootstrap
ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook plays/bootstrap.yml -l new_hosts

# All normal runs use the default (True)
ansible-playbook plays/site.yml
```

**✅ Secure Fix - Add a CI check that fails if the line reappears:**
```yaml
- name: CI: forbid host_key_checking=False in ansible.cfg
  run: |
    if grep -E '^\\s*host_key_checking\\s*=\\s*(?i:false|no|0|off)' ansible.cfg; then
      echo "host_key_checking=False is forbidden; use ANSIBLE_HOST_KEY_CHECKING env var for bootstrap only"
      exit 1
    fi
```

**🔐 Hardening:**
- Keep ansible.cfg under code review - treat it as security-relevant config.
- Never commit `host_key_checking=False` in a shared ansible.cfg.
- Prefer env-var scoping for the rare cases where a bypass is truly needed.
"""

    def _generate_keyscan_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 `ssh-keyscan >> known_hosts` is TOFU, not verification:**
`ssh-keyscan` returns whatever the network hands back. Appending its output to known_hosts without comparing fingerprints to a trusted source just moves the MitM window from "first connection" to "deploy time" - it does not eliminate it.

**✅ Secure Fix 1 - Compare fingerprints to a committed allow-list:**
```yaml
- name: fetch live host keys
  ansible.builtin.shell: ssh-keyscan -T 5 -t ed25519 {{{{ inventory_hostname }}}}
  register: live_keys
  changed_when: false

- name: compute fingerprints of live keys
  ansible.builtin.shell: |
    echo '{{{{ live_keys.stdout }}}}' | ssh-keygen -lf - | awk '{{{{print $2}}}}'
  register: live_fp
  changed_when: false

- name: fail the play if the fingerprint has drifted
  ansible.builtin.assert:
    that:
      - live_fp.stdout == expected_fingerprints[inventory_hostname]
    fail_msg: "Fingerprint drift on {{{{ inventory_hostname }}}}: got {{{{ live_fp.stdout }}}}"

- name: only now append to known_hosts
  ansible.builtin.known_hosts:
    name: "{{{{ inventory_hostname }}}}"
    key: "{{{{ live_keys.stdout }}}}"
    state: present
```

**✅ Secure Fix 2 - Use ansible.builtin.known_hosts with a pinned key:**
```yaml
- name: add pinned host key (key value reviewed in source control)
  ansible.builtin.known_hosts:
    name: "{{{{ inventory_hostname }}}}"
    key: "{{{{ inventory_hostname }} }} ssh-ed25519 {{{{ pinned_host_keys[inventory_hostname] }}}}"
    state: present
```

**✅ Secure Fix 3 - Out-of-band fingerprint delivery:**
```
# From your cloud provider's console (AWS instance-console-output,
# GCP serial console, etc.), capture the host-key fingerprint at
# instance-creation time and store it in Vault / SSM Parameter Store.
# Then look it up at deploy time instead of ssh-keyscanning.
```

**🔐 Hardening:**
- Treat any unpinned `ssh-keyscan` as an accepted risk with an expiry date.
- Prefer cloud-provider instance metadata for first-boot fingerprints (AWS SendInstanceFingerprints, GCP console logs).
- Automate fingerprint rotation: when you rotate host keys, also republish the allow-list.
"""

    def _generate_ssh_args_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 ansible_ssh_common_args / ansible_ssh_extra_args with trust-bypass flags:**
These inventory variables inject raw ssh command-line flags into every SSH connection. When they contain `-o StrictHostKeyChecking=no` or `-o UserKnownHostsFile=/dev/null`, host-key verification is disabled across the entire inventory scope.

**✅ Secure Fix 1 - Remove the bypass flags:**
```yaml
# inventory/group_vars/all.yml
ansible_ssh_common_args: "-o ServerAliveInterval=30 -o ServerAliveCountMax=2"
# Note: no StrictHostKeyChecking flag - defaults (yes) are used
```

**✅ Secure Fix 2 - Use a per-environment ssh config file instead:**
```yaml
# inventory/group_vars/prod.yml
ansible_ssh_common_args: "-F {{{{ playbook_dir }}}}/ssh/prod.conf"

# ssh/prod.conf (reviewed, committed)
# Host *.prod.example.com
#     UserKnownHostsFile ~/.ssh/known_hosts.prod
#     StrictHostKeyChecking yes
```

**✅ Secure Fix 3 - For bastion flows, use ProxyJump (not nested ssh):**
```yaml
ansible_ssh_common_args: "-J bastion.prod.example.com"
# ssh -J verifies BOTH hops against known_hosts; nested ProxyCommand does not.
```

**🔐 Hardening:**
- CI check: `rg -n 'ansible_ssh_(?:common|extra)_args' | rg -i 'stricthostkeychecking\\s*=\\s*no|userknownhostsfile\\s*=\\s*/dev/null'`
- Keep ssh args in a reviewed ssh config file instead of inline strings in inventory.
- Document every allowed `-o` flag; anything else requires a security review.
"""

    def _generate_proxycommand_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 ProxyCommand with trust-bypass flags hides a MitM on the jump host:**
Outer connection is verified, but the nested ssh invocation through the proxy silently accepts any key. An attacker on the jump-host network can impersonate the target host for the duration of the proxied session.

**✅ Secure Fix 1 - Use native ProxyJump (verifies both hops):**
```ini
# ~/.ssh/config
Host target
    HostName 10.0.1.23
    ProxyJump bastion.example.com   # verifies bastion AND target
    StrictHostKeyChecking yes
```

**✅ Secure Fix 2 - If ProxyCommand is required, keep host-key checks on:**
```ini
Host target
    ProxyCommand ssh -W %h:%p bastion.example.com
    # No StrictHostKeyChecking=no - use the default
```

**✅ Secure Fix 3 - Seed known_hosts for both hops:**
```yaml
- name: seed known_hosts for bastion AND target
  ansible.builtin.known_hosts:
    name: "{{{{ item.name }}}}"
    key: "{{{{ item.key }}}}"
    state: present
  loop:
    - {{ name: "bastion.example.com", key: "{{{{ bastion_pubkey }}}}" }}
    - {{ name: "target.internal",     key: "{{{{ target_pubkey }}}}" }}
```

**🔐 Hardening:**
- Prefer `ProxyJump` over `ProxyCommand` - it verifies each hop.
- Never nest `ssh -o StrictHostKeyChecking=no` inside a ProxyCommand.
- Log both hops: ssh-keygen -lf known_hosts should list both bastion and target.
"""

    def _generate_winrm_cert_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 WinRM cert validation = ignore disables TLS verification:**
Every WinRM connection (TCP 5985/5986) to Windows hosts skips certificate validation. The Windows equivalent of StrictHostKeyChecking=no - attacker on-path can impersonate the WinRM listener and capture NTLM/Kerberos handshakes or credentials.

**✅ Secure Fix 1 - Install a proper CA-signed cert on the WinRM listener:**
```powershell
# Issue a cert from your enterprise CA, bind to WinRM HTTPS listener
$cert = New-SelfSignedCertificate -Subject "CN=target.corp.example.com" -CertStoreLocation Cert:\\LocalMachine\\My
New-Item -Path WSMan:\\Localhost\\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force
```

```yaml
# inventory/group_vars/windows.yml
ansible_connection: winrm
ansible_winrm_transport: kerberos          # or credssp
ansible_winrm_server_cert_validation: validate   # the default
ansible_port: 5986
```

**✅ Secure Fix 2 - Private CA? Import it into the controller trust store:**
```yaml
- name: trust our internal CA on the controller
  ansible.builtin.copy:
    src: files/internal_ca.crt
    dest: /usr/local/share/ca-certificates/internal.crt
    mode: '0644'
  notify: update-ca-certificates
```

**✅ Secure Fix 3 - Pin the cert thumbprint via ansible_winrm_ca_trust_path:**
```yaml
ansible_winrm_server_cert_validation: validate
ansible_winrm_ca_trust_path: "{{{{ playbook_dir }}}}/files/ca-bundle.pem"
```

**🔐 Hardening:**
- Never run Ansible -> Windows over WinRM HTTP (port 5985) in production.
- Require `ansible_winrm_server_cert_validation=validate` in all environments.
- Automate cert rotation with cert-manager or ADCS auto-enrollment so expiry is not a reason to disable validation.
"""

    def _generate_generic_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 SSH/Connection Trust Bypass Detected:**
This playbook disables or weakens host-key or TLS verification for SSH, WinRM, or a proxy hop. Trust-bypass patterns are high-impact MitM enablers because they affect every connection made under that scope.

**✅ Secure Fix:**
- Re-enable the verification knob (`StrictHostKeyChecking=yes`, `ansible_host_key_checking=true`, `ansible_winrm_server_cert_validation=validate`).
- Seed known_hosts / trust anchors from a reviewed, version-controlled source.
- Use cryptographic trust (SSH certificates, CA-signed TLS) instead of TOFU wherever possible.

**🔐 Hardening:**
- Audit all inventory files for bypass knobs weekly.
- Forbid bypass flags in shared config via pre-commit hooks.
- Treat any bypass as a one-shot bootstrap that must be removed after use.
"""
