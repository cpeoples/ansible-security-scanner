#!/usr/bin/env python3
"""
Remediation generator for Ansible hygiene issues (no_log, get_url checksum, secrets in comments)
"""

from .base import BaseRemediationGenerator


class AnsibleHygieneRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation examples for Ansible best-practice hygiene issues"""

    _FIX_MAP = {
        "fss_vault_on_non_secret_value": "_generate_fss_vault_fix",
        "get_url_dest_executable_with_insecure_validate": "_generate_get_url_dest_executable_fix",
        "get_url_no_checksum": "_generate_checksum_fix",
        "ignore_errors_security": "_generate_ignore_errors_fix",
        "missing_no_log": "_generate_no_log_fix",
        "no_log_explicitly_false_on_credential_task": "_generate_no_log_explicitly_false_fix",
        "no_log_explicitly_false_on_credential_task_ast": "_generate_no_log_explicitly_false_fix",
        "secret_in_comment": "_generate_secret_comment_fix",
        "tags_never_on_security_task": "_generate_tags_never_security_fix",
    }

    def generate_ansible_hygiene_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_hygiene_fix)

    def _generate_no_log_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
```yaml
- name: Authenticate to service
  ansible.builtin.uri:
    url: "https://api.example.com/auth"
    method: POST
    body_format: json
    body:
      username: "{{{{ service_user }}}}"
      password: "{{{{ vault_service_password }}}}"
  no_log: true   # <-- prevents credentials from appearing in logs
  register: auth_result
```

**Why this matters:** Without `no_log: true`, Ansible prints the full task parameters (including passwords and tokens) to stdout and log files.
"""

    def _generate_checksum_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
```yaml
- name: Download binary with integrity verification
  get_url:
    url: "https://releases.example.com/v1.2.3/binary_amd64.tar.gz"
    dest: /tmp/binary.tar.gz
    checksum: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

**Why this matters:** Without `checksum:`, a compromised CDN/mirror or MITM attack can silently replace the download with a trojanized binary.
"""

    def _generate_ignore_errors_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
```yaml
- name: Verify TLS certificate
  ansible.builtin.command: openssl verify /etc/ssl/cert.pem
  register: cert_result
  failed_when: cert_result.rc != 0
  # Never use ignore_errors on security-critical tasks
```

**Why this matters:** Using `ignore_errors: yes` on security-sensitive operations silently swallows failures, leaving the system in an insecure state.
"""

    def _generate_secret_comment_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
```yaml
# Use variable references even in comments:
#     password: "{{{{ vault_service_password }}}}"
# Or simply use a placeholder:
#     password: "<REDACTED>"
```

**Why this matters:** Credentials in comments remain visible in version control history. Use `git filter-branch` or BFG Repo-Cleaner to purge them from history.
"""

    def _generate_generic_hygiene_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
- Add `no_log: true` to tasks handling credentials
- Add `checksum:` to all `get_url` tasks
- Remove hardcoded credentials from comments
- Never use `ignore_errors` on security-critical tasks
"""

    def _generate_no_log_explicitly_false_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 no_log: false Defeats the Entire Log-Suppression Contract:**
Setting `no_log: false` (or `no`) explicitly tells Ansible to print the task's
resolved arguments on every run - including the looked-up vault/secret values.
Every callback plugin (stdout, syslog, Splunk, Slack, Datadog) receives the
plaintext. In CI, the artifact is typically retained for weeks.

**✅ Secure Fix:**
```yaml
- name: authenticate to service
  ansible.builtin.uri:
    url: "https://api.example.com/auth"
    method: POST
    body_format: json
    body:
      username: "{{{{ service_user }}}}"
      password: "{{{{ vault_service_password }}}}"
  no_log: true       # <-- redact the entire task result
  register: auth_result
```

**🔐 If you genuinely need task output for debugging:**
Split the task: run the secret-handling call with `no_log: true` and register
its result, then `debug:` only the non-sensitive fields:
```yaml
- name: show debug info
  ansible.builtin.debug:
    msg: "status={{{{ auth_result.status }}}}, elapsed={{{{ auth_result.elapsed }}}}"
```

**🔐 Related hardening:**
- Encrypt the secret at rest: `ansible-vault encrypt_string`.
- Pair with `ANSIBLE_NO_LOG=True` as a CI environment variable so debug runs
  still redact.
"""

    def _generate_get_url_dest_executable_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Download-to-Executable-Path With No Certificate Validation:**
`validate_certs: no` disables TLS verification; `dest:` points at a path that
will be executed (e.g., /usr/local/bin/, /opt/, /tmp/*.sh). An attacker on the
network path (or a compromised mirror) replaces the payload with their own
binary - Ansible happily installs and runs it. This is the xz-utils /
shai-hulud / tj-actions attack pattern applied to a playbook.

**✅ Secure Fix:**
```yaml
- name: fetch installer with integrity + cert validation
  ansible.builtin.get_url:
    url: "https://releases.example.com/v1.2.3/installer.sh"
    dest: "/usr/local/bin/installer.sh"
    checksum: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    mode: '0755'
    owner: root
    group: root
    # validate_certs defaults to yes - do NOT set it to no
```

**🔐 Hardening checklist:**
1. Always pair get_url with `checksum: sha256:<hex>` (or sha512:).
2. If the upstream publishes a detached signature, verify it with
   `command: gpg --verify file.sig file` BEFORE making it executable.
3. If the target uses an internal CA, pin it with `ca_path: /etc/ssl/certs/corp-ca.pem`
   instead of disabling cert validation entirely.
4. Prefer `package:` / `apt:` / `dnf:` / `win_chocolatey:` with a pinned-repo
   channel over download-and-execute.
"""

    def _generate_tags_never_security_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Security Task Hidden Behind `tags: never`:**
A task tagged `never` is SKIPPED by every `ansible-playbook` invocation unless
the operator passes `--tags never` explicitly. When the task is a hardening
step (firewall, SELinux, CVE patch, audit config), the playbook silently
reports success without applying the security change. This is defense-in-depth
disabled by default - the worst-of-both-worlds: the code is there, it passes
review, and it never runs.

**✅ Secure Fix (make the task run by default):**
```yaml
- name: apply kernel hardening (CIS 1.5.x)
  ansible.builtin.copy:
    src: sysctl-hardening.conf
    dest: /etc/sysctl.d/99-hardening.conf
    mode: '0644'
  notify: reload sysctl
  # no tags - task runs on every playbook invocation
```

**🔐 If the task is genuinely optional:**
Use a descriptive tag, a variable guard, AND document the opt-in in the role
README:
```yaml
- name: emergency CVE-2024-XXXX remediation (opt-in)
  ansible.builtin.command: /opt/hardening/cve-2024-xxxx
  when: apply_cve_2024_xxxx_remediation | default(false) | bool
  tags: [emergency, cve-2024-xxxx]
```
...then the operator must explicitly set `-e apply_cve_2024_xxxx_remediation=true`
to run it - no magic tag required.

**🔐 Auditing for this pattern across your codebase:**
```bash
# find every `tags: never` anywhere in your playbooks
rg -n '^\\s*tags:\\s*(?:never\\b|\\[.*never.*\\])' roles/ playbooks/
```
"""

    def _generate_fss_vault_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code (vault on non-secret value):**
```yaml
{code_snippet}
```

**🚨 False-Sense-of-Security:**
A hostname, port, URL, path, timeout, or version number is not a secret.
Wrapping it in `!vault` doesn't protect anything - the value wasn't sensitive
to begin with - but it:

1. Obscures the playbook from review (reviewers can't see what IP / URL the
   code actually targets without decrypting).
2. Breaks diff-based audit (every environment change looks like a vault
   rotation).
3. Creates a FALSE sense of security: real secrets and fake secrets become
   indistinguishable, so the real ones stop getting extra scrutiny
   (rotation, access audits, separate vault keys per environment).

**✅ Secure Fix (plain YAML for non-secrets):**
```yaml
# group_vars/prod.yml - plain, reviewable, diff-friendly
api_url: "https://api.internal.corp/v2"
api_port: 8443
api_timeout: 30
```

```yaml
# group_vars/prod/vault.yml - vault ONLY for secrets
api_token: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  6162636465...
```

**🔐 What belongs in a vault (and what doesn't):**

| Vault-worthy                       | Plain YAML                       |
|------------------------------------|----------------------------------|
| Passwords, API tokens, client      | Hostnames, URLs, ports, paths    |
| secrets, private keys, DB creds,   | Timeouts, counts, versions,      |
| TLS key material, OAuth client     | feature flags, region/zone       |
| secrets, session signing keys      | names, protocol choices          |

**🔐 Per-environment separation WITHOUT encrypting non-secrets:**
Use inventory groups and `group_vars/<env>/` to split values by environment.
Never use `!vault` as a substitute for inventory structure.
"""
