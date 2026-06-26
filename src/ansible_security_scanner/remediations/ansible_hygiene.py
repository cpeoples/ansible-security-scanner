#!/usr/bin/env python3
"""
Remediation generator for Ansible hygiene issues (no_log, get_url checksum, secrets in comments)
"""

from __future__ import annotations

import re

from .base import BaseRemediationGenerator, _append_keys, _drop_key_lines, _first


class AnsibleHygieneRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation examples for Ansible best-practice hygiene issues"""

    _FIX_MAP = {
        "fss_vault_on_non_secret_value": "_generate_fss_vault_fix",
        "get_url_dest_executable_with_insecure_validate": "_generate_get_url_dest_executable_fix",
        "get_url_no_checksum": "_generate_checksum_fix",
        "ignore_errors_security": "_generate_ignore_errors_fix",
        "ignore_errors_security_task": "_generate_ignore_errors_fix",
        "missing_no_log": "_generate_no_log_fix",
        "no_log_explicitly_false_on_credential_task": "_generate_no_log_explicitly_false_fix",
        "no_log_explicitly_false_on_credential_task_ast": "_generate_no_log_explicitly_false_fix",
        "secret_in_comment": "_generate_secret_comment_fix",
        "set_fact_secret_alias": "_generate_set_fact_secret_alias_fix",
        "tags_never_on_security_task": "_generate_tags_never_security_fix",
    }

    def generate_ansible_hygiene_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_hygiene_fix)

    def _generate_no_log_fix(self, code_snippet: str) -> str:
        fixed = _append_keys(code_snippet, "no_log: true")
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Missing no_log on a Credential Task:**
Without `no_log: true`, Ansible prints the task's resolved arguments - including
the looked-up password/token - to stdout and every log file and callback plugin.

**✅ Secure Fix Example:**
```yaml
{fixed}
```
"""

    def _generate_checksum_fix(self, code_snippet: str) -> str:
        url = (
            _first(code_snippet, r"url\s*:\s*[\"']?((?:\{\{.*?\}\}|[^\s\"'])+)")
            or "{{ download_url }}"
        )
        fixed = _append_keys(
            code_snippet,
            'checksum: "sha256:{{ expected_sha256 }}"',
        )
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Download Without Integrity Verification:**
`{url}` is fetched with no `checksum:`. A compromised mirror or MITM can
silently swap the artifact for a trojanized one.

**✅ Secure Fix Example:**
```yaml
{fixed}
```

Pin `expected_sha256` from the publisher's signed checksum file (vault it for
internal artifacts). `get_url` re-downloads only when the checksum changes.
"""

    def _generate_ignore_errors_fix(self, code_snippet: str) -> str:
        without = _drop_key_lines(code_snippet, "ignore_errors")
        fixed = _append_keys(
            without,
            "register: task_result",
            "failed_when: task_result.rc not in [0]   # set the conditions you actually tolerate",
        )
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 ignore_errors on a Security-Critical Task:**
`ignore_errors` swallows every failure, so a security operation can fail
silently and leave the host in an insecure state while the play reports success.

**✅ Secure Fix Example:**
```yaml
{fixed}
```

Replace the blanket `ignore_errors` with an explicit `failed_when` that names
the conditions you genuinely tolerate, so unexpected failures still stop the play.
"""

    def _generate_set_fact_secret_alias_fix(self, code_snippet: str) -> str:
        alias = _first(code_snippet, r"set_fact\s*:\s*\n\s*([A-Za-z_][\w]*)\s*:") or "secret_value"
        secret_name = alias if alias.startswith(("vault_", "secret_")) else f"vault_{alias}"
        renamed = re.sub(
            rf"(\b){re.escape(alias)}(\s*:)",
            rf"\g<1>{secret_name}\g<2>",
            code_snippet,
            count=1,
        )
        fixed = _append_keys(renamed, "no_log: true")
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 set_fact Aliases a Secret Into a Generic Name:**
Renaming a credential into a generic fact (`{alias}`) defeats name-based
`no_log` heuristics and review greps, so the value leaks downstream unredacted.

**✅ Secure Fix Example:**
```yaml
{fixed}
```

Keep a secret-shaped name (`{secret_name}`) so downstream rules and reviewers
still treat it as a credential, and set `no_log: true` on every task that reads it.
Prefer a vault/secret-store lookup at the consuming task over aliasing entirely.
"""

    def _generate_secret_comment_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Credential Left in a Comment:**
Comments are not redacted by `no_log` and stay in version-control history.

**✅ Secure Fix Example:**
```yaml
# Reference the variable, never the literal value, even in comments:
#     password: "{{{{ vault_service_password }}}}"
# Or use a placeholder:
#     password: "<REDACTED>"
```

Purge any already-committed secret from history with BFG Repo-Cleaner or
`git filter-repo`, then rotate it.
"""

    def _generate_generic_hygiene_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**✅ Secure Fix Example:**
```yaml
# Apply the matching hardening for this task:
#   - add `no_log: true` to tasks handling credentials
#   - add `checksum: "sha256:..."` to every `get_url`
#   - replace `ignore_errors` with an explicit `failed_when`
#   - keep secrets out of comments and generic fact names
{code_snippet}
```
"""

    def _generate_no_log_explicitly_false_fix(self, code_snippet: str) -> str:
        fixed = re.sub(
            r"(no_log\s*:\s*)(?:false|no)\b",
            r"\1true",
            code_snippet,
            count=1,
            flags=re.IGNORECASE,
        )
        if fixed == code_snippet:
            fixed = _append_keys(_drop_key_lines(code_snippet, "no_log"), "no_log: true")
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

**✅ Secure Fix Example:**
```yaml
{fixed}
```

**🔐 If you genuinely need task output for debugging:**
Split the task: run the secret-handling call with `no_log: true` and register
its result, then `debug:` only the non-sensitive fields:
```yaml
- name: show debug info
  ansible.builtin.debug:
    msg: "status={{{{ auth_result.status }}}}, elapsed={{{{ auth_result.elapsed }}}}"
```
"""

    def _generate_get_url_dest_executable_fix(self, code_snippet: str) -> str:
        without = _drop_key_lines(code_snippet, "validate_certs")
        fixed = _append_keys(
            without,
            'checksum: "sha256:{{ expected_sha256 }}"',
            "mode: '0755'",
            "owner: root",
            "group: root",
            "# validate_certs defaults to yes - do NOT set it to no",
        )
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Download-to-Executable-Path With No Certificate Validation:**
`validate_certs: no` disables TLS verification while `dest:` points at a path
that will be executed. An attacker on the network path (or a compromised
mirror) replaces the payload with their own binary and Ansible installs and
runs it.

**✅ Secure Fix Example:**
```yaml
{fixed}
```

**🔐 Hardening checklist:**
1. Always pair get_url with `checksum: sha256:<hex>` (or sha512:).
2. If the upstream publishes a detached signature, verify it with
   `command: gpg --verify file.sig file` BEFORE making it executable.
3. For an internal CA, pin it with `ca_path: /etc/ssl/certs/corp-ca.pem`
   instead of disabling cert validation entirely.
4. Prefer `package:` / `apt:` / `dnf:` / `win_chocolatey:` with a pinned-repo
   channel over download-and-execute.
"""

    def _generate_tags_never_security_fix(self, code_snippet: str) -> str:
        fixed = _drop_key_lines(code_snippet, "tags")
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Security Task Hidden Behind `tags: never`:**
A task tagged `never` is SKIPPED by every `ansible-playbook` invocation unless
the operator passes `--tags never` explicitly. When the task is a hardening
step (firewall, SELinux, CVE patch, audit config), the playbook silently
reports success without applying the security change.

**✅ Secure Fix Example:**
```yaml
{fixed}
  # no `tags: never` - the hardening task now runs on every invocation
```

**🔐 If the task is genuinely optional:**
Use a descriptive tag plus a variable guard instead of `never`:
```yaml
- name: emergency CVE remediation (opt-in)
  ansible.builtin.command: /opt/hardening/cve-2024-xxxx
  when: apply_cve_2024_xxxx_remediation | default(false) | bool
  tags: [emergency, cve-2024-xxxx]
```
...then the operator must explicitly set `-e apply_cve_2024_xxxx_remediation=true`.
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
to begin with - but it obscures the playbook from review, breaks diff-based
audit, and makes real secrets indistinguishable from fake ones.

**✅ Secure Fix Example:**
```yaml
# group_vars/prod.yml - plain, reviewable, diff-friendly
api_url: "https://api.internal.example.com/v2"
api_port: 8443
api_timeout: 30

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

Use inventory groups and `group_vars/<env>/` to split values by environment;
never use `!vault` as a substitute for inventory structure.
"""
