#!/usr/bin/env python3
"""Remediations for vault-hygiene patterns."""

from .base import BaseRemediationGenerator


class VaultHygieneRemediationGenerator(BaseRemediationGenerator):
    _FIX_MAP = {
        "ask_vault_pass_skipped_in_ci": "_fix_ci_tmp_pw",
        "plaintext_password_should_be_vaulted": "_fix_plaintext_secret",
        "unencrypted_vault_file": "_fix_unencrypted_vault_file",
        "vault_id_hardcoded_in_plaintext": "_fix_vault_id_hardcoded",
        "vault_password_file_in_repo": "_fix_password_file_in_repo",
        "vault_password_in_env_var_literal": "_fix_password_literal_env",
    }

    def generate_vault_hygiene_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._fix_generic)

    def _fix_password_file_in_repo(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```ini
{snip}
```

**🚨 Vault password file lives inside the repo:**
If the password file is committed (even once, even by mistake), the vault is decrypted for everyone with repo read access - forever.

**✅ Secure Fix - Store the password file outside the repo:**
```ini
[defaults]
vault_password_file = ~/.config/ansible/vault_pass
```

**✅ Or use a script that queries a secrets manager:**
```ini
[defaults]
vault_password_file = ./scripts/get_vault_pass.sh
```
```bash
#!/bin/sh
# scripts/get_vault_pass.sh - this script IS committed; the password it prints is not
op read "op://vault/ansible/password"      # 1Password CLI
# or: aws secretsmanager get-secret-value --secret-id ansible/vault --query SecretString --output text
```

**🔐 Hardening:**
- Add `vault_pass`, `.vault_pass`, `*_vault_password*` to .gitignore.
- CI check: grep repo for `$ANSIBLE_VAULT` strings outside expected files.
- Rotate the vault password immediately if it was ever committed.
"""

    def _fix_password_literal_env(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Vault password assigned as literal:**
Setting ANSIBLE_VAULT_PASSWORD(_FILE) inline puts the password in the same place as the data it's supposed to protect.

**✅ Secure Fix - Prompt or read from secret manager:**
```bash
ansible-playbook site.yml --ask-vault-pass

# or via a secret-manager-backed file:
export ANSIBLE_VAULT_PASSWORD_FILE=~/.config/ansible/vault_pass_from_1password
ansible-playbook site.yml
```

**✅ From a CI secret:**
```yaml
# .github/workflows/deploy.yml
- name: run ansible
  env:
    ANSIBLE_VAULT_PASSWORD_FILE: /dev/fd/63           # process substitution
  run: ansible-playbook site.yml \\
    --vault-password-file <(echo "${{{{ secrets.ANSIBLE_VAULT_PW }}}}")
```

**🔐 Hardening:**
- Never put literal vault passwords in playbooks, vars files, or env files that are committed.
- Prefer fd-based process substitution over temp files (password never lands on disk).
"""

    def _fix_plaintext_secret(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Plaintext secret in a `*_password` / `*_secret` / `*_token` variable:**
The variable name itself signals it's a secret, but the value is a literal string committed to version control.

**✅ Secure Fix 1 - Encrypt the single value:**
```bash
ansible-vault encrypt_string 'actual-password' --name 'db_password'
```
```yaml
db_password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  66383439653...
```

**✅ Secure Fix 2 - Separate plaintext references from vault storage:**
```yaml
# group_vars/all/vars.yml (plaintext, committed)
db_password: "{{{{ vault_db_password }}}}"

# group_vars/all/vault.yml (encrypted, committed)
# First run: ansible-vault encrypt group_vars/all/vault.yml
vault_db_password: actual-password
```

**✅ Secure Fix 3 - Fetch from a secrets manager at runtime:**
```yaml
- name: load db password from secrets manager
  ansible.builtin.set_fact:
    db_password: "{{{{ lookup('amazon.aws.aws_secret', 'prod/db/password', region='us-east-1') }}}}"
  no_log: true
```

**🔐 Hardening:**
- Pre-commit: reject any commit that contains `*_password:`/`*_secret:` followed by a non-Jinja, non-vault value.
- Rotate any previously-committed secret and audit who had repo read access.
"""

    def _fix_vault_id_hardcoded(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```ini
{snip}
```

**🚨 vault_identity_list enumerates every vault ID in one line:**
Concentrates many vault passwords' file paths in one config line. Leak of this config = map of every vault file.

**✅ Secure Fix - Dynamic per-ID lookup via a script:**
```ini
[defaults]
vault_identity_list = prod@./scripts/vault_pw_by_id.sh
```
```bash
#!/bin/sh
# ./scripts/vault_pw_by_id.sh
case "$1" in
  --vault-id=prod@prompt) read -s pw; echo "$pw" ;;
  --vault-id=prod@*) op read "op://ansible/prod/password" ;;
  --vault-id=stage@*) op read "op://ansible/stage/password" ;;
  *) echo "unknown vault id: $1" >&2; exit 1 ;;
esac
```

**🔐 Hardening:**
- Short vault_identity_list (1-2 entries).
- Secret-manager-backed scripts instead of static password files.
"""

    def _fix_ci_tmp_pw(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```bash
{snip}
```

**🚨 Vault password written to /tmp:**
Even with best-effort cleanup, the password lands on disk during the run. A crashed CI job, a shared runner, or another tenant can read it.

**✅ Secure Fix - Use process substitution (fd-based):**
```bash
ansible-playbook site.yml \\
  --vault-password-file <(echo "$ANSIBLE_VAULT_PW")
```

**✅ Secure Fix - Use a pipe, not a file:**
```bash
printf '%s\\n' "$ANSIBLE_VAULT_PW" | ansible-playbook site.yml --vault-password-file /dev/stdin
```

**✅ Secure Fix - In GitHub Actions, use the secret-backed env var directly:**
```yaml
env:
  ANSIBLE_VAULT_PASSWORD_FILE: /proc/self/fd/0
run: |
  printf '%s\\n' "${{{{ secrets.ANSIBLE_VAULT_PW }}}}" | ansible-playbook site.yml
```

**🔐 Hardening:**
- Never write the vault password to /tmp, $TMPDIR, or $RUNNER_TEMP.
- Rotate if your CI has ever written it to disk on a shared runner.
"""

    def _fix_unencrypted_vault_file(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 File named `*vault*.yml` but content appears unencrypted:**
Name signals intent to vault; contents don't match. Commonly a developer forgot to run `ansible-vault encrypt` or copied an example template.

**✅ Secure Fix - Encrypt it now:**
```bash
ansible-vault encrypt group_vars/all/vault.yml
head -1 group_vars/all/vault.yml     # must show: $ANSIBLE_VAULT;1.1;AES256
```

**✅ Prevent recurrence - pre-commit hook:**
```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: vault-encrypted
      name: reject unencrypted *vault*.yml
      entry: |
        bash -c '
          for f in "$@"; do
            case "$f" in
              *vault*.yml|*vault*.yaml|*secrets*.yml)
                head -1 "$f" | grep -q "^\\$ANSIBLE_VAULT" || {{ echo "Unencrypted: $f"; exit 1; }}
                ;;
            esac
          done' --
      language: system
      files: '(vault|secrets).*\\.ya?ml$'
```

**🔐 Hardening:**
- File-name-based naming convention: `*vault*.yml` / `*secrets*.yml` must always be encrypted.
- Rotate any values that were ever committed unencrypted.
"""

    def _fix_generic(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Vault hygiene issue detected.**

**✅ Secure Defaults:**
- Vault password files live OUTSIDE the repo.
- Secret vars live inside vault-encrypted files (`$ANSIBLE_VAULT;1.1;AES256` header).
- CI reads the vault password from a secrets manager, never from a literal string.

**🔐 Hardening:**
- Pre-commit hook rejects unencrypted `*vault*.yml`.
- Pre-commit hook rejects `*_password:`/`*_secret:` with literal values.
"""
