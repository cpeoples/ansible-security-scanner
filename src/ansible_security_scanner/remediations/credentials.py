#!/usr/bin/env python3
"""
Credentials remediation generator for Ansible Security Scanner
"""

import os
import re

from .base import BaseRemediationGenerator


class CredentialsRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for hardcoded credentials"""

    def generate_hardcoded_credentials_fix(
        self, code_snippet: str, var_name: str, env_var: str
    ) -> str:
        """Generate fix for hardcoded credentials using actual code context"""

        # Analyze the actual code to provide contextual fixes
        return self._generate_contextual_credential_fix(code_snippet, var_name, env_var)

    def generate_webhook_exposure_fix(self, code_snippet: str, var_name: str, env_var: str) -> str:
        """Generate fix for webhook URL exposure"""

        vault_var = self._get_vault_var_name(var_name)

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Webhook URL Exposure:**
Webhook URLs often contain embedded tokens or secrets that should not be exposed in plaintext.

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook:
{var_name}: "{{{{ {vault_var} }}}}"

# Create vault file:
# ansible-vault create group_vars/all/vault.yml
# Add: {vault_var}: your_actual_webhook_url
```

**✅ Alternative Fix (environment variables):**
```yaml
{var_name}: "{{{{ lookup('env', '{env_var}') }}}}"
```

**✅ Best Fix (Use vaulted variables):**
```yaml
# In group_vars/all/vault.yml (encrypted):
{vault_var}: "your_actual_webhook_url_here"

# In your playbook:
{var_name}: "{{{{ {vault_var} }}}}"
```

**🔗 Webhook Security:**
- Use HTTPS webhooks only
- Implement webhook signature verification
- Consider IP whitelisting for webhook endpoints
- Use separate webhooks for different environments
"""

        return template

    # Param names that signal a secret. Mirrors the `url_encoded_credentials`
    # regex keyword set so the remediation's "secret" classification stays in
    # lock-step with the detector. Adjust in both places if you widen either.
    _SECRET_KEYWORDS = (
        "token",
        "key",
        "secret",
        "auth",
        "credential",
        "pass",
        "pwd",
        "password",
        "login",
        "session",
        "bearer",
        "oauth",
        "jwt",
        "api",
        "access",
        "refresh",
        "csrf",
        "xsrf",
        "verification",
        "reset",
        "activation",
        "confirmation",
    )

    @classmethod
    def _is_secret_param(cls, name: str) -> bool:
        n = name.lower()
        return any(kw in n for kw in cls._SECRET_KEYWORDS)

    @staticmethod
    def _is_already_templated(value: str) -> bool:
        """True when a form-field value is already a Jinja reference.

        We do not want the remediation to rewrite `{{ FOO }}` to
        `{{ vault_foo }}` - the author already parameterized that field and
        churning through it adds noise without improving security."""
        v = value.strip()
        return v.startswith("{{") and v.endswith("}}")

    def generate_form_data_fix(self, code_snippet: str, var_name: str, env_var: str) -> str:
        """Generate fix for complex form data with multiple parameters"""

        # Form parameters are split by `&`. Non-greedy match on the value up
        # to the next `&` or end of string; do NOT terminate on `'` or `"` -
        # those appear inside Jinja filters (e.g. `{{ x | urlsplit('host') }}`)
        # and would otherwise truncate values. The trailing value may include
        # the YAML string's closing quote when `code_snippet` is a raw line
        # like `body: "a=1&b=2"`, so strip a single trailing quote if present.
        form_params = [
            (k, v.rstrip('"').rstrip("'"))
            for k, v in re.findall(r"(\w+)=([^&]+?)(?=&|$)", code_snippet)
        ]

        if not form_params:
            return self.generate_hardcoded_credentials_fix(code_snippet, var_name, env_var)

        # Split into fields that need a vault-backed replacement vs. fields
        # that are either already Jinja-referenced or not secret-looking.
        # Only the former get vaultized; the latter are kept verbatim so the
        # remediation is an actionable minimum-diff, not a "rewrite every
        # field" boilerplate.
        secret_fields: list[tuple[str, str, str]] = []
        passthrough_fields: list[tuple[str, str]] = []
        for param, value in form_params:
            if self._is_secret_param(param) and not self._is_already_templated(value):
                vault_var = f"vault_{param.lower()}"
                secret_fields.append((param, vault_var, value))
            else:
                passthrough_fields.append((param, value))

        # If nothing looked like a secret after filtering (e.g. author already
        # templated the only real secret), fall back to the generic fix so we
        # never drop the remediation entirely.
        if not secret_fields:
            return self.generate_hardcoded_credentials_fix(code_snippet, var_name, env_var)

        credential_info = self._get_credential_type_info("form_data")

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 {credential_info["name"]} Detected:**
{credential_info["description"]} This form contains {len(secret_fields)} secret parameter(s) that must be moved out of the request body.

**Secret Parameters Found:**"""

        for param, vault_var, value in secret_fields:
            display = value[:10] + ("..." if len(value) > 10 else "")
            template += f"""
- **{param}**: `{display}` -> `{{{{ {vault_var} }}}}`"""

        if passthrough_fields:
            template += "\n\n**Non-secret Parameters (kept as-is):**"
            for param, value in passthrough_fields:
                display = value[:40] + ("..." if len(value) > 40 else "")
                template += f"""
- **{param}**: `{display}`"""

        template += """

**✅ Secure Fix (ansible-vault):**
```yaml
# Replace the inline body string with a structured `body:` map so each
# field is explicit and individually auditable. Only the secret fields
# are read from Vault; existing Jinja/literal values are preserved.
- name: Submit form with vault-backed secrets
  ansible.builtin.uri:
    url: "{{ target_url }}"
    method: POST
    body_format: form-urlencoded
    body:"""

        for param, vault_var, _ in secret_fields:
            template += f'''
      {param}: "{{{{ {vault_var} }}}}"'''
        for param, value in passthrough_fields:
            # Already-templated values are rendered verbatim; plain literals
            # are double-quoted so the YAML stays valid.
            rendered = value if self._is_already_templated(value) else f'"{value}"'
            template += f"""
      {param}: {rendered}"""

        template += """
    headers:
      Content-Type: "application/x-www-form-urlencoded"
  register: form_response

# In group_vars/all/vault.yml (encrypted with `ansible-vault encrypt`):"""

        for param, vault_var, _value in secret_fields:
            template += f'''
{vault_var}: "your_secure_{param}_here"'''

        template += """
```

**✅ Alternative (environment variables, for CI/CD contexts):**
```yaml
- name: Submit form with env-backed secrets
  ansible.builtin.uri:
    url: "{{ target_url }}"
    method: POST
    body_format: form-urlencoded
    body:"""
        for param, _vault, _ in secret_fields:
            env_var_name = param.upper()
            template += f'''
      {param}: "{{{{ lookup('env', '{env_var_name}') }}}}"'''
        for param, value in passthrough_fields:
            rendered = value if self._is_already_templated(value) else f'"{value}"'
            template += f"""
      {param}: {rendered}"""

        template += f"""
```

**🔐 {credential_info["name"]} Security:**"""

        for advice in credential_info["security_advice"]:
            template += f"\n- {advice}"

        template += "\n"
        return template

    _TOOL_DISPATCH = {
        "mysql": ("vault_mysql_password", "_generate_mysql_fix"),
        "psql": ("vault_postgres_password", "_generate_postgresql_fix"),
        "postgresql": ("vault_postgres_password", "_generate_postgresql_fix"),
        "docker login": ("vault_docker_registry_password", "_generate_docker_fix"),
        "lftp": ("vault_deploy_ftp_password", "_generate_lftp_fix"),
        "rsync": ("vault_backup_password", "_generate_rsync_fix"),
        "sshpass": ("vault_ssh_password", "_generate_sshpass_fix"),
    }

    def generate_command_line_auth_fix(self, code_snippet: str, var_name: str, env_var: str) -> str:
        """Generate remediation for command-line tools with authentication"""
        code_lower = code_snippet.lower()

        for keyword, (vault_var, method_name) in self._TOOL_DISPATCH.items():
            if keyword in code_lower:
                return getattr(self, method_name)(code_snippet, vault_var)

        if "expect" in code_lower and "sftp" in code_lower:
            return self._generate_expect_sftp_fix(code_snippet, "vault_sftp_password")
        if "ssh" in code_lower:
            return self._generate_sshpass_fix(code_snippet, "vault_ssh_password")

        return self._generate_generic_command_fix(
            code_snippet, self._get_vault_var_name(var_name), env_var
        )

    def _generate_mysql_fix(self, code_snippet: str, vault_var: str) -> str:
        """Generate MySQL-specific remediation"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded MySQL Password:**
This command contains a hardcoded MySQL password that should never be stored in plaintext.

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook:
shell: >-
  mysql -u root -p"{{{{ {vault_var} }}}}" -e "YOUR_SQL_COMMANDS_HERE"

# In group_vars/all/vault.yml (encrypted):
{vault_var}: "your_secure_mysql_password_here"
```

**✅ Alternative Fix (environment variables):**
```yaml
shell: >-
  mysql -u root -p"{{{{ lookup('env', 'MYSQL_PASSWORD') }}}}" -e "YOUR_SQL_COMMANDS_HERE"
```

**✅ Best Fix (Use Ansible mysql modules):**
```yaml
# Much better: Use native Ansible MySQL modules
- name: Execute MySQL query
  mysql_query:
    login_user: root
    login_password: "{{{{ {vault_var} }}}}"
    query: "YOUR_SQL_COMMANDS_HERE"
  register: mysql_result
```

**🔐 MySQL Security Best Practices:**
- **Use proper Ansible modules** instead of shell commands where possible
- **Use SSH keys** instead of passwords for remote authentication
- **Enable SSL/TLS** for database connections in production
- **Use connection pooling** and proper timeout settings
- **Implement least-privilege access** - don't use root/admin accounts
- **Enable audit logging** for all database/system access
- **Rotate credentials regularly** and use strong passwords
- **Consider using service accounts** with limited permissions

"""

        return template

    def _generate_postgresql_fix(self, code_snippet: str, vault_var: str) -> str:
        """Generate PostgreSQL-specific remediation"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded PostgreSQL Password:**
This command contains a hardcoded PostgreSQL password that should never be stored in plaintext.

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook:
shell: >-
  PGPASSWORD="{{{{ {vault_var} }}}}" psql -U postgres -c "YOUR_SQL_COMMANDS_HERE"

# In group_vars/all/vault.yml (encrypted):
{vault_var}: "your_secure_postgres_password_here"
```

**✅ Alternative Fix (environment variables):**
```yaml
shell: >-
  PGPASSWORD="{{{{ lookup('env', 'POSTGRES_PASSWORD') }}}}" psql -U postgres -c "YOUR_SQL_COMMANDS_HERE"
```

**✅ Best Fix (Use Ansible postgresql modules):**
```yaml
# Much better: Use native Ansible PostgreSQL modules
- name: Execute PostgreSQL query
  postgresql_query:
    login_user: postgres
    login_password: "{{{{ {vault_var} }}}}"
    query: "YOUR_SQL_COMMANDS_HERE"
  register: postgres_result
```

**🔐 PostgreSQL Security Best Practices:**
- **Use proper Ansible modules** instead of shell commands where possible
- **Use SSH keys** instead of passwords for remote authentication
- **Enable SSL/TLS** for database connections in production
- **Use connection pooling** and proper timeout settings
- **Implement least-privilege access** - don't use root/admin accounts
- **Enable audit logging** for all database/system access
- **Rotate credentials regularly** and use strong passwords
- **Consider using service accounts** with limited permissions

"""

        return template

    def _generate_docker_fix(self, code_snippet: str, vault_var: str) -> str:
        """Generate Docker-specific remediation"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded Docker Registry Password:**
This command contains a hardcoded Docker registry password that should never be stored in plaintext.

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook:
shell: >-
  echo "{{{{ {vault_var} }}}}" | docker login --username your_username --password-stdin your-registry.com

# In group_vars/all/vault.yml (encrypted):
{vault_var}: "your_secure_docker_password_here"
```

**✅ Alternative Fix (environment variables):**
```yaml
shell: >-
  echo "{{{{ lookup('env', 'DOCKER_REGISTRY_PASSWORD') }}}}" | docker login --username your_username --password-stdin
```

**✅ Best Fix (Use Ansible docker modules):**
```yaml
# Much better: Use native Ansible Docker modules
- name: Log into Docker registry
  docker_login:
    registry_url: "your-registry.com"
    username: "your_username"
    password: "{{{{ {vault_var} }}}}"
  register: docker_login_result
```

**🔐 Docker Security Best Practices:**
- **Use proper Ansible modules** instead of shell commands where possible
- **Use SSH keys** instead of passwords for remote authentication
- **Enable SSL/TLS** for database connections in production
- **Use connection pooling** and proper timeout settings
- **Implement least-privilege access** - don't use root/admin accounts
- **Enable audit logging** for all database/system access
- **Rotate credentials regularly** and use strong passwords
- **Consider using service accounts** with limited permissions

"""

        return template

    def _generate_lftp_fix(self, code_snippet: str, vault_var: str) -> str:
        """Generate LFTP-specific remediation"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded FTP Password:**
This command contains a hardcoded FTP password that should never be stored in plaintext.

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook:
shell: >-
  lftp -c "open -u deploy,{{{{ {vault_var} }}}} ftp://files.example.com;; mirror -R /opt/app /production/"

# In group_vars/all/vault.yml (encrypted):
{vault_var}: "your_secure_ftp_password_here"
```

**✅ Alternative Fix (environment variables):**
```yaml
shell: >-
  lftp -c "open -u deploy,{{{{ lookup('env', 'DEPLOY_FTP_PASSWORD') }}}} ftp://files.example.com;; mirror -R /opt/app /production/"
```

**✅ Best Fix (Use Ansible synchronize module):**
```yaml
# Replace lftp with proper Ansible synchronize module:
- name: Sync files to FTP server
  synchronize:
    src: /opt/app/
    dest: /production/
    rsync_opts:
      - "--password-file={{{{ ftp_password_file }}}}"
  delegate_to: "{{{{ ftp_server }}}}"
  vars:
    ftp_server: "files.example.com;"
    ftp_password_file: "/tmp/.ftp_password"

# Create password file securely:
- name: Create FTP password file
  copy:
    content: "{{{{ {vault_var} }}}}"
    dest: "/tmp/.ftp_password"
    mode: '0600'
  no_log: true
```

**🔐 LFTP Security Best Practices:**
- **Use proper Ansible modules** instead of shell commands where possible
- **Use SSH keys** instead of passwords for remote authentication
- **Enable SSL/TLS** for database connections in production
- **Use connection pooling** and proper timeout settings
- **Implement least-privilege access** - don't use root/admin accounts
- **Enable audit logging** for all database/system access
- **Rotate credentials regularly** and use strong passwords
- **Consider using service accounts** with limited permissions

"""

        return template

    def _generate_rsync_fix(self, code_snippet: str, vault_var: str) -> str:
        """Generate Rsync-specific remediation"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded Backup Password:**
This rsync command contains a hardcoded password in the password-file option.

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook:
- name: Create secure password file
  copy:
    content: "{{{{ {vault_var} }}}}"
    dest: "/tmp/.backup_password"
    mode: '0600'
  no_log: true

- name: Sync backups with password file
  shell: >-
    rsync -av /var/backups/ backup@backup.example.com:/backups/ --password-file=/tmp/.backup_password

- name: Remove password file
  file:
    path: "/tmp/.backup_password"
    state: absent

# In group_vars/all/vault.yml (encrypted):
{vault_var}: "your_secure_backup_password_here"
```

**✅ Alternative Fix (environment variables):**
```yaml
- name: Create password file from environment
  copy:
    content: "{{{{ lookup('env', 'BACKUP_PASSWORD') }}}}"
    dest: "/tmp/.backup_password"
    mode: '0600'
  no_log: true

- name: Sync backups
  shell: >-
    rsync -av /var/backups/ backup@backup.example.com:/backups/ --password-file=/tmp/.backup_password
```

**✅ Best Fix (Use Ansible synchronize module):**
```yaml
# Use proper Ansible synchronize module:
- name: Sync backups securely
  synchronize:
    src: /var/backups/
    dest: backup@backup.example.com:/backups/
    rsync_opts:
      - "--password-file={{{{ backup_password_file }}}}"
  vars:
    backup_password_file: "/tmp/.backup_password"

# With proper password file management:
- name: Create backup password file
  copy:
    content: "{{{{ {vault_var} }}}}"
    dest: "{{{{ backup_password_file }}}}"
    mode: '0600'
  no_log: true
```

**🔐 Rsync Security Best Practices:**
- **Use proper Ansible modules** instead of shell commands where possible
- **Use SSH keys** instead of passwords for remote authentication
- **Enable SSL/TLS** for database connections in production
- **Use connection pooling** and proper timeout settings
- **Implement least-privilege access** - don't use root/admin accounts
- **Enable audit logging** for all database/system access
- **Rotate credentials regularly** and use strong passwords
- **Consider using service accounts** with limited permissions

"""

        return template

    def _generate_sshpass_fix(self, code_snippet: str, vault_var: str) -> str:
        """Generate SSHPass-specific remediation"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded SSH Password:**
This command contains a hardcoded SSH password that should never be stored in plaintext.

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook - but consider using SSH keys instead:
shell: >-
  sshpass -p "{{{{ {vault_var} }}}}" scp -o StrictHostKeyChecking=no /var/log/*.log admin@fileserver.example.com:/logs/

# In group_vars/all/vault.yml (encrypted):
{vault_var}: "your_secure_ssh_password_here"
```

**✅ Alternative Fix (environment variables):**
```yaml
shell: >-
  sshpass -p "{{{{ lookup('env', 'SSH_PASSWORD') }}}}" scp -o StrictHostKeyChecking=no /var/log/*.log admin@fileserver.example.com:/logs/
```

**✅ Best Fix (Use SSH keys and Ansible modules):**
```yaml
# Much better: Use SSH keys and native Ansible modules
- name: Copy log files to remote server
  copy:
    src: "{{{{ item }}}}"
    dest: "/logs/"
  delegate_to: "fileserver.example.com"
  with_fileglob:
    - "/var/log/*.log"
  vars:
    ansible_ssh_private_key_file: "{{{{ ssh_private_key_path }}}}"
    ansible_user: "admin"
```

**🔐 SSHPass Security Best Practices:**
- **Use proper Ansible modules** instead of shell commands where possible
- **Use SSH keys** instead of passwords for remote authentication
- **Enable SSL/TLS** for database connections in production
- **Use connection pooling** and proper timeout settings
- **Implement least-privilege access** - don't use root/admin accounts
- **Enable audit logging** for all database/system access
- **Rotate credentials regularly** and use strong passwords
- **Consider using service accounts** with limited permissions

"""

        return template

    def _generate_expect_sftp_fix(self, code_snippet: str, vault_var: str) -> str:
        """Generate Expect/SFTP-specific remediation"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded SFTP Password:**
This expect script contains a hardcoded SFTP password that should never be stored in plaintext.

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook:
shell: >-
  expect -c "spawn sftp files@secure.example.com; expect password; send '{{{{ {vault_var} }}}}\\n'; interact"

# In group_vars/all/vault.yml (encrypted):
{vault_var}: "your_secure_sftp_password_here"
```

**✅ Alternative Fix (environment variables):**
```yaml
shell: >-
  expect -c "spawn sftp files@secure.example.com; expect password; send '{{{{ lookup('env', 'SFTP_PASSWORD') }}}}\\n'; interact"
```

**✅ Best Fix (Use SSH keys and Ansible modules):**
```yaml
# Much better: Use SSH keys and native Ansible modules
- name: Transfer files via SFTP
  sftp:
    host: "secure.example.com"
    username: "files"
    private_key: "{{{{ ssh_private_key_path }}}}"
    src: "{{{{ local_file }}}}"
    dest: "{{{{ remote_path }}}}"
  vars:
    ssh_private_key_path: "/path/to/private/key"
```

**🔐 Expect/SFTP Security Best Practices:**
- **Use proper Ansible modules** instead of shell commands where possible
- **Use SSH keys** instead of passwords for remote authentication
- **Enable SSL/TLS** for database connections in production
- **Use connection pooling** and proper timeout settings
- **Implement least-privilege access** - don't use root/admin accounts
- **Enable audit logging** for all database/system access
- **Rotate credentials regularly** and use strong passwords
- **Consider using service accounts** with limited permissions

"""

        return template

    def _generate_generic_command_fix(self, code_snippet: str, vault_var: str, env_var: str) -> str:
        """Generate generic command-line remediation"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded Credential in Command:**
This command contains hardcoded credentials that should never be stored in plaintext.

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook:
shell: >-
  # Replace hardcoded credentials with vault variables
  your_command_with_{{{{ {vault_var} }}}}

# In group_vars/all/vault.yml (encrypted):
{vault_var}: "your_secure_credential_here"
```

**✅ Alternative Fix (environment variables):**
```yaml
shell: >-
  your_command_with_{{{{ lookup('env', '{env_var}') }}}}
```

**🔐 Command-Line Security Best Practices:**
- **Use proper Ansible modules** instead of shell commands where possible
- **Use SSH keys** instead of passwords for remote authentication
- **Enable SSL/TLS** for database connections in production
- **Use connection pooling** and proper timeout settings
- **Implement least-privilege access** - don't use root/admin accounts
- **Enable audit logging** for all database/system access
- **Rotate credentials regularly** and use strong passwords
- **Consider using service accounts** with limited permissions

"""

        return template

    def _cleanup_temp_files(self):
        """Clean up temporary files"""
        temp_files = ["temp_credentials.py"]
        for temp_file in temp_files:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def _generate_contextual_credential_fix(
        self, code_snippet: str, var_name: str, env_var: str
    ) -> str:
        """Generate contextual fix based on the actual code found"""

        # Detect the specific pattern in the code
        credential_type = self._detect_credential_type(code_snippet)
        credential_info = self._get_credential_type_info(credential_type)

        # Extract actual values and variable names from the code
        extracted_info = self._extract_credential_info(code_snippet)

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 {credential_info["name"]} Detected:**
{credential_info["description"]}

**✅ Secure Fix - Replace with Ansible Vault:**
```yaml
{self._generate_secure_replacement(code_snippet, extracted_info, var_name, env_var)}
```

**✅ Alternative - Use Environment Variables:**
```yaml
{self._generate_env_var_replacement(code_snippet, extracted_info, env_var)}
```

**🔐 Security Best Practices:**"""

        for advice in credential_info["security_advice"]:
            template += f"\n- {advice}"

        template += "\n"
        return template

    def _extract_credential_info(self, code_snippet: str) -> dict:
        """Extract credential information from the code"""
        # Annotated explicitly so static analysis doesn't infer
        # `dict[str, None]` from the initializer and then complain about
        # every later `str` assignment. All four slots are populated later
        # with either a captured regex group (str) or stay None.
        info: dict[str, str | None] = {
            "variable_name": None,
            "credential_value": None,
            "file_path": None,
            "command": None,
        }

        # Extract from echo statements like: echo "API_KEY=value" > /path/file
        echo_pattern = r'echo\s+"([^"]+)"\s*>\s*([^\s]+)'
        echo_match = re.search(echo_pattern, code_snippet)
        if echo_match:
            assignment = echo_match.group(1)
            info["file_path"] = echo_match.group(2)
            if "=" in assignment:
                key, value = assignment.split("=", 1)
                info["variable_name"] = key.strip()
                info["credential_value"] = value.strip()

        # Extract from export statements like: export VAR=value
        export_pattern = r"export\s+([^=]+)=(.+)"
        export_match = re.search(export_pattern, code_snippet)
        if export_match:
            info["variable_name"] = export_match.group(1).strip()
            info["credential_value"] = export_match.group(2).strip().strip("\"'")

        # Extract from YAML assignments like: api_key: "value"
        yaml_pattern = r'([^:]+):\s*["\']([^"\']+)["\']'
        yaml_match = re.search(yaml_pattern, code_snippet)
        if yaml_match:
            info["variable_name"] = yaml_match.group(1).strip()
            info["credential_value"] = yaml_match.group(2).strip()

        # Extract from variable assignments like: VAR=value
        var_pattern = r"([A-Z_][A-Z0-9_]*)=([^\s]+)"
        var_match = re.search(var_pattern, code_snippet)
        if var_match:
            info["variable_name"] = var_match.group(1).strip()
            info["credential_value"] = var_match.group(2).strip()

        return info

    def _generate_secure_replacement(
        self, code_snippet: str, extracted_info: dict, var_name: str, env_var: str
    ) -> str:
        """Generate secure replacement for the vulnerable code"""

        if extracted_info["file_path"] and extracted_info["variable_name"]:
            # For echo statements writing to files
            safe_var_name = extracted_info["variable_name"].lower()
            vault_var = f"vault_{safe_var_name}"

            return f'''- name: create configuration file securely
  ansible.builtin.template:
    src: config.j2
    dest: {extracted_info["file_path"]}
    mode: '0600'
    backup: yes

# Template file (config.j2):
{extracted_info["variable_name"]}={{{{ {vault_var} }}}}

# In group_vars/all/vault.yml (encrypted with ansible-vault):
{vault_var}: "{extracted_info["credential_value"]}"'''

        if "export" in code_snippet.lower():
            # For export statements
            safe_var_name = (
                extracted_info["variable_name"].lower()
                if extracted_info["variable_name"]
                else var_name
            )
            vault_var = f"vault_{safe_var_name}"

            return f'''- name: set environment variable securely
  ansible.builtin.lineinfile:
    path: /etc/environment
    line: "{extracted_info["variable_name"] or var_name.upper()}={{{{ {vault_var} }}}}"
    backup: yes

# In group_vars/all/vault.yml (encrypted with ansible-vault):
{vault_var}: "{extracted_info["credential_value"] or "your_actual_credential"}"'''

        if ":" in code_snippet and "=" not in code_snippet:
            # For YAML assignments
            safe_var_name = (
                extracted_info["variable_name"].lower()
                if extracted_info["variable_name"]
                else var_name
            )
            vault_var = f"vault_{safe_var_name}"

            return f'''{extracted_info["variable_name"] or var_name}: "{{{{ {vault_var} }}}}"

# In group_vars/all/vault.yml (encrypted with ansible-vault):
{vault_var}: "{extracted_info["credential_value"] or "your_actual_credential"}"'''

        # Generic replacement. If `var_name` is still the sentinel
        # "variable_name" (i.e. the extractor could not identify a
        # better name from the surrounding context), pick the first
        # secret-looking token from the snippet itself so the produced
        # example reads `password: "{{ vault_password }}"` rather than
        # the meaningless `variable_name: "{{ vault_variable_name }}"`.
        effective_name = var_name
        if effective_name in ("variable_name", "vault_variable_name"):
            secret_match = re.search(
                r"\b([A-Za-z_][A-Za-z0-9_]*(?:token|key|secret|auth|credential|pass|pwd|password)[A-Za-z0-9_]*)\s*=",
                code_snippet,
                re.IGNORECASE,
            )
            if secret_match:
                effective_name = secret_match.group(1).lower()
        vault_var = f"vault_{effective_name}"
        return f'''{effective_name}: "{{{{ {vault_var} }}}}"

# In group_vars/all/vault.yml (encrypted with ansible-vault):
{vault_var}: "your_actual_credential"'''

    def _generate_env_var_replacement(
        self, code_snippet: str, extracted_info: dict, env_var: str
    ) -> str:
        """Generate environment variable replacement for the vulnerable code"""

        if extracted_info["file_path"] and extracted_info["variable_name"]:
            # For echo statements writing to files
            env_var_name = extracted_info["variable_name"] or env_var

            return f'''- name: create configuration file from environment
  ansible.builtin.template:
    src: config.j2
    dest: {extracted_info["file_path"]}
    mode: '0600'

# Template file (config.j2):
{extracted_info["variable_name"]}={{{{ lookup('env', '{env_var_name}') }}}}

# Set environment variable before running:
# export {env_var_name}="{extracted_info["credential_value"]}"'''

        if "export" in code_snippet.lower():
            # For export statements
            env_var_name = extracted_info["variable_name"] or env_var

            return f'''- name: set environment variable from lookup
  ansible.builtin.lineinfile:
    path: /etc/environment
    line: "{env_var_name}={{{{ lookup('env', '{env_var_name}') }}}}"

# Set source environment variable before running:
# export {env_var_name}="{extracted_info["credential_value"] or "your_actual_credential"}"'''

        # Generic replacement
        return f'''{extracted_info["variable_name"] or "credential"}: "{{{{ lookup('env', '{env_var}') }}}}"

# Set environment variable before running:
# export {env_var}="{extracted_info["credential_value"] or "your_actual_credential"}"'''

    def _generate_gitlab_ci_job_token_leak_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 GitLab CI Job Token Leaked Outside GitLab:**
`CI_JOB_TOKEN`, `CI_REGISTRY_PASSWORD`, `CI_DEPLOY_PASSWORD`, and `CI_JOB_JWT`
authenticate **as the running pipeline**. Sent anywhere outside GitLab they are
full pipeline-identity tokens: they can push packages, read project secrets via
the job-token API (GitLab 16.2+), and trigger downstream pipelines in any
project that trusts this pipeline's job token.

**✅ Secure Fix - never send CI_JOB_TOKEN outside GitLab:**
```yaml
- name: authenticate to GitLab container registry (in-platform only)
  community.docker.docker_login:
    registry_url: "{{{{ lookup('env', 'CI_REGISTRY') }}}}"
    username: "gitlab-ci-token"
    password: "{{{{ lookup('env', 'CI_JOB_TOKEN') }}}}"
  no_log: true
```

**✅ Better - use OIDC for cross-system auth:**
```yaml
# .gitlab-ci.yml
deploy:
  id_tokens:
    VAULT_ID_TOKEN:
      aud: "https://vault.example.com"
  script:
    - export VAULT_TOKEN="$(curl -X POST -d '{{"jwt":"$VAULT_ID_TOKEN","role":"deploy"}}' \\
        https://vault.example.com/v1/auth/jwt/login | jq -r .auth.client_token)"
    - ansible-playbook deploy.yml
```

**🔐 Hardening:**
- Pipeline permissions -> Job token scope: restrict `CI_JOB_TOKEN` to the minimum
  project allowlist (Settings -> CI/CD -> Token Access).
- Never log `$CI_JOB_TOKEN`, `$CI_REGISTRY_PASSWORD`, or `$CI_JOB_JWT` - mark
  tasks with `no_log: true`.
- Prefer ID tokens (OIDC) for anything outside GitLab - they are audience-scoped
  and short-lived by design.
- Reference: https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html
"""

    def _generate_npm_pypi_publish_token_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Publish Token in Plaintext:**
npm automation tokens (`npm_<36 chars>`), PyPI API tokens (`pypi-AgE...`),
`TWINE_PASSWORD`, and `.npmrc` `_authToken` literals can **publish malicious
package versions** under the owning project's name. This is arguably the
highest-impact supply-chain credential - past incidents (ua-parser-js,
event-stream, coa, rc, etc.) show that a single leaked publish token can
compromise millions of downstream installs within hours.

**✅ Secure Fix - inject at runtime via CI secrets:**
```yaml
# GitHub Actions example (.github/workflows/publish.yml)
- name: publish to PyPI via trusted publishing (OIDC, no token)
  uses: pypa/gh-action-pypi-publish@release/v1
  # No password: argument - action exchanges the OIDC token for a short-lived
  # PyPI upload credential that never touches the repo.

- name: publish to npm with provenance
  run: npm publish --provenance --access public
  env:
    NODE_AUTH_TOKEN: ${{{{ secrets.NPM_TOKEN }}}}  # stored in GitHub secrets
```

**✅ If you must use Ansible to publish, load the token from a vault:**
```yaml
- name: publish package
  community.general.npm:
    path: ./pkg
    state: publish
  environment:
    NODE_AUTH_TOKEN: "{{{{ vault_npm_automation_token }}}}"
  no_log: true
```

**🔐 Rotation + trusted publishing:**
- If this token appeared in a commit, **revoke it immediately**:
  - PyPI: Account Settings -> API tokens -> Revoke
  - npm: `npm token revoke <uuid>` (or https://www.npmjs.com/settings/<user>/tokens)
- Migrate to **trusted publishing** (OIDC) - no long-lived publish token to leak:
  - PyPI: https://docs.pypi.org/trusted-publishers/
  - npm (2024+): `npm publish --provenance` + the npm GitHub OIDC provider.
- Enable 2FA on the registry account; configure publish 2FA so a stolen token
  alone cannot push a new version.
"""

    def _generate_ci_secret_exfil_via_printenv_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 CI Environment Exfiltration Primitive:**
`printenv | curl`, `env | base64 | curl`, `env > /tmp/leak`, `jq -n env | nc`,
and `echo "$GITHUB_TOKEN" >> $GITHUB_STEP_SUMMARY` are the **canonical
secret-sweeping tactics** after compromising any build step. They extract
**every** secret the runner has been given:

- `GITHUB_TOKEN` (write access to the repo)
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
- `NPM_TOKEN`, `PYPI_API_TOKEN`, `TWINE_PASSWORD`
- `CI_JOB_TOKEN`, `DOCKER_PASSWORD`, `SLACK_WEBHOOK_URL`
- Any other secret injected via `secrets.*` / `$SECRET_*`.

No production pipeline should ever execute `printenv | <network>`.

**✅ Secure Fix - remove the pattern entirely:**
```yaml
- name: build and test
  ansible.builtin.command: make test
  # Do NOT precede this with `printenv`, `env`, or `set -o posix`.
  # If you need one specific env var for debugging, echo it with redaction:
  environment:
    BUILD_ID: "{{{{ ansible_date_time.epoch }}}}"
```

**✅ Minimize blast radius with per-job secret scoping:**
```yaml
# GitHub Actions
permissions:
  contents: read        # least-privilege token per workflow
jobs:
  publish:
    permissions:
      id-token: write   # scope elevation only to the publish job
      contents: read
```

**🔐 Defence-in-depth:**
- Enable GitHub's **secret scanning + push protection** on the repository.
- Use OIDC (`id-token: write`) to **exchange** for short-lived cloud creds
  instead of storing long-lived API keys in secrets.
- Audit runner logs for `printenv`, `env`, or `set` invocations - `grep -E
  '\\b(printenv|^env\\b|set\\s+-o\\s+posix)'` across CI logs should
  return zero hits in production pipelines.
- Rotate every secret that could have been exposed if this pattern was in place
  historically. Assume compromise until rotation is complete.
- Configure GitHub's `log_scrubbing` / GitLab's `CI_MASK_VARIABLES` so that
  even if a variable is echoed, the value is redacted in logs.
"""
