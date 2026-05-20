#!/usr/bin/env python3
"""
Template injection remediation generator for Ansible Security Scanner
"""

from .base import BaseRemediationGenerator


class TemplateInjectionRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for template injection patterns"""

    _FIX_MAP = {
        "template_command_substitution": "_generate_command_substitution_fix",
        "template_in_file_path": "_generate_path_traversal_fix",
        "template_in_sql_query": "_generate_sql_injection_fix",
        "template_in_url": "_generate_jinja2_fix",
        "unquoted_template_variable": "_generate_jinja2_fix",
        "user_input_template": "_generate_shell_injection_fix",
        # Jinja / lookup RCE family
        "jinja_in_assert_msg": "_generate_jinja_in_assert_fix",
        "jinja_in_set_fact_unsafe": "_generate_jinja_in_set_fact_fix",
        "jinja_in_when_clause": "_generate_jinja_in_when_fix",
        "jinja_statement_block_lookup": "_generate_jinja_statement_block_fix",
        "lookup_env_leak": "_generate_lookup_env_fix",
        "lookup_file_traversal": "_generate_lookup_file_fix",
        "lookup_password_write_world_readable": "_generate_lookup_password_fix",
        "lookup_pipe_rce": "_generate_lookup_pipe_fix",
        "lookup_url_rce": "_generate_lookup_url_fix",
        "unsafe_tag_bypass": "_generate_unsafe_tag_fix",
        # Jinja2 *.j2 template hardening
        "jinja2_autoescape_false": "_generate_jinja2_autoescape_off_fix",
        "jinja2_comment_contains_todo_secret": "_generate_jinja2_todo_comment_fix",
        "jinja2_eval_via_attr": "_generate_jinja2_sandbox_escape_fix",
        "jinja2_lookup_pipe_in_template": "_generate_jinja2_lookup_in_template_fix",
        "jinja2_render_sensitive_var": "_generate_jinja2_render_secret_fix",
        "jinja2_safe_filter_on_user_input": "_generate_jinja2_safe_filter_fix",
        "jinja2_set_from_env": "_generate_jinja2_set_env_fix",
        # YAML schema abuse
        "yaml_anchor_bomb_potential": "_generate_yaml_anchor_bomb_fix",
        "yaml_binary_tag_on_executable": "_generate_yaml_binary_tag_fix",
        "yaml_duplicate_key_suppression": "_generate_yaml_duplicate_key_fix",
        "yaml_merge_key_with_secret": "_generate_yaml_merge_secret_fix",
        "yaml_python_object_tag": "_generate_yaml_python_object_fix",
        "yaml_unsafe_tag_generic": "_generate_yaml_unsafe_tag_fix",
    }

    def generate_template_injection_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_injection_fix)

    def _generate_jinja2_fix(self, code_snippet: str) -> str:
        """Generate fix for unsafe Jinja2 template usage"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Jinja2 Template Injection Risk:**
Unsafe use of Jinja2 templates with user input can lead to template injection attacks and code execution.

**✅ Secure Fix - Safe Template Usage:**
```yaml
- name: use safe template with input validation
  ansible.builtin.template:
    src: safe_template.j2
    dest: "{{{{ config_path }}}}"
    backup: yes
    mode: '0644'
  vars:
    # Validate and sanitize input variables
    safe_username: "{{{{ username | regex_replace('[^a-zA-Z0-9_-]', '') }}}}"
    safe_hostname: "{{{{ hostname | regex_replace('[^a-zA-Z0-9.-]', '') }}}}"
    safe_port: "{{{{ port | int | default(8080) }}}}"
  when:
    - username is defined
    - hostname is defined
    - username | length > 0
    - hostname | length > 0

- name: validate template variables
  ansible.builtin.assert:
    that:
      - safe_username | length > 0
      - safe_hostname | length > 0
      - safe_port | int > 0
      - safe_port | int < 65536
    fail_msg: "Invalid template variables provided"
```

**✅ Safe Template File (safe_template.j2):**
```jinja2
# Safe template with escaped variables
server_name = {{{{ safe_hostname | quote }}}}
listen_port = {{{{ safe_port | int }}}}
user = {{{{ safe_username | quote }}}}

# Use filters to prevent injection
log_file = /var/log/{{{{ safe_username | regex_replace('[^a-zA-Z0-9_-]', '') }}}}.log

# Avoid dangerous filters like |safe or |raw
config_value = "{{{{ user_input | quote | replace('"', '\\"') }}}}"
```

**✅ Alternative - Use Structured Data:**
```yaml
- name: use structured configuration instead of templates
  ansible.builtin.copy:
    content: "{{{{ app_config | to_nice_json }}}}"
    dest: /etc/app/config.json
    backup: yes
    mode: '0644'
  vars:
    app_config:
      server:
        hostname: "{{{{ hostname | regex_replace('[^a-zA-Z0-9.-]', '') }}}}"
        port: "{{{{ port | int | default(8080) }}}}"
      user:
        name: "{{{{ username | regex_replace('[^a-zA-Z0-9_-]', '') }}}}"
        home: "/home/{{{{ username | regex_replace('[^a-zA-Z0-9_-]', '') }}}}"
```

**🔐 Jinja2 Security Best Practices:**
- Always validate and sanitize template variables
- Use appropriate Jinja2 filters (quote, regex_replace, int)
- Avoid |safe and |raw filters with user input
- Use structured data formats (JSON, YAML) when possible
- Implement input validation before template processing
- Never allow user-controlled template content
"""

    def _generate_shell_injection_fix(self, code_snippet: str) -> str:
        """Generate fix for shell injection in templates"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Shell Injection in Template:**
This template allows shell command injection through unsanitized variables.

**✅ Secure Fix - Safe Command Execution:**
```yaml
- name: use ansible modules instead of shell commands
  ansible.builtin.systemd:
    name: "{{{{ service_name | regex_replace('[^a-zA-Z0-9_-]', '') }}}}"
    state: started
    enabled: yes
  when:
    - service_name is defined
    - service_name | regex_search('^[a-zA-Z0-9_-]+$')

- name: safe file operations
  ansible.builtin.file:
    path: "/var/log/{{{{ app_name | regex_replace('[^a-zA-Z0-9_-]', '') }}}}.log"
    state: touch
    mode: '0644'
    owner: "{{{{ app_user | regex_replace('[^a-zA-Z0-9_-]', '') }}}}"
  when:
    - app_name is defined
    - app_user is defined
```

**✅ Alternative - Use Command Module with Args:**
```yaml
- name: execute command safely with validated arguments
  ansible.builtin.command:
    cmd: "{{{{ base_command }}}}"
    argv:
      - "{{{{ validated_arg1 }}}}"
      - "{{{{ validated_arg2 }}}}"
  vars:
    base_command: /usr/bin/safe-tool
    validated_arg1: "{{{{ user_input1 | regex_replace('[^a-zA-Z0-9_-]', '') }}}}"
    validated_arg2: "{{{{ user_input2 | regex_replace('[^a-zA-Z0-9._-]', '') }}}}"
  when:
    - validated_arg1 | length > 0
    - validated_arg2 | length > 0
  register: command_result

- name: validate command execution
  ansible.builtin.assert:
    that:
      - command_result.rc == 0
    fail_msg: "Command execution failed"
```

**🔐 Shell Injection Prevention:**
- Use Ansible modules instead of shell commands when possible
- Validate and sanitize all variables used in commands
- Use the command module with argv for safe argument passing
- Implement strict input validation with regex patterns
- Never concatenate user input directly into shell commands
- Use quotes and proper escaping for string values
"""

    def _generate_sql_injection_fix(self, code_snippet: str) -> str:
        """Generate fix for SQL injection in templates"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 SQL Injection in Template:**
This template constructs SQL queries with unsanitized user input, leading to SQL injection vulnerabilities.

**✅ Secure Fix - Use Ansible Database Modules:**
```yaml
- name: safe database operations with ansible modules
  ansible.builtin.mysql_user:
    name: "{{{{ db_username | regex_replace('[^a-zA-Z0-9_]', '') }}}}"
    password: "{{{{ vault_db_password }}}}"
    priv: "{{{{ db_name | regex_replace('[^a-zA-Z0-9_]', '') }}}}.*:SELECT,INSERT,UPDATE"
    host: localhost
    state: present
    login_user: "{{{{ vault_mysql_admin_user }}}}"
    login_password: "{{{{ vault_mysql_admin_password }}}}"
  when:
    - db_username is defined
    - db_name is defined
    - db_username | regex_search('^[a-zA-Z0-9_]+$')
    - db_name | regex_search('^[a-zA-Z0-9_]+$')

- name: safe database query execution
  ansible.builtin.mysql_query:
    login_user: "{{{{ vault_db_user }}}}"
    login_password: "{{{{ vault_db_password }}}}"
    login_db: "{{{{ validated_db_name }}}}"
    query: "SELECT * FROM users WHERE id = %s"
    positional_args:
      - "{{{{ user_id | int }}}}"
  vars:
    validated_db_name: "{{{{ db_name | regex_replace('[^a-zA-Z0-9_]', '') }}}}"
  register: query_result
```

**✅ Alternative - Use SQL Templates with Parameters:**
```yaml
- name: create parameterized SQL template
  ansible.builtin.template:
    src: safe_query.sql.j2
    dest: /tmp/safe_query.sql
    mode: '0600'
  vars:
    # Use only validated parameters
    table_name: "{{{{ table | regex_replace('[^a-zA-Z0-9_]', '') }}}}"
    column_name: "{{{{ column | regex_replace('[^a-zA-Z0-9_]', '') }}}}"

# Safe SQL template (safe_query.sql.j2):
# SELECT {{{{ column_name }}}} FROM {{{{ table_name }}}} WHERE id = ?;

- name: execute parameterized query
  ansible.builtin.command:
    cmd: mysql -u "{{{{ vault_db_user }}}}" -p"{{{{ vault_db_password }}}}" -e "source /tmp/safe_query.sql"
  environment:
    MYSQL_PWD: "{{{{ vault_db_password }}}}"
  no_log: yes
  register: sql_result

- name: cleanup temporary SQL file
  ansible.builtin.file:
    path: /tmp/safe_query.sql
    state: absent
```

**🔐 SQL Injection Prevention:**
- Use Ansible database modules instead of raw SQL
- Implement parameterized queries with positional_args
- Validate and sanitize all database identifiers
- Use prepared statements and parameter binding
- Never concatenate user input directly into SQL queries
- Implement strict input validation for database operations
"""

    def _generate_path_traversal_fix(self, code_snippet: str) -> str:
        """Generate fix for path traversal in templates"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Path Traversal in Template:**
This template allows path traversal attacks through unsanitized file path variables.

**✅ Secure Fix - Safe Path Handling:**
```yaml
- name: validate and sanitize file paths
  ansible.builtin.set_fact:
    safe_filename: "{{{{ filename | basename | regex_replace('[^a-zA-Z0-9._-]', '') }}}}"
    safe_directory: "{{{{ base_directory }}}}/{{{{ subdir | regex_replace('[^a-zA-Z0-9_-]', '') }}}}"
  vars:
    base_directory: /var/app/data
  when:
    - filename is defined
    - subdir is defined

- name: validate path is within allowed directory
  ansible.builtin.assert:
    that:
      - safe_directory | regex_search('^/var/app/data/')
      - safe_filename | length > 0
      - "'..'" not in safe_directory
      - "'..'" not in safe_filename
    fail_msg: "Invalid file path detected"

- name: safe file operations
  ansible.builtin.copy:
    src: "{{{{ source_file }}}}"
    dest: "{{{{ safe_directory }}}}/{{{{ safe_filename }}}}"
    backup: yes
    mode: '0644'
  when:
    - safe_directory is defined
    - safe_filename is defined
```

**✅ Alternative - Use Restricted Base Paths:**
```yaml
- name: define allowed base paths
  ansible.builtin.set_fact:
    allowed_paths:
      - /var/app/uploads
      - /var/app/config
      - /var/app/logs

- name: validate requested path
  ansible.builtin.set_fact:
    validated_path: "{{{{ item }}}}/{{{{ filename | basename | regex_replace('[^a-zA-Z0-9._-]', '') }}}}"
  when:
    - requested_base in item
    - filename is defined
  loop: "{{{{ allowed_paths }}}}"
  register: path_validation

- name: ensure path validation succeeded
  ansible.builtin.assert:
    that:
      - validated_path is defined
      - validated_path | length > 0
    fail_msg: "Path validation failed - access denied"

- name: perform file operation with validated path
  ansible.builtin.file:
    path: "{{{{ validated_path }}}}"
    state: "{{{{ file_state | default('file') }}}}"
    mode: '0644'
  when: validated_path is defined
```

**🔐 Path Traversal Prevention:**
- Always use basename filter to remove directory components
- Validate paths against allowed base directories
- Use regex_replace to remove dangerous characters
- Never allow '../' or '..\' in file paths
- Implement whitelist-based path validation
- Use absolute paths with restricted base directories
"""

    def _generate_command_substitution_fix(self, code_snippet: str) -> str:
        """Generate fix for command substitution in templates"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Command Substitution Injection:**
This template uses command substitution with unsanitized variables, allowing command injection.

**✅ Secure Fix - Remove Command Substitution:**
```yaml
- name: get system information safely
  ansible.builtin.setup:
  register: system_facts

- name: use ansible facts instead of command substitution
  ansible.builtin.template:
    src: config.j2
    dest: /etc/app/config.conf
    backup: yes
  vars:
    hostname: "{{{{ ansible_hostname }}}}"
    ip_address: "{{{{ ansible_default_ipv4.address }}}}"
    os_family: "{{{{ ansible_os_family }}}}"
    timestamp: "{{{{ ansible_date_time.iso8601 }}}}"

- name: execute commands safely when needed
  ansible.builtin.command:
    cmd: "{{{{ safe_command }}}}"
  register: command_output
  vars:
    safe_command: /usr/bin/id -u
  when: get_user_id | default(false)
  changed_when: false
```

**✅ Alternative - Use Registered Variables:**
```yaml
- name: gather required information with safe commands
  ansible.builtin.command:
    cmd: "{{{{ item.command }}}}"
  register: "{{{{ item.var }}}}"
  loop:
    - {{ command: '/bin/date +%Y%m%d', var: 'current_date' }}
    - {{ command: '/usr/bin/whoami', var: 'current_user' }}
    - {{ command: '/bin/pwd', var: 'current_dir' }}
  changed_when: false

- name: use registered variables in template
  ansible.builtin.template:
    src: app_config.j2
    dest: /etc/app/config.conf
    backup: yes
  vars:
    config_date: "{{{{ current_date.stdout }}}}"
    config_user: "{{{{ current_user.stdout }}}}"
    config_dir: "{{{{ current_dir.stdout }}}}"

# Template file (app_config.j2):
# date={{{{ config_date }}}}
# user={{{{ config_user }}}}
# directory={{{{ config_dir }}}}
```

**🔐 Command Substitution Prevention:**
- Use Ansible facts instead of command substitution
- Execute commands separately and use registered variables
- Validate all command outputs before using in templates
- Never use $() or `` with user-controlled input
- Use dedicated Ansible modules for system information
- Implement proper command validation and sanitization
"""

    def _generate_generic_injection_fix(self, code_snippet: str) -> str:
        """Generate generic fix for template injection"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Template Injection Risk:**
This template contains patterns that could allow injection attacks through unsanitized user input.

**✅ Secure Fix - Safe Template Processing:**
```yaml
- name: validate all template variables
  ansible.builtin.assert:
    that:
      - template_var is defined
      - template_var | length > 0
      - template_var | string | regex_search('^[a-zA-Z0-9_.-]+$')
    fail_msg: "Invalid template variable format"
  loop: "{{{{ template_variables }}}}"
  loop_control:
    loop_var: template_var

- name: sanitize template variables
  ansible.builtin.set_fact:
    sanitized_vars: "{{ sanitized_vars | default({{}}) | combine({{item.key}}: item.value | regex_replace('[^a-zA-Z0-9_.-]', '')) }}"
  loop: "{{{{ template_data | dict2items }}}}"
  when: template_data is defined

- name: use safe template processing
  ansible.builtin.template:
    src: secure_template.j2
    dest: "{{{{ output_file }}}}"
    backup: yes
    mode: '0644'
  vars:
    safe_data: "{{{{ sanitized_vars }}}}"
  when: sanitized_vars is defined
```

**✅ Alternative - Use Structured Configuration:**
```yaml
- name: use JSON configuration instead of templates
  ansible.builtin.copy:
    content: "{{{{ config_data | to_nice_json }}}}"
    dest: /etc/app/config.json
    backup: yes
    mode: '0644'
  vars:
    config_data:
      app:
        name: "{{{{ app_name | regex_replace('[^a-zA-Z0-9_-]', '') }}}}"
        version: "{{{{ app_version | regex_replace('[^0-9.]', '') }}}}"
      server:
        host: "{{{{ server_host | regex_replace('[^a-zA-Z0-9.-]', '') }}}}"
        port: "{{{{ server_port | int | default(8080) }}}}"

- name: validate configuration file
  ansible.builtin.command:
    cmd: python3 -m json.tool /etc/app/config.json
  register: json_validation
  changed_when: false
  failed_when: json_validation.rc != 0
```

**🔐 Template Injection Prevention:**
- Validate and sanitize all template variables
- Use appropriate Jinja2 filters for data types
- Avoid user-controlled template content
- Use structured data formats when possible
- Implement strict input validation
- Monitor template processing for anomalies
"""

    # Jinja / lookup RCE family

    def _generate_lookup_pipe_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 lookup('pipe', ...) Runs Shell on the Controller:**
The `pipe` lookup invokes `/bin/sh -c <cmd>` on the **Ansible controller** (not the managed host) and returns stdout. Any Jinja interpolation inside the command string turns this into direct RCE against the controller - which usually has SSH keys, vault passwords, cloud credentials, and CI tokens.

**✅ Secure Fix 1 - Run the command on the managed host instead:**
```yaml
- name: read value from managed host (safe)
  ansible.builtin.command:
    cmd: /usr/bin/id -u
  register: uid_result
  changed_when: false

- name: use the captured value
  ansible.builtin.debug:
    msg: "uid is {{{{ uid_result.stdout }}}}"
```

**✅ Secure Fix 2 - Read a file on the controller without shell:**
```yaml
- name: read controller-side data without lookup('pipe')
  ansible.builtin.set_fact:
    license_key: "{{{{ lookup('ansible.builtin.file', '/etc/ansible/license.txt') | trim }}}}"
  no_log: true
```

**✅ Secure Fix 3 - If you must keep pipe, pin the literal command:**
```yaml
- name: literal-only pipe (no variable interpolation)
  ansible.builtin.set_fact:
    controller_ts: "{{{{ lookup('ansible.builtin.pipe', '/bin/date -u +%s') }}}}"
```

**🔐 Hardening:**
- Treat `lookup('pipe', ...)` as a controller-side shell invocation and audit every use.
- Never interpolate `{{{{ var }}}}` inside the pipe argument - route through the managed host with `command:` / `shell:` + `register:` instead.
- Add `# nosec lookup_pipe_rce` only with an approved exception and a linked ticket.
"""

    def _generate_lookup_url_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 lookup('url', ...) Fetches on the Controller:**
This lookup runs on the controller at play-compile time. Failure modes include SSRF into the controller's network, cache poisoning of repeated builds, and ingestion of attacker-controlled JSON/YAML that later feeds into templates.

**✅ Secure Fix 1 - Fetch on the managed host:**
```yaml
- name: download payload on target with integrity check
  ansible.builtin.get_url:
    url: https://cdn.example.com/data.json
    dest: /etc/app/data.json
    checksum: sha256:{{{{ data_sha256 }}}}
    mode: '0644'
    validate_certs: true
```

**✅ Secure Fix 2 - Vendor the data into the repo:**
```yaml
- name: include vendored data from repo (reviewed/committed)
  ansible.builtin.include_vars:
    file: "{{{{ role_path }}}}/files/vendor_data.yml"
```

**✅ Secure Fix 3 - If lookup('url') must stay, pin and validate:**
```yaml
- name: fetch controller-side with strict settings
  ansible.builtin.set_fact:
    remote_doc: >-
      {{{{ lookup('ansible.builtin.url',
                  'https://cdn.example.com/data.json',
                  validate_certs=True,
                  split_lines=False) | from_json }}}}
  vars:
    ansible_python_interpreter: /usr/bin/python3
  # Still audit: remote_doc can be poisoned if the CDN is compromised.
```

**🔐 Hardening:**
- Prefer `ansible.builtin.uri` / `get_url` on the target (can enforce `checksum`, `client_cert`, `validate_certs`).
- Never use `lookup('url')` over plain HTTP or against variable-interpolated URLs.
- Require `validate_certs=True` and pin a SHA256 of the expected content when available.
"""

    def _generate_lookup_env_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 lookup('env', ...) Reads the Controller's Environment:**
This reads env vars from the **Ansible controller** process, not the target. Controllers in CI/CD are rich in secrets (`AWS_*`, `VAULT_TOKEN`, `GITHUB_TOKEN`, `KUBECONFIG`) - a single leaked value in a log or debug task exfiltrates credentials.

**✅ Secure Fix 1 - Read from a secrets backend:**
```yaml
- name: pull secret from vault instead of controller env
  ansible.builtin.set_fact:
    api_token: "{{{{ lookup('community.hashi_vault.hashi_vault',
                            'secret=kv/data/app token=' + vault_token) }}}}"
  no_log: true
```

**✅ Secure Fix 2 - Read from the managed host's env (not the controller):**
```yaml
- name: capture target-side env var
  ansible.builtin.shell: "printenv APP_TOKEN"
  register: app_token_result
  changed_when: false
  no_log: true
```

**✅ Secure Fix 3 - Pass explicitly as an extra-var (CI-friendly):**
```bash
# In CI, pass the secret as an extra var rather than relying on controller env:
ansible-playbook site.yml -e "app_token=$APP_TOKEN"
```

**🔐 Hardening:**
- Treat controller env as **out of scope** for play data.
- Always pair env lookups with `no_log: true`.
- Move CI secrets into a proper secret store (Vault, Secrets Manager) and reference them through a lookup plugin that has its own auth layer.
"""

    def _generate_lookup_file_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Controller-Side File Disclosure:**
`lookup('file', ...)` reads files on the **controller**. When the path contains `{{{{ var }}}}`, a poisoned inventory variable (e.g. `host_vars/bad.yml`) can read `/etc/shadow`, SSH keys, vault files, or CI secrets on the controller.

**✅ Secure Fix 1 - Pin the path to a literal:**
```yaml
- name: read a fixed repo file
  ansible.builtin.set_fact:
    config_blob: "{{{{ lookup('ansible.builtin.file', role_path + '/files/app.conf') }}}}"
```

**✅ Secure Fix 2 - Enforce an allow-list base directory:**
```yaml
- name: validate requested path stays inside allow-list
  ansible.builtin.assert:
    that:
      - requested_file is defined
      - (requested_file | realpath).startswith(role_path + '/files/')
    fail_msg: "path {{{{ requested_file }}}} escapes the allow-listed base"

- name: safe lookup after validation
  ansible.builtin.set_fact:
    config_blob: "{{{{ lookup('ansible.builtin.file', requested_file) }}}}"
```

**✅ Secure Fix 3 - Read on the target with slurp:**
```yaml
- name: read file on the target (not the controller)
  ansible.builtin.slurp:
    src: /etc/app/config.yaml
  register: cfg_b64

- name: decode it
  ansible.builtin.set_fact:
    cfg_text: "{{{{ cfg_b64.content | b64decode }}}}"
```

**🔐 Hardening:**
- Never interpolate inventory-controllable variables into controller-side file lookups.
- Validate every computed path with `realpath`/allow-list before dereferencing.
- Assume inventory is attacker-reachable (group_vars/host_vars) and harden accordingly.
"""

    def _generate_lookup_password_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Plaintext Password Written to Shared/Tmp Path:**
`lookup('password', '/tmp/...')` writes the generated password in plaintext to a world-readable/world-traversable directory on the controller. Any other user on that host - including CI co-tenants - can read it.

**✅ Secure Fix 1 - Write to a vault-encrypted file:**
```yaml
- name: generate password into a vault-managed path
  ansible.builtin.set_fact:
    svc_password: >-
      {{{{ lookup('ansible.builtin.password',
                  '{{{{ playbook_dir }}}}/.secrets/svc_password length=32 chars=ascii_letters,digits') }}}}
  no_log: true
# Check .secrets/ into ansible-vault, never into cleartext git.
```

**✅ Secure Fix 2 - Delegate password generation to a secrets backend:**
```yaml
- name: ask Vault for a rotating dynamic secret
  ansible.builtin.set_fact:
    svc_password: "{{{{ lookup('community.hashi_vault.hashi_vault',
                               'secret=database/creds/app-ro') }}}}"
  no_log: true
```

**✅ Secure Fix 3 - Use a controller-local path with 0600 mode:**
```yaml
- name: create a locked-down secrets dir
  ansible.builtin.file:
    path: "{{{{ lookup('env', 'HOME') }}}}/.ansible_secrets"
    state: directory
    mode: '0700'

- name: write password into it
  ansible.builtin.set_fact:
    svc_password: >-
      {{{{ lookup('ansible.builtin.password',
                  lookup('env','HOME') + '/.ansible_secrets/svc length=32') }}}}
  no_log: true
```

**🔐 Hardening:**
- Never write generated credentials under `/tmp`, `/var/tmp`, `/dev/shm`, or any world-traversable directory.
- Always pair with `no_log: true`.
- Prefer a dynamic-secret backend (Vault leases, AWS Secrets Manager rotation) over file-backed passwords.
"""

    def _generate_unsafe_tag_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 YAML `!unsafe` Tag Strips Sanitisation:**
`!unsafe` tells Ansible: "this string is literal, do not template it and do not mark it for sandboxing". When that same value is later concatenated into a shell/jinja context, it bypasses the usual input validation. This is how several ansible-galaxy role CVEs have chained into RCE.

**✅ Secure Fix 1 - Remove `!unsafe` and escape at the render site:**
```yaml
# Instead of: literal_template: !unsafe "{{{{ raw_content }}}}"
- name: render literal braces with {{{{% raw %}}}} at the consumption point
  ansible.builtin.copy:
    content: |
      {{% raw %}}
      {{{{ please_do_not_render_me }}}}
      {{% endraw %}}
    dest: /etc/app/doc.md
    mode: '0644'
```

**✅ Secure Fix 2 - Use a string filter to neuter template syntax:**
```yaml
- name: neutralise any accidental jinja in user content
  ansible.builtin.set_fact:
    safe_blob: "{{{{ user_blob | replace('{{{{', '&#123;&#123;') | replace('}}}}', '&#125;&#125;') }}}}"
```

**✅ Secure Fix 3 - Validate the untrusted value before use:**
```yaml
- name: assert the value has no template markers
  ansible.builtin.assert:
    that:
      - "'{{{{' not in untrusted_value"
      - "'{{% ' not in untrusted_value"
    fail_msg: "value contains template syntax; refusing to continue"
```

**🔐 Hardening:**
- Treat every `!unsafe` occurrence as a security review trigger.
- Prefer `{{% raw %}}...{{% endraw %}}` at the render site over disabling sanitisation on the whole variable.
- Audit with: `rg -n '!unsafe' roles/ playbooks/ group_vars/ host_vars/`.
"""

    def _generate_jinja_in_when_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Double-Rendered `when:` Clause:**
Ansible already parses the body of `when:` as a Jinja2 expression. Wrapping it in `{{{{ ... }}}}` forces a **second** render pass - if the inner variable is attacker-controlled, that second pass evaluates injected expressions in the template context (and the template context has `lookup`, `pipe`, etc.).

**✅ Secure Fix - Write when: as a raw expression:**
```yaml
- name: run conditionally (correct form)
  ansible.builtin.command: /usr/bin/restart-app
  when: app_enabled | bool
  # Not: when: "{{{{ app_enabled | bool }}}}"
```

**✅ Secure Fix - Multi-condition form:**
```yaml
- name: multiple conditions without braces
  ansible.builtin.service:
    name: app
    state: restarted
  when:
    - app_enabled | default(false) | bool
    - app_version is version('2.0', '>=')
    - inventory_hostname in groups['app_servers']
```

**✅ Secure Fix - Comparing to an attacker-controlled value:**
```yaml
- name: safe equality without double templating
  ansible.builtin.debug:
    msg: "matching"
  when: user_role in ['admin', 'operator']   # list is a literal allow-list
```

**🔐 Hardening:**
- Audit: `rg -n 'when:\\s*"?\\{{\\{{' .`
- Wrap test in an assert earlier in the play: `assert: that: user_role is string and user_role | length < 32`.
- Never put untrusted data in `when:` itself; compare against an allow-list of literals.
"""

    def _generate_jinja_in_set_fact_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Second-Order Template Injection via `set_fact`:**
`set_fact` stores the **rendered** value as a fact. If the rendered value still contains `{{{{ ... }}}}` (because the user supplied those braces), the next task that interpolates the fact performs a second render and evaluates the attacker's expression.

**✅ Secure Fix 1 - Mark the fact !unsafe at the set_fact site:**
```yaml
- name: store user-controlled value without re-rendering
  ansible.builtin.set_fact:
    safe_user_input: !unsafe "{{{{ raw_user_input }}}}"
```

**✅ Secure Fix 2 - Sanitise into a typed primitive:**
```yaml
- name: coerce to a safe type
  ansible.builtin.set_fact:
    user_id: "{{{{ raw_user_input | int }}}}"
    user_name: "{{{{ raw_user_input | regex_replace('[^a-zA-Z0-9_-]', '') }}}}"
    user_enabled: "{{{{ raw_flag | bool }}}}"
```

**✅ Secure Fix 3 - Validate structure before storing:**
```yaml
- name: assert structure
  ansible.builtin.assert:
    that:
      - raw_user_input is string
      - raw_user_input | length <= 128
      - raw_user_input is match('^[A-Za-z0-9._-]+$')
    fail_msg: "user input failed structural validation"

- name: store the validated value
  ansible.builtin.set_fact:
    validated_user: "{{{{ raw_user_input }}}}"
```

**🔐 Hardening:**
- Any fact derived from inventory, extra-vars, or API input is untrusted - sanitise before `set_fact`.
- Prefer typed coercion (`| int`, `| bool`, `| regex_replace`) over passing strings through.
- Combine with a no-op second render check in tests: grep output for `{{{{`/`}}}}` artefacts in stored facts.
"""

    def _generate_jinja_in_assert_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Template Injection via assert Messages:**
`fail_msg` / `success_msg` render Jinja2. Embedding unsanitised variables there enables log-line forgery and, when the resulting string is later fed back into a template (`debug: msg: "{{{{ prior_fail_msg }}}}"`), second-order SSTI.

**✅ Secure Fix - Literal messages, escape variables:**
```yaml
- name: structurally validate config
  ansible.builtin.assert:
    that:
      - app_port | int > 1024
      - app_port | int < 65536
    fail_msg: "app_port out of range (got: {{{{ app_port | string | e }}}})"
    success_msg: "app_port accepted"
```

**✅ Secure Fix - Compose from safe facts only:**
```yaml
- name: log a controlled message
  ansible.builtin.assert:
    that:
      - expected_checksum == computed_checksum
    fail_msg: >-
      checksum mismatch on {{{{ inventory_hostname }}}} (ansible-controlled fact)
```

**✅ Secure Fix - Send details to a structured log, keep msg terse:**
```yaml
- name: keep assert message terse; log details elsewhere
  ansible.builtin.assert:
    that:
      - service_state == 'running'
    fail_msg: "service {{{{ service_name | regex_replace('[^a-zA-Z0-9_-]','') }}}} is not running"
```

**🔐 Hardening:**
- Apply `| e` (html/yaml escape) or `| regex_replace` filters to any variable in `fail_msg`/`success_msg`.
- Do **not** copy `.msg` from a failed assert into another template.
- Prefer static templates with only allow-listed facts (`inventory_hostname`, `ansible_hostname`, etc.).
"""

    def _generate_jinja_statement_block_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 `{{% ... %}}` Block Invokes lookup() Directly:**
Statement blocks can call `lookup('pipe' | 'url' | 'env' | 'file', ...)` - which means an attacker who controls any variable that ends up in a template value can pivot to controller-side RCE or SSRF through what looks like a control-flow directive.

**✅ Secure Fix - Move the data retrieval into an explicit task:**
```yaml
- name: fetch data via a vetted module (not inside jinja)
  ansible.builtin.uri:
    url: https://config.example.com/app.json
    return_content: true
    validate_certs: true
  register: cfg

- name: use the retrieved data
  ansible.builtin.template:
    src: app.conf.j2
    dest: /etc/app/app.conf
    mode: '0644'
  vars:
    app_cfg: "{{{{ cfg.json }}}}"
```

**✅ Secure Fix - Use vars_files / include_vars for static config:**
```yaml
- name: load vetted vars file
  ansible.builtin.include_vars:
    file: "{{{{ role_path }}}}/files/app_defaults.yml"
```

**✅ Secure Fix - If you MUST keep the statement block, constrain it:**
```jinja
{{# ❌ don't: {{% set x = lookup('pipe', cmd) %}} #}}
{{# ✅ only literal args, never variables: #}}
{{% set build_ts = lookup('ansible.builtin.pipe', '/bin/date -u +%s') %}}
```

**🔐 Hardening:**
- Ban `{{% ... lookup( ... ) ... %}}` in lint (pre-commit): `rg -n '\\{{%[^%]*lookup\\('`
- Lookups belong in tasks or `vars:` keys where they are visible in reports, not buried in statement blocks.
- Treat statement-block lookups as equivalent to `eval()` - review line by line.
"""

    # Jinja2 *.j2 template hardening
    def _generate_jinja2_safe_filter_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Jinja2 template snippet:**
```jinja
{code_snippet}
```

**🚨 Why this is dangerous:**
The `|safe` filter tells Jinja2 "this is already-escaped HTML, don't
autoescape". Applied to any variable that carries user-controlled data
(inventory var, lookup result, HTTP payload, module output), autoescape
is bypassed and XSS / HTML injection are trivial.

**✅ Secure fix:**
```jinja
{{{{ user_input }}}}   {{# let Jinja2 autoescape it #}}
```
If the value is genuinely already-escaped HTML from a TRUSTED source, do
the escaping in Python / Ansible rather than in the template:
```yaml
- set_fact:
    safe_html_fragment: "{{{{ raw | regex_replace('<script', '&lt;script') }}}}"
```

**🔐 Hardening checklist:**
- Grep the template tree for `|\\s*safe` as a pre-commit hook.
- Maintain an allow-list of variables that may ever carry `|safe`.
- For Markdown/HTML, prefer a dedicated markdown-to-html filter with
  a strict allow-list tag set.
"""

    def _generate_jinja2_autoescape_off_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Jinja2 template header:**
```jinja
{code_snippet}
```

**🚨 Why this is dangerous:**
Turning off autoescape for an entire template means every `{{{{ var }}}}`
in that file is rendered raw. The moment any of those variables contain
HTML-meaningful characters (which is almost always), XSS is trivial.

**✅ Secure fix:**
```jinja
{{# remove the autoescape:False directive #}}
```
If you have a specific block that renders trusted raw HTML (e.g. a
pre-rendered markdown fragment), scope the disable locally:
```jinja
{{% autoescape false %}}
{{{{ trusted_markdown_html }}}}
{{% endautoescape %}}
```

**🔐 Additional hardening:**
- Only disable autoescape around blocks, never for whole templates.
- Keep a list of `{{% autoescape false %}}` locations and review on each
  security pass - this is the Jinja2 equivalent of `dangerouslySetInnerHTML`.
"""

    def _generate_jinja2_render_secret_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Jinja2 template fragment:**
```jinja
{code_snippet}
```

**🚨 Why this is dangerous:**
Rendering a secret-shaped variable (`*_password`, `*_api_key`, `*_token`,
`*_private_key`, `*_secret`) into a template means the secret ends up in
a file on disk - often with world-readable permissions - on every target
host. Logs, backups, and replicated filesystems can leak it.

**✅ Secure fix:**
Two tiers of hardening:

1. **Keep the secret out of the rendered file**:
   ```yaml
   - name: render config (no secret baked in)
     ansible.builtin.template:
       src: app.conf.j2
       dest: /etc/app/app.conf
       mode: '0644'
   - name: write secret separately, 0600, owned by the service
     ansible.builtin.copy:
       content: "{{{{ db_password }}}}"
       dest: /etc/app/secret
       mode: '0600'
       owner: app
     no_log: true
   ```

2. **Runtime secret lookup** (nothing touches disk):
   ```ini
   ; app.conf.j2
   [db]
   password_cmd = /usr/local/bin/vault-read db/password
   ```

**🔐 Minimum bar:**
If the secret genuinely must land in the rendered config:
```yaml
- ansible.builtin.template:
    src: app.conf.j2
    dest: /etc/app/app.conf
    mode: '0600'
    owner: app
    group: app
  no_log: true
```
"""

    def _generate_jinja2_sandbox_escape_fix(self, code_snippet: str) -> str:
        return f"""
**🚨 CRITICAL - Jinja2 sandbox-escape primitive in a template:**
```jinja
{code_snippet}
```

**🚨 Why this is CRITICAL:**
`__class__`, `__mro__`, `__subclasses__`, `__globals__`, `__builtins__`,
and `__import__` are the classical building blocks of a Jinja2 sandbox
escape. Once any one of these is reachable in a rendered template, any
attacker-controlled variable in the same template can pivot to arbitrary
Python execution on the controller (RCE).

**✅ Secure fix:**
Remove the expression entirely. There is NO legitimate reason to access
these dunder attributes in an Ansible template:
```jinja
{{# REMOVED: {code_snippet} #}}
```

**🔐 If you found this in a playbook you didn't write:**
- Treat it as incident-response: assume the template was authored by an
  attacker who already had repo write access.
- Review recent commits: `git log -p -- path/to/template.j2`
- Rotate any secret that this template could have rendered.
- Revoke Ansible Vault keys and regenerate.

**🔐 Prevention:**
- Add a pre-commit hook grep:
  `rg -n '__(class|mro|subclasses|globals|builtins|import)__' templates/`
- Enable Ansible's SandboxedEnvironment where possible (callback plugins
  and custom filters that render user-provided templates).
"""

    def _generate_jinja2_lookup_in_template_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Jinja2 template fragment:**
```jinja
{code_snippet}
```

**🚨 Why this is dangerous:**
`lookup('pipe', ...)` / `lookup('url', ...)` inside a template runs on the
controller every time the template is rendered. If any argument is
interpolated from a variable (even indirectly), it becomes an RCE (pipe)
or SSRF (url) primitive that's invisible on casual review - lookups in
templates render silently.

**✅ Secure fix:**
Move the lookup out of the template into a `set_fact` task that runs
before the template task. Then reference the resolved value:

```yaml
- name: compute build stamp on the controller
  ansible.builtin.set_fact:
    build_stamp: "{{{{ lookup('ansible.builtin.pipe', '/bin/date -u +%s') }}}}"

- name: render template using the already-resolved value
  ansible.builtin.template:
    src: app.conf.j2
    dest: /etc/app/app.conf
```

```ini
; app.conf.j2 - reads pre-resolved var, no lookup
[meta]
build_stamp = {{{{ build_stamp }}}}
```

**🔐 Hardening:**
- Ban `lookup(` inside .j2 files with a pre-commit grep.
- Allow lookups ONLY in tasks, where they're reviewable.
- For URLs, prefer `ansible.builtin.uri` (a task) over `lookup('url', ...)`
  so you get retries, validation, and logging.
"""

    def _generate_jinja2_set_env_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Jinja2 template fragment:**
```jinja
{code_snippet}
```

**🚨 Why this is dangerous:**
`{{% set x = lookup('env', '...') %}}` inside a template reads a
controller-side environment variable at render time and bakes it into
the rendered output file. Controller env typically holds CI secrets,
cloud credentials, and AWS_*/GH_* tokens - this leaks all of them into a
file on every target host.

**✅ Secure fix:**
Move the env lookup out of the template:
```yaml
- name: read controller env var explicitly
  ansible.builtin.set_fact:
    my_build_id: "{{{{ lookup('env', 'BUILD_ID') }}}}"
  no_log: true  # env values often contain secrets

- name: render template using the explicit fact
  ansible.builtin.template:
    src: app.conf.j2
    dest: /etc/app/app.conf
```

**🔐 Hardening:**
- Audit the CI's exported env vars. If `AWS_SECRET_ACCESS_KEY` is in the
  env when ansible-playbook runs, ONE `{{% set %}}` can exfiltrate it.
- Prefer `environment:` blocks at the task level rather than controller env.
- Log the set of env vars consumed and fail CI on unreviewed additions.
"""

    def _generate_jinja2_todo_comment_fix(self, code_snippet: str) -> str:
        return f"""
**⚠️  Jinja2 template comment that hints at unresolved secret handling:**
```jinja
{code_snippet}
```

**🚨 Why this matters:**
A Jinja2 `{{# TODO / FIXME / HACK / XXX ... #}}` comment that mentions a
credential-shaped word (password, token, secret, api_key, private_key) is
almost always a note that someone hardcoded a "temporary" credential and
never rotated it. This is one of the most common root causes of
credential leaks in real incidents.

**✅ Secure fix:**
Resolve the TODO, then remove the comment:

1. **Replace hardcoded value with a runtime lookup:**
   ```jinja
   db_password = {{{{ lookup('community.hashi_vault.hashi_vault',
                            'secret=kv/data/db:password') }}}}
   ```
2. **Or vault-encrypt the current value:**
   ```bash
   ansible-vault encrypt_string 'current_value' --name db_password
   # move output into group_vars/<env>/vault.yml
   ```
3. **Rotate the exposed credential** (assume it was logged in a build
   artifact somewhere) and delete the TODO comment.

**🔐 Process:**
- Add a pre-commit grep for `{{#[^#]*\\b(TODO|FIXME|HACK)\\b[^#]*\\b(password|token|secret|api[_-]?key|private[_-]?key)\\b[^#]*#}}`
- Track the count of these comments over time as a risk indicator.
"""

    # YAML schema-abuse remediation
    def _generate_yaml_python_object_fix(self, code_snippet: str) -> str:
        return f"""
**🚨 CRITICAL - YAML deserialisation RCE primitive:**
```yaml
{code_snippet}
```

**🚨 Why this is CRITICAL:**
The `!!python/object`, `!!python/module`, `!!python/name`, `!!python/apply`
tag family instructs PyYAML to **construct arbitrary Python objects** at
load time. Anyone who loads this file with `yaml.load()`, `yaml.full_load()`,
or `yaml.unsafe_load()` gets arbitrary code execution - `!!python/object/apply:os.system ['id']`
is the canonical reverse-shell primitive.

Even with `yaml.safe_load` (which rejects the tag) this is a **intent-to-abuse**
signal: someone crafted this file expecting an unsafe loader.

**✅ Secure fix:**
Remove the `!!python/*` tag entirely. If you actually need to serialise a
Python object, use a different format:
```yaml
# ❌ NEVER
exploit: !!python/object/apply:os.system ['id']

# ✅ Plain data only - strings, numbers, bool, list, map
result:
  command: "id"
  stdout: "uid=0(root)"
```

**🔐 Controller-side hardening:**
- Ensure every `yaml.load()` call in your tooling is `yaml.safe_load()`.
  Grep for it: `rg -n "yaml\\.(load|full_load|unsafe_load)\\b"` - each hit
  is a latent RCE.
- Add `PyYAML` ≥ 6.0 as a pinned dep (older releases had `yaml.load()`
  default to unsafe).
- If you found this file in a repo you didn't author, treat it as incident-
  response: rotate any secret whose scope includes that controller.
"""

    def _generate_yaml_binary_tag_fix(self, code_snippet: str) -> str:
        return f"""
**⚠️  Suspiciously large YAML `!!binary` blob:**
```yaml
{code_snippet}
```

**🚨 Why this matters:**
`!!binary` embeds a base64-encoded blob directly inside the YAML. Short
blobs (a tls cert, a kerberos keytab) are legitimate; blobs >2 KB are
almost always a packed executable, shellcode, or malware payload smuggled
into a playbook where `git diff` and PR review tools cannot meaningfully
inspect them.

**✅ Secure fix:**
Move the binary OUT of YAML, into a version-controlled `files/` directory
referenced by `src:`:
```yaml
- name: deliver the binary via a regular file asset
  ansible.builtin.copy:
    src: files/my_app.tar.gz   # committed to the repo as a real file
    dest: /opt/my_app.tar.gz
    mode: '0755'
    checksum: sha256:3b0c4...  # always pin to a checksum
```

Or, better, fetch from a signed artifact repository:
```yaml
- name: fetch release from signed artifact repo
  ansible.builtin.get_url:
    url: "https://releases.example.com/my_app-1.2.3.tar.gz"
    dest: /opt/my_app.tar.gz
    checksum: sha256:3b0c4...
    mode: '0755'
```

**🔐 Hardening checklist:**
- Add a pre-commit hook that rejects any `!!binary` block >1 KB unless the
  file is explicitly allow-listed.
- Prefer `ansible.builtin.get_url` + `checksum:` over `!!binary`.
- Scan `files/` for unexpected binaries during CI (`file files/* | grep executable`).
"""

    def _generate_yaml_anchor_bomb_fix(self, code_snippet: str) -> str:
        return f"""
**🚨 YAML anchor-bomb / billion-laughs primitive:**
```yaml
{code_snippet}
```

**🚨 Why this is dangerous:**
A YAML anchor (`&name`) referenced many times (`*name`) and then itself
re-nested inside another anchor creates exponential expansion at parse time.
A few lines of YAML can balloon to gigabytes in memory - a classic DoS.
Even without malicious intent, this pattern stalls CI and crashes linters.

**✅ Secure fix:**
Replace anchor repetition with explicit Ansible loops - they're reviewable
and cannot exponentially expand:
```yaml
- name: apply the same settings to many items
  ansible.builtin.lineinfile:
    path: /etc/app/config
    line: "{{{{ item }}}}"
  loop:
    - "setting_a"
    - "setting_b"
    - "setting_c"
```

If you genuinely need shared maps, cap repetition and inline the values:
```yaml
common_opts: &common
  retries: 3
  timeout: 30

task1:
  <<: *common
  extra: "foo"
task2:
  <<: *common
  extra: "bar"
# <<: *common used ≤3 times - safe.
```

**🔐 Hardening:**
- Configure yamllint: `rules: {{anchors: {{forbid-unused-anchors: true, forbid-duplicated-anchors: true}}}}`.
- In Python tooling, construct a `yaml.SafeLoader` subclass with a bounded
  alias count and abort on overflow (see `yaml.constructor.SafeConstructor`).
- Never load untrusted YAML without a size + depth limit.
"""

    def _generate_yaml_merge_secret_fix(self, code_snippet: str) -> str:
        return f"""
**⚠️  YAML merge-key that silently scatters a secret:**
```yaml
{code_snippet}
```

**🚨 Why this matters:**
A YAML merge key (`<<: *anchor`) pulls every key from the anchored map
into the current map. When the anchored map contains a secret-shaped key
(`api_token`, `*_password`, `*_private_key`, etc.), the secret is **silently
copied** into every consumer of the merge. Review of any individual consumer
site doesn't reveal the secret - it's inherited from far away in the file.

**✅ Secure fix:**
Either (a) pull the secret out of the shared anchor, or (b) replace the
merge with explicit keys so reviewers see exactly what ends up in each map:
```yaml
# ❌ ANTI-PATTERN
common: &common
  api_token: "{{{{ api_token_from_vault }}}}"
  timeout: 30

service_a:
  <<: *common     # api_token silently included

# ✅ EXPLICIT
common_non_secret: &common
  timeout: 30

service_a:
  <<: *common_non_secret
  api_token: "{{{{ api_token_from_vault }}}}"  # explicit, visible in review
```

**🔐 Hardening:**
- Pre-commit grep: `rg -n "<<:\\s*\\*" -A5 | rg -i "(password|token|secret|api[_-]?key|private[_-]?key)"`
- Never put secret-shaped keys in an anchored map that's merged elsewhere.
- Prefer Jinja2 variable references over YAML anchors for shared values -
  they render once, at task time, and can be vault-encrypted.
"""

    def _generate_yaml_duplicate_key_fix(self, code_snippet: str) -> str:
        return f"""
**⚠️  YAML map contains a duplicate key (silent override):**
```yaml
{code_snippet}
```

**🚨 Why this matters:**
PyYAML (and the YAML 1.1 spec) silently keeps the **last** value when the
same key appears twice in a map. A security-relevant setting (`no_log: true`,
`become: false`, `ignore_errors: false`) set early in a task can be
silently shadowed by a later re-declaration - a reviewer scanning top-down
sees the safe value and approves.

**✅ Secure fix:**
Each key must appear at most once per map:
```yaml
# ❌
- name: risky task
  no_log: true
  when: inventory_hostname in prod_hosts
  no_log: false   # silently overrides; secrets now leak to logs

# ✅
- name: risky task
  no_log: true
  when: inventory_hostname in prod_hosts
```

**🔐 Hardening:**
- Run yamllint with `rules: {{key-duplicates: {{level: error}}}}` on every
  PR - PyYAML silently tolerates duplicates, yamllint does not.
- Enable `ansible-lint` with `--strict` so `key-order[task]` and
  `yaml[key-duplicates]` are errors rather than warnings.
- For security-sensitive keys (`no_log`, `become`, `ignore_errors`,
  `run_once`), grep after every rebase: `rg -c "(no_log|ignore_errors|become):" | sort -u`.
"""

    def _generate_yaml_unsafe_tag_fix(self, code_snippet: str) -> str:
        return f"""
**⚠️  YAML uses a loader-specific unsafe tag:**
```yaml
{code_snippet}
```

**🚨 Why this matters:**
Tags like `!<tag:...>`, `!!js/function`, `!!js/regexp`, `!!perl/ref`, etc.
are interpreter-specific and are only honoured by **unsafe** loaders in
those languages. If this file is ever consumed by, say, `js-yaml` with
`LOAD_SCHEMA: UNSAFE`, `!!js/function` becomes arbitrary JavaScript
execution - the JS equivalent of Python's `!!python/object/apply`.

Even inside Ansible-land where `yaml.safe_load` would reject these tags,
the presence of a loader-specific unsafe tag is an **intent-to-abuse**
signal.

**✅ Secure fix:**
Remove the tag. Use only YAML core types (strings, numbers, bools, lists,
maps):
```yaml
# ❌
validator: !!js/function "function(x){{return x.length<10}}"

# ✅ Describe the intent as data; enforce in Ansible tasks
validator:
  type: max_length
  value: 10

- ansible.builtin.assert:
    that:
      - "input | length < 10"
    fail_msg: "input too long"
```

**🔐 Hardening:**
- Pre-commit grep across the repo: `rg -n "!(?:<tag:|![a-z]+/(function|regexp|ref))"`.
- If this file is shared with non-Python tooling (node, ruby), audit every
  consumer's loader config. `js-yaml.load(str)` (without `{{schema: JSON_SCHEMA}}`)
  was unsafe until v4.0.
- Document in the project README: "All YAML consumers must use the JSON
  core schema; no loader-specific tags permitted."
"""
