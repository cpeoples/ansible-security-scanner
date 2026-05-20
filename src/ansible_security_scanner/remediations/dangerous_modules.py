#!/usr/bin/env python3
"""
Dangerous modules remediation generator for Ansible Security Scanner
"""

from .base import BaseRemediationGenerator


class DangerousModulesRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for dangerous Ansible modules usage"""

    _FIX_MAP = {
        "assemble_module_unsafe": "_generate_file_fix",
        "command_module_with_shell": "_generate_shell_raw_fix",
        "fetch_module_unsafe_dest": "_generate_file_fix",
        "raw_module_usage": "_generate_shell_raw_fix",
        "script_module_unsafe": "_generate_script_fix",
    }

    def generate_dangerous_modules_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_module_fix)

    def _generate_shell_raw_fix(self, code_snippet: str) -> str:
        """Generate fix for unsafe shell/raw module usage"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Dangerous Shell/Raw Module Usage:**
Using shell or raw modules with unvalidated input can lead to command injection and system compromise.

**✅ Secure Fix - Use Specific Ansible Modules:**
```yaml
# Replace shell/raw with specific Ansible modules:

- name: manage packages safely
  ansible.builtin.package:
    name: "{{{{ package_list }}}}"
    state: present
  vars:
    package_list:
      - nginx
      - postgresql
      - python3-pip
  become: yes

- name: manage services safely
  ansible.builtin.systemd:
    name: "{{{{ service_name }}}}"
    state: started
    enabled: yes
    daemon_reload: yes
  loop:
    - nginx
    - postgresql
  loop_control:
    loop_var: service_name
  become: yes

- name: manage files safely
  ansible.builtin.copy:
    src: "{{{{ item.src }}}}"
    dest: "{{{{ item.dest }}}}"
    mode: "{{{{ item.mode }}}}"
    backup: yes
  loop:
    - {{ src: 'nginx.conf', dest: '/etc/nginx/nginx.conf', mode: '0644' }}
    - {{ src: 'app.conf', dest: '/etc/app/app.conf', mode: '0640' }}
  notify: restart nginx
```

**✅ When Shell Module is Necessary:**
```yaml
- name: use shell module safely with validation
  ansible.builtin.shell:
    cmd: "{{{{ validated_command }}}}"
    creates: "{{{{ creates_file }}}}"
  vars:
    validated_command: >-
      {{{{ base_command }}}}
      {{{{ arg1 | quote }}}}
      {{{{ arg2 | quote }}}}
    base_command: /usr/bin/safe-tool
    creates_file: /var/lib/app/installation.complete
  register: shell_result
  when:
    - arg1 is defined
    - arg2 is defined
    - arg1 | regex_search('^[a-zA-Z0-9_.-]+$')
    - arg2 | regex_search('^[a-zA-Z0-9_.-]+$')

- name: validate shell command result
  ansible.builtin.assert:
    that:
      - shell_result.rc == 0
      - shell_result.stderr | length == 0
    fail_msg: "Shell command execution failed"
  when: shell_result is defined
```

**🔐 Shell/Raw Module Security:**
- Use specific Ansible modules instead of shell/raw when possible
- Validate all variables used in shell commands
- Use 'creates' parameter to make commands idempotent
- Quote all user-provided arguments
- Implement proper error handling and validation
- Never use shell/raw with unvalidated user input
"""

    def _generate_script_fix(self, code_snippet: str) -> str:
        """Generate fix for unsafe script module usage"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Dangerous Script Module Usage:**
Executing scripts without proper validation can introduce security vulnerabilities.

**✅ Secure Fix - Use Managed Scripts:**
```yaml
- name: deploy script securely
  ansible.builtin.copy:
    src: "{{{{ script_name }}}}"
    dest: "/usr/local/bin/{{{{ script_name }}}}"
    mode: '0755'
    owner: root
    group: root
    backup: yes
  vars:
    script_name: secure-maintenance.sh
  become: yes

- name: validate script before execution
  ansible.builtin.stat:
    path: "/usr/local/bin/{{{{ script_name }}}}"
    checksum_algorithm: sha256
  register: script_stat
  become: yes

- name: verify script checksum
  ansible.builtin.assert:
    that:
      - script_stat.stat.checksum == expected_checksum
    fail_msg: "Script checksum validation failed"
  vars:
    expected_checksum: "a1b2c3d4e5f6..."  # Known good checksum

- name: execute validated script
  ansible.builtin.command:
    cmd: "/usr/local/bin/{{{{ script_name }}}}"
    creates: /var/lib/app/script.complete
  register: script_result
  become: yes
```

**✅ Alternative - Use Ansible Tasks Instead:**
```yaml
# Replace script execution with native Ansible tasks:

- name: perform maintenance tasks
  block:
    - name: clean temporary files
      ansible.builtin.find:
        paths: /tmp
        patterns: "*.tmp"
        age: "7d"
      register: temp_files

    - name: remove old temporary files
      ansible.builtin.file:
        path: "{{{{ item.path }}}}"
        state: absent
      loop: "{{{{ temp_files.files }}}}"

    - name: rotate log files
      ansible.builtin.command:
        cmd: logrotate -f /etc/logrotate.conf
      become: yes

    - name: update package cache
      ansible.builtin.package:
        update_cache: yes
      become: yes
  rescue:
    - name: handle maintenance errors
      ansible.builtin.debug:
        msg: "Maintenance task failed: {{{{ ansible_failed_result.msg }}}}"
```

**🔐 Script Execution Security:**
- Deploy scripts using copy/template modules first
- Validate script checksums before execution
- Use proper file permissions (755 for executables)
- Replace script logic with Ansible tasks when possible
- Implement error handling and rollback procedures
- Never execute untrusted or unvalidated scripts
"""

    def _generate_uri_fix(self, code_snippet: str) -> str:
        """Generate fix for unsafe URI module usage"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Unsafe URI Module Usage:**
Using URI module without proper validation can expose credentials and allow SSRF attacks.

**✅ Secure Fix - Safe HTTP Requests:**
```yaml
- name: make secure HTTP requests
  ansible.builtin.uri:
    url: "{{{{ api_endpoint }}}}"
    method: "{{{{ http_method | default('GET') }}}}"
    headers:
      Authorization: "Bearer {{{{ vault_api_token }}}}"
      Content-Type: "application/json"
      User-Agent: "Ansible/{{{{ ansible_version.string }}}}"
    body_format: json
    body: "{{ request_body | default({{}}) }}"
    validate_certs: yes
    timeout: 30
    status_code: [200, 201, 202]
  vars:
    api_endpoint: "https://{{{{ validated_host }}}}/api/v1/{{{{ validated_path }}}}"
    validated_host: "{{{{ api_host | regex_replace('[^a-zA-Z0-9.-]', '') }}}}"
    validated_path: "{{{{ api_path | regex_replace('[^a-zA-Z0-9/_-]', '') }}}}"
  register: api_response
  when:
    - api_host is defined
    - api_path is defined
    - vault_api_token is defined

- name: validate API response
  ansible.builtin.assert:
    that:
      - api_response.status == 200
      - api_response.json is defined
    fail_msg: "API request failed or returned invalid response"
  when: api_response is defined
```

**✅ Secure File Downloads:**
```yaml
- name: download files securely
  ansible.builtin.get_url:
    url: "{{{{ download_url }}}}"
    dest: "{{{{ download_path }}}}"
    mode: '0644'
    owner: "{{{{ file_owner | default('root') }}}}"
    group: "{{{{ file_group | default('root') }}}}"
    validate_certs: yes
    checksum: "sha256:{{{{ expected_checksum }}}}"
    timeout: 60
    headers:
      Authorization: "Bearer {{{{ vault_download_token }}}}"
  vars:
    download_url: "https://{{{{ trusted_server }}}}/files/{{{{ validated_filename }}}}"
    download_path: "/tmp/{{{{ validated_filename }}}}"
    validated_filename: "{{{{ filename | basename | regex_replace('[^a-zA-Z0-9._-]', '') }}}}"
    trusted_server: "releases.example.com"
  register: download_result
  when:
    - filename is defined
    - expected_checksum is defined
    - vault_download_token is defined

- name: verify downloaded file
  ansible.builtin.stat:
    path: "{{{{ download_path }}}}"
    checksum_algorithm: sha256
  register: file_stat

- name: validate file integrity
  ansible.builtin.assert:
    that:
      - file_stat.stat.checksum == expected_checksum
    fail_msg: "Downloaded file checksum validation failed"
```

**🔐 URI Module Security:**
- Always use HTTPS and validate certificates
- Implement proper authentication with tokens
- Validate all URL components and parameters
- Use checksum validation for file downloads
- Implement timeout and status code validation
- Never expose credentials in URLs or logs
"""

    def _generate_file_fix(self, code_snippet: str) -> str:
        """Generate fix for unsafe file module usage"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Unsafe File Module Usage:**
Improper file operations can lead to privilege escalation and unauthorized access.

**✅ Secure Fix - Safe File Operations:**
```yaml
- name: manage files securely
  ansible.builtin.file:
    path: "{{{{ safe_file_path }}}}"
    state: "{{{{ file_state | default('file') }}}}"
    mode: "{{{{ file_mode | default('0644') }}}}"
    owner: "{{{{ file_owner | default('root') }}}}"
    group: "{{{{ file_group | default('root') }}}}"
    backup: yes
  vars:
    safe_file_path: "{{{{ base_path }}}}/{{{{ filename | basename | regex_replace('[^a-zA-Z0-9._-]', '') }}}}"
    base_path: /var/app/data
  when:
    - filename is defined
    - filename | length > 0
    - base_path in allowed_paths
  become: yes

- name: validate file permissions
  ansible.builtin.stat:
    path: "{{{{ safe_file_path }}}}"
  register: file_permissions
  become: yes

- name: ensure secure permissions
  ansible.builtin.assert:
    that:
      - file_permissions.stat.mode != '0777'
      - file_permissions.stat.mode != '0666'
      - file_permissions.stat.uid != 0 or file_permissions.stat.gid != 0
    fail_msg: "File has insecure permissions"
  when: file_permissions.stat.exists
```

**✅ Secure File Copying:**
```yaml
- name: copy files securely
  ansible.builtin.copy:
    src: "{{{{ source_file }}}}"
    dest: "{{{{ dest_directory }}}}/{{{{ safe_filename }}}}"
    mode: '0644'
    owner: "{{{{ app_user }}}}"
    group: "{{{{ app_group }}}}"
    backup: yes
    validate: "{{{{ validation_command | default(omit) }}}}"
  vars:
    dest_directory: /var/app/config
    safe_filename: "{{{{ filename | basename | regex_replace('[^a-zA-Z0-9._-]', '') }}}}"
    validation_command: "config-validator %s"
  when:
    - source_file is defined
    - filename is defined
    - dest_directory in allowed_directories
  notify: restart application

- name: set directory permissions securely
  ansible.builtin.file:
    path: "{{{{ directory_path }}}}"
    state: directory
    mode: '0755'
    owner: "{{{{ dir_owner }}}}"
    group: "{{{{ dir_group }}}}"
    recurse: no
  vars:
    directory_path: "{{{{ base_dir }}}}/{{{{ subdir | regex_replace('[^a-zA-Z0-9_-]', '') }}}}"
  when:
    - base_dir in allowed_base_dirs
    - subdir is defined
  become: yes
```

**🔐 File Module Security:**
- Use basename filter to prevent path traversal
- Validate file paths against allowed directories
- Set appropriate permissions (avoid 777, 666)
- Use proper ownership (avoid root when possible)
- Enable backup for important file changes
- Implement file validation when copying
"""

    def _generate_debug_fix(self, code_snippet: str) -> str:
        """Generate fix for unsafe debug module usage"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Sensitive Information in Debug Output:**
Debug module may expose sensitive information in logs and console output.

**✅ Secure Fix - Safe Debug Usage:**
```yaml
- name: debug non-sensitive information only
  ansible.builtin.debug:
    msg: "Application deployment completed successfully"
  when: deployment_complete | default(false)

- name: debug with filtered sensitive data
  ansible.builtin.debug:
    var: filtered_config
  vars:
    filtered_config:
      app_name: "{{{{ app_config.app_name }}}}"
      version: "{{{{ app_config.version }}}}"
      environment: "{{{{ app_config.environment }}}}"
      # Exclude sensitive fields like passwords, tokens, keys
  when: debug_enabled | default(false)

- name: conditional debug for troubleshooting
  ansible.builtin.debug:
    msg: "Connection test result: {{ 'SUCCESS' if connection_test.rc == 0 else 'FAILED' }}"
  when:
    - debug_mode | default(false)
    - connection_test is defined
```

**✅ Use no_log for Sensitive Operations:**
```yaml
- name: handle sensitive data without logging
  ansible.builtin.set_fact:
    processed_config: "{{{{ config_template | combine(secure_overrides) }}}}"
  vars:
    secure_overrides:
      database_url: "{{{{ vault_db_url }}}}"
      api_key: "{{{{ vault_api_key }}}}"
  no_log: yes

- name: debug configuration status only
  ansible.builtin.debug:
    msg: "Configuration updated with {{ processed_config.keys() | length }} settings"
  when: processed_config is defined

- name: secure logging for audit trail
  ansible.builtin.lineinfile:
    path: /var/log/ansible-audit.log
    line: "{{{{ ansible_date_time.iso8601 }}}} - {{{{ ansible_play_name }}}} - {{{{ inventory_hostname }}}} - Configuration updated"
    create: yes
    mode: '0640'
  become: yes
```

**✅ Alternative - Use Proper Logging:**
```yaml
- name: log to system journal instead of debug
  ansible.builtin.systemd:
    name: rsyslog
    state: started
  become: yes

- name: send structured logs to monitoring
  ansible.builtin.uri:
    url: "{{{{ monitoring_endpoint }}}}"
    method: POST
    body_format: json
    body:
      timestamp: "{{{{ ansible_date_time.iso8601 }}}}"
      hostname: "{{{{ ansible_hostname }}}}"
      playbook: "{{{{ ansible_play_name }}}}"
      status: "completed"
      # No sensitive data included
    headers:
      Authorization: "Bearer {{{{ vault_monitoring_token }}}}"
  when: monitoring_endpoint is defined
  no_log: yes
```

**🔐 Debug Module Security:**
- Never debug sensitive variables (passwords, keys, tokens)
- Use no_log: yes for tasks handling sensitive data
- Filter out sensitive fields when debugging configuration
- Use conditional debugging based on debug flags
- Implement proper logging instead of debug for production
- Monitor and audit debug output in logs
"""

    def _generate_generic_module_fix(self, code_snippet: str) -> str:
        """Generate generic fix for dangerous module usage"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Dangerous Module Usage:**
This module is being used in an unsafe manner that could introduce security vulnerabilities.

**✅ Secure Fix - Use Safe Module Practices:**
```yaml
- name: use modules securely with validation
  ansible.builtin.{{{{ safe_module_name }}}}:
    {{{{ safe_module_params | to_nice_yaml | indent(4) }}}}
  vars:
    safe_module_name: "{{{{ module_name | regex_replace('[^a-zA-Z0-9_]', '') }}}}"
    safe_module_params:
      # Use validated parameters only
      name: "{{{{ resource_name | regex_replace('[^a-zA-Z0-9_-]', '') }}}}"
      state: "{{{{ resource_state | default('present') }}}}"
      # Add other safe parameters as needed
  when:
    - resource_name is defined
    - resource_name | length > 0
  become: "{{{{ requires_privilege | default(false) }}}}"

- name: validate module execution result
  ansible.builtin.assert:
    that:
      - module_result is defined
      - module_result.failed is not defined or not module_result.failed
    fail_msg: "Module execution failed or returned unexpected result"
  when: module_result is defined
```

**✅ Alternative - Use Specific Modules:**
```yaml
# Replace generic/dangerous modules with specific alternatives:

- name: manage system resources safely
  block:
    - name: manage packages
      ansible.builtin.package:
        name: "{{{{ package_list }}}}"
        state: present
      when: package_list is defined

    - name: manage services
      ansible.builtin.systemd:
        name: "{{{{ service_name }}}}"
        state: started
        enabled: yes
      when: service_name is defined

    - name: manage files
      ansible.builtin.template:
        src: "{{{{ template_file }}}}"
        dest: "{{{{ config_path }}}}"
        backup: yes
        validate: "{{{{ validation_command | default(omit) }}}}"
      when:
        - template_file is defined
        - config_path is defined
  rescue:
    - name: handle errors gracefully
      ansible.builtin.debug:
        msg: "Operation failed, rolling back changes"

    - name: rollback on failure
      ansible.builtin.include_tasks: rollback.yml
```

**🔐 Module Security Best Practices:**
- Use specific modules instead of generic ones when possible
- Validate all module parameters and inputs
- Implement proper error handling and rollback procedures
- Use least privilege principles (become: no when possible)
- Monitor module execution and results
- Keep modules and Ansible updated to latest versions
"""
