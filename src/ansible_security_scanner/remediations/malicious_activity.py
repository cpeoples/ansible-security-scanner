#!/usr/bin/env python3
"""
Malicious activity remediation generator for Ansible Security Scanner
"""

import re

from .base import BaseRemediationGenerator, _render_from_metadata


class MaliciousActivityRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for malicious activity patterns"""

    _FIX_MAP = {
        "adb_command_injection": "backdoor",
        "advanced_data_harvesting": "credential_harvesting",
        "backdoor_bashrc": "backdoor",
        "backdoor_installation": "backdoor",
        "ci_cd_pipeline_injection": "backdoor",
        "cloud_credential_exposure": "credential_harvesting",
        "container_breakout": "backdoor",
        "container_command_injection": "backdoor",
        "container_root_mount": "backdoor",
        "credential_dump_creation": "credential_harvesting",
        "credential_file_upload": "data_exfiltration",
        "credential_harvesting": "credential_harvesting",
        "credential_harvesting_env": "credential_harvesting",
        "data_archiving_exfiltration": "data_exfiltration",
        "data_exfiltration_curl": "data_exfiltration",
        "database_backdoor_user_creation": "database_backdoor",
        "database_credential_exposure": "database_backdoor",
        "database_privilege_escalation": "database_backdoor",
        "docker_privileged_host": "backdoor",
        "enterprise_service_exploitation": "backdoor",
        "file_permission_tampering": "file_manipulation",
        "generic_template_injection": "backdoor",
        "hardcoded_database_password": "database_backdoor",
        "hidden_command_execution": "backdoor",
        "kubernetes_privileged_pod": "backdoor",
        "mobile_platform_exploitation": "backdoor",
        "monitoring_system_compromise": "backdoor",
        "multi_platform_exploitation": "backdoor",
        "network_backdoor": "backdoor",
        "network_command_injection": "backdoor",
        "network_data_exfiltration": "data_exfiltration",
        "network_enumeration": "credential_harvesting",
        "persistence_mechanism": "backdoor",
        "powershell_command_injection": "backdoor",
        "registry_manipulation": "file_manipulation",
        "scheduled_task_injection": "backdoor",
        "shell_command_injection": "backdoor",
        "ssh_key_backdoor": "backdoor",
        "suspicious_database_maintenance": "database_backdoor",
        "system_file_permissions": "file_manipulation",
        "system_information_gathering": "credential_harvesting",
        "systemd_command_injection": "backdoor",
        "systemd_exploitation": "backdoor",
        "windows_cmd_injection": "backdoor",
        "wmic_command_injection": "backdoor",
        # Reverse shells
        "awk_reverse_shell": "backdoor",
        "bash_dev_tcp_reverse_shell": "backdoor",
        "bash_interactive_shell": "backdoor",
        "lua_reverse_shell": "backdoor",
        "mkfifo_reverse_shell": "backdoor",
        "netcat_reverse_shell": "backdoor",
        "node_reverse_shell": "backdoor",
        "openssl_reverse_shell": "backdoor",
        "perl_reverse_shell": "backdoor",
        "php_reverse_shell": "backdoor",
        "python_reverse_shell": "backdoor",
        "ruby_reverse_shell": "backdoor",
        "socat_reverse_shell": "backdoor",
        "telnet_reverse_shell": "backdoor",
        # Offensive tools
        "bloodhound_sharphound": "credential_harvesting",
        "cobalt_strike_beacon": "backdoor",
        "credential_dump_tool": "credential_harvesting",
        "exploit_framework": "backdoor",
        "hashcat_john": "credential_harvesting",
        "impacket_tools": "credential_harvesting",
        "linpeas_winpeas": "credential_harvesting",
        "mimikatz_usage": "credential_harvesting",
        "responder_tool": "credential_harvesting",
        "rubeus_kerberos": "credential_harvesting",
        "wireless_attack_tools": "credential_harvesting",
        # AD / Windows offensive tooling
        "adcs_certify_abuse": "credential_harvesting",
        "dcsync_keyword": "credential_harvesting",
        "dpapi_extraction": "credential_harvesting",
        "safetykatz_usage": "credential_harvesting",
        # Webshells
        "aspx_webshell": "backdoor",
        "cgi_script_deployment": "backdoor",
        "jsp_webshell": "backdoor",
        "php_webshell": "backdoor",
        "python_webshell": "backdoor",
        "web_directory_write": "backdoor",
        # Data destruction
        "backup_deletion": "file_manipulation",
        "database_drop_truncate": "database_backdoor",
        "disk_wipe_dd": "file_manipulation",
        "lvm_vg_remove": "file_manipulation",
        "mkfs_format_device": "file_manipulation",
        "ransomware_file_encryption": "file_manipulation",
        "recursive_delete_critical": "file_manipulation",
        "shred_wipe_command": "file_manipulation",
        # Binary planting
        "binary_replace_system_path": "backdoor",
        "git_hook_injection": "backdoor",
        "path_trojan_binary": "backdoor",
        # Obfuscation / evasion
        "base32_encoded_payload": "backdoor",
        "curl_output_execution": "backdoor",
        "env_var_constructed_command": "backdoor",
        "gzip_compressed_payload": "backdoor",
        "hex_encoded_payload": "backdoor",
        "perl_obfuscated_exec": "backdoor",
        "python_obfuscated_exec": "backdoor",
        "rev_string_evasion": "backdoor",
        "variable_indirection_evasion": "backdoor",
        # Steganography
        "steganography_extract": "data_exfiltration",
        "steganography_tool": "backdoor",
    }

    def generate_malicious_activity_fix(self, rule_id: str, code_snippet: str) -> str:
        """Generate fix for malicious activity patterns"""

        malicious_details = self._extract_malicious_details(code_snippet)

        type_to_method = {
            "database_backdoor": self._generate_contextual_database_backdoor_fix,
            "data_exfiltration": self._generate_contextual_data_exfiltration_fix,
            "backdoor": self._generate_contextual_backdoor_fix,
            "credential_harvesting": self._generate_contextual_credential_harvesting_fix,
            "network_beacon": self._generate_contextual_network_beacon_fix,
            "file_manipulation": self._generate_contextual_file_manipulation_fix,
        }

        malicious_type = self._FIX_MAP.get(rule_id, "generic")
        gen = type_to_method.get(malicious_type)
        if gen is None:
            return _render_from_metadata(rule_id, code_snippet)
        return gen(code_snippet, malicious_details)

    def _dynamically_extract_database_info(self, code_snippet: str) -> dict:
        """Dynamically extract database information without hardcoding specific patterns"""
        info = {}

        # Dynamic database type detection - look for any database command patterns
        db_commands = {
            "postgresql": ["psql", "pg_dump", "createdb", "dropdb"],
            "mysql": ["mysql", "mysqldump", "mysqladmin"],
            "mssql": ["sqlcmd", "osql"],
            "sqlite": ["sqlite3"],
            "mongodb": ["mongo", "mongodump"],
            "redis": ["redis-cli"],
        }

        for db_type, commands in db_commands.items():
            if any(cmd in code_snippet.lower() for cmd in commands):
                info["database_type"] = db_type
                break

        # Dynamic username extraction - find any identifier after CREATE USER or TO
        username_patterns = [
            r'CREATE\s+USER\s+(?:IF\s+NOT\s+EXISTS\s+)?[\'"]?([a-zA-Z_][a-zA-Z0-9_]*)[\'"]?',
            r'TO\s+[\'"]?([a-zA-Z_][a-zA-Z0-9_]*)[\'"]?',
            r'FOR\s+[\'"]?([a-zA-Z_][a-zA-Z0-9_]*)[\'"]?',
        ]

        for pattern in username_patterns:
            match = re.search(pattern, code_snippet, re.IGNORECASE)
            if match:
                info["username"] = match.group(1)
                break

        # Dynamic password extraction - find any string in password contexts
        password_patterns = [
            r'PASSWORD\s+[\'"]([^\'"]+)[\'"]',
            r'IDENTIFIED\s+BY\s+[\'"]([^\'"]+)[\'"]',
            r'-p\s*[\'"]([^\'"]+)[\'"]',
            r'--password[=\s]+[\'"]([^\'"]+)[\'"]',
        ]

        for pattern in password_patterns:
            match = re.search(pattern, code_snippet, re.IGNORECASE)
            if match:
                info["password"] = match.group(1)
                break

        # Dynamic privilege detection - find any privilege keywords
        privilege_keywords = [
            "SUPERUSER",
            "CREATEDB",
            "CREATEROLE",
            "CREATEUSER",
            "INHERIT",
            "LOGIN",
            "REPLICATION",
            "ALL PRIVILEGES",
            "CREATE",
            "DROP",
            "ALTER",
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "GRANT",
            "REFERENCES",
            "INDEX",
            "TRIGGER",
            "EXECUTE",
            "USAGE",
            "CONNECT",
            "TEMPORARY",
        ]

        found_privileges = [p for p in privilege_keywords if p in code_snippet.upper()]

        if found_privileges:
            info["privileges"] = found_privileges

        # Dynamic host/port extraction
        host_patterns = [
            r"-h\s+([^\s]+)",
            r"--host[=\s]+([^\s]+)",
            r"@([a-zA-Z0-9.-]+)",
            r"HOST[=:\s]+([a-zA-Z0-9.-]+)",
        ]

        for pattern in host_patterns:
            match = re.search(pattern, code_snippet, re.IGNORECASE)
            if match:
                info["host"] = match.group(1)
                break

        port_patterns = [r"-p\s+(\d+)", r"--port[=\s]+(\d+)", r":(\d{4,5})", r"PORT[=:\s]+(\d+)"]

        for pattern in port_patterns:
            match = re.search(pattern, code_snippet, re.IGNORECASE)
            if match:
                info["port"] = match.group(1)
                break

        return info

    def _generate_contextual_database_backdoor_fix(self, code_snippet: str, details: dict) -> str:
        """Generate contextual fix for database backdoor patterns"""

        # Extract details dynamically from code snippet without hardcoding
        extracted_info = self._dynamically_extract_database_info(code_snippet)

        # Use extracted info, falling back to generic descriptions only if extraction completely fails
        username = extracted_info.get("username", "the unauthorized user")
        password = extracted_info.get("password", "the hardcoded password")
        db_type = extracted_info.get("database_type", "the database")
        privileges = extracted_info.get("privileges", [])

        privilege_text = ", ".join(privileges) if privileges else "excessive privileges"

        return f'''
**❌ Database Backdoor Detected:**
```yaml
{code_snippet}
```

**🚨 Critical Security Threat:**
This code creates a backdoor database user "{username}" with {privilege_text} and hardcoded password "{password[:10]}...". This provides persistent unauthorized access to your {db_type} database.

**✅ Immediate Actions Required:**

**1. Remove Backdoor User:**
```sql
-- Connect to {db_type} as admin and remove the backdoor user
DROP USER IF EXISTS {username};

-- Revoke any granted privileges
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {username};
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {username};
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM {username};
```

**2. Secure Database Configuration:**
```yaml
- name: secure database user management
  postgresql_user:
    name: "{{{{ vault_db_app_user }}}}"
    password: "{{{{ vault_db_app_password }}}}"
    priv: "{{{{ app_database }}}}.*:SELECT,INSERT,UPDATE,DELETE"
    no_password_changes: false
    encrypted: yes
  become_user: postgres
  when:
    - vault_db_app_user is defined
    - vault_db_app_password is defined

- name: audit database users
  postgresql_query:
    query: "SELECT usename, usesuper, usecreatedb FROM pg_user WHERE usename NOT IN ('postgres', 'template0', 'template1');"
  register: db_users
  become_user: postgres

- name: verify no unauthorized users exist
  assert:
    that:
      - "'{username}' not in (db_users.query_result | map(attribute='usename'))"
    fail_msg: "Unauthorized database user '{username}' still exists!"
```

**3. Database Security Hardening:**
```yaml
- name: configure secure database access
  lineinfile:
    path: /etc/postgresql/{{{{ postgresql_version }}}}/main/pg_hba.conf
    regexp: "^local\\s+all\\s+all\\s+trust"
    line: "local   all             all                                     md5"
    backup: yes
  notify: restart postgresql

- name: disable remote root access
  lineinfile:
    path: /etc/postgresql/{{{{ postgresql_version }}}}/main/pg_hba.conf
    regexp: "^host\\s+all\\s+postgres"
    state: absent
  notify: restart postgresql

- name: enable connection logging
  lineinfile:
    path: /etc/postgresql/{{{{ postgresql_version }}}}/main/postgresql.conf
    regexp: "^#?log_connections"
    line: "log_connections = on"
  notify: restart postgresql
```

**🔐 Security Best Practices:**
- **Never hardcode database credentials** in scripts or playbooks
- **Use Ansible Vault** for all database passwords
- **Implement least-privilege access** - grant only required permissions
- **Enable database audit logging** to track user activities
- **Regularly review database users** and remove unused accounts
- **Use SSL/TLS** for all database connections
- **Monitor for unauthorized user creation** in database logs

**🚨 Incident Response:**
- **Change all database passwords** immediately
- **Review database logs** for unauthorized activities by user "{username}"
- **Check for data exfiltration** or unauthorized modifications
- **Scan for other backdoor mechanisms** in your infrastructure
'''

    def _generate_data_exfiltration_fix(self, code_snippet: str) -> str:
        """Generate fix for data exfiltration patterns"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Data Exfiltration Detected:**
This code appears to be uploading or transmitting sensitive data to external servers, which poses a severe security risk.

**✅ Secure Fix - Remove Malicious Code:**
```yaml
# REMOVE the above malicious code entirely
# Instead, use legitimate data transfer methods:

- name: secure data backup
  synchronize:
    src: /path/to/data/
    dest: /secure/backup/location/
    delete: yes
    checksum: yes
  delegate_to: trusted-backup-server
```

**✅ Alternative - Use Secure Transfer Methods:**
```yaml
- name: secure file transfer via SCP
  ansible.builtin.copy:
    src: "{{{{ local_file }}}}"
    dest: "{{{{ remote_path }}}}"
    backup: yes
  when: transfer_required | default(false)
```

**🔐 Data Protection Best Practices:**
- Never upload sensitive data to untrusted external servers
- Use encrypted channels (HTTPS, SCP, SFTP) for all data transfers
- Implement data loss prevention (DLP) controls
- Monitor and audit all data transfer activities
- Use legitimate backup and synchronization tools
- Validate destination servers before any data transfer
"""

    def _generate_backdoor_fix(self, code_snippet: str) -> str:
        """Generate fix for backdoor installation patterns"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Backdoor Installation Detected:**
This code is attempting to install backdoors or create unauthorized access channels, which is malicious activity.

**✅ Secure Fix - Remove Malicious Code:**
```yaml
# REMOVE the above malicious code entirely
# Instead, use legitimate remote access methods:

- name: configure SSH access properly
  ansible.builtin.user:
    name: "{{{{ admin_user }}}}"
    groups: wheel
    append: yes
    shell: /bin/bash
  become: yes

- name: setup authorized SSH keys
  ansible.posix.authorized_key:
    user: "{{{{ admin_user }}}}"
    key: "{{{{ ssh_public_key }}}}"
    state: present
  become: yes
```

**✅ Legitimate Remote Access Setup:**
```yaml
- name: configure secure SSH daemon
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "^#?{{{{ item.key }}}}"
    line: "{{{{ item.key }}}} {{{{ item.value }}}}"
  loop:
    - {{ key: 'PermitRootLogin', value: 'no' }}
    - {{ key: 'PasswordAuthentication', value: 'no' }}
    - {{ key: 'PubkeyAuthentication', value: 'yes' }}
  notify: restart sshd
```

**🔐 Secure Access Best Practices:**
- Use SSH key-based authentication instead of passwords
- Disable root login and use sudo for privilege escalation
- Implement proper firewall rules to restrict access
- Use VPN or bastion hosts for remote access
- Monitor and audit all remote access attempts
- Never install unauthorized backdoors or reverse shells
"""

    def _generate_credential_harvesting_fix(self, code_snippet: str) -> str:
        """Generate fix for credential harvesting patterns"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Credential Harvesting Detected:**
This code appears to be harvesting or stealing credentials from the system, which is malicious activity.

**✅ Secure Fix - Remove Malicious Code:**
```yaml
# REMOVE the above malicious code entirely
# Instead, use proper credential management:

- name: setup credential management
  ansible.builtin.file:
    path: /etc/security/credentials
    state: directory
    mode: '0700'
    owner: root
    group: root
  become: yes

- name: configure secure credential storage
  ansible.builtin.template:
    src: credential_policy.j2
    dest: /etc/security/credential_policy.conf
    mode: '0600'
    owner: root
    group: root
  become: yes
```

**✅ Proper Credential Management:**
```yaml
- name: use ansible vault for secrets
  ansible.builtin.debug:
    msg: "Use ansible-vault to encrypt sensitive data"
  vars:
    secure_password: "{{{{ vault_secure_password }}}}"

- name: setup proper authentication
  ansible.builtin.user:
    name: service_account
    password: "{{{{ vault_service_password | password_hash('sha512') }}}}"
    shell: /bin/false
  become: yes
```

**🔐 Credential Security Best Practices:**
- Never harvest or steal credentials from systems
- Use dedicated secret management tools (HashiCorp Vault, AWS Secrets Manager)
- Implement proper authentication and authorization
- Encrypt all sensitive data using ansible-vault
- Use service accounts with minimal required permissions
- Rotate credentials regularly and monitor access
"""

    def _generate_network_beacon_fix(self, code_snippet: str) -> str:
        """Generate fix for network beacon patterns"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Network Beacon Detected:**
This code is creating persistent network connections to external servers, which may be used for command and control.

**✅ Secure Fix - Remove Malicious Code:**
```yaml
# REMOVE the above malicious code entirely
# Instead, use legitimate monitoring and health checks:

- name: setup legitimate health monitoring
  ansible.builtin.cron:
    name: "system health check"
    minute: "*/5"
    job: "/usr/local/bin/health-check.sh"
    user: monitoring
  become: yes

- name: configure proper log forwarding
  ansible.builtin.template:
    src: rsyslog.conf.j2
    dest: /etc/rsyslog.d/50-remote.conf
    backup: yes
  notify: restart rsyslog
```

**✅ Legitimate Monitoring Setup:**
```yaml
- name: install monitoring agent
  ansible.builtin.package:
    name: "{{{{ monitoring_agent }}}}"
    state: present
  become: yes

- name: configure monitoring agent
  ansible.builtin.template:
    src: monitoring.conf.j2
    dest: /etc/monitoring/agent.conf
    mode: '0644'
  notify: restart monitoring
  vars:
    monitoring_server: "{{{{ vault_monitoring_server }}}}"
```

**🔐 Network Security Best Practices:**
- Never create unauthorized network beacons or callbacks
- Use legitimate monitoring and logging solutions
- Implement proper network segmentation and firewalls
- Monitor outbound network connections for anomalies
- Use encrypted channels for all legitimate communications
- Whitelist allowed external connections and block all others
"""

    def _generate_file_manipulation_fix(self, code_snippet: str) -> str:
        """Generate fix for malicious file manipulation"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Malicious File Manipulation Detected:**
This code is performing dangerous file system operations that could compromise system security.

**✅ Secure Fix - Remove Malicious Code:**
```yaml
# REMOVE the above malicious code entirely
# Instead, use proper file management:

- name: manage files securely
  ansible.builtin.file:
    path: "{{{{ target_file }}}}"
    state: file
    mode: '0644'
    owner: "{{{{ file_owner }}}}"
    group: "{{{{ file_group }}}}"
  become: yes
  when: target_file is defined

- name: backup before modification
  ansible.builtin.copy:
    src: "{{{{ source_file }}}}"
    dest: "{{{{ source_file }}}}.backup"
    remote_src: yes
  before: file modification
```

**✅ Proper File Operations:**
```yaml
- name: secure file permissions
  ansible.builtin.file:
    path: "{{{{ item }}}}"
    mode: '0644'
    owner: root
    group: root
  loop:
    - /etc/important.conf
    - /opt/app/config.ini
  become: yes

- name: validate file integrity
  ansible.builtin.stat:
    path: "{{{{ critical_file }}}}"
    checksum_algorithm: sha256
  register: file_stat
```

**🔐 File Security Best Practices:**
- Never use overly permissive file permissions (777, 666)
- Always backup critical files before modification
- Use proper ownership and group assignments
- Implement file integrity monitoring
- Validate file checksums and signatures
- Avoid modifying system binaries or critical system files
"""

    def _generate_generic_malicious_fix(self, code_snippet: str) -> str:
        """Generate generic fix for malicious activity"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Malicious Activity Detected:**
This code contains patterns consistent with malicious activity and should be removed immediately.

**✅ Secure Fix - Remove Malicious Code:**
```yaml
# REMOVE the above malicious code entirely
# Replace with legitimate functionality:

- name: legitimate system operation
  ansible.builtin.service:
    name: "{{{{ service_name }}}}"
    state: started
    enabled: yes
  become: yes
  when: service_name is defined

- name: proper configuration management
  ansible.builtin.template:
    src: config.j2
    dest: /etc/app/config.conf
    backup: yes
    validate: 'config-validator %s'
  notify: restart service
```

**✅ Security Validation:**
```yaml
- name: verify system integrity
  ansible.builtin.command:
    cmd: integrity-check.sh
  register: integrity_result
  changed_when: false
  failed_when: integrity_result.rc != 0

- name: audit system changes
  ansible.builtin.lineinfile:
    path: /var/log/ansible-changes.log
    line: "{{{{ ansible_date_time.iso8601 }}}} - {{{{ ansible_play_name }}}} - {{{{ inventory_hostname }}}}"
    create: yes
```

**🔐 Specific Hardening:**
- Remove all malicious code immediately
- Implement proper change management and approval processes
- Use legitimate tools and methods for system administration
- Monitor and audit all system changes
- Never deploy untrusted or unverified code to production systems
"""

    def _extract_malicious_details(self, code_snippet: str) -> dict:
        """Extract specific details from malicious code"""

        def _dedupe_findall(pattern: str) -> list:
            return list(dict.fromkeys(re.findall(pattern, code_snippet)))

        def _dedupe_findall_many(patterns: list[str]) -> list:
            hits: list = []
            for p in patterns:
                hits.extend(re.findall(p, code_snippet))
            return list(dict.fromkeys(hits))

        details: dict = {
            "urls": _dedupe_findall(r'https?://[^\s\'"`;|&><)]+'),
            "domains": _dedupe_findall(
                r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
                r"(?:com|net|org|io|ru|cn|xyz|info|biz|co|us|top|tk|click|link|onion))\b"
            ),
            "ips": _dedupe_findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
            "files": _dedupe_findall_many(
                [
                    r"(?:>>?|<)\s*([^\s;|&><]+)",
                    r"\b(/(?:etc|var|usr|opt|root|home|tmp|boot|dev|proc|sys|lib|bin|sbin)"
                    r'/[^\s\'"`;|&><)]+)',
                    r'(?:src|dest|path|file|to|from):\s*[\'"]?([^\s\'",;]+)',
                ]
            ),
            "variables": _dedupe_findall_many(
                [r"\$\{?([A-Z_][A-Z0-9_]*)\}?", r"%([A-Z_][A-Z0-9_]*)%"]
            ),
        }

        commands = re.findall(
            r"(?:curl|wget|nc|ncat|netcat|socat|bash|sh|zsh|ksh|python[23]?|perl|ruby|php|node"
            r"|powershell|cmd)\s+([^|;&\n]+)",
            code_snippet,
        )
        details["commands"] = list(dict.fromkeys(c.strip() for c in commands if c.strip()))

        raw_ports = _dedupe_findall_many(
            [
                r"\b(?:port|PORT)\s*[:=]\s*(\d{1,5})\b",
                r":(\d{2,5})\b",
                r"-p\s+(\d{1,5})\b",
                r"\b(\d{4,5})\b",
            ]
        )
        details["ports"] = [p for p in raw_ports if 1 <= int(p) <= 65535]

        details["hosts"] = list(dict.fromkeys(details["domains"] + details["ips"]))

        return details

    def _generate_contextual_data_exfiltration_fix(self, code_snippet: str, details: dict) -> str:
        """Generate contextual fix for data exfiltration, using the full non-contextual remediation template."""

        urls = details.get("urls", [])
        domains = details.get("domains", [])
        files = details.get("files", [])
        hosts = details.get("hosts", [])

        dest_list = urls or hosts or domains
        destinations = ", ".join(dest_list) if dest_list else "unknown destinations"
        files_text = ", ".join(f"`{f}`" for f in files) if files else "unknown paths"

        context_callout = f"""
**🎯 Contextual Analysis:**
- **Exfiltration destinations:** {destinations}
- **Files / paths touched:** {files_text}
- **Shell commands observed:** {len(details.get("commands", []))}
"""
        body = self._generate_data_exfiltration_fix(code_snippet)
        return context_callout + body

    def _generate_contextual_backdoor_fix(self, code_snippet: str, details: dict) -> str:
        """Generate contextual fix for backdoor installation, using the full non-contextual remediation template."""

        commands = details.get("commands", [])
        ports = details.get("ports", [])
        hosts = details.get("hosts", [])

        command_summary = "; ".join(commands[:3]) if commands else "none detected"
        listener_text = (
            ", ".join(f"{h}:{p}" for h in (hosts or ["any"]) for p in ports)
            if ports
            else "none detected"
        )

        context_callout = f"""
**🎯 Contextual Analysis:**
- **Suspicious commands:** `{command_summary}`
- **Potential listeners / C2:** {listener_text}
- **External hosts referenced:** {", ".join(hosts) if hosts else "none"}
"""
        body = self._generate_backdoor_fix(code_snippet)
        return context_callout + body

    def _generate_contextual_credential_harvesting_fix(
        self, code_snippet: str, details: dict
    ) -> str:
        """Generate contextual fix for credential harvesting, using the full non-contextual remediation template."""

        files = details.get("files", [])
        variables = details.get("variables", [])
        urls = details.get("urls", [])

        sensitive_files = (
            ", ".join(f"`{f}`" for f in files) if files else "none explicitly referenced"
        )
        env_vars = ", ".join(f"`${v}`" for v in variables) if variables else "none referenced"
        exfil_targets = ", ".join(urls) if urls else "none detected"

        context_callout = f"""
**🎯 Contextual Analysis:**
- **Credential stores accessed:** {sensitive_files}
- **Environment variables read:** {env_vars}
- **Exfiltration targets:** {exfil_targets}
"""
        body = self._generate_credential_harvesting_fix(code_snippet)
        return context_callout + body

    def _generate_contextual_network_beacon_fix(self, code_snippet: str, details: dict) -> str:
        """Generate contextual fix for network beacons, using the full non-contextual remediation template."""

        urls = details.get("urls", [])
        hosts = details.get("hosts", [])
        ports = details.get("ports", [])

        beacon_destinations = (
            ", ".join(urls) if urls else (", ".join(hosts) if hosts else "unknown")
        )
        port_text = ", ".join(ports) if ports else "unknown"

        context_callout = f"""
**🎯 Contextual Analysis:**
- **Beacon destination(s):** {beacon_destinations}
- **Destination port(s):** {port_text}
- **Callback mechanism:** command-and-control / reverse channel
"""
        body = self._generate_network_beacon_fix(code_snippet)
        return context_callout + body

    def _generate_contextual_file_manipulation_fix(self, code_snippet: str, details: dict) -> str:
        """Generate contextual fix for malicious file manipulation, using the full non-contextual remediation template."""

        files = details.get("files", [])
        commands = details.get("commands", [])

        file_text = ", ".join(f"`{f}`" for f in files) if files else "unknown paths"
        command_text = "; ".join(commands[:3]) if commands else "none detected"

        context_callout = f"""
**🎯 Contextual Analysis:**
- **Files / directories targeted:** {file_text}
- **Modification commands:** `{command_text}`
"""
        body = self._generate_file_manipulation_fix(code_snippet)
        return context_callout + body

    def _generate_contextual_generic_malicious_fix(self, code_snippet: str, details: dict) -> str:
        """Generate contextual generic fix for malicious activity, using the full non-contextual remediation template."""

        urls = details.get("urls", [])
        files = details.get("files", [])
        commands = details.get("commands", [])
        variables = details.get("variables", [])
        ports = details.get("ports", [])

        signals = []
        if urls:
            signals.append(f"**URLs observed:** {', '.join(urls)}")
        if files:
            signals.append(f"**File paths:** {', '.join(f'`{f}`' for f in files)}")
        if commands:
            signals.append(f"**Commands:** `{'; '.join(commands[:3])}`")
        if variables:
            signals.append(f"**Env vars:** {', '.join(f'`${v}`' for v in variables)}")
        if ports:
            signals.append(f"**Ports:** {', '.join(ports)}")

        if signals:
            context_callout = "\n**🎯 Contextual Analysis:**\n- " + "\n- ".join(signals) + "\n"
        else:
            context_callout = "\n**🎯 Contextual Analysis:** no structured indicators were extracted; rely on the template below.\n"

        body = self._generate_generic_malicious_fix(code_snippet)
        return context_callout + body
