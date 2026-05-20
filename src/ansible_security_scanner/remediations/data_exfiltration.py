#!/usr/bin/env python3
"""
Data exfiltration remediation generator for Ansible Security Scanner
"""

from .base import BaseRemediationGenerator


class DataExfiltrationRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for data exfiltration patterns"""

    _FIX_MAP = {
        "archive_creation_suspicious": "_generate_file_copy_fix",
        "credential_file_search": "_generate_file_copy_fix",
        "credential_grep_and_send": "_generate_curl_upload_fix",
        "database_dump_creation": "_generate_database_dump_fix",
        "environment_variable_harvesting": "_generate_file_copy_fix",
        "log_file_collection": "_generate_file_copy_fix",
        "network_configuration_collection": "_generate_file_copy_fix",
        "network_data_exfiltration": "_generate_curl_upload_fix",
        "process_list_collection": "_generate_file_copy_fix",
        "remote_copy_sensitive_data": "_generate_ftp_transfer_fix",
        "sensitive_file_collection": "_generate_file_copy_fix",
    }

    def generate_data_exfiltration_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_exfiltration_fix)

    def _generate_curl_upload_fix(self, code_snippet: str) -> str:
        """Generate fix for curl-based data uploads"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Data Exfiltration via HTTP Upload:**
This code is uploading potentially sensitive data to external servers using curl, which poses a severe security risk.

**✅ Secure Fix - Remove Unauthorized Upload:**
```yaml
# REMOVE the above malicious upload code entirely
# Instead, use legitimate backup or sync methods:

- name: secure local backup
  ansible.builtin.archive:
    path: "{{{{ source_directory }}}}"
    dest: "/secure/backup/{{{{ ansible_date_time.date }}}}.tar.gz"
    format: gz
  become: yes

- name: verify backup integrity
  ansible.builtin.stat:
    path: "/secure/backup/{{{{ ansible_date_time.date }}}}.tar.gz"
    checksum_algorithm: sha256
  register: backup_stat
```

**✅ Legitimate Data Transfer (if required):**
```yaml
- name: secure data transfer to authorized server
  ansible.builtin.synchronize:
    src: "{{{{ local_path }}}}/"
    dest: "{{{{ authorized_backup_path }}}}/"
    delete: no
    checksum: yes
    rsync_opts:
      - "--exclude=*.log"
      - "--exclude=sensitive/*"
  delegate_to: "{{{{ authorized_backup_server }}}}"
  when:
    - authorized_transfer | default(false)
    - authorized_backup_server is defined
```

**🔐 Data Protection Best Practices:**
- Never upload sensitive data to unauthorized external servers
- Use encrypted channels (HTTPS, SCP, SFTP) for legitimate transfers
- Implement data classification and handling policies
- Monitor and audit all data transfer activities
- Use approved backup and synchronization solutions
- Validate destination servers and certificates before any transfer
"""

    def _generate_ftp_transfer_fix(self, code_snippet: str) -> str:
        """Generate fix for FTP-based data transfers"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Data Exfiltration via FTP/File Transfer:**
This code is transferring data using potentially insecure file transfer methods to unauthorized destinations.

**✅ Secure Fix - Remove Unauthorized Transfer:**
```yaml
# REMOVE the above malicious transfer code entirely
# Instead, use secure, authorized file transfer methods:

- name: secure file transfer via SFTP
  ansible.builtin.sftp:
    host: "{{{{ authorized_server }}}}"
    username: "{{{{ vault_sftp_user }}}}"
    password: "{{{{ vault_sftp_password }}}}"
    src: "{{{{ local_file }}}}"
    dest: "{{{{ remote_path }}}}"
    validate_certs: yes
  when:
    - authorized_transfer | default(false)
    - authorized_server in approved_servers
```

**✅ Legitimate Secure Transfer:**
```yaml
- name: setup SSH key for secure transfer
  ansible.builtin.copy:
    content: "{{{{ vault_ssh_private_key }}}}"
    dest: /tmp/transfer_key
    mode: '0600'
  no_log: yes

- name: secure SCP transfer
  ansible.builtin.command:
    cmd: scp -i /tmp/transfer_key -o StrictHostKeyChecking=yes "{{{{ source_file }}}}" "{{{{ authorized_user }}}}@{{{{ authorized_server }}}}:{{{{ dest_path }}}}"
  register: transfer_result
  when: authorized_transfer | default(false)

- name: cleanup temporary key
  ansible.builtin.file:
    path: /tmp/transfer_key
    state: absent
```

**🔐 File Transfer Security Best Practices:**
- Use SFTP or SCP instead of plain FTP
- Authenticate transfers with SSH keys, not passwords
- Verify server certificates and host keys
- Encrypt all data in transit
- Log and monitor all file transfer activities
- Use approved and authorized destination servers only
"""

    def _generate_email_send_fix(self, code_snippet: str) -> str:
        """Generate fix for email-based data exfiltration"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Data Exfiltration via Email:**
This code is sending potentially sensitive data via email, which is insecure and may violate data protection policies.

**✅ Secure Fix - Remove Unauthorized Email:**
```yaml
# REMOVE the above malicious email code entirely
# Instead, use proper notification systems:

- name: send notification to authorized recipients
  ansible.builtin.mail:
    to: "{{{{ authorized_notification_email }}}}"
    subject: "System Status Notification"
    body: "System operation completed successfully on {{{{ ansible_hostname }}}}"
    host: "{{{{ authorized_smtp_server }}}}"
    port: 587
    username: "{{{{ vault_smtp_user }}}}"
    password: "{{{{ vault_smtp_password }}}}"
    secure: starttls
  when:
    - send_notifications | default(false)
    - authorized_notification_email is defined
```

**✅ Secure Logging and Alerting:**
```yaml
- name: log to centralized logging system
  ansible.builtin.syslog:
    msg: "Operation completed: {{{{ operation_name }}}}"
    priority: info
    facility: local0

- name: send to monitoring system
  ansible.builtin.uri:
    url: "{{{{ monitoring_webhook_url }}}}"
    method: POST
    body_format: json
    body:
      hostname: "{{{{ ansible_hostname }}}}"
      status: "completed"
      timestamp: "{{{{ ansible_date_time.iso8601 }}}}"
    headers:
      Authorization: "Bearer {{{{ vault_monitoring_token }}}}"
  when: monitoring_webhook_url is defined
```

**🔐 Email and Communication Security:**
- Never send sensitive data via unencrypted email
- Use secure email protocols (TLS/SSL) for legitimate notifications
- Implement proper access controls for email systems
- Use dedicated notification and alerting systems
- Encrypt sensitive communications end-to-end
- Follow data protection and privacy regulations
"""

    def _generate_database_dump_fix(self, code_snippet: str) -> str:
        """Generate fix for database dump exfiltration"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Database Data Exfiltration:**
This code is dumping database contents and potentially sending them to unauthorized locations.

**✅ Secure Fix - Remove Unauthorized Dump:**
```yaml
# REMOVE the above malicious database dump code entirely
# Instead, use proper backup procedures:

- name: secure database backup
  ansible.builtin.mysql_db:
    name: "{{{{ database_name }}}}"
    state: dump
    target: "/secure/backups/{{{{ database_name }}}}_{{{{ ansible_date_time.date }}}}.sql"
    login_user: "{{{{ vault_db_backup_user }}}}"
    login_password: "{{{{ vault_db_backup_password }}}}"
  become: yes
  when: database_backup_enabled | default(false)

- name: encrypt database backup
  ansible.builtin.command:
    cmd: gpg --cipher-algo AES256 --compress-algo 1 --symmetric --output "{{{{ backup_file }}}}.gpg" "{{{{ backup_file }}}}"
  vars:
    backup_file: "/secure/backups/{{{{ database_name }}}}_{{{{ ansible_date_time.date }}}}.sql"
```

**✅ Proper Database Backup:**
```yaml
- name: create backup directory with proper permissions
  ansible.builtin.file:
    path: /secure/backups
    state: directory
    mode: '0700'
    owner: backup
    group: backup
  become: yes

- name: setup automated backup rotation
  ansible.builtin.cron:
    name: "database backup rotation"
    minute: "0"
    hour: "2"
    job: "/usr/local/bin/rotate-backups.sh /secure/backups 30"
    user: backup
```

**🔐 Database Security Best Practices:**
- Use dedicated backup users with minimal required permissions
- Encrypt all database backups at rest and in transit
- Store backups in secure, access-controlled locations
- Implement proper backup retention and rotation policies
- Monitor and audit all database access and backup activities
- Never dump production databases to unauthorized locations
"""

    def _generate_file_copy_fix(self, code_snippet: str) -> str:
        """Generate fix for file copying exfiltration"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 File System Data Exfiltration:**
This code is copying or archiving potentially sensitive files to unauthorized locations.

**✅ Secure Fix - Remove Unauthorized File Operations:**
```yaml
# REMOVE the above malicious file operations entirely
# Instead, use proper file management:

- name: secure file archival
  ansible.builtin.archive:
    path: "{{{{ source_directory }}}}"
    dest: "/authorized/backup/location/archive_{{{{ ansible_date_time.date }}}}.tar.gz"
    format: gz
    exclude_path:
      - "{{{{ source_directory }}}}/sensitive/*"
      - "{{{{ source_directory }}}}/*.key"
      - "{{{{ source_directory }}}}/*.pem"
  become: yes
  when: authorized_backup | default(false)

- name: set secure permissions on archive
  ansible.builtin.file:
    path: "/authorized/backup/location/archive_{{{{ ansible_date_time.date }}}}.tar.gz"
    mode: '0600'
    owner: backup
    group: backup
```

**✅ Legitimate File Management:**
```yaml
- name: manage log files properly
  ansible.builtin.find:
    paths: /var/log
    patterns: "*.log"
    age: "7d"
    size: "100m"
  register: old_logs

- name: compress old log files
  ansible.builtin.archive:
    path: "{{{{ item.path }}}}"
    dest: "{{{{ item.path }}}}.gz"
    format: gz
    remove: yes
  loop: "{{{{ old_logs.files }}}}"
  when: old_logs.files | length > 0
```

**🔐 File Management Security:**
- Use proper file permissions and ownership
- Exclude sensitive files from archives and backups
- Store backups in authorized, secure locations only
- Implement file integrity monitoring
- Audit and log all file system operations
- Follow data retention and disposal policies
"""

    def _generate_generic_exfiltration_fix(self, code_snippet: str) -> str:
        """Generate generic fix for data exfiltration"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Data Exfiltration Detected:**
This code contains patterns consistent with unauthorized data exfiltration and should be removed immediately.

**✅ Secure Fix - Remove Data Exfiltration Code:**
```yaml
# REMOVE the above malicious code entirely
# Instead, implement proper data handling:

- name: secure data processing
  ansible.builtin.template:
    src: data_config.j2
    dest: /etc/app/data_config.conf
    backup: yes
    mode: '0640'
    owner: app
    group: app
  become: yes

- name: implement data retention policy
  ansible.builtin.cron:
    name: "data cleanup"
    minute: "0"
    hour: "1"
    job: "/usr/local/bin/cleanup-expired-data.sh"
    user: app
```

**✅ Legitimate Data Operations:**
```yaml
- name: process data within system
  ansible.builtin.command:
    cmd: /usr/local/bin/process-data.sh "{{{{ data_file }}}}"
  register: processing_result
  become_user: app
  when: data_file is defined

- name: audit data operations
  ansible.builtin.lineinfile:
    path: /var/log/data-operations.log
    line: "{{{{ ansible_date_time.iso8601 }}}} - Data processed: {{{{ data_file | default('none') }}}}"
    create: yes
```

**🔐 Data Protection Best Practices:**
- Remove all unauthorized data exfiltration code immediately
- Implement proper data classification and handling procedures
- Use encryption for sensitive data at rest and in transit
- Monitor and audit all data access and transfer activities
- Follow data protection regulations (GDPR, HIPAA, etc.)
- Use approved tools and methods for legitimate data operations
"""
