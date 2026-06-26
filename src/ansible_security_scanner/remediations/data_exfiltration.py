#!/usr/bin/env python3
"""
Data exfiltration remediation generator for Ansible Security Scanner
"""

from .base import BaseRemediationGenerator, _first


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
        "rclone_data_sync": "_generate_transfer_tool_fix",
        "rclone_config_setup": "_generate_transfer_tool_fix",
        "mega_cmd_exfiltration": "_generate_transfer_tool_fix",
        "azcopy_data_transfer": "_generate_transfer_tool_fix",
        "magic_wormhole_transfer": "_generate_p2p_transfer_fix",
        "croc_file_transfer": "_generate_p2p_transfer_fix",
        "python_http_server_exfil": "_generate_http_server_fix",
    }

    def generate_data_exfiltration_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_exfiltration_fix)

    def _generate_transfer_tool_fix(self, code_snippet: str) -> str:
        """Replace an exfiltration-tool transfer (rclone/mega/azcopy) with an
        approved, audited transfer to an allow-listed destination."""
        source = (
            _first(
                code_snippet,
                r"(?:copy|sync|put|mega-put)\s+([^\s'\"|>&]+)",
                r"(/[\w./-]+)",
            )
            or "{{ source_path }}"
        )
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Data Exfiltration via Cloud-Sync Tool:**
Tools like rclone, MEGAcmd, and azcopy are among the most common data-exfiltration utilities used by ransomware and intrusion crews. They move data straight to attacker-controlled cloud storage, bypassing the SDK-level audit trail of the provider.

**✅ Secure Fix - Remove the Tool and Use an Approved, Audited Transfer:**
```yaml
# Remove the rclone/mega/azcopy invocation. If the transfer is genuinely
# required, send it to an allow-listed destination through the provider's
# audited module, gated behind an explicit, reviewed approval.
- name: Refuse transfers to destinations that are not on the approved list
  ansible.builtin.assert:
    that:
      - data_transfer_approved | default(false) | bool
      - approved_exfil_destination is defined
    fail_msg: >-
      Bulk data transfer requires data_transfer_approved=true and an
      approved_exfil_destination from the data-handling allow-list.

- name: Upload to the approved bucket through the audited module
  amazon.aws.s3_object:
    bucket: "{{{{ approved_exfil_destination }}}}"
    object: "{{{{ source_path | basename }}}}"
    src: "{source}"
    mode: put
  # S3 server-access logging / CloudTrail data events record this transfer;
  # rclone/mega/azcopy deliberately would not.
```

**🔐 Data Protection Best Practices:**
- Treat rclone, MEGAcmd, croc, and azcopy on a server as exfiltration indicators unless explicitly authorized
- Route legitimate transfers through provider SDKs/modules that emit audit logs
- Restrict destinations to an allow-list of organization-owned storage
- Egress-filter and DLP-monitor outbound bulk transfers
"""

    def _generate_p2p_transfer_fix(self, code_snippet: str) -> str:
        """Replace an encrypted P2P transfer (magic-wormhole/croc) with an
        approved managed-transfer path."""
        tool = "croc" if "croc" in code_snippet.lower() else "magic-wormhole"
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Encrypted Peer-to-Peer Exfiltration ({tool}):**
{tool} establishes an end-to-end encrypted channel keyed by a one-time code, deliberately bypassing network monitoring and DLP. There is no benign reason for unattended automation to move data this way.

**✅ Secure Fix - Remove the P2P Transfer and Use a Managed Path:**
```yaml
# Remove the {tool} send/receive. Move files only through a managed,
# inspectable transfer to an approved internal host.
- name: Confirm this managed transfer is approved
  ansible.builtin.assert:
    that:
      - data_transfer_approved | default(false) | bool
      - managed_transfer_host in approved_transfer_hosts
    fail_msg: >-
      File transfers must go to an approved host via the managed channel,
      not an encrypted P2P tool that bypasses inspection.

- name: Transfer to the approved internal host over the managed channel
  ansible.posix.synchronize:
    src: "{{{{ source_path }}}}/"
    dest: "{{{{ managed_transfer_path }}}}/"
    checksum: true
    delete: false
  delegate_to: "{{{{ managed_transfer_host }}}}"
```

**🔐 Data Protection Best Practices:**
- Block {tool} and similar relays at the egress firewall
- Keep transfers on inspectable, logged channels (managed rsync/SFTP to approved hosts)
- Require explicit approval and a destination allow-list for any bulk move
"""

    def _generate_http_server_fix(self, code_snippet: str) -> str:
        """Replace an ad-hoc python http.server with a controlled pull from an
        approved internal host."""
        directory = (
            _first(
                code_snippet,
                r"--directory[=\s]+([^\s'\"]+)",
                r"http\.server[^\n]*?(/[\w./{}-]+)",
            )
            or "{{ served_directory }}"
        )
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Ad-hoc File Server Exposes Local Files:**
`python -m http.server` exposes a directory over the network with no authentication, no TLS, and no access logging - a common staging step for pulling data off a host.

**✅ Secure Fix - Remove the Server and Pull Through a Controlled Path:**
```yaml
# Remove the ad-hoc http.server. Distribute files by pulling them from an
# approved internal artifact host with a verified checksum, instead of
# standing up an unauthenticated server on the source host.
- name: Fetch the file from the approved internal host with a checksum
  ansible.builtin.get_url:
    url: "https://{{{{ approved_artifact_host }}}}/{{{{ artifact_name }}}}"
    dest: "{directory}/{{{{ artifact_name }}}}"
    checksum: "sha256:{{{{ artifact_sha256 }}}}"
    mode: '0644'
  # No listener is opened on this host; transfer is authenticated and logged.
```

**🔐 Data Protection Best Practices:**
- Never expose local directories with an unauthenticated `http.server`
- Distribute artifacts from an authenticated, logged internal store
- Verify integrity with a checksum on every fetch
"""

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
