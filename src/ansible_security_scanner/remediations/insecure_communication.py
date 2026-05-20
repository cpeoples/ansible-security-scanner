#!/usr/bin/env python3
"""
Insecure communication remediation generator for Ansible Security Scanner
"""

from .base import BaseRemediationGenerator


class InsecureCommunicationRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for insecure communication patterns"""

    _FIX_MAP = {
        "ftp_with_credentials": "_generate_ftp_fix",
        "http_basic_auth": "_generate_http_fix",
        "insecure_protocol_usage": "_generate_generic_insecure_fix",
        "plaintext_smtp": "_generate_email_fix",
        "ssl_verification_disabled": "_generate_generic_insecure_fix",
        "telnet_usage": "_generate_telnet_fix",
        "unencrypted_database_connection": "_generate_database_fix",
        "weak_cipher_suite": "_generate_generic_insecure_fix",
    }

    def generate_insecure_communication_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_insecure_fix)

    def _generate_http_fix(self, code_snippet: str) -> str:
        """Generate fix for HTTP (non-HTTPS) communications"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Unencrypted HTTP Communication:**
This code uses HTTP instead of HTTPS, transmitting data in plaintext which can be intercepted and modified.

**✅ Secure Fix - Use HTTPS:**
```yaml
- name: secure HTTPS communication
  ansible.builtin.uri:
    url: "https://{{{{ api_server }}}}/api/endpoint"
    method: GET
    headers:
      Authorization: "Bearer {{{{ vault_api_token }}}}"
      Content-Type: "application/json"
    validate_certs: yes
    timeout: 30
  register: api_response

- name: verify SSL certificate
  ansible.builtin.uri:
    url: "https://{{{{ api_server }}}}/health"
    method: GET
    validate_certs: yes
    return_content: yes
  register: health_check
```

**✅ Secure Download with HTTPS:**
```yaml
- name: download file securely
  ansible.builtin.get_url:
    url: "https://{{{{ download_server }}}}/{{{{ file_name }}}}"
    dest: "/tmp/{{{{ file_name }}}}"
    mode: '0644'
    validate_certs: yes
    checksum: "sha256:{{{{ expected_checksum }}}}"
  register: download_result

- name: verify downloaded file integrity
  ansible.builtin.stat:
    path: "/tmp/{{{{ file_name }}}}"
    checksum_algorithm: sha256
  register: file_checksum
```

**🔐 HTTPS Security Best Practices:**
- Always use HTTPS for web communications
- Validate SSL/TLS certificates (validate_certs: yes)
- Use strong TLS versions (1.2 or higher)
- Implement certificate pinning for critical connections
- Monitor certificate expiration dates
- Use proper authentication tokens or API keys
"""

    def _generate_ftp_fix(self, code_snippet: str) -> str:
        """Generate fix for plain FTP communications"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Unencrypted FTP Communication:**
Plain FTP transmits credentials and data in cleartext, making it vulnerable to interception and attacks.

**✅ Secure Fix - Use SFTP:**
```yaml
- name: secure file transfer via SFTP
  ansible.builtin.copy:
    src: "{{{{ local_file }}}}"
    dest: "{{{{ remote_path }}}}"
  delegate_to: "{{{{ sftp_server }}}}"
  vars:
    ansible_user: "{{{{ vault_sftp_user }}}}"
    ansible_ssh_private_key_file: "{{{{ sftp_key_path }}}}"
    ansible_ssh_common_args: '-o StrictHostKeyChecking=yes'

- name: alternative - use SCP for file transfer
  ansible.builtin.command:
    cmd: scp -i "{{{{ ssh_key_path }}}}" -o StrictHostKeyChecking=yes "{{{{ local_file }}}}" "{{{{ sftp_user }}}}@{{{{ sftp_server }}}}:{{{{ remote_path }}}}"
  register: scp_result
```

**✅ Secure Synchronization:**
```yaml
- name: secure directory sync with rsync over SSH
  ansible.builtin.synchronize:
    src: "{{{{ local_directory }}}}/"
    dest: "{{{{ remote_directory }}}}/"
    delete: no
    checksum: yes
    rsync_opts:
      - "--chmod=D755,F644"
      - "--exclude=*.tmp"
  delegate_to: "{{{{ sync_server }}}}"
  vars:
    ansible_user: "{{{{ vault_sync_user }}}}"
    ansible_ssh_private_key_file: "{{{{ sync_key_path }}}}"
```

**🔐 Secure File Transfer Best Practices:**
- Use SFTP or SCP instead of plain FTP
- Authenticate with SSH keys, not passwords
- Verify server host keys (StrictHostKeyChecking=yes)
- Use secure file permissions and ownership
- Monitor and log all file transfer activities
- Implement proper access controls and user management
"""

    def _generate_telnet_fix(self, code_snippet: str) -> str:
        """Generate fix for telnet communications"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Insecure Telnet Communication:**
Telnet transmits all data, including passwords, in plaintext and is extremely insecure.

**✅ Secure Fix - Use SSH:**
```yaml
- name: secure remote connection via SSH
  ansible.builtin.command:
    cmd: ssh -i "{{{{ ssh_key_path }}}}" -o StrictHostKeyChecking=yes "{{{{ remote_user }}}}@{{{{ remote_host }}}}" "{{{{ remote_command }}}}"
  register: ssh_result
  delegate_to: localhost

- name: execute commands on remote host securely
  ansible.builtin.shell: "{{{{ command_to_run }}}}"
  delegate_to: "{{{{ target_host }}}}"
  vars:
    ansible_user: "{{{{ vault_ssh_user }}}}"
    ansible_ssh_private_key_file: "{{{{ ssh_key_path }}}}"
    ansible_ssh_common_args: '-o StrictHostKeyChecking=yes'
```

**✅ SSH Configuration:**
```yaml
- name: configure SSH client properly
  ansible.builtin.blockinfile:
    path: /etc/ssh/ssh_config
    block: |
      Host {{{{ remote_host }}}}
          HostName {{{{ remote_host }}}}
          User {{{{ vault_ssh_user }}}}
          IdentityFile {{{{ ssh_key_path }}}}
          StrictHostKeyChecking yes
          PasswordAuthentication no
          PubkeyAuthentication yes
    marker: "# {{{{ ansible_managed }}}} - {{{{ remote_host }}}}"
  become: yes

- name: ensure SSH service is secure
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "^#?{{{{ item.key }}}}"
    line: "{{{{ item.key }}}} {{{{ item.value }}}}"
  loop:
    - {{ key: 'Protocol', value: '2' }}
    - {{ key: 'PermitRootLogin', value: 'no' }}
    - {{ key: 'PasswordAuthentication', value: 'no' }}
    - {{ key: 'PubkeyAuthentication', value: 'yes' }}
  notify: restart sshd
```

**🔐 SSH Security Best Practices:**
- Never use telnet for remote access
- Use SSH with key-based authentication
- Disable password authentication
- Use strong SSH configurations and ciphers
- Implement proper host key verification
- Monitor and audit SSH access logs
"""

    def _generate_database_fix(self, code_snippet: str) -> str:
        """Generate fix for unencrypted database communications"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Unencrypted Database Communication:**
Database connections without SSL/TLS encryption transmit sensitive data in plaintext.

**✅ Secure Fix - Enable SSL/TLS for Database:**
```yaml
- name: secure MySQL connection with SSL
  ansible.builtin.mysql_db:
    name: "{{{{ database_name }}}}"
    state: present
    login_host: "{{{{ db_host }}}}"
    login_user: "{{{{ vault_db_user }}}}"
    login_password: "{{{{ vault_db_password }}}}"
    login_port: 3306
    ca_cert: /etc/mysql/ca-cert.pem
    client_cert: /etc/mysql/client-cert.pem
    client_key: /etc/mysql/client-key.pem
    ssl_mode: REQUIRED

- name: secure PostgreSQL connection with SSL
  ansible.builtin.postgresql_db:
    name: "{{{{ database_name }}}}"
    state: present
    login_host: "{{{{ pg_host }}}}"
    login_user: "{{{{ vault_pg_user }}}}"
    login_password: "{{{{ vault_pg_password }}}}"
    port: 5432
    ssl_mode: require
    ca_cert: /etc/postgresql/ca-cert.pem
```

**✅ Database SSL Configuration:**
```yaml
- name: configure MySQL SSL
  ansible.builtin.blockinfile:
    path: /etc/mysql/mysql.conf.d/mysqld.cnf
    block: |
      [mysqld]
      ssl-ca=/etc/mysql/ca-cert.pem
      ssl-cert=/etc/mysql/server-cert.pem
      ssl-key=/etc/mysql/server-key.pem
      require_secure_transport=ON
    marker: "# {{{{ ansible_managed }}}} - SSL Configuration"
  notify: restart mysql

- name: configure PostgreSQL SSL
  ansible.builtin.lineinfile:
    path: /etc/postgresql/13/main/postgresql.conf
    regexp: "^#?ssl ="
    line: "ssl = on"
  notify: restart postgresql
```

**🔐 Database Security Best Practices:**
- Always use SSL/TLS for database connections
- Validate server certificates
- Use strong authentication methods
- Implement proper access controls and user permissions
- Monitor database connections and access logs
- Keep database software updated with security patches
"""

    def _generate_email_fix(self, code_snippet: str) -> str:
        """Generate fix for plain email communications"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Unencrypted Email Communication:**
Sending emails without encryption exposes sensitive information and credentials to interception.

**✅ Secure Fix - Use Encrypted Email:**
```yaml
- name: send secure email with TLS
  ansible.builtin.mail:
    to: "{{{{ recipient_email }}}}"
    subject: "{{{{ email_subject }}}}"
    body: "{{{{ email_body }}}}"
    host: "{{{{ smtp_server }}}}"
    port: 587
    username: "{{{{ vault_smtp_user }}}}"
    password: "{{{{ vault_smtp_password }}}}"
    secure: starttls
    timeout: 30
  when: send_email | default(false)

- name: alternative - use secure SMTP with SSL
  ansible.builtin.mail:
    to: "{{{{ recipient_email }}}}"
    subject: "{{{{ email_subject }}}}"
    body: "{{{{ email_body }}}}"
    host: "{{{{ smtp_server }}}}"
    port: 465
    username: "{{{{ vault_smtp_user }}}}"
    password: "{{{{ vault_smtp_password }}}}"
    secure: always
```

**✅ Email Server Configuration:**
```yaml
- name: configure Postfix for secure email
  ansible.builtin.lineinfile:
    path: /etc/postfix/main.cf
    regexp: "^#?{{{{ item.key }}}}"
    line: "{{{{ item.key }}}} = {{{{ item.value }}}}"
  loop:
    - {{ key: 'smtpd_use_tls', value: 'yes' }}
    - {{ key: 'smtpd_tls_security_level', value: 'encrypt' }}
    - {{ key: 'smtp_tls_security_level', value: 'encrypt' }}
    - {{ key: 'smtpd_tls_cert_file', value: '/etc/ssl/certs/postfix.pem' }}
    - {{ key: 'smtpd_tls_key_file', value: '/etc/ssl/private/postfix.key' }}
  notify: restart postfix
  become: yes

- name: ensure email certificates are secure
  ansible.builtin.file:
    path: "{{{{ item.path }}}}"
    mode: "{{{{ item.mode }}}}"
    owner: root
    group: root
  loop:
    - {{ path: '/etc/ssl/certs/postfix.pem', mode: '0644' }}
    - {{ path: '/etc/ssl/private/postfix.key', mode: '0600' }}
```

**🔐 Email Security Best Practices:**
- Always use TLS/SSL for SMTP connections
- Use strong authentication for email servers
- Implement SPF, DKIM, and DMARC for email authentication
- Monitor email server logs for suspicious activity
- Use secure email certificates from trusted CAs
- Avoid sending sensitive data via email when possible
"""

    def _generate_generic_insecure_fix(self, code_snippet: str) -> str:
        """Generate generic fix for insecure communications"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Insecure Communication Detected:**
This code uses insecure communication protocols that transmit data in plaintext.

**✅ Secure Fix - Use Encrypted Protocols:**
```yaml
# Replace insecure communication with encrypted alternatives:

- name: secure communication setup
  ansible.builtin.template:
    src: secure_config.j2
    dest: /etc/app/secure_config.conf
    backup: yes
    mode: '0640'
  vars:
    use_encryption: true
    tls_version: "1.2"
    validate_certificates: true

- name: verify secure connection
  ansible.builtin.uri:
    url: "https://{{{{ secure_server }}}}/health"
    method: GET
    validate_certs: yes
    timeout: 10
  register: connection_test
```

**✅ Encryption Configuration:**
```yaml
- name: configure TLS settings
  ansible.builtin.blockinfile:
    path: /etc/app/tls.conf
    block: |
      tls_min_version = 1.2
      tls_ciphers = ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS
      tls_verify_certificates = true
      tls_ca_file = /etc/ssl/certs/ca-certificates.crt
    marker: "# {{{{ ansible_managed }}}} - TLS Configuration"

- name: monitor secure connections
  ansible.builtin.cron:
    name: "check secure connections"
    minute: "*/15"
    job: "/usr/local/bin/check-secure-connections.sh"
```

**🔐 Communication Security Best Practices:**
- Always use encrypted protocols (HTTPS, SFTP, SSH, TLS)
- Validate server certificates and implement certificate pinning
- Use strong TLS/SSL configurations and cipher suites
- Monitor and audit all network communications
- Implement proper authentication and access controls
- Keep communication software updated with security patches
"""
