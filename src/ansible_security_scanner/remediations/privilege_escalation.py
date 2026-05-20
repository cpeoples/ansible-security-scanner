#!/usr/bin/env python3
"""
Privilege escalation remediation generator for Ansible Security Scanner
"""

from .base import BaseRemediationGenerator


class PrivilegeEscalationRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for privilege escalation patterns"""

    _FIX_MAP = {
        "become_method_unsafe": "_generate_sudo_abuse_fix",
        "cron_privilege_abuse": "_generate_cron_abuse_fix",
        "dangerous_world_writable": "_generate_file_permissions_fix",
        "service_privilege_abuse": "_generate_service_abuse_fix",
        "setuid_binary_creation": "_generate_setuid_fix",
        "sudo_nopasswd": "_generate_sudo_abuse_fix",
        "sudo_with_shell": "_generate_sudo_abuse_fix",
        "wheel_group_addition": "_generate_sudo_abuse_fix",
        # Windows / Active Directory privilege escalation
        "ad_shadow_credentials_attack": "_generate_ad_shadow_credentials_fix",
        "win_add_user_to_admin_group": "_generate_windows_admin_group_fix",
        "windows_token_impersonation_privs": "_generate_windows_token_privs_fix",
    }

    def generate_privilege_escalation_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_escalation_fix)

    def _generate_sudo_abuse_fix(self, code_snippet: str) -> str:
        """Generate fix for sudo abuse patterns"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Sudo Privilege Escalation Risk:**
This code grants excessive sudo privileges or uses sudo in an unsafe manner, potentially allowing privilege escalation attacks.

**✅ Secure Fix - Proper Sudo Configuration:**
```yaml
- name: configure sudo with least privilege
  ansible.builtin.lineinfile:
    path: /etc/sudoers.d/ansible-managed
    line: "{{{{ ansible_user }}}} ALL=(root) NOPASSWD: {{{{ allowed_commands | join(', ') }}}}"
    create: yes
    mode: '0440'
    validate: 'visudo -cf %s'
  vars:
    allowed_commands:
      - "/bin/systemctl restart nginx"
      - "/bin/systemctl reload nginx"
      - "/usr/bin/apt-get update"
  become: yes

- name: remove dangerous sudo rules
  ansible.builtin.lineinfile:
    path: /etc/sudoers
    regexp: "ALL.*NOPASSWD.*ALL"
    state: absent
    validate: 'visudo -cf %s'
  become: yes
```

**✅ Alternative - Use Specific Privileges:**
```yaml
- name: create service-specific user
  ansible.builtin.user:
    name: webapp
    system: yes
    shell: /bin/false
    home: /var/lib/webapp
    create_home: no
  become: yes

- name: configure service with proper user
  ansible.builtin.systemd:
    name: webapp
    state: started
    enabled: yes
    daemon_reload: yes
  become: yes

- name: set file ownership instead of sudo
  ansible.builtin.file:
    path: "{{{{ app_directory }}}}"
    owner: webapp
    group: webapp
    recurse: yes
  become: yes
```

**🔐 Sudo Security Best Practices:**
- Use specific command paths instead of ALL
- Avoid NOPASSWD for sensitive commands
- Use dedicated service accounts instead of sudo when possible
- Regularly audit sudo configurations
- Implement sudo logging and monitoring
- Follow the principle of least privilege
"""

    def _generate_setuid_fix(self, code_snippet: str) -> str:
        """Generate fix for setuid/setgid abuse"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Setuid/Setgid Privilege Escalation Risk:**
Setting the setuid or setgid bit on executables can allow privilege escalation attacks.

**✅ Secure Fix - Remove Setuid/Setgid:**
```yaml
- name: remove dangerous setuid/setgid bits
  ansible.builtin.file:
    path: "{{{{ item }}}}"
    mode: "u-s,g-s"
  loop:
    - /usr/bin/suspicious-binary
    - /opt/app/custom-tool
  become: yes

- name: audit existing setuid/setgid files
  ansible.builtin.find:
    paths: /
    file_type: file
    mode: "u+s,g+s"
    recurse: yes
  register: setuid_files
  become: yes

- name: review setuid files
  ansible.builtin.debug:
    msg: "Found setuid/setgid file: {{{{ item.path }}}} - Please review if necessary"
  loop: "{{{{ setuid_files.files }}}}"
```

**✅ Alternative - Use Capabilities:**
```yaml
- name: use file capabilities instead of setuid
  ansible.builtin.command:
    cmd: setcap cap_net_bind_service=+ep "{{{{ binary_path }}}}"
  become: yes
  when: needs_port_binding | default(false)

- name: verify capabilities
  ansible.builtin.command:
    cmd: getcap "{{{{ binary_path }}}}"
  register: cap_result
  changed_when: false

- name: remove setuid after setting capabilities
  ansible.builtin.file:
    path: "{{{{ binary_path }}}}"
    mode: "u-s"
  become: yes
```

**🔐 Setuid/Setgid Security Best Practices:**
- Avoid setuid/setgid bits whenever possible
- Use file capabilities instead of setuid for specific privileges
- Regularly audit systems for unauthorized setuid/setgid files
- Implement file integrity monitoring for critical binaries
- Use dedicated service accounts with appropriate permissions
- Monitor execution of setuid/setgid programs
"""

    def _generate_cron_abuse_fix(self, code_snippet: str) -> str:
        """Generate fix for cron-based privilege escalation"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Cron Privilege Escalation Risk:**
This cron configuration could allow privilege escalation through scheduled tasks running as root.

**✅ Secure Fix - Proper Cron Configuration:**
```yaml
- name: create dedicated cron user
  ansible.builtin.user:
    name: cronuser
    system: yes
    shell: /bin/false
    home: /var/lib/cronuser
  become: yes

- name: setup secure cron job
  ansible.builtin.cron:
    name: "secure maintenance task"
    minute: "0"
    hour: "2"
    job: "/usr/local/bin/maintenance.sh"
    user: cronuser
    cron_file: secure-maintenance
  become: yes

- name: secure cron script permissions
  ansible.builtin.file:
    path: /usr/local/bin/maintenance.sh
    mode: '0750'
    owner: cronuser
    group: cronuser
  become: yes
```

**✅ Cron Security Configuration:**
```yaml
- name: restrict cron access
  ansible.builtin.file:
    path: /etc/cron.allow
    state: touch
    mode: '0644'
    owner: root
    group: root
  become: yes

- name: add authorized users to cron.allow
  ansible.builtin.lineinfile:
    path: /etc/cron.allow
    line: "{{{{ item }}}}"
  loop: "{{{{ authorized_cron_users }}}}"
  vars:
    authorized_cron_users:
      - cronuser
      - backup
  become: yes

- name: remove world-writable cron directories
  ansible.builtin.file:
    path: "{{{{ item }}}}"
    mode: "o-w"
  loop:
    - /etc/cron.d
    - /etc/cron.daily
    - /etc/cron.hourly
    - /etc/cron.monthly
    - /etc/cron.weekly
  become: yes
```

**🔐 Cron Security Best Practices:**
- Use dedicated users for cron jobs, not root
- Secure cron script permissions and ownership
- Use /etc/cron.allow to restrict cron access
- Monitor cron job execution and logs
- Validate all cron scripts for security issues
- Implement proper error handling in cron scripts
"""

    def _generate_service_abuse_fix(self, code_snippet: str) -> str:
        """Generate fix for service-based privilege escalation"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Service Privilege Escalation Risk:**
This service configuration runs with excessive privileges or in an insecure manner.

**✅ Secure Fix - Proper Service Configuration:**
```yaml
- name: create service user
  ansible.builtin.user:
    name: "{{{{ service_name }}}}"
    system: yes
    shell: /bin/false
    home: "/var/lib/{{{{ service_name }}}}"
    create_home: yes
  become: yes

- name: configure secure systemd service
  ansible.builtin.template:
    src: secure-service.service.j2
    dest: "/etc/systemd/system/{{{{ service_name }}}}.service"
    mode: '0644'
  vars:
    service_user: "{{{{ service_name }}}}"
    service_group: "{{{{ service_name }}}}"
    working_directory: "/var/lib/{{{{ service_name }}}}"
    exec_start: "/usr/local/bin/{{{{ service_name }}}}"
  notify: systemd daemon-reload
  become: yes

- name: secure service file permissions
  ansible.builtin.file:
    path: "/usr/local/bin/{{{{ service_name }}}}"
    mode: '0755'
    owner: root
    group: root
  become: yes
```

**✅ Systemd Security Hardening:**
```yaml
- name: create hardened systemd service
  ansible.builtin.blockinfile:
    path: "/etc/systemd/system/{{{{ service_name }}}}.service"
    block: |
      [Unit]
      Description=Secure {{{{ service_name }}}} Service
      After=network.target

      [Service]
      Type=simple
      User={{{{ service_name }}}}
      Group={{{{ service_name }}}}
      WorkingDirectory=/var/lib/{{{{ service_name }}}}
      ExecStart=/usr/local/bin/{{{{ service_name }}}}

      # Security hardening
      NoNewPrivileges=yes
      PrivateTmp=yes
      ProtectSystem=strict
      ProtectHome=yes
      ReadWritePaths=/var/lib/{{{{ service_name }}}}
      CapabilityBoundingSet=CAP_NET_BIND_SERVICE
      AmbientCapabilities=CAP_NET_BIND_SERVICE

      [Install]
      WantedBy=multi-user.target
    marker: "# {{{{ ansible_managed }}}}"
  notify: systemd daemon-reload
  become: yes
```

**🔐 Service Security Best Practices:**
- Run services as dedicated non-root users
- Use systemd security features (NoNewPrivileges, ProtectSystem, etc.)
- Limit service capabilities to minimum required
- Use proper file permissions and ownership
- Implement service monitoring and logging
- Regularly audit service configurations for security
"""

    def _generate_file_permissions_fix(self, code_snippet: str) -> str:
        """Generate fix for dangerous file permission changes"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Dangerous File Permissions:**
This code sets overly permissive file permissions that could allow privilege escalation.

**✅ Secure Fix - Proper File Permissions:**
```yaml
- name: set secure file permissions
  ansible.builtin.file:
    path: "{{{{ item.path }}}}"
    mode: "{{{{ item.mode }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
  loop:
    - {{ path: '/etc/app/config.conf', mode: '0640', owner: 'app', group: 'app' }}
    - {{ path: '/var/log/app', mode: '0750', owner: 'app', group: 'app' }}
    - {{ path: '/opt/app/bin/app', mode: '0755', owner: 'root', group: 'root' }}
  become: yes

- name: audit dangerous permissions
  ansible.builtin.find:
    paths: /
    file_type: file
    mode: "0777"
    recurse: yes
  register: world_writable_files
  become: yes

- name: report dangerous files
  ansible.builtin.debug:
    msg: "World-writable file found: {{{{ item.path }}}} - Please review"
  loop: "{{{{ world_writable_files.files }}}}"
  when: world_writable_files.files | length > 0
```

**✅ Directory Security:**
```yaml
- name: secure directory permissions
  ansible.builtin.file:
    path: "{{{{ item.path }}}}"
    state: directory
    mode: "{{{{ item.mode }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
  loop:
    - {{ path: '/etc/app', mode: '0750', owner: 'root', group: 'app' }}
    - {{ path: '/var/lib/app', mode: '0750', owner: 'app', group: 'app' }}
    - {{ path: '/var/log/app', mode: '0750', owner: 'app', group: 'adm' }}
  become: yes

- name: implement file integrity monitoring
  ansible.builtin.template:
    src: aide.conf.j2
    dest: /etc/aide/aide.conf.d/custom
    backup: yes
  notify: initialize aide
  become: yes
```

**🔐 File Permission Security Best Practices:**
- Use the principle of least privilege for file permissions
- Never use 777 or 666 permissions unless absolutely necessary
- Use proper user and group ownership
- Implement file integrity monitoring (AIDE, Tripwire)
- Regularly audit file permissions across the system
- Use umask settings to enforce secure default permissions
"""

    def _generate_windows_token_privs_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Sensitive Windows Token Privilege Granted to Low-Trust Account:**
SeDebugPrivilege, SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege, SeTcbPrivilege, and SeBackupPrivilege
are the primitives attackers need for lsass dumping, Potato-family escalation, and acting as SYSTEM.
Granting any of them to a service or user account essentially hands over local machine root.

**✅ Secure Fix - Scope Privileges to System Principals:**
```yaml
- name: Assign SeServiceLogonRight only (no sensitive privileges)
  ansible.windows.win_user_right:
    name: SeServiceLogonRight
    users: "{{{{ service_account }}}}"
    action: add

- name: Explicitly deny sensitive privileges to service account
  ansible.windows.win_user_right:
    name: "{{{{ item }}}}"
    users: "{{{{ service_account }}}}"
    action: remove
  loop:
    - SeDebugPrivilege
    - SeImpersonatePrivilege
    - SeAssignPrimaryTokenPrivilege
    - SeTcbPrivilege
    - SeBackupPrivilege
```

If a task genuinely requires elevated privileges, run it under LOCAL SYSTEM or a Group Managed Service Account
with auditing, not a shared service account.

**🔐 Best Practice:** Baseline User Rights Assignment against the CIS Microsoft Windows Server benchmark.
Audit changes via the event log (Event ID 4704 / 4705) and forward to SIEM. Prefer Credential Guard
+ Protected Users group over broad privilege grants.
"""

    def _generate_windows_admin_group_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Direct Addition to Highly Privileged Group:**
Administrators, Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators,
and DnsAdmins are Tier-0 groups. Direct membership grants permanent, high-power access that bypasses
just-in-time elevation workflows and leaves a weak audit trail.

**✅ Secure Fix - Role-Based, Time-Bound Access:**
```yaml
- name: Nest service principals via an RBAC group, never directly
  community.windows.win_domain_group:
    name: "tier1-webops"
    scope: global
    state: present

- name: Grant the RBAC group only the rights it actually needs
  ansible.windows.win_user_right:
    name: SeServiceLogonRight
    users: "tier1-webops"
    action: add

- name: Add the user to the RBAC group (NOT Domain Admins)
  community.windows.win_domain_group_membership:
    name: "tier1-webops"
    members: "{{{{ operator_sam }}}}"
    state: present
```

For break-glass scenarios, use time-bound Privileged Access Management (PAM) or Just-in-Time
group membership via Microsoft PAM / Azure AD Privileged Identity Management:

```yaml
- name: Request temporary Domain Admin access (24h expiry) via PAM shadow principal
  ansible.builtin.uri:
    url: "https://pam.example.com/api/v1/requests"
    method: POST
    body_format: json
    body:
      principal: "{{{{ operator_upn }}}}"
      role: "Domain Admins"
      duration_hours: 4
      justification: "Ticket CHG-12345: emergency password reset"
    headers:
      Authorization: "Bearer {{{{ lookup('env', 'PAM_TOKEN') }}}}"
```

**🔐 Best Practice:** Enforce the Red Forest / AD Tier model. Use Privileged Access Workstations for
Tier-0 administration. Audit group membership changes (Event ID 4728/4729/4732/4733) and alert on
direct Domain Admins additions.
"""

    def _generate_ad_shadow_credentials_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Shadow Credentials Attack Primitive:**
Writing msDS-KeyCredentialLink on a user or computer object lets an attacker enroll a certificate
bound to a key they control and then authenticate as the victim via PKINIT. This is the Whisker
/ pyWhisker technique - it converts 'Write on msDS-KeyCredentialLink' ACEs into full impersonation.

**✅ Secure Fix - Remove the Write and Restore Protected Access:**
```yaml
- name: Clear msDS-KeyCredentialLink on the target account
  community.general.ldap_attrs:
    dn: "CN={{{{ target_sam }}}},OU=Users,DC=example,DC=com"
    attributes:
      msDS-KeyCredentialLink: []
    state: exact

- name: Audit who can write msDS-KeyCredentialLink on privileged OUs
  ansible.windows.win_powershell:
    script: |
      $ou = "OU=Tier0,DC=example,DC=com"
      Get-Acl "AD:$ou" | Select-Object -ExpandProperty Access |
        Where-Object {{ $_.ObjectType -eq "5b47d60f-6090-40b2-9f37-2a4de88f3063" }} |
        Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType
```

Then revoke the write permission:

```powershell
# Only SELF should be able to write msDS-KeyCredentialLink (for Windows Hello enrollment).
dsacls "OU=Tier0,DC=example,DC=com" /R "BUILTIN\\Users" /I:S
```

**🔐 Best Practice:** Enable the AD CS `CertificateMappingMethods` strong binding (May 2022 patch).
Audit WriteProperty grants on msDS-KeyCredentialLink across the domain (should only be inherited
SELF and legitimate Windows Hello enrollment services). Alert on any direct write.
"""

    def _generate_generic_escalation_fix(self, code_snippet: str) -> str:
        """Generate generic fix for privilege escalation"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Privilege Escalation Risk:**
This code contains patterns that could allow unauthorized privilege escalation.

**✅ Secure Fix - Remove Privilege Escalation:**
```yaml
# Remove the above dangerous code and implement proper access controls:

- name: create dedicated service account
  ansible.builtin.user:
    name: "{{{{ service_account }}}}"
    system: yes
    shell: /bin/false
    home: "/var/lib/{{{{ service_account }}}}"
  become: yes

- name: configure proper permissions
  ansible.builtin.file:
    path: "{{{{ resource_path }}}}"
    owner: "{{{{ service_account }}}}"
    group: "{{{{ service_account }}}}"
    mode: '0640'
  become: yes
  when: resource_path is defined

- name: use sudo with specific commands only
  ansible.builtin.lineinfile:
    path: /etc/sudoers.d/{{{{ service_account }}}}
    line: "{{{{ service_account }}}} ALL=(root) NOPASSWD: {{{{ specific_command }}}}"
    create: yes
    mode: '0440'
    validate: 'visudo -cf %s'
  become: yes
  when: sudo_required | default(false)
```

**✅ Security Monitoring:**
```yaml
- name: monitor privilege escalation attempts
  ansible.builtin.lineinfile:
    path: /etc/audit/rules.d/privilege-escalation.rules
    line: "{{{{ item }}}}"
  loop:
    - "-w /etc/sudoers -p wa -k privilege_escalation"
    - "-w /etc/passwd -p wa -k user_modification"
    - "-w /bin/su -p x -k privilege_escalation"
  notify: restart auditd
  become: yes

- name: configure log monitoring
  ansible.builtin.template:
    src: rsyslog-security.conf.j2
    dest: /etc/rsyslog.d/10-security.conf
    backup: yes
  notify: restart rsyslog
  become: yes
```

**🔐 Privilege Escalation Prevention:**
- Follow the principle of least privilege
- Use dedicated service accounts with minimal permissions
- Monitor and audit privilege escalation attempts
- Implement proper access controls and authentication
- Regularly review and update security configurations
- Use security frameworks and compliance standards
"""
