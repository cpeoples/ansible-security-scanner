#!/usr/bin/env python3
"""
System compromise remediation generator for Ansible Security Scanner
"""

from . import _pattern_index
from .base import BaseRemediationGenerator, _render_from_metadata


class SystemCompromiseRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for system compromise patterns"""

    _FIX_MAP = {
        "backdoor_listener": "_generate_backdoor_listener_fix",
        "crontab_modification": "_generate_cron_backdoor_fix",
        "file_permission_777": "_generate_privilege_escalation_fix",
        "firewall_rule_modification": "_generate_security_service_disable_fix",
        "privilege_escalation_sudo": "_generate_sudo_backdoor_fix",
        "root_ssh_key_modification": "_generate_ssh_key_injection_fix",
        "setuid_binary_creation": "_generate_privilege_escalation_fix",
        "system_service_manipulation": "_generate_security_service_disable_fix",
        "user_account_creation": "_generate_sudo_backdoor_fix",
        "web_shell_drop": "_generate_web_shell_fix",
        # Windows defense evasion / impact
        "event_log_clear_windows": "_generate_event_log_clear_fix",
        "windows_defender_tamper": "_generate_windows_defender_tamper_fix",
        "windows_shadow_copies_delete": "_generate_windows_shadow_copies_fix",
    }

    def generate_system_compromise_fix(self, rule_id: str, code_snippet: str) -> str:
        method_name = self._FIX_MAP.get(rule_id)
        if method_name:
            return getattr(self, method_name)(code_snippet)
        return _render_from_metadata(rule_id, code_snippet)

    def _generate_history_manipulation_fix(self, code_snippet: str) -> str:
        """Generate fix for history manipulation"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Security Risk:**
This command attempts to clear or disable command history, which is a common technique used by attackers to hide their activities.

**✅ Secure Fix (Remove malicious commands):**
```yaml
# Remove the history manipulation commands entirely
# If you need to manage history for legitimate purposes, use proper configuration:

- name: Configure history settings properly
  lineinfile:
    path: /etc/bash.bashrc
    line: "export HISTSIZE=1000"
    state: present
  become: yes

- name: Set proper history file permissions
  file:
    path: /home/{{{{ ansible_user }}}}/.bash_history
    mode: '0600'
    owner: "{{{{ ansible_user }}}}"
    group: "{{{{ ansible_user }}}}"
  become: yes
```

**✅ Security Best Practices:**
- Enable system-wide logging and monitoring
- Use centralized log management (rsyslog, journald)
- Implement file integrity monitoring (AIDE, Tripwire)
- Regular security audits and compliance checks
"""

        return template

    def _generate_log_tampering_fix(self, code_snippet: str) -> str:
        """Generate fix for log tampering"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Security Risk:**
This command attempts to delete, truncate, or redirect system logs, which destroys audit trails and is a sign of malicious activity.

**✅ Secure Fix (Remove malicious commands):**
```yaml
# Remove log tampering commands entirely
# If you need to manage logs, use proper log rotation:

- name: Configure proper log rotation
  template:
    src: logrotate.conf.j2
    dest: /etc/logrotate.d/application
  become: yes

- name: Ensure log directory permissions
  file:
    path: /var/log
    mode: '0755'
    owner: root
    group: root
    recurse: no
  become: yes
```

**✅ Security Best Practices:**
- Implement centralized logging (send logs to SIEM)
- Use immutable log storage
- Set up log integrity monitoring
- Configure automated log backup and retention
"""

        return template

    def _generate_security_service_disable_fix(self, code_snippet: str) -> str:
        """Generate fix for security service disabling"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Security Risk:**
This command disables critical security services like firewalls, SELinux, or AppArmor, leaving the system vulnerable to attacks.

**✅ Secure Fix (Proper security configuration):**
```yaml
# Instead of disabling security services, configure them properly:

- name: Configure firewall rules
  ufw:
    rule: allow
    port: "{{{{ required_port }}}}"
    proto: tcp
  become: yes
  when: ansible_os_family == "Debian"

- name: Configure SELinux properly
  selinux:
    policy: targeted
    state: enforcing
  become: yes
  when: ansible_os_family == "RedHat"

- name: Configure AppArmor profiles
  command: aa-enforce /etc/apparmor.d/*
  become: yes
  when: ansible_os_family == "Debian"
```

**✅ Security Best Practices:**
- Never disable security services in production
- Use proper configuration instead of disabling
- Implement defense in depth
- Regular security hardening audits
"""

        return template

    def _generate_backdoor_listener_fix(self, code_snippet: str) -> str:
        """Generate fix for backdoor listeners"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Security Risk:**
This command creates a network backdoor that allows unauthorized remote access to the system.

**✅ Secure Fix (Remove malicious patterns):**
```yaml
# Remove the backdoor command entirely
# Replace with legitimate network services:

- name: Configure legitimate SSH service
  service:
    name: ssh
    state: started
    enabled: yes
  become: yes

- name: Configure SSH security
  lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "{{{{ item.regexp }}}}"
    line: "{{{{ item.line }}}}"
    state: present
  loop:
    - {{ regexp: '^PermitRootLogin', line: 'PermitRootLogin no' }}
    - {{ regexp: '^PasswordAuthentication', line: 'PasswordAuthentication no' }}
    - {{ regexp: '^Port', line: 'Port 2222' }}
  become: yes
  notify: restart ssh
```

**✅ Security Best Practices:**
- Use proper SSH configuration with key-based authentication
- Implement network segmentation and firewalls
- Monitor network connections and unusual traffic
- Use intrusion detection systems (IDS)
"""

        return template

    def _generate_cron_backdoor_fix(self, code_snippet: str) -> str:
        """Generate fix for cron backdoors"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Security Risk:**
This command contains patterns commonly associated with system compromise, backdoors, or malicious activities.

**✅ Secure Fix (Remove malicious patterns):**
```yaml
# Remove the malicious command entirely
# Replace with legitimate system administration tasks:

- name: Perform legitimate system maintenance
  package:
    name: "{{{{ required_packages }}}}"
    state: present
  become: yes

- name: Configure system properly
  template:
    src: config.j2
    dest: /etc/application/config.conf
    mode: '0644'
  become: yes
```

**✅ Security Best Practices:**
- Remove all suspicious or malicious commands
- Implement proper monitoring and alerting
- Use configuration management instead of raw commands
- Regular security audits and penetration testing
- Follow security hardening guidelines
"""

        return template

    def _generate_ssh_key_injection_fix(self, code_snippet: str) -> str:
        """Generate fix for SSH key injection"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Security Risk:**
This command contains patterns commonly associated with system compromise, backdoors, or malicious activities.

**✅ Secure Fix (Remove malicious patterns):**
```yaml
# Remove the malicious command entirely
# Replace with legitimate system administration tasks:

- name: Perform legitimate system maintenance
  package:
    name: "{{{{ required_packages }}}}"
    state: present
  become: yes

- name: Configure system properly
  template:
    src: config.j2
    dest: /etc/application/config.conf
    mode: '0644'
  become: yes
```

**✅ Security Best Practices:**
- Remove all suspicious or malicious commands
- Implement proper monitoring and alerting
- Use configuration management instead of raw commands
- Regular security audits and penetration testing
- Follow security hardening guidelines
"""

        return template

    def _generate_web_shell_fix(self, code_snippet: str) -> str:
        """Generate fix for web shell creation"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Web Shell Deployment Detected:**
This task is writing an executable script (PHP/JSP/ASPX/CGI) into a
webroot. Web shells give an attacker full remote-code-execution through
the web server and are one of the most common post-compromise backdoors.

**✅ Secure Fix - Remove the web shell and restore integrity:**
```yaml
- name: Remove the dropped web shell artifact
  ansible.builtin.file:
    path: "{{{{ web_shell_path }}}}"
    state: absent
  become: yes

- name: Audit webroot for other suspicious files
  ansible.builtin.find:
    paths:
      - /var/www/html
      - /srv/www
      - /usr/share/nginx/html
    patterns:
      - '*.php'
      - '*.jsp'
      - '*.aspx'
      - '*.cgi'
    file_type: file
    age: '-7d'
  register: recent_webroot_files
  become: yes

- name: Fail if unexpected executable content exists in webroot
  ansible.builtin.fail:
    msg: "Unexpected files in webroot - investigate {{{{ item.path }}}}"
  loop: "{{{{ recent_webroot_files.files }}}}"
  when: recent_webroot_files.files | length > 0
```

**✅ Harden the webroot so shells cannot be dropped or executed:**
```yaml
- name: Enforce restrictive webroot ownership
  ansible.builtin.file:
    path: /var/www/html
    owner: root
    group: www-data
    mode: '0750'
    recurse: yes
  become: yes

- name: Disable script execution in upload directories
  ansible.builtin.copy:
    dest: /var/www/html/uploads/.htaccess
    mode: '0644'
    content: |
      <FilesMatch "\\.(php|phtml|jsp|aspx?|cgi|pl|py)$">
        Require all denied
      </FilesMatch>
  become: yes

- name: Enable file integrity monitoring on the webroot (AIDE)
  ansible.builtin.package:
    name: aide
    state: present
  become: yes
```

**🔐 Web Shell Prevention Best Practices:**
- Never allow the web server process to write into its own document root
- Separate upload directories and strip execute permission on uploads
- Use a Web Application Firewall (WAF) with web-shell signatures
- Deploy file-integrity monitoring (AIDE, Tripwire, Wazuh) on webroots
- Rotate web server credentials and audit all webroot content after an incident
- Investigate how the shell got there (upload bypass, RCE in app, stolen creds)
"""

        return template

    def _generate_privilege_escalation_fix(self, code_snippet: str) -> str:
        """Generate fix for privilege escalation"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Security Risk:**
This command creates unauthorized privilege escalation paths, allowing attackers to gain root access.

**✅ Secure Fix (Proper privilege management):**
```yaml
# Remove dangerous privilege escalation
# If you need elevated privileges, use proper sudo configuration:

- name: Configure specific sudo permissions
  lineinfile:
    path: /etc/sudoers.d/application
    line: "{{{{ application_user }}}} ALL=(root) NOPASSWD: /usr/bin/systemctl restart {{{{ service_name }}}}"
    create: yes
    mode: '0440'
  become: yes

- name: Remove dangerous SUID bits
  file:
    path: "{{{{ item }}}}"
    mode: "u-s"
  loop:
    - /usr/bin/find
    - /usr/bin/vim
    - /bin/bash
  become: yes
```

**✅ Security Best Practices:**
- Follow principle of least privilege
- Use specific sudo rules instead of blanket permissions
- Regular audit of SUID/SGID binaries
- Implement proper access controls
"""

        return template

    def _generate_sudo_backdoor_fix(self, code_snippet: str) -> str:
        """Generate fix for sudo backdoors"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Security Risk:**
This command creates unauthorized privilege escalation paths, allowing attackers to gain root access.

**✅ Secure Fix (Proper privilege management):**
```yaml
# Remove dangerous privilege escalation
# If you need elevated privileges, use proper sudo configuration:

- name: Configure specific sudo permissions
  lineinfile:
    path: /etc/sudoers.d/application
    line: "{{{{ application_user }}}} ALL=(root) NOPASSWD: /usr/bin/systemctl restart {{{{ service_name }}}}"
    create: yes
    mode: '0440'
  become: yes

- name: Remove dangerous SUID bits
  file:
    path: "{{{{ item }}}}"
    mode: "u-s"
  loop:
    - /usr/bin/find
    - /usr/bin/vim
    - /bin/bash
  become: yes
```

**✅ Security Best Practices:**
- Follow principle of least privilege
- Use specific sudo rules instead of blanket permissions
- Regular audit of SUID/SGID binaries
- Implement proper access controls
"""

        return template

    def _generate_metadata_compromise_fix(self, rule_id: str, code_snippet: str) -> str:
        """Build a rule-specific remediation from the pattern's own metadata.

        The rule's ``title``, ``description``, ``recommendation`` and
        ``negative_examples`` (when present) carry far better context than
        any category-level boilerplate could - so render them. When a rule
        has no recommendation we still emit the rule's title and description
        verbatim, which beats the legacy "perform legitimate maintenance"
        template that had no relationship to the actual finding.
        """
        meta = _pattern_index.get(rule_id)
        title = meta.get("title") or rule_id
        description = meta.get("description") or ""
        recommendation = meta.get("recommendation") or ""
        negs = meta.get("negative_examples") or []

        secure_block = ""
        if negs:
            secure_block = f"\n**\u2705 Secure Fix Example:**\n```yaml\n{negs[0]}\n```\n"

        rec_block = ""
        if recommendation:
            rec_block = f"\n**\U0001f6e0 Recommendation:**\n{recommendation}\n"

        return (
            f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
            f"\n**\U0001f50d {title} ({rule_id}):**\n{description}\n"
            f"{rec_block}"
            f"{secure_block}"
        )

    def _generate_generic_compromise_fix(self, code_snippet: str) -> str:
        """Legacy boilerplate fallback. Retained for backward compatibility
        with tests that pin the old shape; new dispatch goes through
        ``_generate_metadata_compromise_fix`` so the remediation reflects
        the actual rule rather than category-level prose.
        """
        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Security Risk:**
This command contains patterns commonly associated with system compromise, backdoors, or malicious activities.

**✅ Secure Fix (Remove malicious patterns):**
```yaml
# Remove the malicious command entirely
# Replace with legitimate system administration tasks:

- name: Perform legitimate system maintenance
  package:
    name: "{{{{ required_packages }}}}"
    state: present
  become: yes

- name: Configure system properly
  template:
    src: config.j2
    dest: /etc/application/config.conf
    mode: '0644'
  become: yes
```

**✅ Security Best Practices:**
- Remove all suspicious or malicious commands
- Implement proper monitoring and alerting
- Use configuration management instead of raw commands
- Regular security audits and penetration testing
- Follow security hardening guidelines
"""

        return template

    def _generate_windows_shadow_copies_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Shadow Copy / Backup Deletion:**
Volume Shadow Copy and backup-catalog deletion is a near-universal ransomware precursor (MITRE T1490 Inhibit System Recovery). There is almost never a legitimate configuration-management reason to run `vssadmin delete shadows`, `wbadmin delete catalog`, or `Remove-WmiObject Win32_ShadowCopy`.

**✅ Secure Fix - Keep Shadow Copies and Add Off-Host Protection:**
```yaml
- name: Enable Volume Shadow Copy on the system volume
  ansible.windows.win_powershell:
    script: |
      vssadmin add shadowstorage /for=C: /on=C: /maxsize=10%
      wmic shadowcopy call create Volume=C:\\

- name: Back up the System State off-host
  ansible.windows.win_shell: |
    wbadmin start systemstatebackup -backuptarget:\\\\backup-nas\\systemstate\\{{{{ inventory_hostname }}}} -quiet
  become: yes
```

If you need to *prune* old shadow copies safely (legitimate capacity management), do it by retention, not by wholesale delete:

```powershell
$copies = Get-CimInstance Win32_ShadowCopy | Sort-Object InstallDate -Descending
$copies | Select-Object -Skip 7 | ForEach-Object {{ $_ | Remove-CimInstance }}
```

**🔐 Best Practice:** Alert in your SIEM on `vssadmin delete shadows`, `wbadmin delete`, and `Win32_ShadowCopy` Delete WMI calls (Sysmon Event ID 1 with those command lines, or Windows Security 4104 for PowerShell). Treat any match as a potential ransomware early indicator.
"""

    def _generate_windows_defender_tamper_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Defender Configuration Tampering:**
Disabling real-time protection, adding broad exclusion paths (C:\\, %TEMP%, %APPDATA%, `*`), or setting DisableAntiSpyware are MITRE T1562.001 Impair Defenses primitives. These are almost always post-exploitation steps that precede payload execution.

**✅ Secure Fix - Manage Defender Centrally, Re-Enable Protection:**
```yaml
- name: Re-enable Defender real-time protection
  ansible.windows.win_powershell:
    script: |
      Set-MpPreference -DisableRealtimeMonitoring $false
      Set-MpPreference -DisableBehaviorMonitoring $false
      Set-MpPreference -DisableIOAVProtection $false
      Set-MpPreference -DisableScriptScanning $false
      Set-MpPreference -MAPSReporting Advanced
      Set-MpPreference -SubmitSamplesConsent SendSafeSamples

- name: Remove overly broad Defender exclusions
  ansible.windows.win_powershell:
    script: |
      $prefs = Get-MpPreference
      $prefs.ExclusionPath |
        Where-Object {{ $_ -match '^[A-Z]:\\\\?$' -or $_ -eq '*' -or $_ -match '%(TEMP|APPDATA)%' }} |
        ForEach-Object {{ Remove-MpPreference -ExclusionPath $_ }}
```

Enforce via Group Policy / Intune so host-local `Set-MpPreference` calls can't regress:

```
Computer Config > Administrative Templates > Windows Components > Microsoft Defender Antivirus
  > Real-time Protection > Turn off real-time protection = Disabled   (enforce ON)
  > Exclusions > Exclusion paths = <empty or narrow list>
  > MAPS > Join Microsoft MAPS = Advanced
```

**🔐 Best Practice:** Use Defender for Endpoint (MDE) in tamper-protection mode - host-local preference changes are rejected. Alert on Event ID 5001 (real-time protection disabled) and 5004 (exclusion added). Never allow broad path exclusions (root drive, %TEMP%, %APPDATA%, wildcard).
"""

    def _generate_event_log_clear_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Windows Event Log Clearing:**
`wevtutil cl`, `Clear-EventLog`, `Remove-EventLog`, and `Win32_NTEventLogFile.ClearEventLog()` wipe host-local logs - MITRE T1070.001 Indicator Removal: Clear Windows Event Logs. This is a defense-evasion primitive with essentially no legitimate automation use case.

**✅ Secure Fix - Forward Logs, Don't Clear Them:**
```yaml
- name: Configure Windows Event Forwarding to a central collector
  ansible.windows.win_powershell:
    script: |
      wecutil qc /q
      winrm quickconfig -q
      wecutil cs subscription.xml

- name: Ensure event logs have adequate retention and auto-archive
  ansible.windows.win_powershell:
    script: |
      Limit-EventLog -LogName Security    -MaximumSize 1024MB -OverflowAction OverwriteOlder
      Limit-EventLog -LogName System      -MaximumSize 512MB  -OverflowAction OverwriteOlder
      Limit-EventLog -LogName Application -MaximumSize 512MB  -OverflowAction OverwriteOlder
```

If disk pressure is the real concern, raise retention + archive off-host rather than clearing:

```powershell
wevtutil epl Security "\\\\siem-archive\\logs\\$env:COMPUTERNAME-Security-$(Get-Date -f yyyyMMdd).evtx"
```

**🔐 Best Practice:** Forward all Security / System / Application / Sysmon / PowerShell Operational logs via WEF to a SIEM. Alert on Event ID 1102 (Security log cleared) and 104 (System log cleared) - these should *never* fire outside of a documented IR action.
"""
