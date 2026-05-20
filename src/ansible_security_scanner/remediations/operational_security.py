#!/usr/bin/env python3
"""
Remediation generator for operational security issues
"""

from .base import BaseRemediationGenerator
from .system_compromise import SystemCompromiseRemediationGenerator


class OperationalSecurityRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation examples for operational security issues"""

    def __init__(self):
        super().__init__()
        self._system_compromise = SystemCompromiseRemediationGenerator()

    _FIX_MAP = {
        "ansible_galaxy_untrusted": "_generate_galaxy_fix",
        "arp_spoofing": "_generate_nat_redirect_fix",
        "at_scheduled_execution": "_generate_time_delayed_fix",
        "audit_log_tampering": "_generate_log_tamper_fix",
        "aws_credentials_file_write": "_generate_credential_file_fix",
        "credential_file_creation": "_generate_credential_file_fix",
        "crypto_mining_binary": "_generate_crypto_mining_fix",
        "crypto_mining_pool": "_generate_crypto_mining_fix",
        "database_cli_credentials": "_generate_db_creds_fix",
        "dns_exfiltration": "_generate_dns_exfil_fix",
        "firewall_disable": "_generate_firewall_fix",
        "git_clone_in_playbook": "_generate_galaxy_fix",
        "history_file_tampering": "_generate_log_tamper_fix",
        "init_script_creation": "_generate_persistence_fix",
        "iptables_nat_redirect": "_generate_nat_redirect_fix",
        "kernel_module_load": "_generate_kernel_fix",
        "ld_library_path_manipulation": "_generate_ld_preload_fix",
        "ld_preload_injection": "_generate_ld_preload_fix",
        "log_file_deletion": "_generate_log_tamper_fix",
        "network_packet_capture": "_generate_recon_fix",
        "network_port_scan": "_generate_recon_fix",
        "nohup_background_persistence": "_generate_time_delayed_fix",
        "nsenter_container_escape": "_generate_container_escape_fix",
        "package_gpg_check_disabled": "_generate_gpg_fix",
        "pam_module_manipulation": "_generate_pam_fix",
        "proc_sysrq_trigger": "_generate_container_escape_fix",
        "process_memory_access": "_generate_process_memory_fix",
        "proxy_credential_exposure": "_generate_proxy_creds_fix",
        "rogue_ca_certificate": "_generate_ca_cert_fix",
        "ssh_authorized_keys_write": "_generate_authorized_keys_fix",
        "ssh_config_manipulation": "_generate_ssh_config_fix",
        "ssh_tunnel_creation": "_generate_ssh_tunnel_fix",
        "ssl_cert_generation": "_generate_ca_cert_fix",
        "systemd_service_creation": "_generate_persistence_fix",
        "untrusted_apt_repo": "_generate_package_repo_fix",
        "untrusted_yum_repo": "_generate_package_repo_fix",
        # Anti-forensics
        "apparmor_disable": "_generate_firewall_fix",
        "audit_daemon_disable": "_generate_log_tamper_fix",
        "coredump_enable": "_generate_process_memory_fix",
        "journal_log_flush": "_generate_log_tamper_fix",
        "seccomp_disable": "_generate_container_escape_fix",
        "selinux_disable": "_generate_firewall_fix",
        "syslog_redirect": "_generate_log_tamper_fix",
        "timestomping": "_generate_log_tamper_fix",
        "utmp_wtmp_tamper": "_generate_log_tamper_fix",
        # Environment hijacking
        "alternatives_manipulation": "_generate_generic_opsec_fix",
        "etc_hosts_manipulation": "_generate_generic_opsec_fix",
        "ld_config_manipulation": "_generate_ld_preload_fix",
        "library_path_injection": "_generate_ld_preload_fix",
        "motd_banner_injection": "_generate_persistence_fix",
        "ntp_server_manipulation": "_generate_generic_opsec_fix",
        "path_env_prepend": "_generate_ld_preload_fix",
        "pythonpath_manipulation": "_generate_ld_preload_fix",
        "resolv_conf_manipulation": "_generate_dns_exfil_fix",
        # Tunneling
        "chisel_tunnel": "_generate_ssh_tunnel_fix",
        "cloudflared_tunnel": "_generate_ssh_tunnel_fix",
        "frp_tunnel": "_generate_ssh_tunnel_fix",
        "ligolo_tunnel": "_generate_ssh_tunnel_fix",
        "ngrok_exposure": "_generate_ssh_tunnel_fix",
        "revsocks_tunnel": "_generate_ssh_tunnel_fix",
        "ssh_remote_forward": "_generate_ssh_tunnel_fix",
        "ssh_socks_proxy": "_generate_ssh_tunnel_fix",
        "vpn_setup_unauthorized": "_generate_generic_opsec_fix",
        # Binary planting
        "alias_command_hijack": "_generate_persistence_fix",
        "function_command_hijack": "_generate_persistence_fix",
        "pip_install_editable_path": "_generate_galaxy_fix",
        # IPMI / BMC
        "ipmi_bmc_access": "_generate_recon_fix",
        "redfish_bmc_api": "_generate_recon_fix",
        # DNS reconnaissance
        "dns_enum_tool": "_generate_recon_fix",
        "dns_zone_transfer": "_generate_recon_fix",
        # Systemd timer persistence
        "systemd_run_timer": "_generate_persistence_fix",
        "systemd_timer_creation": "_generate_persistence_fix",
        # Kernel / boot
        "ebpf_program_load": "_generate_kernel_fix",
        "grub_bootloader_modification": "_generate_kernel_fix",
        "initramfs_modification": "_generate_kernel_fix",
        # Container / cgroup escape
        "cgroup_escape": "_generate_container_escape_fix",
        # Memory harvest
        "swap_file_credential_harvest": "_generate_process_memory_fix",
        # Scheduled execution
        "at_job_persistence": "_generate_time_delayed_fix",
        # Active Directory operational security
        "krbtgt_password_reset": "_generate_krbtgt_reset_fix",
        "laps_password_read": "_generate_laps_read_fix",
    }

    def generate_operational_security_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_opsec_fix)

    def _generate_package_repo_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Untrusted Package Repository:**
Adding third-party repos allows malicious packages to be installed.

**Secure Fix:**
- Use internal package mirrors vetted by security
- Verify GPG signing keys for all repositories
- Pin package versions in all install tasks
"""

    def _generate_gpg_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Package GPG Verification Disabled:**
Disabling GPG checks allows unsigned or tampered packages to be installed.

**Secure Fix:**
- Never disable GPG verification
- Import and trust only approved signing keys
- Use `gpgcheck=yes` (or remove the override to use the default)
"""

    def _generate_ca_cert_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**CA Certificate Trust Store Manipulation:**
Installing a CA certificate enables MITM interception of all TLS traffic
on the target machine.

**Secure Fix:**
CA certificate management must go through your organization's PKI team.
Never install CA certs from playbooks without security review.
"""

    def _generate_recon_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Network Reconnaissance from Ansible:**
Port scanning and packet capture are reconnaissance techniques that should
not appear in standard automation playbooks.

**Required Action:**
- Remove network scanning tools from playbooks
- If needed for security testing, use approved vulnerability scanning platforms
"""

    def _generate_log_tamper_fix(self, code_snippet: str) -> str:
        snippet_lower = code_snippet.lower()
        syscomp = self._system_compromise
        if "history" in snippet_lower or "histfile" in snippet_lower or "histsize" in snippet_lower:
            return syscomp._generate_history_manipulation_fix(code_snippet)
        if "auditctl" in snippet_lower or "auditd" in snippet_lower:
            return syscomp._generate_log_tampering_fix(code_snippet)
        # Default to the rich log-tampering template for any other log deletion / truncation / redirect
        return syscomp._generate_log_tampering_fix(code_snippet)

    def _generate_persistence_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Unauthorized Persistence Mechanism:**
Creating systemd services or init scripts establishes processes that
survive reboots and may not be tracked by configuration management.

**Secure Fix:**
- Deploy services through approved configuration management (Ansible roles, Puppet)
- All services must be tracked in a CMDB
- Use security monitoring to detect unauthorized service creation
"""

    def _generate_ssh_tunnel_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**SSH Tunnel / Port Forwarding:**
SSH tunnels bypass network security controls (firewalls, IDS, DLP) by
creating encrypted channels to arbitrary destinations.

**Secure Fix:**
Use approved VPN or network access solutions. If internal connectivity
is required, request proper firewall rules through your network team.
"""

    def _generate_ssh_config_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**SSH Configuration Weakened:**
Enabling PermitRootLogin, PasswordAuthentication, or disabling
StrictHostKeyChecking weakens SSH security.

**Secure Fix:**
Follow CIS SSH benchmarks:
- PermitRootLogin no
- PasswordAuthentication no (use keys)
- StrictHostKeyChecking yes
"""

    def _generate_db_creds_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Database CLI with Inline Credentials:**
Passwords in command-line arguments are visible in `ps`, `/proc`, and logs.

**Secure Fix:**
```yaml
# Use credential files:
- name: query database
  ansible.builtin.shell: mysql --defaults-file=/root/.my.cnf -e "SELECT 1"
  no_log: true

# Or use Ansible modules:
- name: query database
  community.mysql.mysql_query:
    login_host: "{{{{ db_host }}}}"
    login_user: "{{{{ db_user }}}}"
    login_password: "{{{{ vault_db_password }}}}"
    query: "SELECT 1"
  no_log: true
```
"""

    def _generate_galaxy_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Ansible Galaxy Role from External Source:**
External Galaxy roles can contain arbitrary code that executes with
full privileges on target machines.

**Secure Fix:**
- Use a requirements.yml with pinned versions
- Mirror approved roles to an internal Galaxy server
- Review role code before first use
- Use `ansible-galaxy install --force` cautiously
"""

    def _generate_firewall_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**CRITICAL: Host Firewall Disabled:**
Flushing iptables or disabling firewalld/ufw removes all network
access controls from the host.

**Required Action:**
- Never disable host firewalls from automation
- Manage firewall rules through approved IaC
- Use `iptables -A` (append) for specific rules, never `-F` (flush)
"""

    def _generate_dns_exfil_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Potential DNS Exfiltration:**
Embedding variable data in DNS queries is a common technique for
exfiltrating data through DNS, bypassing most network controls.

**Required Action:**
Remove dynamic data from DNS queries. If DNS lookups are needed,
use static hostnames only.
"""

    def _generate_kernel_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Kernel Module Loading:**
Loading kernel modules can install rootkits, keyloggers, or network
sniffers that are invisible to userspace security tools.

**Required Action:**
- Kernel module management should only occur during approved system builds
- Use module signing enforcement (CONFIG_MODULE_SIG_FORCE)
- Monitor for unexpected module loads with auditd
"""

    def _generate_generic_opsec_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Operational Security Issue:**
- Follow CIS benchmarks for system hardening
- Use centralized, immutable logging
- Never disable security controls from automation
- All system changes should go through approved change management
"""

    def _generate_crypto_mining_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Cryptocurrency Mining Detected:**
This playbook installs or executes cryptocurrency mining software, which abuses compute resources and violates acceptable use policies.

**Action Required:**
- Remove the mining software immediately
- Investigate how this code entered the codebase
- Check for compromised credentials or insider threats
- Review billing for unexpected compute charges
"""

    def _generate_ld_preload_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**LD_PRELOAD Injection Detected:**
LD_PRELOAD forces the dynamic linker to load a shared library into every process, enabling function interception (hooking).

**Secure Alternative:**
- Never set LD_PRELOAD in playbooks -- this is a rootkit technique
- If library override is genuinely needed, use a systemd override instead:
```yaml
- name: Configure library override via systemd
  ansible.builtin.systemd:
    name: myservice
    override: |
      [Service]
      Environment=LD_PRELOAD=/approved/lib.so
```
"""

    def _generate_pam_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**PAM Module Manipulation Detected:**
Modifying PAM configuration can backdoor authentication, allowing login without valid credentials.

**Secure Alternative:**
```yaml
# PAM changes must go through approved hardening roles
- name: Apply CIS-hardened PAM configuration
  ansible.builtin.include_role:
    name: approved_security_hardening
    tasks_from: pam_configuration
```

**Action:** PAM changes require security team review and change control approval.
"""

    def _generate_process_memory_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Process Memory Access Detected:**
Accessing /proc/PID/mem, using ptrace, strace, or gdb on running processes can extract credentials from memory.

**Action Required:**
- Remove process debugging commands from playbooks
- This is a credential extraction technique -- investigate intent
- If debugging is genuinely needed, use approved observability tools (not ptrace/gdb in automation)
"""

    def _generate_time_delayed_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Deferred/Background Execution Detected:**
Using `at`, `nohup`, `disown`, `screen`, or `tmux` to run background processes can establish persistence outside management tooling.

**Secure Alternative:**
```yaml
# Use systemd services for long-running processes
- name: Create managed service
  ansible.builtin.systemd:
    name: myprocess
    state: started
    enabled: true
```

**Why:** systemd services are auditable and managed; nohup/screen processes are invisible to management.
"""

    def _generate_nat_redirect_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Network Traffic Redirection Detected:**
iptables NAT/DNAT/REDIRECT/MASQUERADE rules or ARP spoofing tools redirect network traffic, enabling man-in-the-middle attacks.

**Secure Alternative:**
```yaml
# Manage network rules through approved infrastructure
- name: Configure firewall via firewalld
  ansible.posix.firewalld:
    rich_rule: "rule family=ipv4 forward-port port=80 protocol=tcp to-port=8080"
    permanent: true
    state: enabled
```

**Action:** Network redirection rules should be managed through approved network infrastructure, not ad-hoc iptables commands.
"""

    def _generate_container_escape_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Container Escape Technique Detected:**
`nsenter` into PID 1 or accessing `/proc/sysrq-trigger` breaks out of container isolation, granting full host access.

**Action Required:**
- Remove container escape techniques immediately
- This is a strong indicator of malicious intent
- Review container security policies (no privileged mode, no host PID namespace)
- Use container-native tooling instead of host namespace access
"""

    def _generate_credential_file_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Credential File Creation Detected:**
Writing credential dotfiles (.netrc, .pgpass, .my.cnf, .boto, .aws/credentials) persists plaintext secrets on disk.

**Secure Alternative:**
```yaml
# Use secret manager lookups instead of credential files
- name: Access database with Vault credentials
  community.mysql.mysql_query:
    login_host: "{{{{ db_host }}}}"
    login_user: "{{{{ lookup('hashi_vault', 'secret/db:user') }}}}"
    login_password: "{{{{ lookup('hashi_vault', 'secret/db:password') }}}}"
    query: SELECT 1
  no_log: true
```
"""

    def _generate_authorized_keys_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**SSH Authorized Keys Modification:**
Adding SSH keys to authorized_keys establishes persistent access. Ensure this is intentional and auditable.

**Secure Alternative:**
```yaml
# Use the authorized_key module with explicit key management
- name: Deploy approved SSH key
  ansible.posix.authorized_key:
    user: deploy
    key: "{{{{ lookup('file', 'keys/deploy_ed25519.pub') }}}}"
    exclusive: true  # Remove unauthorized keys
    state: present
```

**Best Practice:** Use `exclusive: true` to ensure only approved keys are present. Audit all key additions.
"""

    def _generate_proxy_creds_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Proxy Credentials Exposed:**
Embedding username:password in proxy URLs exposes credentials in logs and process listings.

**Secure Alternative:**
```yaml
# Use credential-free proxy configuration
- name: Set proxy via environment
  ansible.builtin.environment:
    http_proxy: "http://proxy.internal:8080"
    https_proxy: "http://proxy.internal:8080"
    # Authenticate via PAC file or NTLM/Kerberos, not inline creds
```
"""

    def _generate_krbtgt_reset_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**krbtgt Password Reset:**
The krbtgt account's hash signs every Kerberos ticket in the domain. Resetting it is a legitimate
domain-recovery action (golden-ticket remediation) but must follow Microsoft's two-reset procedure
with a >10 hour gap; running it from routine automation either breaks Kerberos or launders a
compromise recovery.

**Secure Procedure - Two-Reset Playbook:**
```yaml
- name: First krbtgt password reset (uses double-password hashing)
  community.windows.win_domain_user:
    name: krbtgt
    password: "{{{{ lookup('password', '/dev/null length=64') }}}}"
    password_reset: true
    state: present

- name: Pause for >10 hours so existing TGTs age out naturally
  ansible.builtin.pause:
    prompt: "Wait at least 10 hours + max TGT lifetime, then run the second reset via a separate job."
  when: manual_gate | default(true)

- name: Second krbtgt password reset (finalizes invalidation of N-1 tickets)
  community.windows.win_domain_user:
    name: krbtgt
    password: "{{{{ lookup('password', '/dev/null length=64') }}}}"
    password_reset: true
    state: present
  when: second_reset_authorized | default(false)
```

**Best Practice:** Use Microsoft's signed `Reset-KrbtgtKeys.ps1` script, gated behind a change ticket
+ Tier-0 approver. Audit the event in the Security log (Event ID 4781 on krbtgt). Never run krbtgt
resets from scheduled automation without a human approver.
"""

    def _generate_laps_read_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**LAPS Password Attribute Read:**
LAPS (ms-Mcs-AdmPwd / msLAPS-Password) stores per-machine local administrator passwords. Bulk reads
from automation indicate either excessive scope (the script has more rights than it needs) or
credential harvesting. Legitimate reads should be just-in-time, for a specific host, by a named
engineer.

**Secure Pattern - Scoped, Audited LAPS Retrieval:**
```yaml
- name: Fetch the LAPS password for a single specific host
  ansible.windows.win_powershell:
    script: |
      Import-Module LAPS
      Get-LapsADPassword -Identity "{{{{ target_hostname }}}}" -AsPlainText
  register: laps_result
  no_log: true
  delegate_to: laps-reader-host
  become: false

- name: Use it transiently, never store it
  ansible.builtin.set_fact:
    ansible_password: "{{{{ laps_result.output.Password }}}}"
  no_log: true
```

**Audit Current LAPS Read ACEs:**
```powershell
# Who can read ms-Mcs-AdmPwd on OU=Servers? Should be a small, named ops group.
Get-Acl "AD:OU=Servers,DC=example,DC=com" | Select-Object -ExpandProperty Access |
  Where-Object {{ $_.ObjectType -eq 'ea1b7b93-5e48-46d5-bc6c-4df4fda78a35' }} |
  Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType
```

**Best Practice:** Prefer Windows LAPS (2023+) with encrypted password storage. Rotate LAPS passwords
after every use (Reset-LapsPassword). Audit ControlAccessRight reads of ms-Mcs-AdmPwd (Event ID 4662
with the attribute GUID above). Investigate any bulk retrieval as a potential credential-harvest event.
"""
