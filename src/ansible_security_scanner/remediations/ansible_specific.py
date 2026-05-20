#!/usr/bin/env python3
"""
Remediation generator for Ansible-specific security patterns
"""

from __future__ import annotations

from .base import BaseRemediationGenerator


class AnsibleSpecificRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation examples for Ansible-specific security issues"""

    _FIX_MAP = {
        "ansible_become_pass": "_fix_become_pass",
        "ansible_connection_password": "_fix_connection_password",
        "ansible_ssh_pass": "_fix_ssh_pass",
        "ansible_winrm_password": "_fix_winrm_pass",
        "cicd_token_echo": "_fix_cicd_token",
        "cicd_token_exposure": "_fix_cicd_token",
        "elasticsearch_unauthenticated": "_fix_elasticsearch_unauth",
        "kubeconfig_access": "_fix_kubeconfig",
        "mongodb_unauthenticated": "_fix_mongodb_unauth",
        "powershell_download_cradle": "_fix_powershell_cradle",
        "powershell_invoke_expression": "_fix_powershell_iex",
        "redis_unauthenticated": "_fix_redis_unauth",
        "snmp_community_string": "_fix_snmp",
        "terraform_state_access": "_fix_terraform_state",
        "vault_password_file": "_fix_vault_password",
        "windows_registry_persistence": "_fix_registry_persistence",
        # AWX / AAP / Tower runtime
        "awx_ask_credential_on_launch": "_fix_awx_ask_credential",
        "awx_controller_host_literal_admin": "_fix_awx_token",
        "awx_credential_inputs_literal": "_fix_awx_credential_inputs",
        "awx_execution_environment_privileged": "_fix_awx_ee_privileged",
        "awx_inventory_source_untrusted_scm": "_fix_awx_inventory_source",
        "awx_job_launch_user_extra_vars": "_fix_awx_survey_whitelist",
        "awx_notification_template_token": "_fix_awx_token",
        "awx_oauth_token_literal": "_fix_awx_token",
        "awx_survey_password_literal_default": "_fix_awx_survey_password",
        "awx_webhook_secret_literal": "_fix_awx_token",
        # Lateral movement
        "add_host_dynamic": "_fix_lateral_movement",
        "ansible_config_override": "_fix_custom_plugin",
        "ansible_python_interpreter_override": "_fix_python_interpreter",
        "ansible_vault_password_env": "_fix_vault_password",
        "connection_local_shell": "_fix_lateral_movement",
        "custom_callback_plugin": "_fix_custom_plugin",
        "custom_filter_plugin": "_fix_custom_plugin",
        "delegate_to_external_host": "_fix_lateral_movement",
        "facts_d_injection": "_fix_facts_injection",
        "include_role_from_url": "_fix_custom_plugin",
        "local_action_shell": "_fix_lateral_movement",
        "wait_for_port_scan": "_fix_lateral_movement",
        # Windows / AD lateral movement
        "ad_constrained_delegation_modify": "_fix_ad_delegation_modify",
        "psexec_style_service_install": "_fix_psexec_service_install",
        "winrm_unencrypted_transport": "_fix_winrm_encrypted_transport",
    }

    def generate_ansible_specific_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._fix_generic)

    def _fix_become_pass(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Use Vault-encrypted variable instead of plaintext
ansible_become_password: "{{{{ vault_become_password }}}}"

# Or prompt at runtime:
#   ansible-playbook site.yml --ask-become-pass
```

**\\U0001f510 Best Practice:** Store become passwords in Ansible Vault or an external credential manager (HashiCorp Vault, CyberArk). Never commit plaintext passwords.
"""

    def _fix_ssh_pass(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Use SSH key-based authentication (preferred)
ansible_ssh_private_key_file: "~/.ssh/id_ed25519"

# Or Vault-encrypted password as fallback
ansible_ssh_password: "{{{{ vault_ssh_password }}}}"
```

**\\U0001f510 Best Practice:** SSH key-based authentication is always preferred over password auth. If passwords are required, encrypt them with Ansible Vault.
"""

    def _fix_winrm_pass(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Use Vault-encrypted WinRM credentials
ansible_winrm_password: "{{{{ vault_winrm_password }}}}"
ansible_winrm_transport: kerberos  # Preferred over basic auth
```

**\\U0001f510 Best Practice:** Use Kerberos authentication for WinRM. If password auth is required, store credentials in Vault.
"""

    def _fix_connection_password(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Use Vault-encrypted connection credentials
ansible_password: "{{{{ vault_connection_password }}}}"
```

**\\U0001f510 Best Practice:** All connection-level passwords should be Vault-encrypted or sourced from an external credential store.
"""

    def _fix_vault_password(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Use a vault-id with a script-based lookup
# ansible-playbook site.yml --vault-id prod@/path/to/vault-client.py

# Or use environment variable
# export ANSIBLE_VAULT_PASSWORD_FILE=/path/to/secure/script.sh
```

**\\U0001f510 Best Practice:** Use vault-id with a script that retrieves the password from a secret manager at runtime, not a plaintext file.
"""

    def _fix_snmp(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Use SNMPv3 with authentication and encryption
- name: Query device via SNMPv3
  community.general.snmp_facts:
    host: "{{{{ inventory_hostname }}}}"
    version: v3
    username: "{{{{ vault_snmp_user }}}}"
    auth: SHA
    authkey: "{{{{ vault_snmp_auth_key }}}}"
    privacy: AES
    privkey: "{{{{ vault_snmp_priv_key }}}}"
```

**\\U0001f510 Best Practice:** Migrate from SNMPv1/v2c to SNMPv3. Never use default community strings like "public" or "private".
"""

    def _fix_terraform_state(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Use Terraform outputs through a remote backend with encryption
- name: Get infrastructure outputs
  ansible.builtin.command:
    cmd: terraform output -json vpc_id
    chdir: /path/to/terraform
  register: tf_output
  no_log: true  # State may contain secrets
```

**\\U0001f510 Best Practice:** Use encrypted remote state backends (S3+DynamoDB, Consul). Never access terraform.tfstate directly; it contains all resource attributes including secrets.
"""

    def _fix_kubeconfig(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Use short-lived tokens from OIDC or service accounts
- name: Authenticate to cluster
  kubernetes.core.k8s_auth:
    host: "{{{{ k8s_api_url }}}}"
    api_key: "{{{{ vault_k8s_token }}}}"
  register: k8s_auth

# Don't distribute kubeconfig files; use token-based auth
```

**\\U0001f510 Best Practice:** Use OIDC or service account tokens instead of distributing kubeconfig files. Tokens should be short-lived and scoped.
"""

    def _fix_cicd_token(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# CI/CD tokens should only be used via masked environment variables
- name: Authenticate to CI system
  ansible.builtin.uri:
    url: "{{{{ ci_api_url }}}}"
    headers:
      Authorization: "Bearer {{{{ lookup('env', 'CI_JOB_TOKEN') }}}}"
  no_log: true
```

**\\U0001f510 Best Practice:** CI/CD tokens are scoped to pipeline runs. Never hardcode them; access via environment with no_log: true.
"""

    def _fix_redis_unauth(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Always authenticate to Redis
- name: Query Redis with auth
  ansible.builtin.command:
    cmd: redis-cli -a "{{{{ vault_redis_password }}}}" --tls PING
  no_log: true
```

**\\U0001f510 Best Practice:** Enable Redis AUTH and TLS. Use ACLs for fine-grained access control (Redis 6+).
"""

    def _fix_elasticsearch_unauth(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Use authenticated Elasticsearch access
- name: Query Elasticsearch
  ansible.builtin.uri:
    url: "https://{{{{ es_host }}}}:9200/_cluster/health"
    user: "{{{{ vault_es_user }}}}"
    password: "{{{{ vault_es_password }}}}"
    validate_certs: true
  no_log: true
```

**\\U0001f510 Best Practice:** Enable Elasticsearch security (X-Pack) with RBAC, TLS, and authentication. Never expose port 9200 without auth.
"""

    def _fix_mongodb_unauth(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Authenticate to MongoDB with SCRAM-SHA-256
- name: Query MongoDB
  community.mongodb.mongodb_shell:
    login_host: "{{{{ mongodb_host }}}}"
    login_user: "{{{{ vault_mongo_user }}}}"
    login_password: "{{{{ vault_mongo_password }}}}"
    db: admin
    eval: "db.runCommand({{ ping: 1 }})"
  no_log: true
```

**\\U0001f510 Best Practice:** Enable MongoDB authentication with SCRAM-SHA-256. Use TLS for transport encryption.
"""

    def _fix_powershell_cradle(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Download to disk with checksum verification, then execute
- name: Download script
  ansible.windows.win_get_url:
    url: "{{{{ approved_script_url }}}}"
    dest: C:\\temp\\setup.ps1
    checksum: "{{{{ script_sha256 }}}}"

- name: Execute verified script
  ansible.windows.win_shell: C:\\temp\\setup.ps1
```

**\\U0001f510 Best Practice:** Never use download cradles (IEX + WebClient). Download to disk, verify integrity, then execute.
"""

    def _fix_powershell_iex(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Use explicit cmdlets with validated parameters
- name: Run specific command
  ansible.windows.win_shell: |
    Get-Service -Name "wuauserv" | Select-Object Status
```

**\\U0001f510 Best Practice:** Invoke-Expression (IEX) is a code injection vector. Use explicit PowerShell cmdlets instead.
"""

    def _fix_registry_persistence(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
```yaml
# Manage startup applications through Group Policy, not registry
- name: Configure startup via GPO
  ansible.windows.win_group_policy:
    name: "Startup Scripts"
    state: present
```

**\\U0001f510 Best Practice:** Registry Run/RunOnce keys are a classic persistence technique. Use GPO or SCCM for legitimate startup configuration.
"""

    def _fix_generic(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\u2705 Secure Fix:**
Apply security best practices for this Ansible-specific security issue.

**\\U0001f510 Best Practice:**
- Store all credentials in Ansible Vault or external secret managers
- Use no_log: true on tasks that handle secrets
- Prefer key-based authentication over passwords
- Use short-lived tokens instead of long-lived credentials
"""

    def _fix_lateral_movement(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 Ansible Lateral Movement Risk:**
This pattern can pivot execution to unintended hosts or run commands on the Ansible controller itself.

**\\u2705 Secure Fix:**
```yaml
# Only delegate to hosts from trusted inventory groups
- name: safe delegated task
  ansible.builtin.command: hostname
  delegate_to: "{{{{ groups['trusted_servers'][0] }}}}"
  when: groups['trusted_servers'] | length > 0
```

**\\U0001f510 Best Practice:**
- Never use user-supplied variables in delegate_to or add_host
- Restrict local_action and connection: local to read-only tasks
- Audit all delegate_to targets against an approved host list
- Use inventory groups instead of dynamic host injection
"""

    def _fix_python_interpreter(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 Python Interpreter Override:**
Overriding ansible_python_interpreter to a custom binary allows arbitrary code execution.

**\\u2705 Secure Fix:**
```yaml
ansible_python_interpreter: auto
# Or: ansible_python_interpreter: /usr/bin/python3
```

**\\U0001f510 Best Practice:** Never point the interpreter to user-writable paths. Use `auto` for discovery.
"""

    def _fix_custom_plugin(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 Custom Plugin / Config Override:**
Custom plugins execute arbitrary Python code. Custom ansible.cfg can disable security features.

**\\u2705 Secure Fix:**
```yaml
# Only use plugins from trusted Ansible collections
# ansible-galaxy collection install community.general:==8.0.0
```

**\\U0001f510 Best Practice:** Only use official Ansible collections with pinned versions. Audit all custom plugin code.
"""

    def _fix_facts_injection(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 Custom Facts Script Injection:**
Scripts in /etc/ansible/facts.d/ execute automatically during fact gathering with root privileges.

**\\u2705 Secure Fix:**
```yaml
- name: set custom facts safely
  ansible.builtin.set_fact:
    custom_app_version: "{{{{ app_version }}}}"
```

**\\U0001f510 Best Practice:** Use set_fact instead of facts.d scripts. Never deploy executable scripts from playbooks to facts.d.
"""

    def _fix_awx_survey_whitelist(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 Unconstrained extra_vars at Job Launch:**
Forwarding webhook/API payloads directly into extra_vars lets attackers override playbook defaults
(become_user, ansible_python_interpreter, task vars) without authorization.

**\\u2705 Secure Fix:**
```yaml
- name: Launch approved deploy job with whitelisted variables only
  awx.awx.job_launch:
    job_template: "Deploy Web Tier"
    extra_vars:
      target_env: "{{{{ allowed_envs | select('equalto', requested_env) | first }}}}"
      build_id: "{{{{ build_id | regex_search('^[0-9a-f]{{8,40}}$') }}}}"
```

Configure the Job Template:

```yaml
- name: Harden Job Template against variable injection
  awx.awx.job_template:
    name: "Deploy Web Tier"
    ask_variables_on_launch: false
    survey_enabled: true
    survey_spec:
      name: "Deployment inputs"
      description: "Validated inputs only"
      spec:
        - question_name: "Environment"
          variable: "target_env"
          type: "multiplechoice"
          choices: ["dev", "stage", "prod"]
          required: true
```

**\\U0001f510 Best Practice:** Prefer a Survey Spec with typed, enumerated inputs over ask_variables_on_launch.
Validate any webhook payload against an allowlist before forwarding it as extra_vars.
"""

    def _fix_awx_survey_password(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 Plaintext Password in Survey Spec:**
A password-type survey field with a literal default leaks the value into the Job Template export,
the controller database, and anyone with read access to the Survey.

**\\u2705 Secure Fix:**
```yaml
survey_spec:
  spec:
    - question_name: "Deploy token"
      variable: "deploy_token"
      type: "password"
      required: true
      default: ""        # never inline the real value
```

If an automation-time default is required, reference a credential instead:

```yaml
- name: Launch deploy with vaulted secret
  awx.awx.job_launch:
    job_template: "Deploy"
    extra_vars:
      deploy_token: "{{{{ lookup('community.hashi_vault.hashi_vault',
                         'secret=secret/data/deploy:token') }}}}"
```

**\\U0001f510 Best Practice:** Passwords never live in survey_spec defaults. Pull them from
HashiCorp Vault, CyberArk, or an AWX Credential object at runtime.
"""

    def _fix_awx_token(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 AWX/AAP Token or Webhook Secret in Source:**
OAuth tokens, controller passwords, and webhook signing keys grant job-launch authority.
Committing them exposes automation to anyone with repo read access.

**\\u2705 Secure Fix:**
```yaml
- name: Run against AWX with short-lived token from Vault
  awx.awx.job_launch:
    job_template: "Deploy"
    controller_host: "https://awx.example.com"
    controller_oauthtoken: "{{{{ lookup('env', 'TOWER_OAUTHTOKEN') }}}}"
    validate_certs: true
```

Rotate any committed token **immediately** - rotation is the fix; removing the line is not enough:

```bash
awx-manage revoke_oauth2_tokens --user ci-bot
awx-manage create_oauth2_token --user ci-bot   # save the new token to Vault, not to Git
```

**\\U0001f510 Best Practice:** Issue tokens per-user, scope them to the minimum required Job Templates,
and rotate on a schedule (30-90 days). Prefer short-lived OAuth tokens over long-lived personal tokens.
"""

    def _fix_awx_credential_inputs(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 Inline Secret in awx.awx.credential.inputs:**
The credential object is meant to *protect* secrets. An inline literal in its `inputs` block
leaks the value in source control and defeats that protection.

**\\u2705 Secure Fix:**
```yaml
- name: Register a deploy credential, sourcing the password from Vault
  awx.awx.credential:
    name: "prod-deploy"
    organization: "Default"
    credential_type: "Machine"
    inputs:
      username: "deployer"
      password: "{{{{ lookup('community.hashi_vault.hashi_vault',
                     'secret=secret/data/awx/deploy:password') }}}}"
      become_method: "sudo"
      become_username: "root"
      become_password: "{{{{ lookup('community.hashi_vault.hashi_vault',
                            'secret=secret/data/awx/deploy:become_password') }}}}"
```

Prefer an **External Credential** plugin so AWX fetches the secret from Vault at runtime:

```yaml
- name: Wire an External Credential backed by HashiCorp Vault
  awx.awx.credential:
    name: "vault-backed-deploy"
    credential_type: "HashiCorp Vault Secret Lookup"
    inputs:
      url: "https://vault.example.com"
      token: "{{{{ lookup('env', 'VAULT_TOKEN') }}}}"
      api_version: "v2"
```

**\\U0001f510 Best Practice:** Use External Credentials so the secret never materializes in AWX's
own database. Treat AWX as a workflow engine, not as a secret store.
"""

    def _fix_awx_ee_privileged(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 Privileged Execution Environment:**
--privileged, --network=host, hostPath mounts, and `pull: always` with a `:latest` image all
break the EE sandbox - a compromised playbook can reach the controller host kernel.

**\\u2705 Secure Fix:**
```yaml
- name: Register a least-privilege execution environment
  awx.awx.execution_environment:
    name: "deploy-ee"
    image: "quay.io/acme/deploy-ee:1.4.2@sha256:<digest>"   # pinned tag + digest
    pull: "missing"
```

If elevated capabilities are required, scope them explicitly instead of --privileged:

```yaml
# In the EE Containerfile:
USER 1000
# Runtime (podman/docker):
#   --cap-add=NET_ADMIN --cap-add=NET_RAW  (instead of --privileged)
```

**\\U0001f510 Best Practice:** Default to rootless, unprivileged EEs. Pin images by digest.
Add capabilities one-by-one based on actual task needs, and review additions in security review.
"""

    def _fix_awx_inventory_source(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 Untrusted Inventory Source:**
Inventory controls which hosts run what. A source that points at an unauthenticated URL,
a raw gist, or a wildcard branch lets an attacker who takes over the source redirect automation
to arbitrary hosts.

**\\u2705 Secure Fix:**
```yaml
- name: Inventory sourced from a signed, pinned Project
  awx.awx.inventory_source:
    name: "prod-inventory"
    inventory: "Production"
    source: "scm"
    source_project: "infra-prod"
    source_path: "inventories/prod/hosts.yml"
    update_on_launch: true
    verbosity: 1

- name: Require signed commits on the inventory branch
  awx.awx.project:
    name: "infra-prod"
    scm_type: "git"
    scm_url: "git@github.com:acme/infra-prod.git"
    scm_branch: "release/2026.04"       # pinned tag or release branch
    scm_update_on_launch: false
```

**\\U0001f510 Best Practice:** Point inventory Projects at a private, signed-commit-required repo.
Pin to a specific release branch or tag, not main/HEAD. Audit SCM credentials separately.
"""

    def _fix_awx_ask_credential(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 ask_credential_on_launch with Privileged Become:**
Letting launchers pick their own credential removes the deterministic identity/audit trail
for privileged automation. Anyone who can launch can substitute a credential with more power
than the Job Template's author intended.

**\\u2705 Secure Fix:**
```yaml
- name: Pin credentials on privileged Job Templates
  awx.awx.job_template:
    name: "Prod Deploy"
    project: "infra-prod"
    playbook: "site.yml"
    credentials: ["prod-deploy-machine", "prod-aws-iam"]   # explicit
    ask_credential_on_launch: false
    become_enabled: true
```

If on-demand credential choice is genuinely needed (ad-hoc ops), scope it:

```yaml
- name: Ad-hoc runbook with credential prompt but no become
  awx.awx.job_template:
    name: "Ops Query"
    ask_credential_on_launch: true
    become_enabled: false                              # cannot escalate
    allowed_credentials: ["readonly-machine"]          # whitelist
```

**\\U0001f510 Best Practice:** Pin credentials on any Job Template with become_enabled=true.
Require MFA on user accounts that can launch privileged templates.
"""

    def _fix_winrm_encrypted_transport(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 Unencrypted WinRM Transport:**
basic-auth over HTTP, or `message_encryption: never`, sends credentials and task output in
cleartext - anyone on the path can harvest tokens or relay NTLM authentication.

**\\u2705 Secure Fix - Kerberos over HTTPS:**
```yaml
# group_vars/windows.yml
ansible_connection: winrm
ansible_port: 5986
ansible_winrm_scheme: https
ansible_winrm_transport: kerberos            # or credssp, certificate
ansible_winrm_server_cert_validation: validate
ansible_winrm_message_encryption: always
```

Configure the Windows target to require HTTPS + message encryption:

```powershell
# Enforce HTTPS-only WinRM on the target
winrm quickconfig -transport:https
winrm set winrm/config/service '@{{AllowUnencrypted="false"}}'
winrm set winrm/config/service/auth '@{{Basic="false"; Kerberos="true"; Negotiate="true"}}'
```

**\\U0001f510 Best Practice:** Use Kerberos transport on domain-joined machines (no password on the
wire, mutual auth). Require `AllowUnencrypted=false` via Group Policy so individual misconfigurations
can't regress the fleet.
"""

    def _fix_psexec_service_install(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 PsExec-Style Remote Binary Start:**
Telling the service manager to fetch and run a binary from a UNC share or HTTP URL at start time
is the PsExec / Impacket lateral-movement primitive. If the remote source is attacker-controlled
(or attacker-replaceable), every restart re-executes untrusted code as SYSTEM.

**\\u2705 Secure Fix - Stage Locally With Integrity Check:**
```yaml
- name: Stage the signed binary to local disk
  ansible.windows.win_copy:
    src: "files/myservice-1.4.2.exe"
    dest: "C:\\\\Program Files\\\\MyService\\\\myservice.exe"
    checksum: "sha256:9f1c2a...b3e4"   # verified at copy time

- name: Verify Authenticode signature before registering the service
  ansible.windows.win_powershell:
    script: |
      $sig = Get-AuthenticodeSignature "C:\\\\Program Files\\\\MyService\\\\myservice.exe"
      if ($sig.Status -ne "Valid") {{ throw "Signature invalid: $($sig.Status)" }}

- name: Register the service pointing at the LOCAL path
  ansible.windows.win_service:
    name: "MyService"
    display_name: "MyService"
    path: "C:\\\\Program Files\\\\MyService\\\\myservice.exe"
    start_mode: auto
    state: started
```

**\\U0001f510 Best Practice:** Never let the service manager resolve a remote path at start time.
Stage, verify signature, then register. Audit services with remote `ImagePath` values
(`Get-CimInstance Win32_Service | Where PathName -match '^\\\\\\\\'`).
"""

    def _fix_ad_delegation_modify(self, code_snippet: str) -> str:
        return f"""
**\\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\\U0001f6a8 Kerberos Delegation Attribute Modification:**
msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity, and the
TRUSTED_FOR_DELEGATION / TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION UAC flags control
Kerberos delegation. Writes to these attributes enable Resource-Based Constrained
Delegation (RBCD) abuse - an attacker who can write on a target computer object can
impersonate arbitrary users via S4U2Self/S4U2Proxy.

**\\u2705 Secure Fix - Remove Unintended Delegation and Audit ACEs:**
```yaml
- name: Clear RBCD on a computer object
  community.general.ldap_attrs:
    dn: "CN={{{{ target_computer }}}},OU=Servers,DC=example,DC=com"
    attributes:
      msDS-AllowedToActOnBehalfOfOtherIdentity: []
    state: exact

- name: Enumerate who has GenericWrite/WriteProperty on OU=Servers
  ansible.windows.win_powershell:
    script: |
      Import-Module ActiveDirectory
      Get-Acl "AD:OU=Servers,DC=example,DC=com" |
        Select-Object -ExpandProperty Access |
        Where-Object {{ $_.ActiveDirectoryRights -match 'GenericWrite|WriteProperty' }} |
        Format-Table IdentityReference, ActiveDirectoryRights, InheritanceType
```

Mark sensitive accounts as "Account is sensitive and cannot be delegated":

```yaml
- name: Protect privileged accounts from delegation
  microsoft.ad.user:
    identity: "{{{{ item }}}}"
    account_not_delegated: true
  loop:
    - "svc-backup"
    - "admin-prod"
```

**\\U0001f510 Best Practice:** Put Tier-0 accounts in the "Protected Users" group. Limit who
can write on computer objects' AllowedToActOnBehalfOfOtherIdentity (should be Tier-0 admins only).
Audit with BloodHound's `HasAllExtendedRights`/`WriteDacl` edges during regular purple-team reviews.
"""
