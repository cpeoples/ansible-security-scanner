#!/usr/bin/env python3
"""
Curl remediation generator for Ansible Security Scanner
"""

import logging
import re
from typing import Any

from .base import BaseRemediationGenerator

logger = logging.getLogger(__name__)


class CurlRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for curl-related security issues"""

    def generate_curl_remediation(
        self, code_snippet: str, command_parts: dict[str, Any], variables: list[str]
    ) -> str:
        """Generate specific curl remediation based on the actual command"""
        if "-u" in code_snippet and ":" in code_snippet:
            return self._generate_basic_auth_fix(code_snippet)
        if "-d" in code_snippet and "{" in code_snippet:
            return self._generate_json_payload_fix(code_snippet)
        if any(
            header in code_snippet.lower() for header in ["authorization:", "x-api-key:", "bearer"]
        ):
            return self._generate_header_auth_fix(code_snippet)
        return self._generate_generic_curl_fix(code_snippet, variables)

    def generate_basic_auth_fix(self, code_snippet: str, var_name: str, env_var: str) -> str:
        """Generate remediation for curl commands with basic authentication"""

        # Extract username and password from -u flag
        auth_match = re.search(r'-u\s+["\']([^:]+):([^"\']+)["\']', code_snippet)
        if not auth_match:
            auth_match = re.search(r"-u\s+([^:]+):([^\s]+)", code_snippet)

        if auth_match:
            username = auth_match.group(1)
            auth_match.group(2)
        else:
            username = "user"

        field_match = re.search(r"^([^:]+):", code_snippet.strip())
        field_name = field_match.group(1).strip() if field_match else "shell"

        base_name = username.lower().replace("-", "_")
        username_var = f"vault_{base_name}_username"
        password_var = f"vault_{base_name}_password"

        full_command = (
            code_snippet.split(":", 1)[1].strip() if ":" in code_snippet else code_snippet
        )
        curl_without_auth = re.sub(r'-u\s+["\']?[^:]+:[^\s"\']+["\']?\s*', "", full_command).strip()

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded Credentials in curl Command:**
This curl command contains hardcoded username and password in the -u flag, which should never be stored in plaintext.

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook:
{field_name}: >-
  curl -k -u "{{{{ {username_var} }}}}:{{{{ {password_var} }}}}" {curl_without_auth}"""

        template += f'''

# In group_vars/all/vault.yml (encrypted):
{username_var}: "{username}"
{password_var}: "your_secure_password_here"
```

**✅ Alternative Fix (environment variables):**
```yaml
{field_name}: >-
  curl -k -u "{{{{ lookup('env', '{username.upper()}_USERNAME') }}}}:{{{{ lookup('env', '{username.upper()}_PASSWORD') }}}}" {curl_without_auth}
```

**✅ Best Fix (Use Ansible uri module):**
```yaml
# Replace curl with proper Ansible uri module:
- name: Make authenticated API request
  uri:
    url: "https://your-api-endpoint.com"
    method: GET
    user: "{{{{ {username_var} }}}}"
    password: "{{{{ {password_var} }}}}"
    force_basic_auth: yes
    validate_certs: yes
  register: api_response
```

**🔐 curl Basic Auth Security Best Practices:**
- **Use Ansible uri module** instead of shell curl for better error handling and security
- **Use SSH keys** instead of passwords for remote authentication
- **Enable SSL/TLS** for database connections in production
- **Use connection pooling** and proper timeout settings
- **Implement least-privilege access** - don't use root/admin accounts
- **Enable audit logging** for all database/system access
- **Rotate credentials regularly** and use strong passwords
- **Consider using service accounts** with limited permissions

'''

        return template

    def generate_json_payload_fix(self, code_snippet: str, var_name: str, env_var: str) -> str:
        """Generate remediation for curl commands with JSON payloads containing credentials"""

        # Extract URL from curl command
        url_match = re.search(r"curl.*?(?:-X\s+\w+\s+)?(?:https?://[^\s]+)", code_snippet)
        url = url_match.group(0).split()[-1] if url_match else "https://api.example.com/endpoint"

        # Handle single-, double-, and unquoted -d payloads.
        json_patterns = [
            r"-d\s+\'(\{[^\']+\})\'",  # Single quotes: -d '{"key": "value"}'
            r'-d\s+"(\{[^"]+\})"',  # Double quotes: -d "{"key": "value"}"
            r"-d\s+(\{[^}]+\})",  # No quotes: -d {"key": "value"}
        ]

        json_match = None
        for pattern in json_patterns:
            json_match = re.search(pattern, code_snippet, re.DOTALL)
            if json_match:
                break

        credentials = []
        if json_match:
            json_payload = json_match.group(1)
            logger.debug("Extracted JSON payload: %s...", json_payload[:100])

            # Normalize escaped quotes before regex-matching credentials.
            normalized_json = json_payload.replace('\\"', '"').replace("\\'", "'")

            credential_keywords = [
                "password",
                "pass",
                "pwd",
                "secret",
                "key",
                "token",
                "api_key",
                "apikey",
                "auth_key",
                "auth_token",
                "ssh_key",
                "sshkey",
                "private_key",
                "public_key",
                "user",
                "username",
                "admin_user",
                "login",
                "account",
            ]

            # Use a flexible pattern that works with any quote style
            # This pattern looks for: any_quotes + credential_word + any_quotes + colon + any_quotes + value + any_quotes
            flexible_pattern = (
                r'["\']?([^"\']*(?:'
                + "|".join(credential_keywords)
                + r')[^"\']*)["\']?\s*:\s*["\']?([^"\',:}]+)["\']?'
            )

            all_matches = re.findall(flexible_pattern, normalized_json, re.IGNORECASE)
            logger.debug("Found %d potential matches: %s", len(all_matches), all_matches)

            processed_credentials = set()  # dedupe across re-matches of the same key
            for key, value in all_matches:
                key = key.strip().lower()
                value = value.strip()

                # Skip if value is too short (likely not a real credential)
                if len(value) < 3:
                    continue

                # Skip if it looks like a template variable
                if "{{" in value and "}}" in value:
                    continue

                cred_type = "password"
                if any(word in key for word in ["api_key", "apikey", "auth_key", "token"]):
                    cred_type = "api_key"
                elif any(
                    word in key for word in ["ssh_key", "sshkey", "private_key", "public_key"]
                ):
                    cred_type = "ssh_key"
                elif any(
                    word in key for word in ["user", "username", "admin_user", "login", "account"]
                ):
                    cred_type = "username"

                # Dedupe across the extracted credentials block - the YAML
                # may repeat the same (key, type) pair in several tasks.
                unique_key = f"{key}_{cred_type}"
                if unique_key not in processed_credentials:
                    processed_credentials.add(unique_key)
                    credentials.append(
                        {
                            "key": key,
                            "value": value,
                            "type": cred_type,
                            "vault_var": f"vault_{key.replace('-', '_').replace(' ', '_').lower()}",
                        }
                    )

        if not credentials:
            # Fallback if no credentials found
            credentials = [
                {
                    "key": "credential",
                    "value": "hidden",
                    "type": "password",
                    "vault_var": f"vault_{var_name}",
                }
            ]

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded Credentials in curl JSON Payload:**
This curl command contains {len(credentials)} hardcoded credential(s) in the JSON payload that should never be stored in plaintext.

**Detected Credentials:**"""

        for cred in credentials:
            template += f"""
- **{cred["key"]}**: {cred["type"]} (value: `{cred["value"][:10]}...`)"""

        template += f'''

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook:
- name: Register with monitoring service
  uri:
    url: "{url}"
    method: POST
    body_format: json
    body:
      hostname: "{{{{ ansible_hostname }}}}"'''

        for cred in credentials:
            template += f'''
      {cred["key"]}: "{{{{ {cred["vault_var"]} }}}}"'''

        template += """
    headers:
      Content-Type: "application/json"
    status_code: [200, 201]
  register: monitoring_registration

# In group_vars/all/vault.yml (encrypted):"""

        for cred in credentials:
            template += f'''
{cred["vault_var"]}: "your_secure_{cred["type"]}_here"'''

        template += f'''
```

**✅ Alternative Fix (environment variables):**
```yaml
- name: Register with monitoring service
  uri:
    url: "{url}"
    method: POST
    body_format: json
    body:
      hostname: "{{{{ ansible_hostname }}}}"'''

        for cred in credentials:
            env_var_name = cred["key"].upper().replace("-", "_").replace(" ", "_")
            template += f'''
      {cred["key"]}: "{{{{ lookup('env', '{env_var_name}') }}}}"'''

        template += f'''
    headers:
      Content-Type: "application/json"
```

**✅ Best Fix (Structured and secure):**
```yaml
# In your playbook:
- name: Register with monitoring service securely
  uri:
    url: "{url}"
    method: POST
    body_format: json
    body: "{{{{ monitoring_payload }}}}"
    headers:
      Content-Type: "application/json"
    status_code: [200, 201]
  vars:
    monitoring_payload:
      hostname: "{{{{ ansible_hostname }}}}"'''

        for cred in credentials:
            template += f'''
      {cred["key"]}: "{{{{ {cred["vault_var"]} }}}}"'''

        template += """
  register: monitoring_result

- name: Verify registration success
  debug:
    msg: "Successfully registered {{ ansible_hostname }} with monitoring service"
  when: monitoring_result.status == 200
```

**🔐 curl JSON Security Best Practices:**
- **Use Ansible uri module** instead of shell curl for better error handling and security
- **Structure JSON payloads** as YAML variables for better readability and maintenance
- **Separate credentials by type** - use different vault variables for different credential types
- **Validate API responses** and implement proper error handling
- **Use HTTPS only** and validate SSL certificates in production
- **Implement credential rotation** for API keys and passwords
- **Log API interactions** (without credentials) for debugging and audit trails

**🎯 Production-Ready Example:**
```yaml
# Complete secure monitoring registration
- name: Ensure monitoring credentials are available
  assert:
    that:"""

        for cred in credentials:
            template += f"""
      - {cred["vault_var"]} is defined"""

        template += f'''
    fail_msg: "Missing required monitoring credentials"

- name: Register host with monitoring service
  uri:
    url: "{url}"
    method: POST
    body_format: json
    body:
      hostname: "{{{{ ansible_hostname }}}}"
      timestamp: "{{{{ ansible_date_time.iso8601 }}}}"'''

        for cred in credentials:
            template += f'''
      {cred["key"]}: "{{{{ {cred["vault_var"]} }}}}"'''

        template += """
    headers:
      Content-Type: "application/json"
      User-Agent: "Ansible/{{ ansible_version.full }}"
    validate_certs: yes
    timeout: 30
    status_code: [200, 201]
  register: monitoring_registration
  retries: 3
  delay: 5

- name: Handle registration failure
  fail:
    msg: "Failed to register with monitoring service: {{ monitoring_registration.msg }}"
  when: monitoring_registration.failed | default(false)
```"""

        return template

    def _generate_basic_auth_fix(self, code_snippet: str) -> str:
        """Generate basic auth fix without variable names"""
        return self.generate_basic_auth_fix(code_snippet, "user", "USER")

    def _generate_json_payload_fix(self, code_snippet: str) -> str:
        """Generate JSON payload fix without variable names"""
        return self.generate_json_payload_fix(code_snippet, "credential", "CREDENTIAL")

    def _generate_header_auth_fix(self, code_snippet: str) -> str:
        """Generate remediation for curl commands with authorization headers"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded Authorization Header:**
This curl command contains hardcoded authorization credentials in headers.

**✅ Secure Fix (ansible-vault):**
```yaml
# In your playbook:
- name: Make authenticated API request
  uri:
    url: "https://api.example.com/endpoint"
    method: GET
    headers:
      Authorization: "Bearer {{{{ vault_api_token }}}}"
    validate_certs: yes
  register: api_response

# In group_vars/all/vault.yml (encrypted):
vault_api_token: "your_secure_token_here"
```

**✅ Alternative Fix (environment variables):**
```yaml
- name: Make authenticated API request
  uri:
    url: "https://api.example.com/endpoint"
    method: GET
    headers:
      Authorization: "Bearer {{{{ lookup('env', 'API_TOKEN') }}}}"
    validate_certs: yes
```"""

        return template

    def _generate_generic_curl_fix(self, code_snippet: str, variables: list[str]) -> str:
        """Generate generic curl security fix"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Insecure curl Usage:**
This curl command may contain security issues or hardcoded values.

**✅ Secure Fix (Use Ansible uri module):**
```yaml
# Replace curl with proper Ansible uri module:
- name: Make API request
  uri:
    url: "https://api.example.com/endpoint"
    method: GET
    validate_certs: yes
    timeout: 30
  register: api_response

- name: Process API response
  debug:
    var: api_response.json
```

**🔐 curl Security Best Practices:**
- **Use Ansible uri module** instead of shell curl commands
- **Always validate SSL certificates** in production
- **Implement proper timeout settings**
- **Use structured error handling**
- **Never hardcode credentials or sensitive data**
- **Log API interactions** (without sensitive data) for debugging"""

        return template
