#!/usr/bin/env python3
"""
Command injection remediation generator for Ansible Security Scanner
"""

import re
from typing import Any

from .base import BaseRemediationGenerator


class CommandInjectionRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for command injection vulnerabilities"""

    def generate_intelligent_command_injection_fix(
        self, code_snippet: str, command_parts: dict[str, Any], variables: list[str]
    ) -> str:
        """Build the remediation block for a command-injection finding by inspecting the parsed command shape."""

        if self._is_download_execute_pattern(code_snippet):
            return self._generate_download_execute_fix(code_snippet, code_snippet)
        if self._is_command_chaining_pattern(code_snippet):
            return self._generate_command_chaining_fix(code_snippet, code_snippet)
        if self._is_command_substitution_pattern(code_snippet):
            return self._generate_command_substitution_fix(code_snippet, code_snippet)
        if self._is_pipe_to_shell_pattern(code_snippet):
            return self._generate_pipe_to_shell_fix(code_snippet, code_snippet)
        return self._generate_generic_shell_fix(code_snippet, code_snippet, variables)

    def _is_download_execute_pattern(self, code_snippet: str) -> bool:
        """Check if the code matches download-and-execute pattern"""
        patterns = [
            r"curl.*\|.*bash",
            r"wget.*\|.*sh",
            r"curl.*>.*\.sh.*&&.*bash",
            r"wget.*>.*\.sh.*&&.*sh",
        ]
        return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in patterns)

    def _is_command_chaining_pattern(self, code_snippet: str) -> bool:
        """Check if the code contains command chaining"""
        return any(op in code_snippet for op in ["&&", "||", ";"])

    def _is_command_substitution_pattern(self, code_snippet: str) -> bool:
        """Check if the code contains command substitution"""
        return any(pattern in code_snippet for pattern in ["$(", "`"])

    def _is_pipe_to_shell_pattern(self, code_snippet: str) -> bool:
        """Check if the code pipes to shell"""
        return any(
            pattern in code_snippet.lower()
            for pattern in ["| bash", "| sh", "| /bin/sh", "| /bin/bash"]
        )

    def _generate_download_execute_fix(self, code_snippet: str, command: str) -> str:
        """Generate fix for download-and-execute patterns"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Download-and-Execute Pattern Detected:**
This command downloads and executes code directly from the internet, which is extremely dangerous.

**✅ Secure Fix (Use proper modules):**
```yaml
# Instead of downloading and executing, use proper Ansible modules:
- name: Download script safely
  get_url:
    url: "https://example.com/script.sh"
    dest: "/tmp/script.sh"
    mode: '0755'
    validate_certs: yes
    timeout: 30
  register: download_result

- name: Verify script integrity (optional but recommended)
  stat:
    path: "/tmp/script.sh"
    checksum_algorithm: sha256
  register: script_stat

- name: Execute script only after verification
  script: /tmp/script.sh
  when:
    - download_result is succeeded
    - script_stat.stat.checksum == "expected_sha256_hash"

- name: Clean up downloaded script
  file:
    path: "/tmp/script.sh"
    state: absent
```

**✅ Better Fix (Use native Ansible modules):**
```yaml
# Even better: Replace the script with native Ansible tasks
# Example: Instead of a script that installs packages, use:
- name: Install required packages
  package:
    name:
      - package1
      - package2
    state: present
  become: yes
```

**🔐 Security Best Practices:**
- Never pipe downloads directly to shell interpreters
- Always verify script integrity with checksums
- Use native Ansible modules instead of shell scripts when possible
- Download scripts to temporary locations and clean up after execution
- Implement proper error handling and logging
"""

        return template

    def _generate_command_chaining_fix(self, code_snippet: str, command: str) -> str:
        """Generate fix for command chaining"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Command Chaining Detected:**
This command uses operators like &&, ||, or ; which can lead to injection vulnerabilities.

**✅ Secure Fix (Separate tasks):**
```yaml
# Break command chains into separate, idempotent tasks:
- name: First command
  command: first_part_of_command
  register: first_result

- name: Second command (only if first succeeded)
  command: second_part_of_command
  when: first_result is succeeded

- name: Third command (conditional)
  command: third_part_of_command
  when: some_condition
```

**✅ Better Fix (Use proper modules):**
```yaml
# Use specific Ansible modules instead of chained shell commands:
- name: Ensure directory exists
  file:
    path: /path/to/directory
    state: directory
    mode: '0755'

- name: Copy configuration file
  template:
    src: config.j2
    dest: /path/to/directory/config.conf
    mode: '0644'
  notify: restart_service

- name: Start service
  service:
    name: myservice
    state: started
    enabled: yes
```

**🔐 Security Best Practices:**
- Break complex commands into individual Ansible tasks
- Use proper error handling with `failed_when` and `when` conditions
- Implement idempotent operations
- Use native Ansible modules instead of shell commands
- Validate all input parameters
"""

        return template

    def _generate_command_substitution_fix(self, code_snippet: str, command: str) -> str:
        """Generate fix for command substitution"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Command Substitution Detected:**
This command uses $() or backticks which can lead to injection vulnerabilities.

**✅ Secure Fix (Use Ansible facts and variables):**
```yaml
# Replace command substitution with Ansible facts and variables:
- name: Get system information
  setup:
  register: system_facts

- name: Use system information safely
  debug:
    msg: "Hostname: {{{{ ansible_hostname }}}}, OS: {{{{ ansible_os_family }}}}"

# Or use specific modules to gather information:
- name: Get current user
  command: whoami
  register: current_user
  changed_when: false

- name: Use the gathered information
  debug:
    msg: "Current user: {{{{ current_user.stdout }}}}"
```

**✅ Better Fix (Use built-in variables):**
```yaml
# Use Ansible's built-in variables instead of command substitution:
- name: Display system information
  debug:
    msg: |
      Hostname: {{{{ ansible_hostname }}}}
      User: {{{{ ansible_user_id }}}}
      Home: {{{{ ansible_env.HOME }}}}
      Date: {{{{ ansible_date_time.iso8601 }}}}
```

**🔐 Security Best Practices:**
- Use Ansible facts and built-in variables instead of command substitution
- Register command outputs and use them as variables
- Validate and sanitize any dynamic content
- Use the `quote` filter for shell variables
- Implement proper error handling
"""

        return template

    def _generate_pipe_to_shell_fix(self, code_snippet: str, command: str) -> str:
        """Generate fix for pipe-to-shell patterns"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Pipe-to-Shell Pattern Detected:**
This command pipes data directly to shell interpreters, which is dangerous.

**✅ Secure Fix (Use proper file handling):**
```yaml
# Instead of piping to shell, use proper file operations:
- name: Create script content
  copy:
    content: |
      #!/bin/bash
      # Your script content here
      echo "Safe script execution"
    dest: /tmp/safe_script.sh
    mode: '0755'

- name: Execute script safely
  script: /tmp/safe_script.sh
  register: script_result

- name: Clean up script
  file:
    path: /tmp/safe_script.sh
    state: absent
```

**✅ Better Fix (Use native modules):**
```yaml
# Replace shell operations with native Ansible modules:
- name: Perform file operations
  file:
    path: /path/to/file
    state: "{{{{ desired_state }}}}"
    mode: "{{{{ file_mode }}}}"

- name: Process data with template
  template:
    src: data_processor.j2
    dest: /tmp/processed_data
  register: processing_result

- name: Use processed data
  debug:
    var: processing_result
```

**🔐 Security Best Practices:**
- Never pipe untrusted data directly to shell interpreters
- Use Ansible's file and template modules for data processing
- Validate all input data before processing
- Use temporary files with proper permissions
- Clean up temporary files after use
"""

        return template

    def _generate_generic_shell_fix(
        self, code_snippet: str, command: str, variables: list[str]
    ) -> str:
        """Generate generic shell command fix"""

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**✅ Secure Fix (Use specific modules):**
```yaml
# Consider using specific Ansible modules instead of shell commands
# For example: package, service, copy, template, file, etc.
```

**✅ Minimal Fix (Quote variables):**
```yaml
# If you must use shell, quote all variables:
shell: |
  safe_command "{{{{ variable_name | quote }}}}"
```

**🔐 Security Best Practices:**
- Use specific Ansible modules instead of generic shell commands
- Always quote variables when used in shell contexts
- Validate input parameters with `assert` tasks
- Use `creates` or `removes` parameters to make tasks idempotent
- Implement proper error handling with `failed_when`
"""

        return template
