#!/usr/bin/env python3
"""
Variable injection remediation generator for Ansible Security Scanner
"""

from .base import BaseRemediationGenerator


class VariableInjectionRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for variable injection vulnerabilities"""

    def generate_intelligent_variable_injection_fix(
        self, code_snippet: str, variables: list[str]
    ) -> str:
        """Build a per-snippet fix proposal for variable-injection findings."""

        # Extract the variable name from the code snippet
        var_match = None
        for var in variables:
            if var in code_snippet:
                var_match = var
                break

        if not var_match:
            var_match = "variable_name"

        template = f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**✅ Minimal Fix (Validate input):**
```yaml
- name: Validate {var_match}
  assert:
    that:
      - {var_match} is defined
      - {var_match} is match("^[a-zA-Z0-9._-]+$")
    fail_msg: "Invalid or undefined {var_match}"

- name: Use validated variable
  # Your original task here with the validated variable
```

**✅ Best Practice Fix (Sanitize and validate):**
```yaml
- name: Sanitize {var_match}
  set_fact:
    validated_{var_match}: "{{{{ {var_match} | regex_replace('[^a-zA-Z0-9._-]', '') }}}}"
  when:
    - {var_match} is defined
    - {var_match} | length > 0

- name: Use sanitized variable
  # Your original task here with validated_{var_match}
  when: validated_{var_match} is defined
```

**🔐 Variable Security Best Practices:**
- Always validate input variables
- Use the `quote` filter for shell variables
- Sanitize variables before use
- Use `assert` tasks to validate assumptions
- Implement proper error handling
"""

        return template
