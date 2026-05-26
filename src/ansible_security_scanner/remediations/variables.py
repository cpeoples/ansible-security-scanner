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

**✅ Validate and reject (preferred):**
```yaml
- name: Validate {var_match}
  ansible.builtin.assert:
    that:
      - {var_match} is defined
      - {var_match} is string
      - {var_match} is match("^[a-zA-Z0-9._-]+$")
    fail_msg: "Invalid or undefined {var_match}"

- name: Use validated variable
  # Your original task here with the validated variable
```

**✅ Constrain at the role boundary (recommended for roles):**
Define the variable in `meta/argument_specs.yml` so Ansible enforces the
type and pattern before the role runs:

```yaml
# meta/argument_specs.yml
argument_specs:
  main:
    options:
      {var_match}:
        type: str
        required: true
        # restrict to the exact shape you accept
        # (see: https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_reuse_roles.html#specification-format)
```

**🔐 Notes:**
- Reject invalid input with `assert`. Do not silently strip characters with
  `regex_replace` - silent rewriting can mask attempted injection and turn
  a clear failure into a hard-to-debug success.
- Use the `quote` filter when interpolating any variable into shell/command.
- Prefer `meta/argument_specs.yml` for role inputs; it runs before the role
  and gives a single, declarative validation point.
"""

        return template
