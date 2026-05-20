# Adding Custom Patterns

Create a YAML file in `src/ansible_security_scanner/patterns/` with this
structure:

```yaml
name: "My Custom Patterns"
author: "Your Name"
description: "What these patterns detect"

patterns:
  - id: "my_custom_rule"
    category: "my_category"
    severity: "HIGH"            # CRITICAL, HIGH, MEDIUM, LOW
    title: "Human-Readable Title"
    description: "What this detects and why it matters"
    regex: "the.*regex.*to.*match"
    recommendation: "How to fix it"
```

Pattern files are auto-discovered on startup. No code changes needed.
