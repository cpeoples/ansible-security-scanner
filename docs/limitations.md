# Limitations

This is a **static, pattern-based scanner**. It analyzes YAML text and
structure without executing playbooks. You should be aware of what it can
and cannot do.

**What it catches:**

- Known-bad patterns, commands, modules, and configurations
- Hardcoded secrets, credentials, and tokens
- Common evasion techniques (encoding, obfuscation, variable indirection)
- Structural issues in parsed YAML (missing `no_log`, `ignore_errors` on
  security tasks)

**What it cannot catch:**

- **Runtime behavior** - dynamically constructed commands, values resolved at
  execution time via lookups/facts/registered variables, or logic gated
  behind conditionals
- **Semantic intent** - it cannot distinguish between a legitimate
  `aws s3 cp` in an approved deployment role and the same command used
  maliciously
- **Custom obfuscation** - novel encoding schemes, steganographic payloads,
  or patterns not covered by existing rules
- **External content** - malicious code pulled in via `include_role`,
  `import_tasks`, Galaxy roles, or fetched scripts that aren't part of the
  scanned file set
- **Multi-file logic** - attack chains that span multiple playbooks,
  inventories, or variable files

**Recommendations:**

- Use this scanner as one layer in a defense-in-depth strategy, not the only
  control
- Combine with runtime controls (AWX/AAP approval workflows, execution
  environment lockdown, network egress policies)
- Review allowlisted findings periodically - suppressed rules can hide new
  risks
- Contribute new patterns when you encounter real-world evasions the scanner
  misses
