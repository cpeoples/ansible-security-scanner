# Companion Remediation Files

Each YAML file in this directory carries hand-written `Secure Fix` Ansible
snippets keyed by `rule_id`. The remediation renderer
(`src/ansible_security_scanner/remediations/base.py::_render_from_metadata`)
looks here when the matching pattern in `../<category>.yml` does not carry
a `negative_examples:` field.

This separation keeps pattern definitions (rule, regex, severity, metadata)
distinct from remediation guidance (the safe Ansible to ship instead),
which makes both reviewable in small focused diffs.

## File layout

```yaml
# patterns/remediations/<category>.yml
remediations:
  <rule_id>:
    secure_fix: |
      - name: Use HashiCorp Vault for secrets
        community.hashi_vault.vault_kv2_get:
          path: "secret/data/myapp"
        register: secret
```

Multiple lines of Ansible per `secure_fix` are encouraged. The renderer
emits the body verbatim inside a fenced ```yaml block.

## Adding a new rule

1. Define the rule in `../<category>.yml` as usual.
2. Add a matching `secure_fix:` entry here under the same `<rule_id>`.
3. Run `pytest tests/test_remediations.py::test_remediation_includes_secure_fix_yaml_block`
   to verify the contract is satisfied.

The relevance contract (`test_remediation_is_relevant_to_the_rule`) plus
this Secure Fix block contract together guarantee every rule produces
output that mentions the rule's own keywords AND ships a copy-pasteable
Ansible fix.

## When a rule has no Ansible-task fix

Some rules detect actions whose correct response is procedural - run
through a reviewed IaC pipeline, escalate, audit, apply a vendor patch.
A copy-pasteable Ansible task would actively mislead the user. For
those rules, set `no_ansible_remediation: true` on the rule's pattern
YAML entry instead of adding a `secure_fix:` here. The renderer emits a
`✅ Secure Response` prose block sourced from `recommendation:`, and
the contract test treats that as compliant.

The curated list of such rules lives at
`scripts/data/procedural_rule_ids.txt`; running
`scripts/stamp_no_ansible_remediation.py` applies the flag idempotently
across every pattern file.
