# Companion Remediation Files

Each YAML file in this directory carries hand-written `secure_fix` Ansible
snippets keyed by `rule_id`. The remediation renderer
(`src/ansible_security_scanner/remediations/base.py::_render_from_metadata`)
emits the companion entry verbatim under `✅ Secure Fix Example`.

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

## `negative_examples` is not a remediation source

`negative_examples:` on a pattern is a regex non-match fixture - inputs the
rule must NOT flag. Many are intentionally degenerate strings chosen to
exercise the regex's negative space, so surfacing them as
`✅ Secure Fix Example` produces misleading guidance. The renderer accepts
exactly two sources, in order:

1. A `secure_fix:` entry in this directory.
2. A tailored handler under `remediations/<category>.py`.

Every shipped rule must produce a `✅ Secure Fix` block from one of these
two sources - there is no procedural opt-out. `tests/test_remediations.py`
fails if any rule renders without a Secure Fix, and
`test_no_rule_opts_out_of_remediation` rejects the old
`no_ansible_remediation` escape hatch outright.
