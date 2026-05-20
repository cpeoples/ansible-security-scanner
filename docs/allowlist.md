# Allowlist (Suppressing Findings)

Some findings are expected for approved playbooks. The allowlist lets you
suppress specific rules for specific files without disabling the scanner.

## Configuration

Edit `.security-scanner-allowlist.yml` (next to `main.py`), or pass a custom
path with `--allowlist /path/to/config.yml`.

```yaml
allowlist:
  # Suppress specific rules for a file
  - file: ansible/deploy_prod.yml
    rules:
      - direct_sqs_send_message
      - direct_sqs_queue_url
    reason: "Uses approved API Gateway endpoint, not direct SQS"

  # Suppress ALL rules for a legacy file
  - file: ansible/legacy_playbook.yml
    rules:
      - "*"
    reason: "Legacy playbook pending migration; tracked in TICKET-1234"
```

## How it works

- `file:` is the path relative to the scan directory
- `rules:` is a list of rule IDs to suppress. Use `"*"` to suppress everything.
- `reason:` is logged at INFO level for audit trail (visible with `--verbose`)
- Suppressed findings do **not** count toward the security score or exit code
- Suppressed findings **are** logged at INFO level so they remain auditable

## Finding rule IDs

Run the scanner with `--format json` and check each finding's `rule_id` field:

```bash
ansible-security-scanner --files ansible/my_playbook.yml --output findings.json
python3 -c "import json; [print(f['rule_id']) for f in json.load(open('findings.json'))['findings']]"
```
