# CI/CD Integration

## GitLab CI

```yaml
ansible_security_scan:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install ansible-security-scanner
  script:
    - ansible-security-scanner
        --directory ansible
        --changed-files "$CHANGED_FILES"
        --format junit --output reports/security-results.xml
        --allowlist .security-scanner-allowlist.yml
  artifacts:
    reports:
      junit: reports/security-results.xml
    expire_in: 30 days
```

## GitHub Actions

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"

- name: Install Ansible Security Scanner
  run: pip install ansible-security-scanner

- name: Ansible Security Scan
  run: |
    ansible-security-scanner \
      --directory ansible \
      --format sarif --output results.sarif

- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## GitLab CI - Security Dashboard integration

Use the `gl-sast` format to populate GitLab's native Security Dashboard and
the MR security widget. The `artifacts:reports:sast` keyword tells GitLab to
ingest the JSON report - no extra tooling or analyzer image required.

```yaml
ansible-sast:
  stage: test
  image: python:3.12-slim
  script:
    - pip install ansible-security-scanner
    - >
      ansible-security-scanner
      --directory ansible
      --format gl-sast
      --output gl-sast-report.json
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
```

For per-PR/MR comment posting, see [PR/MR Comments](mr-pr-comments.md).
