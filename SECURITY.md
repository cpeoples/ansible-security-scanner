# Security policy

## Reporting a vulnerability

Please open a private security advisory via the
[Security tab](https://github.com/cpeoples/ansible-security-scanner/security/advisories/new)
rather than a public issue.

## Scope

In scope:

- Vulnerabilities in the scanner itself, e.g. a code path that lets an
  attacker leak unredacted secrets through an MR/PR comment, or a parser
  bug that lets a crafted playbook execute code in the scanner process.

Out of scope:

- Vulnerabilities in *Ansible playbooks detected by the scanner*. Those
  belong to the playbook's maintainer, not this project.
- Findings produced by the scanner against this repository's own test
  fixtures (`tests/playbooks/**`) - those fixtures contain deliberate
  vulnerabilities by design.

## Supported versions

Only the latest minor release line is supported. See [PyPI](https://pypi.org/project/ansible-security-scanner/)
for the current version.
