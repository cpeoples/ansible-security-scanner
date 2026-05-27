# About

## The project

Ansible Security Scanner is a static analysis (SAST) tool for Ansible
playbooks, roles, collections, task files, vars, and inventories. It
focuses on real security signals: malicious code, RCE, command and
template injection, hardcoded credentials, supply-chain risk,
unauthorized cloud access, lateral movement, and reverse shells. Style
and linting concerns are intentionally left to other tools.

The scanner ships [1,000+ rules](/dashboard/) organized by threat
category, mapped to OWASP, CWE, NIST, CIS, and MITRE ATT&CK. It produces
SARIF, CycloneDX SBOM, GitLab SAST, JUnit, JSON, HTML, and Markdown
output, and can post PR/MR comments directly from CI.

The full source lives at
[github.com/cpeoples/ansible-security-scanner](https://github.com/cpeoples/ansible-security-scanner)
under the Apache-2.0 license.

## The author

Hi 👋, I'm [Chris Peoples](https://github.com/cpeoples). I'm a software
engineer who has spent a lot of time around DevSecOps, static analysis,
supply-chain security, security research, mobile forensics, and
full-stack development. This project started because the gap between
"lint" and "security scanner" felt much wider in the Ansible ecosystem
than what I was used to from other languages and toolchains, and I
wanted to help close it.

The best places to reach me about the scanner:

- GitHub Issues:
  [github.com/cpeoples/ansible-security-scanner/issues](https://github.com/cpeoples/ansible-security-scanner/issues)
- Ansible Forum:
  [forum.ansible.com/u/cpeoples](https://forum.ansible.com/u/cpeoples)
- LinkedIn:
  [linkedin.com/in/chrispeoples](https://www.linkedin.com/in/chrispeoples)

## Contributions are welcome

Bug reports, false-positive reports, new patterns, docs improvements,
typo fixes, ideas, opinions, all of it. There's a
[CONTRIBUTING.md](https://github.com/cpeoples/ansible-security-scanner/blob/main/CONTRIBUTING.md)
in the repo with the dev setup and PR checklist, but if you'd rather
just open an issue and talk it through first, that's great too.

## How rules are written

Every rule in [`src/ansible_security_scanner/patterns/`](https://github.com/cpeoples/ansible-security-scanner/tree/main/src/ansible_security_scanner/patterns)
is a YAML plugin with a curated `id`, `severity`, `description`,
remediation guidance, and at least one mapping to an external taxonomy
(CWE, CVE, OWASP, NIST, CIS, MITRE ATT&CK). The framework-catalog test
fails the build on any rule that cites an unresolvable id, so every
shipped rule has a verified link.

False positives are tracked in
[GitHub Issues](https://github.com/cpeoples/ansible-security-scanner/issues)
and have dedicated regression tests in
[`tests/`](https://github.com/cpeoples/ansible-security-scanner/tree/main/tests)
to make sure they stay fixed.

## Privacy

The scanner is offline by default. There is no telemetry, no
analytics, no usage pings, and no remote rule fetch. Rules ship in
the package, are loaded from disk, and run entirely on your
machine.

The only outbound network call is PR/MR comment posting, and it
only happens when you opt in with `--gh-comment` or `--mr-comment`
and pass an explicit token. The target is the GitHub or GitLab
host you point it at, and the request body is the same Markdown
report you would see in CI logs.

If you spot anything in the codebase that looks like it talks to
the network outside of that path, please open an issue. That kind
of report is exactly the kind of contribution this project wants.

## AI-assistance disclosure

This project follows the
[Ansible community AI policy](https://docs.ansible.com/projects/ansible/latest/community/ai_policy.html).
LLM tooling has helped with scaffolding, refactoring, test generation,
and documentation. All of it is reviewed, edited, and tested by a human
before being committed. The rules, threat models, and design decisions
are mine, and every PR runs the full test, lint, and security gate
before merge.
