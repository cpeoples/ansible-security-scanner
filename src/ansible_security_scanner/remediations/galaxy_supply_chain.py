#!/usr/bin/env python3
"""Remediations for Galaxy / collections supply-chain patterns."""

from .base import BaseRemediationGenerator


class GalaxySupplyChainRemediationGenerator(BaseRemediationGenerator):
    _FIX_MAP = {
        "ansible_galaxy_install_force_latest": "_fix_install_force",
        "ansible_galaxy_install_ignore_errors": "_fix_install_ignore_errors",
        "galaxy_requirements_git_branch_ref": "_fix_branch_ref",
        "galaxy_requirements_http_source": "_fix_http_source",
        "galaxy_requirements_non_galaxy_source": "_fix_non_galaxy_source",
    }

    def generate_galaxy_supply_chain_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._fix_generic)

    def _fix_role_unpinned(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Role has no version pin:**
`ansible-galaxy install` resolves to the latest tag (or HEAD) at install time. The artefact you test is not the artefact you deploy, and a compromised Galaxy publisher can inject code between test and prod.

**✅ Secure Fix 1 - Pin to a release tag:**
```yaml
roles:
  - src: geerlingguy.nginx
    version: 3.1.4
  - src: https://github.com/example/role.git
    name: example.role
    version: v1.2.3
```

**✅ Secure Fix 2 - Pin to an immutable commit SHA:**
```yaml
roles:
  - src: https://github.com/example/role.git
    name: example.role
    version: 3f4a1c8d9e0b1c2a3f4b5c6d7e8f9a0b1c2d3e4f
```

**✅ Secure Fix 3 - Treat requirements.yml as a lockfile:**
```bash
ansible-galaxy install -r requirements.yml --force-with-deps
git add requirements.yml roles/
git commit -m "Bump role pin"
```

**🔐 Hardening:**
- CI check: reject PRs whose requirements.yml adds a role entry without `version:`.
- Use a private Galaxy mirror (Automation Hub / pulp_ansible) and fetch only from it.
- Renovate/Dependabot bump PRs give reviewed upgrades instead of drift.
"""

    def _fix_collection_unpinned(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Collection has no version pin:**
Every `ansible-galaxy collection install` pulls latest. A hijacked publisher, a typo-squatted collection, or a withdrawn version silently change what your plays execute.

**✅ Secure Fix - Pin every collection:**
```yaml
collections:
  - name: community.general
    version: "10.0.0"
  - name: ansible.posix
    version: ">=1.5.0,<1.6.0"
  - name: amazon.aws
    version: "9.0.0"
    source: https://galaxy.ansible.com
    # source: https://hub.example.com/api/galaxy/    # private mirror
```

**✅ Secure Fix - Lockfile-driven installs (ansible-core ≥ 2.18):**
```bash
ansible-galaxy collection install -r requirements.yml --offline
ansible-galaxy collection verify -r requirements.yml
```

**🔐 Hardening:**
- Mirror upstream collections into Automation Hub / Pulp and point `source:` at your mirror.
- Verify signatures: `ansible-galaxy collection verify --signature-keyring ...`.
- CI rejects unpinned collections at PR time.
"""

    def _fix_http_source(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Supply-chain fetch over http://:**
Anyone on the network path can swap the tarball or git ref mid-flight. This is indistinguishable from a legit install and becomes RCE on the controller the next time ansible-galaxy runs.

**✅ Secure Fix - Use https:// for every supply-chain URL:**
```yaml
roles:
  - src: https://github.com/example/role.git    # HTTPS only
    version: v1.2.3

collections:
  - name: amazon.aws
    version: "9.0.0"
    source: https://galaxy.ansible.com
```

**🔐 Hardening:**
- CI grep: `rg -n 'src:\\s*[\"\\']?http://|url:\\s*[\"\\']?http://'`
- Mirror any http-only upstream to an https internal mirror.
"""

    def _fix_branch_ref(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Version points at a moving ref (main / master / HEAD / develop):**
An attacker with push access to the upstream repo, or even a maintainer accidentally force-pushing, changes what ansible-galaxy installs the next run - without bumping anything in your repo.

**✅ Secure Fix - Immutable ref (tag or commit SHA):**
```yaml
roles:
  - src: https://github.com/example/role.git
    name: example.role
    version: 1.2.3          # tag (signed, ideally)

  - src: https://github.com/example/other.git
    name: example.other
    version: 3f4a1c8d9e...  # 40-char SHA, immutable
```

**🔐 Hardening:**
- Forbid `main`, `master`, `HEAD`, `develop`, `latest` as version values in CI.
- Prefer signed git tags; verify with `git tag -v`.
"""

    def _fix_non_galaxy_source(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Direct URL / git source without integrity check:**
Fetching a tarball or raw git repo skips Galaxy's signature/namespace checks. No mechanism catches content-tampering between publisher and controller.

**✅ Secure Fix - Prefer Galaxy / Automation Hub:**
```yaml
collections:
  - name: community.general          # resolved via Galaxy, signed/verified
    version: "10.0.0"
```

**✅ If a direct URL is truly required:**
```yaml
roles:
  - src: https://github.com/example/role.git
    name: example.role
    version: 3f4a1c8d9e0b1c2a3f4b5c6d7e8f9a0b1c2d3e4f   # immutable SHA
```

**✅ Verify out-of-band:**
```bash
ansible-galaxy install -r requirements.yml
sha256sum -c expected_checksums.txt
```

**🔐 Hardening:**
- Mirror any non-Galaxy source into Automation Hub / Pulp.
- Pin SHA + verify signed git tag.
"""

    def _fix_install_ignore_errors(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```bash
{snip}
```

**🚨 ansible-galaxy install --ignore-errors:**
Masks install failures that often indicate a hijacked, withdrawn, or unreachable collection. The play continues with stale or missing content and may fail open elsewhere.

**✅ Secure Fix - Fail loud:**
```bash
set -euo pipefail
ansible-galaxy collection install -r requirements.yml
ansible-galaxy role    install -r requirements.yml
```

**🔐 Hardening:**
- Never use `--ignore-errors` in CI.
- Pin versions so missing content is a hard failure worth investigating.
"""

    def _fix_install_force(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```bash
{snip}
```

**🚨 ansible-galaxy install --force bypasses lockfile:**
Even with a pinned requirements.yml, `--force` can reinstall at a different version (especially when combined with unpinned deps), breaking determinism.

**✅ Secure Fix:**
```bash
set -euo pipefail
ansible-galaxy collection install -r requirements.yml        # no --force
# If you need to refresh a lockfile intentionally:
ansible-galaxy collection install -r requirements.yml --force-with-deps
git diff requirements.yml                                    # review the bump
```

**🔐 Hardening:**
- Reserve `--force-with-deps` for explicit lockfile-refresh PRs, not routine installs.
- Commit resolved versions; CI rejects drift.
"""

    def _fix_generic(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Galaxy / collections supply-chain risk detected.**

**✅ Secure Defaults:**
- Pin every role and collection to a tag or immutable commit SHA.
- Use https:// exclusively.
- Prefer Galaxy / Automation Hub over raw URLs.
- Verify signatures where supported.

**🔐 Hardening:**
- Mirror upstream into a private Automation Hub / Pulp.
- CI rejects unpinned, http://, or `main`/`HEAD` references.
"""
