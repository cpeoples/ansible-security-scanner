#!/usr/bin/env python3
"""
External URLs remediation generator for Ansible Security Scanner
"""

from .base import BaseRemediationGenerator, _first


class ExternalUrlsRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for external URLs security issues"""

    _FIX_MAP = {
        "bitbucket_raw_content": "_generate_script_download_fix",
        "codeberg_gitea_raw": "_generate_script_download_fix",
        "gitlab_raw_content": "_generate_script_download_fix",
        "ip_address_url": "_generate_untrusted_domain_fix",
        "pastebin_like_service": "_generate_script_download_fix",
        "raw_github_content": "_generate_script_download_fix",
        "suspicious_download_url": "_generate_package_download_fix",
        "temporary_file_sharing": "_generate_untrusted_domain_fix",
        "gitlab_snippet_execution": "_generate_snippet_pipe_fix",
        "additional_paste_services": "_generate_paste_service_fix",
        "encrypted_paste_service": "_generate_paste_service_fix",
    }

    def generate_external_urls_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_url_fix)

    def _generate_snippet_pipe_fix(self, code_snippet: str) -> str:
        """Replace a `curl <snippet> | sh` with download, checksum-verify, then run."""
        url = (
            _first(
                code_snippet,
                r"(https?://[^\s'\"|>]+)",
                r"(gitlab\.com/[^\s'\"|>]+)",
            )
            or "{{ snippet_url }}"
        )
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Remote Snippet Piped Directly to a Shell:**
Piping a downloaded snippet straight into `sh` runs whatever the URL serves at that moment, with no integrity check and no chance to review it. The content can change between runs.

**✅ Secure Fix - Download, Verify, Then Run:**
```yaml
# Never pipe a remote snippet into a shell. Fetch it to disk, pin it to a
# known checksum so the content cannot change underneath you, then run the
# verified copy.
- name: Download the snippet to disk (not executable, not piped)
  ansible.builtin.get_url:
    url: "{url}"
    dest: /tmp/snippet.sh
    mode: '0644'
    checksum: "sha256:{{{{ snippet_sha256 }}}}"
    validate_certs: true

- name: Run the verified snippet
  ansible.builtin.command: /bin/sh /tmp/snippet.sh
  # snippet_sha256 is the reviewed, pinned digest; a content change fails the
  # download task above before anything executes.
```

**🔐 Best Practices:**
- Prefer vendoring the snippet's logic into a reviewed role over fetching it at all
- Always pin a checksum; treat an unpinned remote script as untrusted code
- Keep the fetched file non-executable and run it explicitly so the flow is auditable
"""

    def _generate_paste_service_fix(self, code_snippet: str) -> str:
        """Replace a paste/anonymous-share URL with a pull from an approved
        internal artifact store, with a checksum."""
        url = _first(code_snippet, r"(https?://[^\s'\"|>]+)") or "{{ paste_url }}"
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Artifact Sourced From a Paste / Anonymous Sharing Service:**
Paste and anonymous file-sharing services (and zero-knowledge/encrypted pastes whose contents network controls cannot inspect) are routinely abused to host payloads and to stage exfiltration. They are not a trustworthy source for anything a playbook installs or runs.

**✅ Secure Fix - Pull From an Approved Internal Store With a Checksum:**
```yaml
# Do not fetch artifacts from {url} or any paste/anonymous-share service.
# Host the artifact in the approved internal store and pull it with a pinned
# checksum so its integrity and provenance are verifiable.
- name: Refuse sources that are not on the approved artifact-host list
  ansible.builtin.assert:
    that:
      - approved_artifact_host is defined
    fail_msg: >-
      Artifacts must come from an approved internal host, never a paste or
      anonymous file-sharing service.

- name: Fetch the artifact from the approved internal host with a checksum
  ansible.builtin.get_url:
    url: "https://{{{{ approved_artifact_host }}}}/{{{{ artifact_name }}}}"
    dest: "/opt/artifacts/{{{{ artifact_name }}}}"
    checksum: "sha256:{{{{ artifact_sha256 }}}}"
    validate_certs: true
    mode: '0644'
```

**🔐 Best Practices:**
- Mirror required third-party artifacts into an internal, access-controlled store
- Pin a checksum on every fetch; reject content that cannot be inspected
- Egress-filter paste and anonymous-share domains on managed hosts
"""

    def _generate_untrusted_domain_fix(self, code_snippet: str) -> str:
        """Generate fix for untrusted domain usage"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Untrusted External Domain:**
Connecting to untrusted or malicious domains can compromise system security.

**✅ Secure Fix - Use Trusted Sources:**
```yaml
- name: define trusted domains whitelist
  ansible.builtin.set_fact:
    trusted_domains:
      - "releases.ubuntu.com"
      - "download.docker.com"
      - "github.com"
      - "pypi.org"
      - "registry.npmjs.org"

- name: validate domain against whitelist
  ansible.builtin.assert:
    that:
      - requested_domain in trusted_domains
    fail_msg: "Domain {{{{ requested_domain }}}} is not in trusted domains list"
  vars:
    requested_domain: "{{{{ url | urlsplit('hostname') }}}}"
  when: url is defined

- name: download from trusted source
  ansible.builtin.get_url:
    url: "https://{{{{ validated_domain }}}}/{{{{ file_path }}}}"
    dest: "{{{{ download_path }}}}"
    validate_certs: yes
    checksum: "sha256:{{{{ file_checksum }}}}"
  vars:
    validated_domain: "{{{{ requested_domain }}}}"
    file_path: "releases/latest/package.tar.gz"
    download_path: "/tmp/package.tar.gz"
  when: requested_domain in trusted_domains
```

**✅ Alternative - Use Internal Mirrors:**
```yaml
- name: use internal package mirror
  ansible.builtin.get_url:
    url: "https://{{{{ internal_mirror }}}}/packages/{{{{ package_name }}}}"
    dest: "{{{{ package_dest }}}}"
    validate_certs: yes
    headers:
      Authorization: "Bearer {{{{ vault_mirror_token }}}}"
  vars:
    internal_mirror: "mirror.company.com"
    package_name: "application-v1.0.0.tar.gz"
    package_dest: "/opt/packages/application-v1.0.0.tar.gz"
  register: mirror_download

- name: verify internal mirror package
  ansible.builtin.command:
    cmd: gpg --verify "{{{{ package_dest }}}}.sig" "{{{{ package_dest }}}}"
  register: signature_check
  changed_when: false
  failed_when: signature_check.rc != 0

- name: use local repository instead of external
  ansible.builtin.yum_repository:
    name: internal-repo
    description: Internal Company Repository
    baseurl: "https://{{{{ internal_repo_server }}}}/centos/{{{{ ansible_distribution_major_version }}}}"
    gpgcheck: yes
    gpgkey: "https://{{{{ internal_repo_server }}}}/RPM-GPG-KEY-company"
    enabled: yes
  when: ansible_os_family == "RedHat"
```

**🔐 Domain Security Best Practices:**
- Maintain a whitelist of trusted domains
- Use internal mirrors and repositories when possible
- Validate domain certificates and signatures
- Implement domain reputation checking
- Monitor and log all external connections
- Use corporate proxies and content filtering
"""

    def _generate_package_download_fix(self, code_snippet: str) -> str:
        """Generate fix for package download from external sources"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Untrusted Package Download:**
Downloading packages from untrusted sources can introduce malware and security vulnerabilities.

**✅ Secure Fix - Use Official Repositories:**
```yaml
- name: use official package repositories
  ansible.builtin.package:
    name: "{{{{ package_list }}}}"
    state: present
    update_cache: yes
  vars:
    package_list:
      - nginx
      - postgresql
      - python3-pip
  become: yes

- name: configure trusted repositories only
  ansible.builtin.yum_repository:
    name: "{{{{ item.name }}}}"
    description: "{{{{ item.description }}}}"
    baseurl: "{{{{ item.baseurl }}}}"
    gpgcheck: yes
    gpgkey: "{{{{ item.gpgkey }}}}"
    enabled: yes
  loop:
    - name: epel
      description: Extra Packages for Enterprise Linux
      baseurl: "https://download.fedoraproject.org/pub/epel/{{{{ ansible_distribution_major_version }}}}/Everything/{{{{ ansible_architecture }}}}/"
      gpgkey: "https://download.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{{{{ ansible_distribution_major_version }}}}"
  when: ansible_os_family == "RedHat"
  become: yes

- name: verify package signatures
  ansible.builtin.command:
    cmd: rpm -K "{{{{ package_file }}}}"
  register: signature_check
  changed_when: false
  when: package_file is defined and ansible_os_family == "RedHat"
```

**✅ Secure Package Download (when necessary):**
```yaml
- name: download package from trusted source with verification
  ansible.builtin.get_url:
    url: "https://{{{{ trusted_package_server }}}}/{{{{ package_path }}}}"
    dest: "/tmp/{{{{ package_filename }}}}"
    checksum: "sha256:{{{{ package_checksum }}}}"
    validate_certs: yes
    timeout: 300
  vars:
    trusted_package_server: "packages.elastic.co"
    package_path: "downloads/elasticsearch/elasticsearch-8.0.0-x86_64.rpm"
    package_filename: "elasticsearch-8.0.0-x86_64.rpm"
    package_checksum: "known_good_checksum_here"
  register: package_download

- name: verify package signature
  ansible.builtin.command:
    cmd: rpm --checksig "/tmp/{{{{ package_filename }}}}"
  register: package_sig_check
  changed_when: false
  failed_when: "'OK' not in package_sig_check.stdout"

- name: install verified package
  ansible.builtin.package:
    name: "/tmp/{{{{ package_filename }}}}"
    state: present
  become: yes
  when: package_sig_check.rc == 0

- name: cleanup downloaded package
  ansible.builtin.file:
    path: "/tmp/{{{{ package_filename }}}}"
    state: absent
```

**🔐 Package Security Best Practices:**
- Use official distribution repositories when possible
- Verify package signatures and checksums
- Use trusted package servers and mirrors
- Implement package vulnerability scanning
- Monitor package sources and updates
- Use package managers with security features enabled
"""

    def _generate_script_download_fix(self, code_snippet: str) -> str:
        """Generate fix for script download and execution"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Untrusted Script Download and Execution:**
Downloading and executing scripts from external sources is extremely dangerous and can lead to system compromise.

**✅ Secure Fix - Avoid External Script Execution:**
```yaml
# DO NOT download and execute external scripts directly
# Instead, implement the functionality using Ansible modules:

- name: install software using package manager
  ansible.builtin.package:
    name: "{{{{ software_package }}}}"
    state: present
  vars:
    software_package: docker-ce
  become: yes

- name: configure software using templates
  ansible.builtin.template:
    src: "{{{{ config_template }}}}"
    dest: "{{{{ config_path }}}}"
    backup: yes
    validate: "{{{{ validation_command }}}}"
  vars:
    config_template: docker-daemon.json.j2
    config_path: /etc/docker/daemon.json
    validation_command: "python3 -m json.tool %s"
  notify: restart docker

- name: start and enable service
  ansible.builtin.systemd:
    name: docker
    state: started
    enabled: yes
    daemon_reload: yes
  become: yes
```

**✅ If Script Download is Absolutely Necessary:**
```yaml
- name: download script from trusted source with verification
  ansible.builtin.get_url:
    url: "https://{{{{ trusted_source }}}}/{{{{ script_path }}}}"
    dest: "/tmp/{{{{ script_name }}}}"
    mode: '0644'  # Not executable yet
    checksum: "sha256:{{{{ known_script_checksum }}}}"
    validate_certs: yes
  vars:
    trusted_source: "get.docker.com"
    script_path: "install.sh"
    script_name: "docker-install.sh"
    known_script_checksum: "verified_checksum_here"
  register: script_download

- name: verify script content and signature
  block:
    - name: check script signature
      ansible.builtin.command:
        cmd: gpg --verify "/tmp/{{{{ script_name }}}}.sig" "/tmp/{{{{ script_name }}}}"
      register: sig_check
      changed_when: false

    - name: review script content manually
      ansible.builtin.debug:
        msg: "MANUAL REVIEW REQUIRED: Please review /tmp/{{{{ script_name }}}} before execution"

    - name: wait for manual approval
      ansible.builtin.pause:
        prompt: "Have you manually reviewed the script? Press enter to continue or Ctrl+C to abort"
      when: manual_review_required | default(true)

- name: execute script with restrictions (only after manual review)
  ansible.builtin.script:
    cmd: "/tmp/{{{{ script_name }}}}"
    creates: "{{{{ creates_file }}}}"
  vars:
    creates_file: /var/lib/docker/docker.installed
  become: yes
  when:
    - manual_approval | default(false)
    - sig_check.rc == 0

- name: cleanup script after execution
  ansible.builtin.file:
    path: "/tmp/{{{{ script_name }}}}"
    state: absent
```

**🔐 Script Security Best Practices:**
- Never download and execute scripts directly from the internet
- Use Ansible modules and package managers instead
- If absolutely necessary, verify checksums and signatures
- Require manual review of all external scripts
- Use restricted execution environments
- Monitor and log all script executions
"""

    def _generate_generic_url_fix(self, code_snippet: str) -> str:
        """Generate generic fix for external URL usage"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 External URL Security Risk:**
Connecting to external URLs without proper validation poses security risks.

**✅ Secure Fix - Validate External URLs:**
```yaml
- name: define URL validation rules
  ansible.builtin.set_fact:
    url_validation_rules:
      allowed_protocols: ["https"]
      trusted_domains:
        - "github.com"
        - "releases.ubuntu.com"
        - "download.docker.com"
      blocked_domains:
        - "evil.com"
        - "malicious.net"
        - "untrusted.org"

- name: validate URL against security rules
  ansible.builtin.set_fact:
    url_parts: "{{{{ target_url | urlsplit }}}}"
  vars:
    target_url: "{{{{ external_url }}}}"

- name: check URL security
  ansible.builtin.assert:
    that:
      - url_parts.scheme in url_validation_rules.allowed_protocols
      - url_parts.hostname in url_validation_rules.trusted_domains
      - url_parts.hostname not in url_validation_rules.blocked_domains
    fail_msg: "URL {{{{ external_url }}}} failed security validation"

- name: make secure request to validated URL
  ansible.builtin.uri:
    url: "{{{{ external_url }}}}"
    method: GET
    validate_certs: yes
    timeout: 30
    headers:
      User-Agent: "Ansible/{{{{ ansible_version.string }}}} (Security Scanner)"
  register: url_response
  when: url_parts.hostname in url_validation_rules.trusted_domains
```

**✅ Alternative - Use Proxy/Gateway:**
```yaml
- name: route external requests through corporate proxy
  ansible.builtin.uri:
    url: "{{{{ external_url }}}}"
    method: GET
    validate_certs: yes
    timeout: 30
  environment:
    https_proxy: "{{{{ corporate_proxy_url }}}}"
    http_proxy: "{{{{ corporate_proxy_url }}}}"
  vars:
    corporate_proxy_url: "https://proxy.company.com:8080"
  register: proxied_response

- name: log external URL access
  ansible.builtin.lineinfile:
    path: /var/log/external-url-access.log
    line: "{{{{ ansible_date_time.iso8601 }}}} - {{{{ inventory_hostname }}}} - {{{{ external_url }}}} - {{{{ proxied_response.status | default('FAILED') }}}}"
    create: yes
  become: yes
```

**🔐 External URL Security Best Practices:**
- Validate all external URLs against security policies
- Use HTTPS only and validate certificates
- Implement URL whitelisting and blacklisting
- Route traffic through corporate proxies or gateways
- Monitor and log all external connections
- Implement timeout and retry policies
"""
