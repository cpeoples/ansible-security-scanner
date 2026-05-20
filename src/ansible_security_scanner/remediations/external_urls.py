#!/usr/bin/env python3
"""
External URLs remediation generator for Ansible Security Scanner
"""

from .base import BaseRemediationGenerator


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
    }

    def generate_external_urls_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_url_fix)

    def _generate_http_fix(self, code_snippet: str) -> str:
        """Generate fix for HTTP (non-HTTPS) URLs"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Insecure HTTP URL:**
Using HTTP instead of HTTPS exposes data to man-in-the-middle attacks and eavesdropping.

**✅ Secure Fix - Use HTTPS:**
```yaml
- name: download from secure HTTPS source
  ansible.builtin.get_url:
    url: "https://{{{{ trusted_server }}}}/{{{{ file_path }}}}"
    dest: "{{{{ local_path }}}}"
    mode: '0644'
    validate_certs: yes
    checksum: "sha256:{{{{ expected_checksum }}}}"
    timeout: 30
  vars:
    trusted_server: "releases.example.com"
    file_path: "v1.0.0/application.tar.gz"
    local_path: "/tmp/application.tar.gz"
    expected_checksum: "a1b2c3d4e5f6..."  # Known good checksum
  register: download_result

- name: verify download integrity
  ansible.builtin.stat:
    path: "{{{{ local_path }}}}"
    checksum_algorithm: sha256
  register: file_checksum

- name: validate file integrity
  ansible.builtin.assert:
    that:
      - file_checksum.stat.checksum == expected_checksum
    fail_msg: "Downloaded file checksum validation failed"
```

**✅ Secure API Requests:**
```yaml
- name: make secure API request
  ansible.builtin.uri:
    url: "https://{{{{ api_server }}}}/api/v1/{{{{ endpoint }}}}"
    method: GET
    headers:
      Authorization: "Bearer {{{{ vault_api_token }}}}"
      Content-Type: "application/json"
      User-Agent: "Ansible/{{{{ ansible_version.string }}}}"
    validate_certs: yes
    timeout: 30
    status_code: [200, 201]
  vars:
    api_server: "api.trusted-service.com"
    endpoint: "status"
  register: api_response
  when: vault_api_token is defined

- name: process API response securely
  ansible.builtin.set_fact:
    service_status: "{{{{ api_response.json.status }}}}"
  when:
    - api_response is defined
    - api_response.json is defined
    - api_response.json.status is defined
```

**🔐 HTTPS Security Best Practices:**
- Always use HTTPS for external communications
- Validate SSL/TLS certificates (validate_certs: yes)
- Use checksum verification for downloaded files
- Implement proper timeout settings
- Use trusted certificate authorities
- Monitor certificate expiration dates
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

    def _generate_api_endpoint_fix(self, code_snippet: str) -> str:
        """Generate fix for external API endpoint usage"""
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Untrusted External API Endpoint:**
Connecting to untrusted API endpoints can expose sensitive data and credentials.

**✅ Secure Fix - Use Trusted API Endpoints:**
```yaml
- name: define trusted API endpoints
  ansible.builtin.set_fact:
    trusted_apis:
      github: "api.github.com"
      docker: "registry-1.docker.io"
      npm: "registry.npmjs.org"
      pypi: "pypi.org"

- name: validate API endpoint
  ansible.builtin.assert:
    that:
      - api_host in trusted_apis.values()
    fail_msg: "API endpoint {{{{ api_host }}}} is not trusted"
  vars:
    api_host: "{{{{ api_url | urlsplit('hostname') }}}}"

- name: make secure API request
  ansible.builtin.uri:
    url: "https://{{{{ api_host }}}}/{{{{ api_path }}}}"
    method: "{{{{ http_method | default('GET') }}}}"
    headers:
      Authorization: "{{{{ auth_header }}}}"
      Content-Type: "application/json"
      User-Agent: "Ansible-{{{{ ansible_version.string }}}}/Company"
    body_format: json
    body: "{{ request_body | default({{}}) }}"
    validate_certs: yes
    timeout: 30
    status_code: [200, 201, 202]
  vars:
    auth_header: "Bearer {{{{ vault_api_token }}}}"
    api_path: "v1/status"
  register: api_response
  when: api_host in trusted_apis.values()

- name: validate API response
  ansible.builtin.assert:
    that:
      - api_response.status in [200, 201, 202]
      - api_response.json is defined
    fail_msg: "API returned unexpected response"
  when: api_response is defined
```

**✅ Use Internal API Gateway:**
```yaml
- name: route through internal API gateway
  ansible.builtin.uri:
    url: "https://{{{{ internal_gateway }}}}/external-api/{{{{ service_name }}}}/{{{{ endpoint }}}}"
    method: "{{{{ http_method | default('GET') }}}}"
    headers:
      Authorization: "Bearer {{{{ vault_internal_token }}}}"
      X-External-Service: "{{{{ service_name }}}}"
      Content-Type: "application/json"
    validate_certs: yes
    timeout: 30
  vars:
    internal_gateway: "api-gateway.company.com"
    service_name: "github"
    endpoint: "user/repos"
  register: gateway_response

- name: monitor API gateway usage
  ansible.builtin.uri:
    url: "https://{{{{ monitoring_endpoint }}}}/api-usage"
    method: POST
    body_format: json
    body:
      service: "{{{{ service_name }}}}"
      endpoint: "{{{{ endpoint }}}}"
      status: "{{{{ gateway_response.status }}}}"
      timestamp: "{{{{ ansible_date_time.iso8601 }}}}"
    headers:
      Authorization: "Bearer {{{{ vault_monitoring_token }}}}"
  when: gateway_response is defined
```

**🔐 API Security Best Practices:**
- Use a whitelist of trusted API endpoints
- Route external API calls through internal gateways
- Validate SSL certificates and use proper authentication
- Implement rate limiting and monitoring
- Use API keys and tokens securely
- Monitor and log all external API communications
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
