"""Path-based scoping for findings.

Centralises four policies that the scanner needs to apply consistently
across both the per-file scanner and the cross-file taint tracker:

* Molecule scenario trees: test orchestration where production-deploy
  rules (mutable image tags, taint-flow from local state files, dynamic
  set_fact keys, etc.) categorically don't apply.
* Integration-test fixture trees (``tests/integration/targets/`` in
  Ansible collections): scaffolding whose entire purpose is to drive
  the module under test, so the same suppression list as Molecule
  applies plus a few module-test-specific rules.
* Test-fixture trees (general ``test/``, ``tests/``): rules with
  intentional insecurity (e.g. ``validate_certs: false`` in CI
  scaffolding) get a severity demotion rather than full suppression.
* Vendor-collection trees: device-management collections whose modules
  ship with self-signed certs by default.

This module is the single source of truth for those path policies so
``file_scanner`` and ``scanner`` cannot disagree on, say, what counts
as a Molecule path.
"""

from __future__ import annotations

import re
from pathlib import Path

MOLECULE_PATH_RE: re.Pattern[str] = re.compile(
    r"(?:^|/)(?:extensions/)?molecule/|(?:^|/)molecule\.ya?ml$",
    re.IGNORECASE,
)

# Collection integration-test fixture trees. These exist solely to
# exercise modules under test, so :latest images, dummy /usr/bin/foo
# paths, dynamic include scaffolding, and intentional cert-validation
# disables are all part of the test contract.
INTEGRATION_TEST_FIXTURE_PATH_RE: re.Pattern[str] = re.compile(
    r"(?:^|/)tests?/integration/targets/|"
    r"(?:^|/)integration/targets/",
    re.IGNORECASE,
)

# Today's test fixture is tomorrow's copy-pasted production playbook,
# so we demote rather than suppress here.
TEST_FIXTURE_PATH_RE: re.Pattern[str] = re.compile(
    r"(?:^|/)(?:test|tests|molecule|integration_tests)(?:/|$)|"
    r"(?:^|/)integration/targets/|"
    r"(?:^|/)\.github/workflows/(?:test|ci|integration)",
    re.IGNORECASE,
)

# Files under a vendor device-management collection (vSphere, iDRAC,
# F5, Junos, Palo Alto, NetApp, Pure Storage, Cisco IOS, etc). These
# target an internal management plane that ships with self-signed certs
# by default, so ``validate_certs: false`` is the documented bootstrap
# shape until the operator configures trust roots.
VENDOR_COLLECTION_PATH_RE: re.Pattern[str] = re.compile(
    r"(?:^|/)(?:"
    r"community\.vmware|community\.network|"
    r"dell(?:emc)?[-./](?:openmanage|powerflex|powerstore|powerscale|unity|networking)|"
    r"f5networks?[-./](?:f5_modules|f5os|f5_bigip)|"
    r"juniper[-./]?(?:device|junos)|"
    r"paloaltonetworks[-./]panos|"
    r"netapp[-./](?:ontap|elementsw|aws|azure|cloudmanager|um_info)|"
    r"purestorage[-./](?:flasharray|flashblade|fusion)|"
    r"cisco[-./](?:ios|iosxr|nxos|asa|aci|meraki|intersight|ucs)|"
    r"check_point[-./](?:gaia|mgmt)|"
    r"fortinet[-./](?:fortios|fortimanager|fortianalyzer)|"
    r"vyos[-./]vyos"
    r")(?:/|$)",
    re.IGNORECASE,
)

# Rules that describe production-deploy risk and never make sense
# inside a Molecule scenario. Suppressed outright there rather than
# demoted - Molecule fixtures pin ``:latest`` tags on purpose, register
# fact state from developer-controlled JSON, and use dynamic-key
# ``set_fact`` to fan a single fixture out across many parameter sets.
SUPPRESS_IN_MOLECULE: frozenset[str] = frozenset(
    {
        "k8s_image_latest_or_untagged",
        "cross_file_taint",
        "set_fact_injection",
        "dynamic_include_injection",
        "jinja_in_assert_msg",
        "ee_untrusted_base_image",
        "ansible_python_interpreter_override",
        "lookup_env_leak",
        "recursive_delete_critical",
        "raw_module_usage",
        "kubernetes_privileged_pod",
        "kubernetes_sa_token_automount_not_disabled",
        "inventory_host_pattern_all_hosts",
    }
)

# Rules suppressed inside ``tests/integration/targets/``. Same baseline
# as Molecule (test orchestration, not production deploy) plus a handful
# of module-test-specific rules: collection authors test their own
# modules by writing ``- alternatives: path: /usr/bin/dummy1`` and
# ``- pip: name: foo`` (no hash) and ``- npm: name: bar`` (no
# integrity check) - those are the *correct* shape to validate the
# module's behavior, not a deploy risk.
SUPPRESS_IN_INTEGRATION_TESTS: frozenset[str] = SUPPRESS_IN_MOLECULE | frozenset(
    {
        "binary_replace_system_path",
        "container_image_unpinned_tag",
        "k8s_no_resource_limits",
        "pip_install_without_hash_check_from_public_index",
        "npm_install_runs_postinstall_scripts_from_untrusted_registry",
        "user_input_template",
        "lookup_file_traversal",
        "script_module_unsafe",
        "plaintext_password_should_be_vaulted",
        "ip_address_url",
        "container_image_over_http_registry",
        "ansible_galaxy_untrusted",
        # Module-under-test rules: collection integration tests exist
        # to drive the module they ship, so flagging that drive as a
        # "module misuse" is just flagging the test for testing.
        "ssh_authorized_keys_write",
        "firewalld_flush_or_disable",
        "command_module_with_shell",
        "ansible_block_without_rescue_or_always",
        "ignore_errors_security_task",
        "ignore_errors_security",
        # Network-device collection ACL fixtures contain ``eq telnet``
        # tokens describing a port match, not actual telnet usage.
        "telnet_usage",
        # Module-test fixtures inevitably string-concatenate
        # ``client_id=...&secret=...`` style URL params to verify the
        # module's wire format. The module is what we actually want
        # to flag, not its test scaffold.
        "url_encoded_credentials",
        # Module-test fixtures verify failure modes by intentionally
        # using insecure shapes (``http://`` URLs to test HTTP handling,
        # ``disable_gpg_check: true`` to test --nogpgcheck, ``fetch:``
        # to /tmp paths, ``no_log`` defaults to test logging). The
        # rule's signal is the production playbook, not the unit test.
        "unquoted_template_variable",
        "missing_no_log",
        "fetch_module_unsafe_dest",
        "get_url_no_checksum",
        "insecure_protocol_usage",
        "unsafe_tag_bypass",
        "dnf_disable_gpg_check_true",
        "yum_disable_gpg_check_true",
        "apt_disable_gpg_check_true",
        "uri_module_url_plaintext_http",
        # SSL/TLS verification toggles in module-test fixtures: tests
        # exercise both ``validate_certs: true`` and
        # ``validate_certs: false`` paths to verify the module honors
        # the param. Same for ``verify_ssl: false`` on AWX/Tower
        # collection tests, and ``ssl_verification_disabled`` on
        # vCenter/vSphere fixtures (vCenter ships with self-signed
        # certs; collection tests can't bring an enterprise CA).
        "ssl_verification_disabled",
        "uri_module_validate_certs_false",
        "get_url_validate_certs_false",
        # Test scaffolds that exercise ``ANSIBLE_CONFIG`` overrides,
        # ``shell: cd ... && ...`` chaining for setup/teardown, ``assemble:``
        # behavior, and ``lookup('pipe', ...)`` semantics. The signal is
        # the production playbook, not the assertion harness.
        "ansible_config_override",
        "command_chaining",
        "assemble_module_unsafe",
        "lookup_pipe_rce",
        "lookup_url_rce",
        "jinja2_lookup_pipe_in_template",
        "untrusted_apt_repo",
        "untrusted_yum_repo",
        "ansible_galaxy_install_force_latest",
        "role_meta_dependency_without_version",
        "template_in_file_path",
        "hardcoded_password",
        "hardcoded_api_key",
        "elastic_apm_secret_token_or_api_key_literal",
        "become_method_unsafe",
        "ssl_cert_generation",
        # Cloud-IaC rules in module test fixtures: collection
        # integration tests exercise their own modules by creating
        # the resource under test (Azure subnets, GCP buckets,
        # disks, DNS zones, etc.). Those resources are torn down at
        # end-of-test, so missing NSGs / CMEK / access logging
        # there is part of the test contract, not a deployment risk.
        # The same rules continue to fire on production playbooks.
        "azure_subnet_without_network_security_group",
        "azure_vm_disk_encryption_not_enabled",
        "azure_ml_access",
        "gcp_storage_bucket_without_access_logging",
        "gcp_compute_disk_without_cmek",
        "gcp_dns_managed_zone_dnssec_rsasha1_or_disabled",
        "gcp_service_account_key",
        "ansible_k8s_module",
        # Other rules whose signal is dominated by collection test
        # scaffolding: throwaway hardcoded creds in module-auth
        # smoke tests, ``add_host`` / ``delegate_to`` rig wiring
        # for multi-host fixtures, ``crontab`` / ``world_writable``
        # / ``raw_github_content`` / ``http_basic_auth`` /
        # ``ssh_userknownhosts_devnull`` used to drive the module
        # under test, ``apt_force_flag_true`` exercising the
        # module's force path, and ``facts_d_injection`` /
        # ``ansible_become_pass`` / ``jinja_in_when_clause``
        # patterns vendored as fixture inputs.
        "hardcoded_credentials",
        "crontab_modification",
        "user_input_execution",
        "world_writable_files",
        "add_host_dynamic",
        "delegate_to_external_host",
        "raw_github_content",
        "backup_deletion",
        "package_gpg_check_disabled",
        "jinja2_render_sensitive_var",
        "subshell_execution",
        "dangerous_world_writable",
        "ssh_userknownhosts_devnull",
        "ssh_stricthostkey_disabled",
        "slsa_provenance_verification_missing",
        "git_hook_or_config_write",
        "http_basic_auth",
        "apt_force_flag_true",
        "jinja_in_when_clause",
        "ansible_become_pass",
        "facts_d_injection",
        "nohup_background_persistence",
    }
)

# GitHub Actions workflow trees. ``.github/workflows/`` files use
# GitHub's own ``${{ ... }}`` expression syntax which collides with
# our Jinja2-injection regexes (the inner ``{{ inputs.foo }}``
# substring matches), so a focused suppression list keeps Ansible
# Jinja rules from firing on GHA contexts. The dedicated
# ``github_actions_*`` rules still apply.
GITHUB_ACTIONS_PATH_RE: re.Pattern[str] = re.compile(
    r"(?:^|/)\.github/workflows/",
    re.IGNORECASE,
)

SUPPRESS_IN_GITHUB_ACTIONS: frozenset[str] = frozenset(
    {
        "user_input_template",
        "unquoted_template_variable",
        "jinja_in_assert_msg",
        "set_fact_injection",
        "register_variable_injection",
        "dynamic_include_injection",
        "ansible_python_interpreter_override",
        "lookup_env_leak",
        "ip_address_url",
        "missing_no_log",
        "ignore_errors_security",
        "ignore_errors_security_task",
        # GHA jobs install test dependencies straight from PyPI; the
        # rule's "pin to a hash" advice belongs in production
        # ``requirements.txt`` files, not throwaway CI matrices.
        "pip_install_without_hash_check_from_public_index",
        "pip_install_no_version",
        "npm_install_runs_postinstall_scripts_from_untrusted_registry",
    }
)


# Per-rule filename scope. A rule listed here only fires when the
# scanned file's path matches its regex. Rules without an entry fire
# everywhere.
RULE_PATH_SCOPES: dict[str, re.Pattern[str]] = {
    "galaxy_requirements_git_branch_ref": re.compile(
        r"(?:^|/)(?:requirements|collections|roles)\.ya?ml$|"
        r"(?:^|/)galaxy[^/]*\.ya?ml$",
        re.IGNORECASE,
    ),
    "galaxy_requirements_http_source": re.compile(
        r"(?:^|/)(?:requirements|collections|roles)\.ya?ml$|"
        r"(?:^|/)galaxy[^/]*\.ya?ml$",
        re.IGNORECASE,
    ),
    # YAML-specific rules cannot fire on Jinja templates - .j2 files
    # render to non-YAML target formats (apt.conf, nginx.conf, etc.)
    # so duplicate-key semantics don't apply.
    "yaml_duplicate_key_suppression": re.compile(
        r"\.ya?ml(?:\.j2)?$|\.json$",
        re.IGNORECASE,
    ),
    # bindep profiles live in ``bindep.txt`` or ``bindep.yml`` (next to
    # ``execution-environment.yml``), or are embedded into a playbook
    # via ``copy.content: |``. The rule is meaningless on plain prose
    # files like ``changelogs/changelog.yaml`` where backticks denote
    # markdown code spans, not bindep shell-execs - constrain to those
    # three shapes.
    "bindep_profile_runs_shell": re.compile(
        r"(?:^|/)bindep[^/]*\.(?:txt|ya?ml)$|"
        r"(?:^|/)execution[_-]environment\.ya?ml$|"
        r"(?:^|/)(?:tasks|playbooks?|roles)/",
        re.IGNORECASE,
    ),
    # The Ansible ``raw:`` MODULE only ever appears in task files
    # (``tasks/*.yml``, ``handlers/*.yml``) or top-level playbooks.
    # In ``defaults/``, ``vars/``, ``meta/``, ``host_vars/``, and
    # ``group_vars/`` a ``raw:`` line is just a YAML dict key in
    # role-author-defined data (e.g. debops's ``divert``/``raw:`` config
    # blocks); it is never a module invocation. Constraining the rule
    # to task-bearing locations eliminates ~200 FPs in role libraries
    # that use ``raw`` as a domain term in their config schema.
    "raw_module_usage": re.compile(
        r"(?:^|/)(?:tasks|handlers|playbooks?)/[^/]+\.ya?ml$|"
        r"(?:^|/)site\.ya?ml$|"
        r"^[^/]+\.ya?ml$",
        re.IGNORECASE,
    ),
}


def is_molecule_path(file_path: Path) -> bool:
    return bool(MOLECULE_PATH_RE.search(file_path.as_posix()))


def is_integration_test_fixture_path(file_path: Path) -> bool:
    return bool(INTEGRATION_TEST_FIXTURE_PATH_RE.search(file_path.as_posix()))


def is_test_fixture_path(file_path: Path) -> bool:
    return bool(TEST_FIXTURE_PATH_RE.search(file_path.as_posix()))


def is_vendor_collection_path(file_path: Path) -> bool:
    return bool(VENDOR_COLLECTION_PATH_RE.search(file_path.as_posix()))


def is_github_actions_path(file_path: Path) -> bool:
    return bool(GITHUB_ACTIONS_PATH_RE.search(file_path.as_posix()))


def is_helm_template_file(file_path: Path) -> bool:
    """Return ``True`` when ``file_path`` is a Helm chart template.

    Helm templates are Go-templates that render to Kubernetes manifests at
    ``helm install`` time, so the Ansible / K8s rules don't apply - the
    shapes inside are template *source*, not deployed manifests.

    Detection: ``.yaml`` / ``.yml`` / ``.tpl`` file inside a ``templates/``
    directory whose chart root (within four levels) holds ``Chart.yaml``.
    """
    posix = file_path.as_posix()
    if file_path.suffix == ".tpl":
        return True
    if file_path.suffix not in (".yaml", ".yml"):
        return False
    if "/templates/" not in posix and not posix.startswith("templates/"):
        return False
    # Four-level cap accommodates ``<umbrella>/charts/<sub>/templates/<file>.yaml``.
    cursor = file_path.parent
    for _ in range(4):
        if cursor == cursor.parent:
            break
        if (cursor / "Chart.yaml").is_file():
            return True
        cursor = cursor.parent
    return False


def rule_path_scope_allows(rule_id: str, file_path: Path) -> bool:
    scope = RULE_PATH_SCOPES.get(rule_id)
    return scope is None or bool(scope.search(file_path.as_posix()))
