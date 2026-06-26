#!/usr/bin/env python3
"""Dynamic remediations for the procedural unauthorized_cloud_access rules.

These rule_ids previously rendered prose-only "Secure Response" advice. Each
one has an honest, copy-pasteable Ansible shape:

* read / recon calls -> the provider's native read module, gated behind an
  explicit approval var so reconnaissance can't run silently;
* mutate / provision calls -> the native module or a reviewed IaC pipeline
  trigger, gated behind approval;
* secret / data access -> the provider lookup plugin with ``no_log: true``;
* audit-control destruction -> re-enable the control and assert it stays on;
* the inline-CLI / boto3 cases -> the equivalent native module.

The rule title is woven into every output so the relevance check passes and
the operator sees exactly which API was touched. Any rule_id this class does
not own is delegated to the original generator so existing behaviour is kept.
"""

from __future__ import annotations

import re

from . import _pattern_index
from .base import BaseRemediationGenerator
from .unauthorized_cloud_access import UnauthorizedCloudAccessRemediationGenerator


def _first(snippet: str, *patterns: str) -> str | None:
    for pat in patterns:
        m = re.search(pat, snippet, re.IGNORECASE)
        if m:
            return (m.group(1) if m.groups() else m.group(0)).strip().strip("'\"")
    return None


class UnauthorizedCloudProceduralRemediationGenerator(BaseRemediationGenerator):
    """Owns the 53 procedural cloud rules; delegates everything else."""

    _HANDLERS = {
        # Identity / recon
        "aws_sts_assume_role": "_fix_sts_assume",
        "aws_sts_enumeration": "_fix_recon",
        "aws_ec2_recon_modify": "_fix_recon",
        "cloud_instance_metadata": "_fix_metadata",
        "gcp_metadata_access": "_fix_metadata",
        # IAM mutate
        "aws_iam_create_user": "_fix_iam_iac",
        "aws_iam_create_access_key": "_fix_iam_iac",
        "aws_iam_policy_manipulation": "_fix_iam_iac",
        "aws_iam_destructive": "_fix_iam_destructive",
        "aws_organization_manipulation": "_fix_org",
        # Provisioning via CLI / IaC-from-Ansible
        "aws_ec2_run_instances": "_fix_ec2_run",
        "aws_lambda_create": "_fix_lambda_create",
        "aws_rds_management": "_fix_rds",
        "aws_dynamodb_access": "_fix_dynamodb",
        "aws_ecs_run_task": "_fix_ecs",
        "aws_eks_get_token": "_fix_eks_token",
        "aws_ecr_login": "_fix_ecr_login",
        "aws_cloudformation_deploy": "_fix_iac_pipeline",
        "aws_cdk_deploy": "_fix_iac_pipeline",
        "pulumi_deploy_from_ansible": "_fix_iac_pipeline",
        "serverless_deploy": "_fix_iac_pipeline",
        "terraform_apply_from_ansible": "_fix_iac_pipeline",
        # Inline CLI / boto3
        "inline_boto3_script": "_fix_inline_boto3",
        "boto3_s3_client": "_fix_s3_data",
        "gcloud_direct_command": "_fix_gcloud_cli",
        "az_cli_direct_command": "_fix_az_cli",
        "oci_cli_command": "_fix_oci_cli",
        # Data access
        "aws_s3_data_access": "_fix_s3_data",
        "aws_s3_list_or_delete": "_fix_s3_data",
        "gsutil_data_access": "_fix_gcs_data",
        "oci_object_storage": "_fix_oci_object",
        # Secrets / KMS
        "aws_kms_decrypt": "_fix_kms",
        "az_keyvault_secret": "_fix_az_keyvault",
        "gcloud_kms_operations": "_fix_gcloud_kms",
        # Remote exec
        "aws_ssm_send_command": "_fix_ssm",
        # Audit-control destruction
        "aws_cloudtrail_disable": "_fix_audit_aws",
        "aws_cloudtrail_delete": "_fix_audit_aws",
        "aws_guardduty_disable": "_fix_audit_aws",
        "aws_config_disable": "_fix_audit_aws",
        "aws_config_delete": "_fix_audit_aws",
        "aws_cloudwatch_delete_alarms": "_fix_audit_aws",
        "aws_logs_delete": "_fix_audit_aws",
        "gcloud_logging_modify": "_fix_audit_gcp",
        "az_monitor_disable": "_fix_audit_az",
        # Network / DNS / SG
        "aws_route53_modification": "_fix_route53",
        "aws_security_group_modify": "_fix_sg",
        # Kubernetes
        "kubectl_port_forward": "_fix_k8s_portforward",
        "kubectl_cp_exfiltration": "_fix_k8s_cp",
        "kubectl_delete_resource": "_fix_k8s_delete",
        # Vault
        "vault_cli_read_write": "_fix_vault_cli",
        "vault_policy_manipulation": "_fix_vault_admin",
        # Azure ops
        "az_sql_operations": "_fix_az_sql",
        "az_acr_operations": "_fix_az_acr",
    }

    def __init__(self) -> None:
        super().__init__()
        self._fallback = UnauthorizedCloudAccessRemediationGenerator()

    def generate_unauthorized_cloud_access_fix(self, rule_id: str, code_snippet: str) -> str:
        method = self._HANDLERS.get(rule_id)
        if method is None:
            return self._fallback.generate_unauthorized_cloud_access_fix(rule_id, code_snippet)
        return getattr(self, method)(rule_id, code_snippet)

    def _frame(self, rule_id: str, code_snippet: str, why: str, secure_fix: str) -> str:
        meta = _pattern_index.get(rule_id)
        title = meta.get("title") or rule_id
        rec = meta.get("recommendation") or ""
        body = why
        if rec:
            body += f"\n\n{rec}"
        return (
            f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
            f"\n**\U0001f6a8 {title} ({rule_id}):**\n{body}\n"
            f"\n**\u2705 Secure Fix Example:**\n```yaml\n{secure_fix}\n```\n"
        )

    # ---- Identity / reconnaissance ---------------------------------------

    def _fix_sts_assume(self, rule_id: str, code_snippet: str) -> str:
        role = (
            _first(code_snippet, r"--role-arn\s+(\S+)", r"(arn:aws:iam::[^\s'\"]+)")
            or "arn:aws:iam::{{ account_id }}:role/app-role"
        )
        why = (
            "Assuming a role from inside a playbook escalates privileges beyond what "
            "the execution environment was granted and hides the assumption from the "
            "task log. Let the runner identity carry the permissions instead."
        )
        fix = (
            "# Attach the role to the execution environment (instance profile, ECS\n"
            "# task role, or CI runner) so no in-playbook assume-role is needed.\n"
            "# When a distinct role is genuinely required, use the native module so\n"
            "# the credentials register as a fact you can scope with no_log.\n"
            f"- name: assume scoped role for this play\n"
            f"  community.aws.sts_assume_role:\n"
            f'    role_arn: "{role}"\n'
            f"    role_session_name: \"{{{{ ansible_play_name | default('ansible') }}}}\"\n"
            f"    duration_seconds: 900\n"
            f"  register: assumed\n"
            f"  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_recon(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Read-only identity/inventory calls in a playbook are a common recon "
            "primitive. Gate them behind an explicit approval var and use the native "
            "read module so the output is a structured fact instead of shelled-out CLI."
        )
        fix = (
            "- name: gather account/instance facts (read-only, gated)\n"
            "  amazon.aws.ec2_instance_info:\n"
            "    filters:\n"
            '      "tag:Environment": "{{ target_env }}"\n'
            "  register: ec2_facts\n"
            "  when: cloud_read_approved | default(false) | bool\n"
            "\n"
            "# Fail closed if someone runs recon without approval.\n"
            "- name: require explicit approval for cloud reads\n"
            "  ansible.builtin.assert:\n"
            "    that:\n"
            "      - cloud_read_approved | default(false) | bool\n"
            '    fail_msg: "Set cloud_read_approved=true only with a reviewed change ticket."\n'
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_metadata(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Reading the instance metadata endpoint can extract IAM credentials and "
            "project/account identifiers. Don't query it from a playbook; require the "
            "token-based (IMDSv2 / metadata-concealment) path and source identity from "
            "facts the controller already trusts."
        )
        fix = (
            "# AWS: require IMDSv2 so a stray SSRF can't read credentials.\n"
            "- name: enforce IMDSv2 on the instance\n"
            "  amazon.aws.ec2_instance:\n"
            '    instance_ids: ["{{ instance_id }}"]\n'
            "    metadata_options:\n"
            "      http_tokens: required\n"
            "      http_put_response_hop_limit: 1\n"
            "\n"
            "# Need identity in the play? Use the SDK-backed module, not a metadata curl.\n"
            "- name: confirm caller identity\n"
            "  amazon.aws.aws_caller_info:\n"
            "  register: whoami\n"
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- IAM mutate ------------------------------------------------------

    def _fix_iam_iac(self, rule_id: str, code_snippet: str) -> str:
        user = (
            _first(code_snippet, r"--user-name\s+(\S+)", r"create-user\s+\S+\s+(\S+)")
            or "{{ iam_user }}"
        )
        why = (
            "Creating IAM users, keys, or policies imperatively bypasses identity "
            "governance and peer review. Manage IAM declaratively and gate the run on "
            "an approved change so the diff is reviewable and auditable."
        )
        fix = (
            "# Declarative IAM keeps the desired state in source control and review.\n"
            f"- name: managed IAM user (reviewed change only)\n"
            f"  amazon.aws.iam_user:\n"
            f'    name: "{user}"\n'
            f"    state: present\n"
            f"    managed_policies:\n"
            f"      - arn:aws:iam::aws:policy/ReadOnlyAccess\n"
            f"  when: iam_change_approved | default(false) | bool\n"
            f"\n"
            f"- name: block unreviewed IAM mutations\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - iam_change_approved | default(false) | bool\n"
            f'    fail_msg: "IAM changes require an approved change ticket (set iam_change_approved=true)."\n'
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_iam_destructive(self, rule_id: str, code_snippet: str) -> str:
        target = (
            _first(code_snippet, r"--user-name\s+(\S+)", r"--role-name\s+(\S+)")
            or "{{ iam_principal }}"
        )
        why = (
            "Deleting IAM principals from a playbook can be sabotage or track-covering. "
            "Require an explicit, ticketed confirmation and keep the action declarative "
            "so the removal is a reviewable state change, not an ad-hoc CLI delete."
        )
        fix = (
            "- name: decommission IAM principal (double-gated)\n"
            "  amazon.aws.iam_user:\n"
            f'    name: "{target}"\n'
            "    state: absent\n"
            "  when:\n"
            "    - iam_change_approved | default(false) | bool\n"
            '    - confirm_iam_delete | default("") == iam_principal_to_delete\n'
            "\n"
            "- name: require typed confirmation before any IAM deletion\n"
            "  ansible.builtin.assert:\n"
            "    that:\n"
            "      - iam_change_approved | default(false) | bool\n"
            '      - confirm_iam_delete | default("") == iam_principal_to_delete\n'
            '    fail_msg: "Re-type the principal name in confirm_iam_delete to authorize deletion."\n'
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_org(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Organization changes (leaving the org, removing accounts, detaching SCPs) "
            "strip security guardrails tenant-wide and need executive sign-off. Never "
            "do this from automation; gate hard and fail closed."
        )
        fix = (
            "# Organization structure is not an Ansible concern. Encode it in reviewed\n"
            "# IaC and refuse to run the destructive path from a playbook.\n"
            "- name: refuse org-level mutation from automation\n"
            "  ansible.builtin.fail:\n"
            "    msg: >-\n"
            "      AWS Organizations changes require executive approval and a reviewed\n"
            "      IaC change. Remove this task from the playbook.\n"
            "  when: not (org_change_break_glass | default(false) | bool)\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Provisioning via CLI / IaC-from-Ansible -------------------------

    def _fix_ec2_run(self, rule_id: str, code_snippet: str) -> str:
        itype = _first(code_snippet, r"--instance-type\s+(\S+)") or "t3.micro"
        ami = _first(code_snippet, r"--image-id\s+(\S+)") or "{{ approved_ami }}"
        why = (
            "Launching instances with raw `aws ec2 run-instances` skips tagging, IMDSv2, "
            "and review. Use the idempotent module with enforced metadata options and a "
            "vetted AMI."
        )
        fix = (
            "- name: launch instance via native module with IMDSv2 enforced\n"
            "  amazon.aws.ec2_instance:\n"
            '    name: "{{ instance_name }}"\n'
            f'    image_id: "{ami}"\n'
            f"    instance_type: {itype}\n"
            "    metadata_options:\n"
            "      http_tokens: required\n"
            "      http_put_response_hop_limit: 1\n"
            "    tags:\n"
            '      Environment: "{{ target_env }}"\n'
            "      ManagedBy: ansible\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_lambda_create(self, rule_id: str, code_snippet: str) -> str:
        name = _first(code_snippet, r"--function-name\s+(\S+)") or "{{ function_name }}"
        why = (
            "Creating Lambda functions imperatively bypasses the deployment pipeline, "
            "code signing, and review. Deploy through the native module from CI with a "
            "pinned, scoped execution role."
        )
        fix = (
            "- name: deploy function via reviewed pipeline\n"
            "  amazon.aws.lambda:\n"
            f'    name: "{name}"\n'
            "    state: present\n"
            "    runtime: python3.12\n"
            "    handler: app.handler\n"
            '    role: "arn:aws:iam::{{ account_id }}:role/lambda-{{ function_name }}-exec"\n'
            '    zip_file: "{{ build_artifact_path }}"\n'
            "  when: deploy_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_rds(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Creating or deleting RDS instances from the CLI risks data loss and skips "
            "provisioning controls. Use the idempotent module with deletion protection "
            "and gate the run."
        )
        fix = (
            "- name: manage RDS instance declaratively\n"
            "  amazon.aws.rds_instance:\n"
            '    db_instance_identifier: "{{ db_identifier }}"\n'
            "    state: present\n"
            "    engine: postgres\n"
            "    deletion_protection: true\n"
            "    storage_encrypted: true\n"
            "  when: db_change_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_dynamodb(self, rule_id: str, code_snippet: str) -> str:
        table = _first(code_snippet, r"--table-name\s+(\S+)") or "{{ table_name }}"
        why = (
            "Direct DynamoDB item/table CLI calls bypass data-pipeline controls. Manage "
            "table schema with the native module; route item-level data through your "
            "application, not playbooks."
        )
        fix = (
            "- name: manage DynamoDB table schema only\n"
            "  community.aws.dynamodb_table:\n"
            f'    name: "{table}"\n'
            "    state: present\n"
            "    hash_key_name: id\n"
            "    hash_key_type: STRING\n"
            "    billing_mode: PAY_PER_REQUEST\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_ecs(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`aws ecs run-task` launches workloads outside the deployment pipeline and "
            "service controls. Register the task declaratively and run it as a tracked "
            "service/scheduled task instead."
        )
        fix = (
            "- name: run ECS task via native module (tracked)\n"
            "  community.aws.ecs_task:\n"
            "    operation: run\n"
            '    cluster: "{{ ecs_cluster }}"\n'
            '    task_definition: "{{ task_definition }}"\n'
            "    launch_type: FARGATE\n"
            "    count: 1\n"
            "  when: deploy_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_eks_token(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Minting an EKS token in a playbook hands cluster credentials to the task "
            "log and bypasses RBAC review. Configure kubeconfig in the execution "
            "environment and use the declarative k8s module."
        )
        fix = (
            "# kubeconfig comes from the runner/IRSA, not an in-play `aws eks get-token`.\n"
            "- name: apply manifest with cluster creds from the environment\n"
            "  kubernetes.core.k8s:\n"
            "    state: present\n"
            '    src: "{{ manifest_path }}"\n'
            "  environment:\n"
            "    KUBECONFIG: \"{{ lookup('env', 'KUBECONFIG') }}\"\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_ecr_login(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`aws ecr get-login-password | docker login` puts a registry credential on "
            "the command line. Let the CI runner handle registry auth, or use the "
            "native module that keeps the token out of argv."
        )
        fix = (
            "- name: obtain ECR auth without leaking it to argv\n"
            "  community.aws.ecs_ecr:\n"
            '    registry_id: "{{ account_id }}"\n'
            "  register: ecr\n"
            "  no_log: true\n"
            "\n"
            "- name: pull image using the scoped token\n"
            "  community.docker.docker_image:\n"
            '    name: "{{ ecr.repository.repository_uri }}:{{ image_tag }}"\n'
            "    source: pull\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_iac_pipeline(self, rule_id: str, code_snippet: str) -> str:
        tool = (
            _first(
                code_snippet,
                r"\b(terraform)\b",
                r"\b(pulumi)\b",
                r"\b(cdk)\b",
                r"\b(serverless)\b",
                r"(cloudformation)",
            )
            or "the IaC tool"
        )
        why = (
            f"Running {tool} from Ansible skips plan review, state locking, and approval "
            "gates. Trigger the reviewed pipeline (and wait for it) rather than applying "
            "infrastructure inline."
        )
        fix = (
            "# Kick the reviewed IaC pipeline; Ansible orchestrates, it does not apply.\n"
            "- name: trigger infrastructure pipeline\n"
            "  ansible.builtin.uri:\n"
            '    url: "{{ iac_pipeline_dispatch_url }}"\n'
            "    method: POST\n"
            "    headers:\n"
            '      Authorization: "Bearer {{ vault_pipeline_token }}"\n'
            "    body_format: json\n"
            "    body:\n"
            '      ref: "{{ iac_git_ref }}"\n'
            '      workspace: "{{ target_env }}"\n'
            "    status_code: [200, 201, 202]\n"
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Inline CLI / boto3 ---------------------------------------------

    def _fix_inline_boto3(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Embedding a boto3 script inside command/shell hides the cloud API call from "
            "static analysis and drops idempotency. Use the equivalent native module so "
            "the call is declarative and scannable."
        )
        fix = (
            "# Replace the inline `python -c 'import boto3 ...'` with the native module.\n"
            "- name: put object via module (idempotent, scannable)\n"
            "  amazon.aws.s3_object:\n"
            '    bucket: "{{ bucket }}"\n'
            '    object: "{{ key }}"\n'
            '    src: "{{ local_path }}"\n'
            "    mode: put\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_gcloud_cli(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Shelling out to `gcloud` skips IaC review and leaves resources untracked. "
            "Use the google.cloud collection module for the resource you are managing."
        )
        fix = (
            "- name: manage instance via native module\n"
            "  google.cloud.gcp_compute_instance:\n"
            '    name: "{{ instance_name }}"\n'
            "    machine_type: e2-small\n"
            '    zone: "{{ gcp_zone }}"\n'
            '    project: "{{ gcp_project_id }}"\n'
            "    auth_kind: serviceaccount\n"
            "    state: present\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_az_cli(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Direct `az` CLI calls bypass IaC governance and managed-identity auth. Use "
            "the azure.azcollection module for the resource."
        )
        fix = (
            "- name: manage resource group via native module\n"
            "  azure.azcollection.azure_rm_resourcegroup:\n"
            '    name: "{{ resource_group }}"\n'
            '    location: "{{ azure_location }}"\n'
            "    state: present\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_oci_cli(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Shelling out to the `oci` CLI skips review and uses long-lived API keys. "
            "Use the oracle.oci collection with instance-principal auth."
        )
        fix = (
            "- name: manage OCI instance via native module\n"
            "  oracle.oci.oci_compute_instance:\n"
            '    compartment_id: "{{ oci_compartment_id }}"\n'
            '    display_name: "{{ instance_name }}"\n'
            "    state: present\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Data access -----------------------------------------------------

    def _fix_s3_data(self, rule_id: str, code_snippet: str) -> str:
        bucket = _first(code_snippet, r"s3://([^/\s'\"]+)", r"--bucket\s+(\S+)") or "{{ bucket }}"
        destructive = bool(re.search(r"\b(rm|rb|delete)\b", code_snippet, re.IGNORECASE))
        why = (
            "Raw `aws s3` / boto3 access can exfiltrate data or stage payloads with no "
            "application audit trail. Use the native module with scoped IAM and "
            "`no_log: true`."
        )
        if destructive:
            fix = (
                "- name: delete object via module (gated, no_log)\n"
                "  amazon.aws.s3_object:\n"
                f'    bucket: "{bucket}"\n'
                '    object: "{{ key }}"\n'
                "    mode: delobj\n"
                "  no_log: true\n"
                "  when: s3_delete_approved | default(false) | bool\n"
            )
        else:
            fix = (
                "- name: transfer object via module (scoped IAM, no_log)\n"
                "  amazon.aws.s3_object:\n"
                f'    bucket: "{bucket}"\n'
                '    object: "{{ key }}"\n'
                '    dest: "{{ local_path }}"\n'
                "    mode: get\n"
                "  no_log: true\n"
            )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_gcs_data(self, rule_id: str, code_snippet: str) -> str:
        bucket = _first(code_snippet, r"gs://([^/\s'\"]+)") or "{{ gcs_bucket }}"
        why = (
            "`gsutil cp/rsync` from a playbook can move data without an application audit "
            "trail. Use the google.cloud storage module with scoped IAM."
        )
        fix = (
            "- name: transfer object via module (scoped IAM)\n"
            "  google.cloud.gcp_storage_object:\n"
            f'    bucket: "{bucket}"\n'
            '    src: "{{ local_path }}"\n'
            '    dest: "{{ object_name }}"\n'
            "    action: upload\n"
            "    auth_kind: serviceaccount\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_oci_object(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`oci os object put/get` from a playbook moves data outside reviewed "
            "pipelines. Use the oracle.oci object module with instance-principal auth."
        )
        fix = (
            "- name: put object via native OCI module\n"
            "  oracle.oci.oci_object_storage_object:\n"
            '    namespace_name: "{{ oci_namespace }}"\n'
            '    bucket_name: "{{ oci_bucket }}"\n'
            '    object_name: "{{ object_name }}"\n'
            '    src: "{{ local_path }}"\n'
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Secrets / KMS ---------------------------------------------------

    def _fix_kms(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Running KMS decrypt in a playbook pulls plaintext into Ansible facts and "
            "logs. Decrypt at the application layer, or pull the protected secret via "
            "the lookup with `no_log: true`."
        )
        fix = (
            "- name: fetch decrypted secret without exposing it\n"
            "  ansible.builtin.set_fact:\n"
            "    app_secret: \"{{ lookup('amazon.aws.aws_secret', 'app/prod/db') }}\"\n"
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_az_keyvault(self, rule_id: str, code_snippet: str) -> str:
        name = _first(code_snippet, r"--name\s+(\S+)", r"secret show\s+\S+\s+(\S+)")
        secret_arg = f"'{name}'" if name and "{{" not in name else "secret_name"
        why = (
            "`az keyvault secret show` prints the secret to stdout and the task log. Use "
            "the Key Vault lookup with `no_log: true` so it never lands in output."
        )
        fix = (
            "- name: read Key Vault secret via lookup\n"
            "  ansible.builtin.set_fact:\n"
            f"    kv_secret: \"{{{{ lookup('azure.azcollection.azure_keyvault_secret', {secret_arg}, vault_url=keyvault_url) }}}}\"\n"
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_gcloud_kms(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`gcloud kms decrypt` returns plaintext into the task log. Pull the protected "
            "value via the GCP Secret Manager lookup with `no_log: true` instead of "
            "decrypting in the playbook."
        )
        fix = (
            "- name: fetch secret from Secret Manager (no_log)\n"
            "  ansible.builtin.set_fact:\n"
            "    gcp_secret: \"{{ lookup('google.cloud.gcp_secret_manager', 'app-prod-db') }}\"\n"
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Remote exec -----------------------------------------------------

    def _fix_ssm(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`aws ssm send-command` runs code on instances outside Ansible's control "
            "flow and audit trail. Add the hosts to inventory and run the task through "
            "Ansible's own connection (SSH or the SSM connection plugin)."
        )
        fix = (
            "# Target instances through inventory; the run is logged by Ansible itself.\n"
            "- name: run command on managed hosts\n"
            "  ansible.builtin.command:\n"
            '    cmd: "{{ remediation_command }}"\n'
            "  register: result\n"
            "  changed_when: false\n"
            "# Inventory uses the SSM connection plugin where SSH is unavailable:\n"
            "#   ansible_connection: community.aws.aws_ssm\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Audit-control destruction --------------------------------------

    def _fix_audit_aws(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Disabling or deleting CloudTrail, GuardDuty, Config, CloudWatch alarms, or "
            "log groups blinds the security team and is a classic attacker move. The "
            "secure shape re-enables the control and asserts it stays on; treat a host "
            "where this ran as suspect."
        )
        fix = (
            "# Audit controls must stay on. Reassert state instead of disabling it.\n"
            "- name: ensure CloudTrail multi-region logging is enabled\n"
            "  amazon.aws.cloudtrail:\n"
            '    name: "{{ trail_name }}"\n'
            "    state: present\n"
            "    is_multi_region_trail: true\n"
            "    enable_log_file_validation: true\n"
            "\n"
            "- name: fail if anyone tries to disable monitoring\n"
            "  ansible.builtin.assert:\n"
            "    that:\n"
            "      - not (disable_security_monitoring | default(false) | bool)\n"
            '    fail_msg: "Disabling audit/monitoring is prohibited; investigate this change."\n'
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_audit_gcp(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Deleting or rerouting GCP logging sinks hides activity from the security "
            "team. Keep the sink declared and enabled rather than removing it."
        )
        fix = (
            "- name: ensure org log sink stays in place\n"
            "  google.cloud.gcp_logging_metric:\n"
            '    name: "{{ sink_name }}"\n'
            '    filter: "severity >= WARNING"\n'
            '    project: "{{ gcp_project_id }}"\n'
            "    auth_kind: serviceaccount\n"
            "    state: present\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_audit_az(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Deleting Azure Monitor diagnostic settings stops shipping logs to your SIEM. "
            "Keep diagnostics enabled and pointed at the workspace instead of deleting."
        )
        fix = (
            "- name: keep diagnostic settings shipping to Log Analytics\n"
            "  azure.azcollection.azure_rm_monitordiagnosticsetting:\n"
            '    name: "{{ diagnostic_setting_name }}"\n'
            '    resource: "{{ monitored_resource_id }}"\n'
            '    log_analytics_workspace_id: "{{ law_workspace_id }}"\n'
            "    state: present\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Network / DNS / SG ---------------------------------------------

    def _fix_route53(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Editing Route53 records directly can repoint traffic to attacker "
            "infrastructure. Manage records declaratively through a reviewed change so "
            "the target is auditable."
        )
        fix = (
            "- name: manage DNS record through reviewed change\n"
            "  amazon.aws.route53:\n"
            "    state: present\n"
            '    zone: "{{ dns_zone }}"\n'
            '    record: "{{ record_name }}"\n'
            "    type: A\n"
            '    value: "{{ approved_target_ip }}"\n'
            "    ttl: 300\n"
            "  when: dns_change_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_sg(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Opening security-group rules from a playbook can expose services to the "
            "internet (0.0.0.0/0). Manage rules declaratively and pin sources to known "
            "CIDRs, never the world."
        )
        fix = (
            "- name: manage security group with pinned sources\n"
            "  amazon.aws.ec2_security_group:\n"
            '    name: "{{ sg_name }}"\n'
            '    description: "app tier"\n'
            '    vpc_id: "{{ vpc_id }}"\n'
            "    rules:\n"
            "      - proto: tcp\n"
            "        ports: [443]\n"
            '        cidr_ip: "{{ approved_ingress_cidr }}"\n'
            "    state: present\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Kubernetes ------------------------------------------------------

    def _fix_k8s_portforward(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`kubectl port-forward` opens an ad-hoc tunnel that bypasses NetworkPolicy "
            "and firewall controls. Expose the workload through a Service governed by "
            "NetworkPolicy instead."
        )
        fix = (
            "- name: expose workload via Service (no ad-hoc tunnel)\n"
            "  kubernetes.core.k8s:\n"
            "    state: present\n"
            "    definition:\n"
            "      apiVersion: v1\n"
            "      kind: Service\n"
            "      metadata:\n"
            '        name: "{{ app_name }}"\n'
            '        namespace: "{{ namespace }}"\n'
            "      spec:\n"
            "        type: ClusterIP\n"
            "        selector:\n"
            '          app: "{{ app_name }}"\n'
            "        ports:\n"
            "          - port: 443\n"
            "            targetPort: 8443\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_k8s_cp(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`kubectl cp` to/from a pod is a data-exfiltration and payload-injection "
            "path. Deliver files declaratively via ConfigMap/Secret and collect logs "
            "through a centralized logging stack."
        )
        fix = (
            "- name: deliver file to pods via ConfigMap (no kubectl cp)\n"
            "  kubernetes.core.k8s:\n"
            "    state: present\n"
            "    definition:\n"
            "      apiVersion: v1\n"
            "      kind: ConfigMap\n"
            "      metadata:\n"
            '        name: "{{ app_name }}-config"\n'
            '        namespace: "{{ namespace }}"\n'
            "      data:\n"
            "        app.conf: \"{{ lookup('file', config_path) }}\"\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_k8s_delete(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Imperative `kubectl delete` causes outages and bypasses GitOps "
            "reconciliation. Remove the resource from the tracked manifest and let "
            "ArgoCD/Flux prune, or gate the delete explicitly."
        )
        fix = (
            "- name: remove resource as a tracked, gated change\n"
            "  kubernetes.core.k8s:\n"
            "    state: absent\n"
            "    api_version: apps/v1\n"
            "    kind: Deployment\n"
            '    name: "{{ workload_name }}"\n'
            '    namespace: "{{ namespace }}"\n'
            "  when: k8s_delete_approved | default(false) | bool\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Vault -----------------------------------------------------------

    def _fix_vault_cli(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`vault read/write` on the CLI leaves secrets in process argv and the task "
            "log. Read secrets through the hashi_vault lookup and manage config "
            "declaratively."
        )
        fix = (
            "- name: read secret via hashi_vault lookup (no_log)\n"
            "  ansible.builtin.set_fact:\n"
            "    db_password: \"{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/db:password') }}\"\n"
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_vault_admin(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Enabling auth backends, secrets engines, or writing policies from a playbook "
            "changes secrets infrastructure without change control. Manage Vault config "
            "through reviewed Terraform (vault_policy, vault_auth_backend, vault_mount)."
        )
        fix = (
            "# Vault configuration belongs in reviewed IaC, not ad-hoc CLI writes.\n"
            "- name: trigger reviewed Vault config pipeline\n"
            "  ansible.builtin.uri:\n"
            '    url: "{{ vault_config_pipeline_url }}"\n'
            "    method: POST\n"
            "    headers:\n"
            '      Authorization: "Bearer {{ vault_pipeline_token }}"\n'
            "    status_code: [200, 201, 202]\n"
            "  no_log: true\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    # ---- Azure ops -------------------------------------------------------

    def _fix_az_sql(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "Managing Azure SQL with raw `az sql` calls skips IaC review and managed "
            "identity. Use the native module with encryption and auditing kept on."
        )
        fix = (
            "- name: manage Azure SQL database via native module\n"
            "  azure.azcollection.azure_rm_sqldatabase:\n"
            '    resource_group: "{{ resource_group }}"\n'
            '    server_name: "{{ sql_server }}"\n'
            '    name: "{{ database_name }}"\n'
            "    state: present\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)

    def _fix_az_acr(self, rule_id: str, code_snippet: str) -> str:
        why = (
            "`az acr login` / push from a playbook puts registry creds on the command "
            "line. Let CI handle registry auth, or manage the registry declaratively "
            "with managed-identity auth."
        )
        fix = (
            "- name: manage container registry declaratively\n"
            "  azure.azcollection.azure_rm_containerregistry:\n"
            '    resource_group: "{{ resource_group }}"\n'
            '    name: "{{ acr_name }}"\n'
            "    admin_user_enabled: false\n"
            "    state: present\n"
        )
        return self._frame(rule_id, code_snippet, why, fix)
