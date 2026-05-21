#!/usr/bin/env python3
"""
Unauthorized cloud access remediation generator for Ansible Security Scanner
"""

from .base import BaseRemediationGenerator


class UnauthorizedCloudAccessRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation for direct cloud service calls in Ansible playbooks"""

    _FIX_MAP = {
        # AWS: SQS
        "ansible_aws_sqs_module": "_generate_sqs_fix",
        "boto3_sqs_client": "_generate_sqs_fix",
        "direct_sqs_queue_url": "_generate_sqs_url_hygiene_fix",
        "direct_sqs_send_message": "_generate_sqs_fix",
        # AWS: SNS / Lambda
        "direct_lambda_invoke": "_generate_lambda_fix",
        "direct_sns_publish": "_generate_sns_fix",
        # AWS: IAM / STS
        "aws_ec2_run_instances": "_generate_sts_fix",
        "aws_iam_create_access_key": "_generate_iam_fix",
        "aws_iam_create_user": "_generate_iam_fix",
        "aws_iam_passrole_wildcard": "_generate_iam_passrole_fix",
        "aws_iam_policy_wildcard_action": "_generate_iam_wildcard_action_fix",
        "aws_iam_trust_policy_public": "_generate_iam_trust_public_fix",
        "aws_imds_v1_enabled": "_generate_imds_v1_fix",
        "aws_oidc_trust_policy_weak": "_generate_oidc_trust_fix",
        "aws_sts_assume_role": "_generate_sts_fix",
        # AWS: Inline Scripts / Credentials
        "aws_credentials_in_playbook": "_generate_boto3_inline_fix",
        "inline_boto3_script": "_generate_boto3_inline_fix",
        # GCP
        "gcloud_direct_command": "_generate_gcp_fix",
        "gcloud_kms_operations": "_generate_audit_evasion_fix",
        "gcloud_logging_modify": "_generate_audit_evasion_fix",
        "gcloud_secrets_access": "_generate_gcp_secrets_fix",
        "gcp_iam_binding_all_users": "_generate_gcp_iam_public_fix",
        "gcp_metadata_access": "_generate_metadata_fix",
        "gcp_service_account_key": "_generate_gcp_fix",
        "gsutil_data_access": "_generate_gcp_storage_fix",
        # Azure
        "az_acr_operations": "_generate_azure_fix",
        "az_cli_direct_command": "_generate_azure_fix",
        "az_keyvault_secret": "_generate_azure_keyvault_fix",
        "az_monitor_disable": "_generate_audit_evasion_fix",
        "az_sql_operations": "_generate_azure_fix",
        "azure_credentials_in_playbook": "_generate_azure_fix",
        "azure_rbac_owner_broad_scope": "_generate_azure_rbac_owner_fix",
        # Kubernetes
        "ansible_k8s_module": "_generate_kubernetes_fix",
        "helm_untrusted_repo": "_generate_helm_fix",
        "kubectl_cp_exfiltration": "_generate_k8s_exfil_fix",
        "kubectl_create_secret": "_generate_kubernetes_fix",
        "kubectl_delete_resource": "_generate_k8s_destroy_fix",
        "kubectl_exec_in_pod": "_generate_kubernetes_fix",
        "kubectl_port_forward": "_generate_k8s_tunnel_fix",
        "kubectl_run_privileged": "_generate_kubernetes_fix",
        # Terraform / IaC
        "aws_cdk_deploy": "_generate_iac_bypass_fix",
        "aws_cloudformation_deploy": "_generate_iac_bypass_fix",
        "pulumi_deploy_from_ansible": "_generate_iac_bypass_fix",
        "serverless_deploy": "_generate_iac_bypass_fix",
        "terraform_apply_from_ansible": "_generate_terraform_fix",
        # Vault
        "vault_cli_read_write": "_generate_vault_cli_fix",
        "vault_policy_manipulation": "_generate_vault_admin_fix",
        "vault_token_in_playbook": "_generate_vault_token_fix",
        # Cloud metadata
        "cloud_instance_metadata": "_generate_metadata_fix",
        # AWS: S3
        "ansible_aws_s3_module": "_generate_s3_fix",
        "aws_s3_block_public_access_disabled": "_generate_s3_public_access_fix",
        "aws_s3_data_access": "_generate_s3_fix",
        "boto3_s3_client": "_generate_s3_fix",
        # AWS: Secrets / SSM / KMS
        "aws_kms_decrypt": "_generate_kms_fix",
        "aws_secrets_manager_get": "_generate_aws_secrets_fix",
        "aws_ssm_parameter_store": "_generate_aws_ssm_fix",
        "aws_ssm_send_command": "_generate_aws_ssm_fix",
        # AWS: Database
        "aws_dynamodb_access": "_generate_aws_database_fix",
        "aws_rds_management": "_generate_aws_database_fix",
        # AWS: Containers
        "aws_ecr_login": "_generate_aws_container_fix",
        "aws_ecs_run_task": "_generate_aws_container_fix",
        "aws_eks_get_token": "_generate_aws_container_fix",
        # AWS: Infrastructure
        "aws_route53_modification": "_generate_dns_hijack_fix",
        "aws_security_group_modify": "_generate_firewall_bypass_fix",
        # AWS: Audit evasion
        "aws_cloudtrail_disable": "_generate_audit_evasion_fix",
        "aws_cloudwatch_delete_alarms": "_generate_audit_evasion_fix",
        "aws_config_disable": "_generate_audit_evasion_fix",
        "aws_guardduty_disable": "_generate_audit_evasion_fix",
        # Docker / Containers
        "docker_exec_command": "_generate_docker_fix",
        "docker_host_mount": "_generate_docker_privileged_fix",
        "docker_login_command": "_generate_docker_fix",
        "docker_privileged": "_generate_docker_privileged_fix",
        "docker_run_command": "_generate_docker_fix",
        "podman_run_command": "_generate_docker_fix",
        # Ansible collections
        "ansible_aws_collection": "_generate_ansible_module_fix",
        "ansible_azure_collection": "_generate_ansible_module_fix",
        "ansible_gcp_collection": "_generate_ansible_module_fix",
        # Oracle Cloud (OCI)
        "oci_cli_command": "_generate_gcp_fix",
        "oci_object_storage": "_generate_s3_fix",
    }

    def generate_unauthorized_cloud_access_fix(
        self,
        rule_id: str,
        code_snippet: str,
    ) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._generate_generic_cloud_fix)

    def _generate_sqs_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Direct SQS Access from Ansible Playbook:**
Sending messages directly to an SQS queue bypasses provisioning controls and audit
workflows. Anyone who can trigger this playbook can inject messages into the queue.

**✅ Secure Fix - Use a Gated API Endpoint:**
```yaml
- name: request provisioning through controlled API
  ansible.builtin.uri:
    url: "https://your-api-gateway.execute-api.region.amazonaws.com/prod/provision"
    method: POST
    headers:
      X-API-Key: "{{{{ vault_api_key }}}}"
      Content-Type: "application/json"
    body_format: json
    body:
      account_id: "{{{{ account_id }}}}"
      stack: "{{{{ stack_name }}}}"
    validate_certs: yes
    status_code: [200, 201, 202]
```

**🔐 Why This Matters:**
- Direct SQS has no authentication at the message level
- API Gateway provides request validation, rate limiting, and audit logging
- API keys can be rotated and scoped per consumer
"""

    def _generate_sqs_url_hygiene_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Hardcoded SQS Queue URL:**
The queue URL embeds the AWS account id and region directly in the playbook,
leaking ownership info to anyone with repo read access and pinning the
playbook to a single environment. The same playbook can't run in
non-prod/prod/DR without hand-editing YAML.

**✅ Secure Fix - Externalize the URL per environment:**
```yaml
# group_vars/<env>/sqs.yml  (vault if the URL is sensitive)
sqs_provisioning_queue_url: "https://sqs.{{{{ aws_region }}}}.amazonaws.com/{{{{ aws_account_id }}}}/provisioning"

# playbook
- name: enqueue provisioning request
  community.aws.sqs_queue:
    queue: "{{{{ sqs_provisioning_queue_url }}}}"
    state: present
```

**🔐 Why This Matters:**
- AWS account ids in source control are a low-effort recon target
- Per-environment overrides become a `group_vars` change instead of a YAML edit
- If the URL ever rotates, one variable change beats grep-and-replace
- Vaulting the variable hides it from forks and CI logs

If your real concern is *talking to SQS from a playbook at all*, see the
`direct_sqs_send_message` / `boto3_sqs_client` / `ansible_aws_sqs_module`
rules - they recommend routing through a gated API endpoint instead.
"""

    def _generate_sns_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Direct SNS Publish from Ansible Playbook:**
Publishing directly to an SNS topic bypasses notification governance and could fan out
unintended actions to all topic subscribers.

**✅ Secure Fix - Use a Gated API:**
```yaml
- name: send notification through controlled API
  ansible.builtin.uri:
    url: "{{{{ notification_api_endpoint }}}}"
    method: POST
    headers:
      Authorization: "Bearer {{{{ vault_api_token }}}}"
    body_format: json
    body:
      event_type: "provisioning_complete"
      payload: "{{{{ notification_data }}}}"
    validate_certs: yes
```
"""

    def _generate_lambda_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Direct Lambda Invocation:**
Directly invoking Lambda functions bypasses API Gateway controls, WAF rules,
and request validation.

**✅ Secure Fix - Invoke Through API Gateway:**
```yaml
- name: call function through API Gateway
  ansible.builtin.uri:
    url: "{{{{ api_gateway_url }}}}/{{{{ function_endpoint }}}}"
    method: POST
    headers:
      X-API-Key: "{{{{ vault_api_key }}}}"
    body_format: json
    body: "{{{{ function_payload }}}}"
    validate_certs: yes
    timeout: 30
```
"""

    def _generate_iam_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Direct IAM Operations from Ansible Playbook:**
Creating IAM users, roles, or access keys from playbooks bypasses identity governance.

**✅ Secure Fix:**
IAM operations must go through approved Terraform/CloudFormation workflows with
peer review and audit logging. Remove all IAM management from Ansible playbooks.

**🔐 IAM Security:**
- IAM changes should be version-controlled and peer-reviewed
- Use infrastructure-as-code (Terraform, CloudFormation) for IAM
- Audit all IAM changes through CloudTrail
"""

    def _generate_sts_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 STS AssumeRole from Ansible Playbook:**
Assuming IAM roles within playbooks can escalate privileges beyond what the
execution environment was granted.

**✅ Secure Fix:**
Configure role assumption in the execution environment (EC2 instance profile,
ECS task role, CI/CD runner role) rather than within playbook logic.
"""

    def _generate_boto3_inline_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Inline Boto3 Script in Ansible Task:**
Embedding Python boto3 scripts inside command/shell tasks bypasses Ansible module
safety mechanisms and hides cloud API calls from static analysis.

**✅ Secure Fix:**
- If an Ansible module exists for the operation, use it
- If no module exists, create a dedicated script with proper error handling
- Route cloud service calls through gated APIs

**🔐 Why Inline Boto3 is Dangerous:**
- Security scanning cannot introspect inline Python
- No structured error handling or idempotency
- Credentials may leak through process argument lists
"""

    def _generate_gcp_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Direct GCP Access from Ansible Playbook:**
Running gcloud commands or embedding service account keys in Ansible tasks
bypasses IaC pipeline controls and can create untracked resources.

**✅ Secure Fix:**
- Use Terraform or Deployment Manager for GCP resource management
- Use workload identity federation instead of service account key files
- Never set GOOGLE_APPLICATION_CREDENTIALS in playbook variables

**🔐 GCP Security:**
- Service account keys should be managed through Secret Manager
- Use short-lived tokens from workload identity federation
- All resource changes should go through reviewed IaC pipelines
"""

    def _generate_azure_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Direct Azure CLI Access from Ansible Playbook:**
Running az CLI commands from Ansible tasks bypasses IaC pipeline controls.

**✅ Secure Fix:**
- Use Terraform or ARM/Bicep templates for Azure resource management
- Use managed identities instead of client secrets
- Never embed AZURE_CLIENT_SECRET in playbook variables

**🔐 Azure Security:**
- Azure resource changes should go through reviewed IaC pipelines
- Use managed identities wherever possible
- Rotate client secrets regularly and scope them narrowly
"""

    def _generate_kubernetes_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Direct kubectl Commands from Ansible Playbook:**
Running kubectl exec, create secret, or run with overrides from Ansible tasks
can bypass RBAC controls and create untracked workloads.

**✅ Secure Fix:**
```yaml
# Instead of kubectl exec, use Kubernetes Jobs:
- name: run migration as a Kubernetes Job
  kubernetes.core.k8s:
    state: present
    definition:
      apiVersion: batch/v1
      kind: Job
      metadata:
        name: db-migration
      spec:
        template:
          spec:
            containers:
              - name: migrate
                image: "{{{{ migration_image }}}}"
            restartPolicy: Never
```

**🔐 Kubernetes Security:**
- Use declarative manifests/Helm instead of imperative kubectl commands
- Manage secrets through sealed-secrets or external-secrets-operator
- Avoid kubectl exec in automation; use Jobs or init containers
"""

    def _generate_terraform_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Terraform Apply/Destroy from Ansible Playbook:**
Running terraform apply from Ansible bypasses plan review, approval gates,
and state locking in your IaC pipeline.

**✅ Secure Fix:**
Terraform should run through its own CI/CD pipeline with:
- Plan output review before apply
- State locking and remote backends
- Approval gates for production changes
- Drift detection and reconciliation

Remove all terraform apply/destroy calls from Ansible playbooks.
"""

    def _generate_metadata_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Cloud Instance Metadata Access:**
Querying cloud metadata endpoints (169.254.169.254, metadata.google.internal)
can extract IAM credentials, project IDs, and other sensitive configuration.

**✅ Secure Fix:**
- Use environment variables or Ansible facts for instance metadata
- Restrict metadata endpoint access via firewall rules or IMDSv2 (AWS)
- Never extract credentials from metadata in playbooks

**🔐 Metadata Security:**
- AWS: Require IMDSv2 (token-based) to prevent SSRF-based credential theft
- GCP: Use metadata concealment for GKE workloads
- Azure: Use managed identity token endpoints with audience scoping
"""

    def _generate_vault_token_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**HashiCorp Vault Token in Playbook:**
Embedding Vault root or service tokens in playbooks creates a persistent,
unrotatable credential that can access all secrets.

**Secure Fix:**
```yaml
- name: authenticate to Vault via AppRole
  ansible.builtin.uri:
    url: "{{{{ vault_addr }}}}/v1/auth/approle/login"
    method: POST
    body_format: json
    body:
      role_id: "{{{{ lookup('env', 'VAULT_ROLE_ID') }}}}"
      secret_id: "{{{{ lookup('env', 'VAULT_SECRET_ID') }}}}"
  register: vault_auth
```

**Vault Security:**
- Never embed tokens in source code; use AppRole or agent auto-auth
- Scope tokens to minimum required policies
- Use response wrapping for secret distribution
"""

    def _generate_vault_cli_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct Vault CLI from Ansible:**
Using `vault read/write/kv` CLI commands bypasses Ansible's native Vault
integration and leaves credentials in process argument lists.

**Secure Fix:**
```yaml
# Use the hashi_vault lookup plugin instead:
- name: retrieve database password
  set_fact:
    db_password: "{{{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/db:password') }}}}"
```
"""

    def _generate_vault_admin_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Vault Administrative Operations from Ansible:**
Creating policies, enabling auth backends, or enabling secrets engines from
Ansible bypasses change management controls for secrets infrastructure.

**Secure Fix:**
Vault configuration must be managed through reviewed Terraform/IaC pipelines:
- `vault policy write` -> Terraform `vault_policy` resource
- `vault auth enable` -> Terraform `vault_auth_backend` resource
- `vault secrets enable` -> Terraform `vault_mount` resource
"""

    def _generate_audit_evasion_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**CRITICAL: Security Monitoring Disabled from Ansible:**
Disabling CloudTrail, GuardDuty, AWS Config, GCP logging, or Azure Monitor
from a playbook is a strong indicator of malicious intent. This hides all
subsequent activity from security teams.

**Required Action:**
- Remove this task immediately
- Investigate who added it and why
- Check CloudTrail/audit logs for prior executions
- Security monitoring must NEVER be disabled from automation
"""

    def _generate_dns_hijack_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**DNS Record Modification from Ansible:**
Modifying Route53 or DNS records directly can redirect traffic to attacker-
controlled infrastructure (DNS hijacking).

**Secure Fix:**
DNS changes must go through:
- Reviewed IaC pipelines (Terraform `aws_route53_record`)
- Change management approval for production zones
- Automated validation of record targets
"""

    def _generate_firewall_bypass_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Security Group Modification from Ansible:**
Modifying VPC security groups can open unauthorized network access paths,
including inbound access from the internet (0.0.0.0/0).

**Secure Fix:**
Security group rules must be managed through:
- Reviewed IaC pipelines (Terraform `aws_security_group_rule`)
- Network policy review and approval
- Automated validation against baseline rules
"""

    def _generate_aws_secrets_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct Secrets Manager Access from Ansible:**
Extracting secrets from AWS Secrets Manager in a playbook exposes them in
Ansible logs, facts, and registered variables.

**Secure Fix:**
```yaml
# Use the AWS SSM lookup plugin with no_log:
- name: retrieve secret
  set_fact:
    my_secret: "{{{{ lookup('amazon.aws.aws_secret', 'my/secret/name') }}}}"
  no_log: true
```
"""

    def _generate_aws_ssm_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**AWS SSM Remote Command Execution:**
SSM send-command enables remote code execution on EC2 instances outside
Ansible's control flow, bypassing playbook audit trails.

**Secure Fix:**
Use Ansible's native SSH-based execution model. If you need to run commands
on EC2 instances, add them to your inventory and target them directly.
SSM send-command should never appear in Ansible playbooks.
"""

    def _generate_kms_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct KMS Operations from Ansible:**
KMS encrypt/decrypt from a playbook processes sensitive data through
Ansible's execution context, exposing it in logs and facts.

**Secure Fix:**
KMS operations should be handled by the application layer or through
ansible-vault for local encryption. Remove direct KMS CLI calls.
"""

    def _generate_s3_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct S3 Access from Ansible:**
Direct S3 cp/sync/presign operations can be used for data exfiltration
(copying sensitive data out) or payload staging (placing malicious files).

**Secure Fix:**
- Use approved data transfer mechanisms
- If S3 access is required, use the `amazon.aws.s3_object` module with
  proper IAM scoping and `no_log: true`
- Never use `aws s3 presign` in playbooks (creates unauthenticated URLs)
"""

    def _generate_aws_database_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct Database Service Management from Ansible:**
Creating, modifying, or deleting RDS/DynamoDB resources from playbooks
bypasses provisioning controls and could lead to data loss.

**Secure Fix:**
Database provisioning must go through approved IaC pipelines:
- Terraform `aws_db_instance` / `aws_dynamodb_table`
- CloudFormation with review gates
- Never modify production databases from ad-hoc playbooks
"""

    def _generate_aws_container_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct Container Service Access from Ansible:**
Launching ECS tasks, retrieving EKS tokens, or logging into ECR from
playbooks bypasses deployment pipeline controls.

**Secure Fix:**
- ECS deployments -> CI/CD pipeline with review gates
- EKS access -> configure via execution environment, not playbook code
- ECR login -> handle in CI/CD runner configuration
"""

    def _generate_docker_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct Docker Commands from Ansible:**
Running docker run/exec/login from shell tasks bypasses Ansible module
safety mechanisms and container security policies.

**Secure Fix:**
```yaml
# Use the community.docker module instead:
- name: run application container
  community.docker.docker_container:
    name: myapp
    image: "registry.internal/myapp:{{{{ app_version }}}}"
    state: started
    security_opts:
      - no-new-privileges
    read_only: true
```
"""

    def _generate_docker_privileged_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**CRITICAL: Docker Privileged Mode:**
Running containers in privileged mode grants full access to the host kernel,
devices, and filesystem. This is equivalent to root access on the host.

**Secure Fix:**
```yaml
# Use specific capabilities instead of --privileged:
- name: run container with minimal capabilities
  community.docker.docker_container:
    name: myapp
    image: "myapp:latest"
    capabilities:
      - NET_BIND_SERVICE   # only what's needed
    security_opts:
      - no-new-privileges
```

**Never use --privileged in production. If a container requires it, the
architecture needs to be redesigned.**
"""

    def _generate_gcp_storage_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct GCS Access via gsutil:**
gsutil cp/mv/rsync from playbooks can exfiltrate data or stage payloads
in GCS buckets without application-level audit trails.

**Secure Fix:**
Use approved data transfer mechanisms. If GCS access is necessary,
use the `google.cloud.gcp_storage_object` module with scoped IAM.
"""

    def _generate_gcp_secrets_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct GCP Secret Manager Access:**
Extracting secrets via `gcloud secrets` exposes them in Ansible logs
and process argument lists.

**Secure Fix:**
```yaml
# Use workload identity + the GCP lookup plugin:
- name: retrieve secret
  set_fact:
    my_secret: "{{{{ lookup('google.cloud.gcp_secret_manager', 'my-secret') }}}}"
  no_log: true
```
"""

    def _generate_azure_keyvault_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct Azure Key Vault Access:**
Extracting secrets via `az keyvault secret show` exposes them in Ansible
logs and process argument lists.

**Secure Fix:**
```yaml
# Use the Azure Key Vault lookup plugin:
- name: retrieve secret
  set_fact:
    my_secret: "{{{{ lookup('azure.azcollection.azure_keyvault_secret', 'my-secret', vault_url='https://myvault.vault.azure.net') }}}}"
  no_log: true
```
"""

    def _generate_k8s_tunnel_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**kubectl Port Forward from Ansible:**
Port forwarding creates network tunnels that bypass Kubernetes NetworkPolicy
controls and cloud firewall rules.

**Secure Fix:**
Use Kubernetes Services and Ingress resources for network access.
If internal access is needed, use a Service of type ClusterIP with
proper NetworkPolicy controls.
"""

    def _generate_k8s_exfil_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**kubectl cp from Ansible:**
Copying files to/from pods can be used for data exfiltration or payload
injection into running containers.

**Secure Fix:**
Use ConfigMaps, Secrets, or init containers for file delivery.
For log collection, use a centralized logging stack (Fluentd/Loki).
"""

    def _generate_k8s_destroy_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**kubectl Delete from Ansible:**
Deleting Kubernetes resources directly can cause service disruption and
data loss. This bypasses GitOps reconciliation controls.

**Secure Fix:**
Resource lifecycle should be managed through GitOps (ArgoCD/Flux) or Helm.
Never delete production resources from ad-hoc Ansible tasks.
"""

    def _generate_helm_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Helm Install from External Repo:**
Installing Helm charts from untrusted or unverified repositories can
introduce malicious workloads into your cluster.

**Secure Fix:**
- Use an internal chart registry (ChartMuseum, Harbor, ECR, ACR)
- Verify chart signatures with `helm verify`
- Pin chart versions explicitly
- Review chart templates before deployment
"""

    def _generate_iac_bypass_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**IaC Tool Executed from Ansible:**
Running Terraform/Pulumi/CDK/CloudFormation/Serverless directly from
Ansible bypasses plan review, approval gates, and state locking.

**Secure Fix:**
IaC tools should run through their own CI/CD pipelines with:
- Plan output review before apply
- State locking and remote backends
- Approval gates for production changes
- Drift detection and reconciliation
"""

    def _generate_ansible_module_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Cloud Ansible Collection Module Usage:**
Using cloud provider Ansible modules (community.aws, azure.azcollection,
google.cloud) creates resources outside your IaC governance controls.

**Recommended Action:**
- Verify this module usage is approved by your cloud governance team
- Ensure RBAC is scoped to the minimum required permissions
- Consider migrating resource management to Terraform/Pulumi
- If approved, add this file to the scanner allowlist with justification
"""

    def _generate_generic_cloud_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Unauthorized Cloud/Infrastructure Access:**
Calling cloud services or infrastructure APIs directly from Ansible playbooks
bypasses provisioning controls, audit workflows, and approval gates.

**✅ Secure Fix:**
- Route cloud service calls through gated APIs with authentication
- Use IaC tools (Terraform, CloudFormation, ARM) for resource management
- Keep Ansible focused on application-level configuration
- Never embed cloud credentials in playbooks

**🔐 General Cloud Security in Ansible:**
- Use IAM roles, managed identities, or workload identity
- Audit all cloud API calls through provider logging (CloudTrail, Audit Logs)
- Implement least-privilege access for all operations
"""

    def _generate_imds_v1_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 IMDSv1 Allowed on EC2 Instance:**
With HttpTokens=optional, any SSRF or file-read vulnerability in a workload on
this instance can reach 169.254.169.254 unauthenticated and steal the
instance-profile credentials. This is the Capital One 2019 breach primitive.

**✅ Secure Fix - Require IMDSv2:**
```yaml
- name: launch EC2 with IMDSv2 required
  amazon.aws.ec2_instance:
    name: "app-worker"
    image_id: "{{{{ ami_id }}}}"
    instance_type: t3.medium
    metadata_options:
      http_tokens: required
      http_endpoint: enabled
      http_put_response_hop_limit: 1
      instance_metadata_tags: enabled
```

**🔐 Organization-Wide Enforcement:**
- SCP: Deny `ec2:RunInstances` and `ec2:ModifyInstanceMetadataOptions` when
  `ec2:MetadataHttpTokens` is not `required`.
- Set `http_put_response_hop_limit: 1` so containers/pods on the host cannot
  reach IMDS through the extra hop.
- Audit the fleet with: `aws ec2 describe-instances --filters   Name=metadata-options.http-tokens,Values=optional`.
"""

    def _generate_iam_wildcard_action_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 IAM Policy With Wildcard Action on Wildcard Resource:**
A policy statement with `Effect: Allow`, `Action: "*"` (or a service-level
wildcard like `"iam:*"`) and `Resource: "*"` grants administrator-equivalent
access. Any principal holding this policy can read any data, create users,
disable logging, and pivot to the organization.

**✅ Secure Fix - Enumerate Exact Actions:**
```yaml
- name: scoped read-only policy for the worker role
  amazon.aws.iam_managed_policy:
    policy_name: worker-read-objects
    policy:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action:
            - s3:GetObject
            - s3:ListBucket
          Resource:
            - "arn:aws:s3:::acme-prod-data"
            - "arn:aws:s3:::acme-prod-data/*"
    state: present
```

**🔐 Defense in Depth:**
- Attach a permission boundary capping the maximum permissions the role can
  ever acquire (even through chained AssumeRole / attach-policy).
- Use `aws iam simulate-principal-policy` in CI to prove a role cannot perform
  sensitive actions like `iam:PutRolePolicy` or `s3:PutBucketPolicy`.
- Prefer AWS-managed policies + service-linked roles over hand-written
  wildcard statements.
"""

    def _generate_iam_trust_public_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 IAM Role Trust Policy Open to the World:**
`Principal: "*"` (or `{{"AWS": "*"}}`) with no Condition means any AWS
account, including the attacker's throwaway account, can call
`sts:AssumeRole` on this role and immediately operate with its permissions.

**✅ Secure Fix - Scope the Trust Principal:**
```yaml
- name: scoped cross-account trust policy
  amazon.aws.iam_role:
    name: partner-data-reader
    assume_role_policy_document:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            AWS: "arn:aws:iam::111122223333:role/partner-etl"
          Action: sts:AssumeRole
          Condition:
            StringEquals:
              sts:ExternalId: "{{{{ vault_partner_external_id }}}}"
              aws:PrincipalOrgID: "{{{{ aws_org_id }}}}"
    managed_policies:
      - arn:aws:iam::aws:policy/ReadOnlyAccess
```

**🔐 Controls to Apply:**
- Require a unique `sts:ExternalId` per partner to defeat the confused-deputy
  problem.
- Pin `aws:PrincipalOrgID` when the trust is inside your Organization.
- Audit all roles with `Principal: "*"` across the account:
  `aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal==``*``]].RoleName'`.
"""

    def _generate_iam_passrole_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 iam:PassRole on Wildcard Resource:**
`iam:PassRole` with `Resource: "*"` lets the holder hand any role in the
account to an AWS service (EC2, Lambda, ECS, Glue, Batch, CodeBuild). That
is a direct privilege-escalation primitive - the attacker simply passes a
more-privileged role to a Lambda they create and invokes it.

**✅ Secure Fix - Pin Role ARN and Target Service:**
```yaml
- name: scoped passrole policy for lambda-invoker role
  amazon.aws.iam_managed_policy:
    policy_name: lambda-invoker-passrole
    policy:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action: iam:PassRole
          Resource:
            - "arn:aws:iam::{{{{ account_id }}}}:role/app-lambda-exec-*"
          Condition:
            StringEquals:
              iam:PassedToService: "lambda.amazonaws.com"
    state: present
```

**🔐 Controls to Apply:**
- Always pair `iam:PassRole` with a `iam:PassedToService` condition.
- Enumerate allowed role ARNs as a prefix pattern (`arn:aws:iam::*:role/app-*`)
  rather than `*`.
- Hunt the org: `aws iam generate-service-last-accessed-details` and look for
  principals that can `PassRole` admin-tier roles they do not normally use.
"""

    def _generate_oidc_trust_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 OIDC / Web-Identity Trust Missing Subject Pinning:**
Federating an IdP (GitHub Actions, Cognito, GitLab, EKS IRSA) without a
`StringEquals` / `StringLike` condition on `:sub` and `:aud` allows ANY
workload using that IdP - including public forks, arbitrary repos, or any
Cognito-authenticated user - to mint a token and assume this role.

**✅ Secure Fix - Pin `sub` and `aud`:**
```yaml
- name: scoped github actions trust policy
  amazon.aws.iam_role:
    name: gha-deployer-prod
    assume_role_policy_document:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            Federated: "arn:aws:iam::{{{{ account_id }}}}:oidc-provider/token.actions.githubusercontent.com"
          Action: sts:AssumeRoleWithWebIdentity
          Condition:
            StringEquals:
              token.actions.githubusercontent.com:aud: "sts.amazonaws.com"
            StringLike:
              token.actions.githubusercontent.com:sub:
                - "repo:acme-org/infra:ref:refs/heads/main"
                - "repo:acme-org/infra:environment:prod"
    managed_policies:
      - arn:aws:iam::{{{{ account_id }}}}:policy/DeployProd
```

**🔐 Controls to Apply:**
- Never use a trailing `*` on the `:sub` claim that matches `repo:*` - that
  trusts every repository on GitHub.
- For EKS IRSA, pin `:sub` to `system:serviceaccount:<namespace>:<sa-name>`.
- Audit with `aws iam list-roles` + parse trust policies for OIDC federation
  without a `sub` condition.
"""

    def _generate_s3_public_access_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 S3 Block Public Access Disabled or Public ACL:**
Disabling any of the four Block Public Access settings (BlockPublicAcls,
IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets), or applying an
ACL of `public-read` / `public-read-write`, re-opens the data-exfiltration
path that BPA exists to prevent. This is how most public-S3 breaches happen.

**✅ Secure Fix - Enforce Block Public Access + BucketOwnerEnforced:**
```yaml
- name: create private bucket with BPA enforced
  amazon.aws.s3_bucket:
    name: "acme-prod-customer-data"
    state: present
    public_access:
      block_public_acls: true
      ignore_public_acls: true
      block_public_policy: true
      restrict_public_buckets: true
    object_ownership: BucketOwnerEnforced
    encryption: "aws:kms"
    encryption_key_id: "{{{{ kms_key_arn }}}}"
    versioning: true
```

**🔐 Organization-Wide Enforcement:**
- Enable account-level Block Public Access:
  `aws s3control put-public-access-block --account-id <id>      --public-access-block-configuration      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`.
- SCP: Deny `s3:PutBucketPublicAccessBlock` and `s3:PutBucketAcl` with any
  public ACL value.
- For legitimate public distribution, front the bucket with CloudFront using
  Origin Access Control (OAC) - the bucket stays private.
"""

    def _generate_gcp_iam_public_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 GCP IAM Binding to allUsers / allAuthenticatedUsers:**
`allUsers` = the entire internet, unauthenticated. `allAuthenticatedUsers` =
any Google account in the world. Granting even `roles/storage.objectViewer`
to these principals is typically a data-exposure incident.

**✅ Secure Fix - Use Signed URLs or a Specific Member:**
```yaml
- name: grant object read to a specific service account
  google.cloud.gcp_projects_iam_policy_binding:
    project: "{{{{ gcp_project_id }}}}"
    role: roles/storage.objectViewer
    member: "serviceAccount:app-worker@{{{{ gcp_project_id }}}}.iam.gserviceaccount.com"
    auth_kind: serviceaccount
    state: present

- name: issue short-lived signed URL for public download
  ansible.builtin.command:
    cmd: >-
      gcloud storage sign-url gs://acme-prod-assets/report.pdf
      --duration=15m
      --impersonate-service-account={{{{ signer_sa }}}}
  register: signed_url
```

**🔐 Organization-Wide Enforcement:**
- Set Organization Policy `iam.allowedPolicyMemberDomains` to your allowed
  domain list - this blocks `allUsers` / `allAuthenticatedUsers` bindings at
  the org level.
- Audit existing bindings: `gcloud asset search-all-iam-policies   --scope=organizations/<id> --query='memberTypes:(allUsers OR allAuthenticatedUsers)'`.
- For public web content, front a private bucket with Cloud CDN.
"""

    def _generate_azure_rbac_owner_fix(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Owner / Contributor Assigned at Subscription or Management-Group Scope:**
Owner grants full control PLUS the right to delegate access - assigning it
at `/subscriptions/<id>` or `/providers/Microsoft.Management/managementGroups/<id>`
gives the principal tenant-wide blast radius. Contributor is only marginally
better (no access delegation) but still can create/delete all resources.

**✅ Secure Fix - Scope to a Resource Group + Use PIM:**
```yaml
- name: scoped contributor on a single resource group
  azure.azcollection.azure_rm_roleassignment:
    scope: "/subscriptions/{{{{ subscription_id }}}}/resourceGroups/rg-app-prod"
    assignee_object_id: "{{{{ sp_object_id }}}}"
    role_definition_id: "/subscriptions/{{{{ subscription_id }}}}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"  # Contributor
    state: present
```

**🔐 Controls to Apply:**
- Use Azure AD Privileged Identity Management (PIM) for time-bound,
  approval-required Owner elevations.
- Prefer a custom role scoped to the minimum `actions` / `dataActions` the
  workload truly needs.
- Audit: `az role assignment list --all --role Owner --include-inherited` and
  review assignments above resource-group scope quarterly.
- Enable Azure Policy `Audit usage of custom RBAC roles` and alert on any new
  subscription-scope Owner/UAA grants via Sentinel.
"""
