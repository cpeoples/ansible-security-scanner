#!/usr/bin/env python3
"""
Remediation generator for AI/ML security issues
"""

from .base import BaseRemediationGenerator


class AiMlSecurityRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation examples for AI/ML security issues"""

    _FIX_MAP = {
        "anthropic_api_key": "api_key",
        "aws_bedrock_access": "bedrock",
        "aws_sagemaker_access": "sagemaker",
        "azure_ml_access": "azure_ml",
        "azure_openai_key": "api_key",
        "cohere_api_key": "api_key",
        "gcp_vertex_ai_access": "vertex",
        "generic_llm_api_key": "api_key",
        "google_ai_api_key": "api_key",
        "gpu_instance_launch": "gpu",
        "huggingface_model_download": "model_download",
        "huggingface_token": "api_key",
        "jupyter_no_auth": "jupyter",
        "jupyter_server_start": "jupyter",
        "mlflow_direct_access": "mlflow",
        "model_from_url": "model_download",
        "openai_api_key": "api_key",
        "pickle_remote_load": "pickle",
        "replicate_api_token": "api_key",
        "template_in_llm_prompt": "prompt_injection",
        "wandb_api_key": "api_key",
    }

    def generate_ai_ml_security_fix(self, rule_id: str, code_snippet: str) -> str:
        generators = {
            "api_key": self._generate_api_key_fix,
            "model_download": self._generate_model_download_fix,
            "pickle": self._generate_pickle_fix,
            "sagemaker": self._generate_ai_service_fix,
            "bedrock": self._generate_ai_service_fix,
            "vertex": self._generate_ai_service_fix,
            "azure_ml": self._generate_ai_service_fix,
            "gpu": self._generate_gpu_fix,
            "jupyter": self._generate_jupyter_fix,
            "prompt_injection": self._generate_prompt_injection_fix,
            "mlflow": self._generate_mlops_fix,
        }
        issue = self._FIX_MAP.get(rule_id, "generic")
        gen = generators.get(issue, self._generate_generic_ai_fix)
        return gen(code_snippet)

    def _generate_api_key_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**AI/LLM API Key Exposed in Playbook:**
LLM API keys grant access to expensive AI services and billing accounts.
A leaked key can result in significant financial damage and data exposure.

**Secure Fix:**
```yaml
# Store in Vault and retrieve at runtime:
- name: get AI API key from Vault
  set_fact:
    ai_api_key: "{{{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/ai:api_key') }}}}"
  no_log: true

# Or use environment-provided credentials:
- name: call AI service
  ansible.builtin.uri:
    url: "https://api.openai.com/v1/chat/completions"
    headers:
      Authorization: "Bearer {{{{ lookup('env', 'OPENAI_API_KEY') }}}}"
  no_log: true
```

**AI Key Security:**
- Set usage limits and alerts on all AI API keys
- Use separate keys per environment (dev/staging/prod)
- Rotate keys regularly and after any potential exposure
"""

    def _generate_model_download_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Untrusted ML Model Download:**
ML models from Hugging Face and other hubs can contain arbitrary code
(via pickle serialization). Downloading without verification is a supply
chain attack vector.

**Secure Fix:**
```yaml
- name: download model with pinned revision
  get_url:
    url: "https://huggingface.co/org/model/resolve/<commit-sha>/model.safetensors"
    dest: /opt/models/model.safetensors
    checksum: "sha256:<known-good-hash>"

# Prefer safetensors format over pickle-based formats (.pt, .pkl, .bin)
```

**ML Supply Chain Security:**
- Pin model downloads to specific commit SHAs
- Prefer safetensors format (no arbitrary code execution)
- Scan models with tools like Fickling or ModelScan
- Use an internal model registry with signature verification
"""

    def _generate_pickle_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**CRITICAL: Pickle Deserialization = Remote Code Execution:**
`pickle.load`, `torch.load`, `joblib.load`, and `dill.load` execute
arbitrary Python code during deserialization. A malicious pickle file
achieves full RCE on the target machine.

**Secure Fix:**
- Use safetensors for ML model weights (no code execution)
- Use JSON, MessagePack, or Protocol Buffers for data serialization
- If pickle is unavoidable, use `torch.load(..., weights_only=True)`
- Never load pickle files from untrusted sources
"""

    def _generate_ai_service_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct AI/ML Service Provisioning from Ansible:**
Creating SageMaker endpoints, Bedrock invocations, Vertex AI pipelines,
or Azure ML workspaces from playbooks bypasses ML governance controls
and can incur significant costs.

**Secure Fix:**
AI/ML infrastructure should be provisioned through:
- Approved ML platform pipelines (MLflow, Kubeflow, SageMaker Pipelines)
- Reviewed IaC (Terraform) with cost controls and auto-shutdown
- Budget alerts and instance hour limits
"""

    def _generate_gpu_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**GPU Instance Launch from Ansible:**
GPU instances (p3, p4, g5, A100, etc.) cost $3-$30+/hour. Unauthorized
launches can result in massive bills, and could indicate crypto mining.

**Secure Fix:**
GPU instance provisioning must be:
- Approved by cost center owner
- Tagged with purpose, owner, and auto-shutdown schedule
- Provisioned through IaC with budget limits
- Monitored for unexpected utilization patterns
"""

    def _generate_jupyter_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Jupyter Notebook Server Exposure:**
Jupyter provides interactive code execution. Without authentication and
network controls, it's equivalent to an open RCE endpoint.

**Secure Fix:**
```yaml
# Always require token auth and restrict binding:
- name: start Jupyter with authentication
  ansible.builtin.shell: >
    jupyter lab
    --ip=127.0.0.1
    --port=8888
    --no-browser
    --NotebookApp.token='{{{{ vault_jupyter_token }}}}'
  no_log: true
```

**Jupyter Security:**
- Never disable authentication (--NotebookApp.token='')
- Never bind to 0.0.0.0 without a firewall
- Use JupyterHub for multi-user environments
"""

    def _generate_prompt_injection_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Prompt Injection via Template Variables:**
Injecting unvalidated Ansible variables into LLM prompts allows prompt
injection attacks. An attacker who controls the variable value can
manipulate the LLM's behavior.

**Secure Fix:**
- Validate and sanitize all user-controlled input before LLM prompts
- Use system prompts to constrain LLM behavior
- Implement input/output guardrails (e.g., AWS Bedrock Guardrails)
- Never pass raw user input directly into prompt templates
"""

    def _generate_mlops_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**Direct MLOps Platform Access:**
Accessing MLflow, W&B, or other ML platforms directly from playbooks
bypasses pipeline governance controls.

**Secure Fix:**
- Use CI/CD-triggered ML pipelines for model training and deployment
- Store MLflow/W&B credentials in Vault, not playbooks
- Implement model approval gates before production deployment
"""

    def _generate_generic_ai_fix(self, code_snippet: str) -> str:
        return f"""
**Vulnerable Code:**
```yaml
{code_snippet}
```

**AI/ML Security Issue:**
- Store all AI API keys in secrets management (Vault, AWS Secrets Manager)
- Pin and verify checksums for all model downloads
- Use safetensors format instead of pickle-based formats
- Provision AI infrastructure through reviewed IaC pipelines
- Set cost controls and budget alerts on all AI services
"""
