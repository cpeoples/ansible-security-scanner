#!/usr/bin/env python3
"""
Remediation generator for AI/ML security issues.

Every procedural AI/ML rule has a concrete, copy-pasteable safe shape:
load weights as data (safetensors) instead of executing a pickle, pin and
checksum model/RAG sources, gate provider/GPU/Jupyter/MLflow provisioning
behind an approval var, and replace "LLM/agent output to a shell" with a
parsed, allow-listed, validated invocation. The credential-style AI rules
(API keys, unauthenticated Jupyter, world-readable vector DBs, ...) are
companion-backed and never reach this generator.
"""

import re

from .base import BaseRemediationGenerator


def _first(snippet: str, *patterns: str) -> str | None:
    for pat in patterns:
        m = re.search(pat, snippet, re.IGNORECASE)
        if m:
            return (m.group(1) if m.groups() else m.group(0)).strip().strip("'\"")
    return None


def _inner_expr(value: str) -> str:
    """Return the inner Jinja expression of a ``{{ ... }}`` token.

    A value extracted from a snippet is often already a full ``{{ var }}``
    expression. Embedding it inside another ``{{ ... }}`` would produce
    invalid nested Jinja, so strip the wrapping braces and hand back the
    bare expression for safe re-use inside an outer expression.
    """
    m = re.fullmatch(r"\{\{\s*(.+?)\s*\}\}", value.strip())
    return m.group(1) if m else value


class AiMlSecurityRemediationGenerator(BaseRemediationGenerator):
    """Generates remediation examples for AI/ML security issues"""

    _FIX_MAP = {
        "pickle_remote_load": "_fix_pickle",
        "pickle_load_as_root": "_fix_pickle",
        "model_from_url": "_fix_model_download",
        "aws_sagemaker_access": "_fix_service",
        "aws_bedrock_access": "_fix_service",
        "gcp_vertex_ai_access": "_fix_service",
        "azure_ml_access": "_fix_service",
        "mlflow_direct_access": "_fix_service",
        "gpu_instance_launch": "_fix_gpu",
        "jupyter_server_start": "_fix_jupyter",
        "template_in_llm_prompt": "_fix_prompt_template",
        "prompt_injection_untrusted_to_shell_sink": "_fix_llm_to_shell",
        "langchain_shell_tool_unconstrained": "_fix_agent_shell_tool",
        "mcp_tool_definition_exposes_arbitrary_shell_execution": "_fix_mcp_shell_tool",
        "rag_pipeline_ingests_untrusted_external_urls_without_sanitisation": "_fix_rag_ingest",
    }

    def generate_ai_ml_security_fix(self, rule_id: str, code_snippet: str) -> str:
        method = self._FIX_MAP.get(rule_id)
        if method is None:
            return self._fix_generic(code_snippet)
        return getattr(self, method)(rule_id, code_snippet)

    def _frame(self, rule_id: str, code_snippet: str, why: str, secure_fix: str) -> str:
        from . import _pattern_index

        meta = _pattern_index.get(rule_id)
        title = meta.get("title") or rule_id
        recommendation = meta.get("recommendation") or ""
        body = f"This task involves {title.lower()}."
        if why:
            body += f" {why}"
        if recommendation:
            body += f" {recommendation}"
        return (
            f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
            f"\n**\U0001f50d {title} ({rule_id}):**\n{body}\n"
            f"\n**\u2705 Secure Fix Example:**\n```yaml\n{secure_fix}\n```\n"
        )

    def _fix_pickle(self, rule_id: str, code_snippet: str) -> str:
        path = (
            _first(
                code_snippet,
                r"(?:pickle|torch|joblib|dill)\.loads?\(\s*open\(\s*['\"]([^'\"]+)",
                r"(?:pickle|torch|joblib|dill)\.loads?\([^)]*?([\w./{}-]+\.(?:pkl|pickle|pt|bin|pth|model))",
                r"([\w./{}-]+\.(?:pkl|pickle|pt|bin|pth|model))",
            )
            or "{{ model_path }}"
        )
        as_root = rule_id == "pickle_load_as_root"
        secure_fix = (
            "# pickle/torch/joblib.load executes arbitrary code while deserialising.\n"
            "# Load weights as pure data with safetensors instead, and verify the\n"
            "# artefact's checksum before reading it"
            + (".\n" if not as_root else " - never as root.\n")
            + f"- name: Verify the model artefact against a known-good checksum\n"
            f"  ansible.builtin.get_url:\n"
            f'    url: "{{{{ model_source_url }}}}"\n'
            f'    dest: "{path if not path.endswith((".pkl", ".pickle")) else "{{ model_path }}"}.safetensors"\n'
            f'    checksum: "sha256:{{{{ model_sha256 }}}}"\n'
            f"    mode: '0644'\n"
            + (
                ""
                if not as_root
                else "  become: false   # load/parse model data as an unprivileged user\n"
            )
            + "\n"
            "- name: Load the weights as data (no code execution)\n"
            "  ansible.builtin.command:\n"
            "    argv:\n"
            "      - python3\n"
            "      - -c\n"
            "      - \"from safetensors.torch import load_file; load_file('{{ model_path }}.safetensors')\"\n"
            + ("  become: false\n" if as_root else "")
        )
        why = (
            "Deserialising a pickle as root turns an untrusted file into root RCE."
            if as_root
            else "Pickle deserialisation runs arbitrary code from the file."
        )
        return self._frame(rule_id, code_snippet, why, secure_fix)

    def _fix_model_download(self, rule_id: str, code_snippet: str) -> str:
        url = _first(code_snippet, r"(https?://[^\s'\"]+)") or "{{ model_url }}"
        secure_fix = (
            f"# Pin the model to an immutable revision and verify its checksum so the\n"
            f"# bytes cannot change underneath you. Prefer safetensors over .pt/.bin.\n"
            f"- name: Download the model pinned to a revision and checksum\n"
            f"  ansible.builtin.get_url:\n"
            f'    url: "{url}"   # pin to a commit SHA / immutable revision, not a branch\n'
            f"    dest: /opt/models/model.safetensors\n"
            f'    checksum: "sha256:{{{{ model_sha256 }}}}"\n'
            f"    validate_certs: true\n"
            f"    mode: '0644'"
        )
        return self._frame(
            rule_id,
            code_snippet,
            "An unpinned, unverified model download is a supply-chain vector.",
            secure_fix,
        )

    def _fix_service(self, rule_id: str, code_snippet: str) -> str:
        secure_fix = (
            "# Provision/invoke managed AI services through a reviewed pipeline with\n"
            "# cost controls, not ad-hoc from a playbook. Gate any direct call behind\n"
            "# an explicit approval and a tagged, budgeted request.\n"
            "- name: Refuse direct provisioning unless explicitly approved\n"
            "  ansible.builtin.assert:\n"
            "    that:\n"
            "      - ml_provisioning_approved | default(false) | bool\n"
            "      - cost_center is defined\n"
            "    fail_msg: >-\n"
            "      AI/ML provisioning must run through the approved ML pipeline with a\n"
            "      cost center and budget guardrails, not directly from Ansible.\n"
            "\n"
            "- name: Trigger the reviewed ML pipeline instead of calling the API directly\n"
            "  ansible.builtin.uri:\n"
            '    url: "https://{{ ml_pipeline_endpoint }}/runs"\n'
            "    method: POST\n"
            "    headers:\n"
            '      Authorization: "Bearer {{ vault_ml_pipeline_token }}"\n'
            "    body_format: json\n"
            "    body:\n"
            '      cost_center: "{{ cost_center }}"\n'
            "  no_log: true"
        )
        return self._frame(
            rule_id,
            code_snippet,
            "Direct provisioning bypasses ML governance and cost controls.",
            secure_fix,
        )

    def _fix_gpu(self, rule_id: str, code_snippet: str) -> str:
        itype = (
            _first(
                code_snippet,
                r"\b((?:p[0-9]|g[0-9]|inf[0-9]|trn[0-9])[\w.]*x?large|a100|h100|v100)\b",
            )
            or "{{ gpu_instance_type }}"
        )
        secure_fix = (
            f"# GPU instances are expensive and a common cryptomining indicator. Require\n"
            f"# approval and tag the instance with an owner, cost center, and expiry.\n"
            f"- name: Refuse GPU launches without approval and cost tagging\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - gpu_launch_approved | default(false) | bool\n"
            f"      - cost_center is defined\n"
            f"      - auto_shutdown_at is defined\n"
            f"    fail_msg: >-\n"
            f"      GPU instance launches require approval and a cost-center / expiry tag.\n"
            f"\n"
            f"- name: Launch the approved, tagged GPU instance\n"
            f"  amazon.aws.ec2_instance:\n"
            f'    instance_type: "{itype}"\n'
            f"    tags:\n"
            f'      cost_center: "{{{{ cost_center }}}}"\n'
            f'      owner: "{{{{ requesting_user }}}}"\n'
            f'      auto_shutdown_at: "{{{{ auto_shutdown_at }}}}"'
        )
        return self._frame(
            rule_id,
            code_snippet,
            "Unapproved GPU launches risk runaway cost and cryptomining.",
            secure_fix,
        )

    def _fix_jupyter(self, rule_id: str, code_snippet: str) -> str:
        secure_fix = (
            "# A Jupyter server is an interactive RCE endpoint. Bind it to localhost\n"
            "# and require a token; never --ip=0.0.0.0 with auth disabled.\n"
            "- name: Start Jupyter bound to localhost with token auth\n"
            "  ansible.builtin.command:\n"
            "    argv:\n"
            "      - jupyter\n"
            "      - lab\n"
            "      - --ip=127.0.0.1\n"
            "      - --no-browser\n"
            "      - --ServerApp.token={{ vault_jupyter_token }}\n"
            "  no_log: true\n"
            "  # Front with an authenticating reverse proxy / JupyterHub for remote access."
        )
        return self._frame(
            rule_id,
            code_snippet,
            "An unauthenticated, broadly-bound Jupyter server is open RCE.",
            secure_fix,
        )

    def _fix_prompt_template(self, rule_id: str, code_snippet: str) -> str:
        var = _first(code_snippet, r"(\{\{\s*[\w.]+\s*\}\})") or "{{ user_input }}"
        expr = _inner_expr(var)
        secure_fix = (
            f"# Validate and constrain any variable before it reaches an LLM prompt so a\n"
            f"# crafted value cannot hijack the model's instructions.\n"
            f"- name: Validate the untrusted input before templating it into the prompt\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - \"{expr} is match('^[A-Za-z0-9 _.,:-]{{1,500}}$')\"\n"
            f'    fail_msg: "Prompt input failed the allow-list validation."\n'
            f"\n"
            f"- name: Build the prompt with the validated value and a fixed system prompt\n"
            f"  ansible.builtin.set_fact:\n"
            f'    llm_prompt: "{{{{ system_guardrail_prompt }}}}\\n\\nUser data: {var}"\n'
            f"  # Keep instructions in the system prompt; treat user data as data only."
        )
        return self._frame(
            rule_id,
            code_snippet,
            "Unvalidated variables in a prompt enable prompt injection.",
            secure_fix,
        )

    def _fix_llm_to_shell(self, rule_id: str, code_snippet: str) -> str:
        var = _first(code_snippet, r"(\{\{\s*[\w.]+\s*\}\})") or "{{ llm_response.stdout }}"
        expr = _inner_expr(var)
        secure_fix = (
            f"# Never pipe raw LLM output into a shell. Parse it as structured JSON,\n"
            f"# allow-list the action, and invoke a fixed command by name with validated\n"
            f"# arguments - no string interpolation into a shell.\n"
            f"- name: Parse the model output as a strict JSON action\n"
            f"  ansible.builtin.set_fact:\n"
            f'    llm_action: "{{{{ ({expr} | from_json) }}}}"\n'
            f"\n"
            f"- name: Refuse any action that is not on the allow-list\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - llm_action.command in allowed_llm_commands\n"
            f'    fail_msg: "LLM requested a command outside the allow-list."\n'
            f"\n"
            f"- name: Run the allow-listed command with validated args (argv, no shell)\n"
            f"  ansible.builtin.command:\n"
            f'    argv: "{{{{ [llm_action.command] + (llm_action.args | default([])) }}}}"'
        )
        return self._frame(
            rule_id,
            code_snippet,
            "Piping model output to a shell is direct prompt-injection-to-RCE.",
            secure_fix,
        )

    def _fix_agent_shell_tool(self, rule_id: str, code_snippet: str) -> str:
        secure_fix = (
            "# Do not bind an unconstrained ShellTool to an agent. Expose narrow,\n"
            "# parameterised tools that run a fixed command via argv with validation.\n"
            "- name: Render the agent tool config with no generic shell tool\n"
            "  ansible.builtin.copy:\n"
            "    dest: /opt/agent/tools.py\n"
            "    mode: '0644'\n"
            "    content: |\n"
            "      from langchain_core.tools import Tool\n"
            "      import subprocess\n"
            "      # One narrow tool per operation; arguments validated, argv (no shell=True).\n"
            "      def list_project(_):\n"
            "          return subprocess.run(\n"
            "              ['ls', PROJECT_DIR], check=True, capture_output=True, text=True\n"
            "          ).stdout\n"
            "      tools = [Tool(name='list_project', func=list_project, description='List project files')]\n"
            "  # Run the agent's tool process in a locked-down sandbox (no network, ro-fs)."
        )
        return self._frame(
            rule_id,
            code_snippet,
            "An unconstrained agent shell tool is arbitrary command execution.",
            secure_fix,
        )

    def _fix_mcp_shell_tool(self, rule_id: str, code_snippet: str) -> str:
        secure_fix = (
            "# Never expose a generic shell/exec tool over MCP. Define narrow, typed\n"
            "# tools per operation, each constrained to an allow-listed root.\n"
            "- name: Render an MCP server that exposes only narrow, typed tools\n"
            "  ansible.builtin.copy:\n"
            "    dest: /opt/mcp/server.py\n"
            "    mode: '0644'\n"
            "    content: |\n"
            "      from pathlib import Path\n"
            "      ALLOWED_ROOT = Path('/srv/app').resolve()\n"
            "      @server.tool()\n"
            "      def read_file(path: str) -> str:\n"
            "          target = (ALLOWED_ROOT / path).resolve()\n"
            "          if not target.is_relative_to(ALLOWED_ROOT):\n"
            "              raise ValueError('path escapes allowed root')\n"
            "          return target.read_text()\n"
            "      # No subprocess(shell=True); no generic exec tool is defined.\n"
            "  # Run the MCP server as an unprivileged user in a throwaway sandbox."
        )
        return self._frame(
            rule_id,
            code_snippet,
            "A generic shell tool over MCP hands the agent arbitrary execution.",
            secure_fix,
        )

    def _fix_rag_ingest(self, rule_id: str, code_snippet: str) -> str:
        url = _first(code_snippet, r"(https?://[^\s'\"]+|\{\{[^}]*\}\})") or "{{ ingest_url }}"
        expr = _inner_expr(url)
        secure_fix = (
            f"# Never ingest arbitrary URLs into a RAG index. Canonicalise the URL and\n"
            f"# reject anything whose host is not on a code-reviewed allow-list.\n"
            f"- name: Reject ingestion URLs outside the reviewed domain allow-list\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - \"({expr} | urlsplit('hostname')) in rag_allowed_domains\"\n"
            f"      - \"({expr} | urlsplit('scheme')) == 'https'\"\n"
            f"    fail_msg: >-\n"
            f"      RAG ingestion is restricted to the reviewed domain allow-list; {url}\n"
            f"      resolves outside it.\n"
            f"  # Re-check the final host after following redirects before indexing."
        )
        return self._frame(
            rule_id,
            code_snippet,
            "Ingesting arbitrary URLs lets attackers poison the RAG index.",
            secure_fix,
        )

    def _fix_generic(self, code_snippet: str) -> str:
        return (
            f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
            f"\n**\U0001f50d AI/ML Security Issue:**\n"
            "This task involves an AI/ML operation that needs hardening.\n"
            f"\n**\u2705 Secure Fix Example:**\n```yaml\n"
            "# Store AI API keys in a secret manager; pin and checksum model/RAG sources;\n"
            "# load weights as safetensors (never pickle); provision AI infra through a\n"
            "# reviewed pipeline with cost controls; allow-list any agent/LLM-driven action.\n"
            "- name: Gate the AI/ML operation behind explicit approval\n"
            "  ansible.builtin.assert:\n"
            "    that:\n"
            "      - ml_operation_approved | default(false) | bool\n"
            '    fail_msg: "This AI/ML operation requires explicit, reviewed approval."\n'
            "```\n"
        )
