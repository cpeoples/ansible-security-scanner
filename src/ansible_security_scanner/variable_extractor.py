#!/usr/bin/env python3
"""
Variable extraction utilities for Ansible Security Scanner
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Patterns that, walking upwards from a `password: "literal"` line, can
# describe the credential the literal belongs to. Compiled once at import
# time because ``extract_variable_name_from_context`` retries them per
# line for up to a 10-line scan window per finding.
_NAME_RE = re.compile(r'^name:\s*["\']([^"\']+)["\']')
_USERNAME_RE = re.compile(r'^username:\s*["\']([^"\']+)["\']')
_USER_RE = re.compile(r'^user:\s*["\']([^"\']+)["\']')
_TASK_NAME_RE = re.compile(r'^\s*-\s*name:\s*["\']([^"\']+)["\']')
_NON_IDENT_RE = re.compile(r"[^a-zA-Z0-9_]")
_CREDENTIAL_KEYWORDS = ("password", "secret", "key", "token", "credential", "auth")


class VariableExtractor:
    """Handles extraction of variables and context from Ansible code"""

    def extract_variables_from_code(self, code_snippet: str) -> list[str]:
        """Extract all Jinja2 variables from the code snippet"""
        # Matches {{ var }}, {{ var.key }}, {{ var | filter }}, {{ var.key | filter }}.
        # Returns the base name (pre-dot, pre-pipe) as well as the full expression.
        pattern = r"\{\{\s*([^}|]+)(?:\s*\|[^}]*)?\s*\}\}"
        matches = re.findall(pattern, code_snippet)

        variables = []
        for match in matches:
            if not match:
                continue
            var = match.strip().strip("\"'")
            if not var:
                continue
            base_var = var.split(".")[0].split()[0]
            if base_var and base_var not in variables:
                variables.append(base_var)

        full_vars = []
        for match in matches:
            if not match:
                continue
            var = match.strip().strip("\"'")
            if var and var not in full_vars:
                full_vars.append(var)

        all_vars = [v for v in variables + full_vars if v and v.strip()]
        return list(dict.fromkeys(all_vars))

    def extract_variable_name(self, code_snippet: str, rule_id: str) -> str:
        """Extract the actual variable name from the vulnerable code snippet"""
        if rule_id == "hardcoded_credentials":
            # Pattern order matters: URL-encoded form data is checked before the
            # generic YAML `key: "value"` pattern because a form-encoded body can
            # otherwise be mis-parsed as a YAML mapping.

            form_password_match = re.search(r"[&?]password=([^&]+)", code_snippet)
            if form_password_match:
                form_password_match.group(1)
                username_match = re.search(r"[&?](?:name|username|user)=([^&]+)", code_snippet)
                if username_match:
                    username = username_match.group(1)
                    return f"{username}_password"
                return "soar_admin_password"

            match = re.search(r'^\s*([^:]+):\s*["\']', code_snippet.strip())
            if match:
                var_name = match.group(1).strip()
                return self._clean_variable_name(var_name)

            if "mysql" in code_snippet.lower() and "-p" in code_snippet:
                return "mysql_password"
            if "psql" in code_snippet.lower() or "postgresql" in code_snippet.lower():
                return "postgres_password"
            if "docker login" in code_snippet.lower():
                return "docker_registry_password"
            if "lftp" in code_snippet.lower() and "-u" in code_snippet:
                match = re.search(r"-u\s+([^,\s]+),", code_snippet)
                if match:
                    username = match.group(1).strip("\"'")
                    return f"{username}_ftp_password"
                return "ftp_password"
            if "sshpass" in code_snippet.lower() and "-p" in code_snippet:
                return "ssh_password"
            if "expect" in code_snippet.lower() and "sftp" in code_snippet.lower():
                return "sftp_password"
            if "rsync" in code_snippet.lower() and "password-file" in code_snippet:
                return "backup_password"
            if "ssh" in code_snippet.lower() and (
                "pass" in code_snippet.lower() or "-p" in code_snippet
            ):
                return "ssh_password"
            if "-p" in code_snippet:
                return "admin_password"

            match = re.search(r"([A-Z_]+)=", code_snippet)
            if match:
                env_var = match.group(1).lower()
                return env_var

            if any(
                db_indicator in code_snippet.lower()
                for db_indicator in ["mysql", "postgres", "mongodb", "redis"]
            ):
                if "mysql" in code_snippet.lower():
                    return "mysql_password"
                if "postgres" in code_snippet.lower():
                    return "postgres_password"
                if "mongodb" in code_snippet.lower():
                    return "mongodb_password"
                if "redis" in code_snippet.lower():
                    return "redis_password"

        return "variable_name"

    def _clean_variable_name(self, var_name: str) -> str:
        """Clean and normalize variable names"""
        var_name = var_name.strip().strip("\"'")
        var_name = var_name.lower().replace("-", "_")
        var_name = re.sub(r"[^a-zA-Z0-9_]", "_", var_name)
        var_name = re.sub(r"_+", "_", var_name).strip("_")

        return var_name if var_name else "variable_name"

    def extract_variable_name_from_context(
        self, file_path: str, line_number: int, rule_id: str
    ) -> str:
        """Extract the actual variable name from the broader context around the vulnerable line"""
        if rule_id != "hardcoded_credentials":
            return self.extract_variable_name("", rule_id)

        try:
            with open(file_path, encoding="utf-8") as f:
                lines = f.readlines()

            current_line = lines[line_number - 1].strip()

            extracted_name = self.extract_variable_name(current_line, rule_id)
            if extracted_name != "variable_name":
                return extracted_name

            if var_match := re.match(r"^\s*([^:]+):\s*", current_line):
                return self._clean_variable_name(var_match.group(1).strip())

            # Walk up to 10 lines backwards to find a task-level `name:`, `username:`,
            # or `user:` field that describes what this credential is for.
            start_line = max(0, line_number - 10)

            for i in range(line_number - 1, start_line - 1, -1):
                line = lines[i].strip()

                # Only adopt a `name:` value as the credential identifier if it
                # *looks* like a credential (password/secret/token/...); otherwise
                # we'd alias unrelated config params like "soar_config_id".
                if m := _NAME_RE.match(line):
                    var_name = m.group(1).strip()
                    if any(k in var_name.lower() for k in _CREDENTIAL_KEYWORDS):
                        return var_name
                    continue

                if m := _USERNAME_RE.match(line):
                    username = m.group(1).strip()
                    if username:
                        if username.startswith("vault_"):
                            return f"{username}_password"
                        return f"vault_{username}_password"
                    continue

                if m := _USER_RE.match(line):
                    user_name = m.group(1).strip()
                    if user_name:
                        return f"{user_name}_password"
                    continue

                if m := _TASK_NAME_RE.match(line):
                    safe_name = _NON_IDENT_RE.sub("_", m.group(1).strip().lower())
                    return f"{safe_name}_password"

                # A bare `- ` at this indent marks the start of the *previous*
                # task - stop walking upwards so we don't pull a name from a
                # sibling task's block.
                if line.startswith("- ") and not line.startswith("- name:"):
                    break

            return self.extract_variable_name("", rule_id)

        except Exception as e:
            logger.debug("variable extraction from context failed: %s", e)
            return self.extract_variable_name("", rule_id)

    def extract_env_var_name(
        self, code_snippet: str, rule_id: str, file_path: str = "", line_number: int = 0
    ) -> str:
        """Extract the environment variable name from the vulnerable code snippet"""
        if rule_id == "hardcoded_credentials":
            var_name = self.extract_variable_name(code_snippet, rule_id)

            env_var = var_name.upper().replace("-", "_")

            # Only append `_PASSWORD` when the base variable actually reads as
            # a password; otherwise we'd turn e.g. `api_key` into `API_KEY_PASSWORD`.
            if "password" in var_name.lower() and "PASSWORD" not in env_var.upper():
                env_var = f"{env_var}_PASSWORD" if not env_var.endswith("_PASSWORD") else env_var

            return env_var

        return "VARIABLE_NAME"

    def extract_env_var_name_from_context(
        self, file_path: str, line_number: int, rule_id: str
    ) -> str:
        """Extract the environment variable name from the broader context around the vulnerable line"""
        if rule_id != "hardcoded_credentials":
            return self.extract_env_var_name("", rule_id)

        var_name = self.extract_variable_name_from_context(file_path, line_number, rule_id)

        env_var = var_name.upper().replace("-", "_")

        if "password" in var_name.lower() and "PASSWORD" not in env_var.upper():
            env_var = f"{env_var}_PASSWORD" if not env_var.endswith("_PASSWORD") else env_var

        return env_var

    def extract_shell_command_parts(self, code_snippet: str) -> dict[str, Any]:
        """Extract and analyze parts of shell/command/raw tasks"""
        parts = {
            "full_command": code_snippet.strip(),
            "base_command": "",
            "variables": [],
            "unsafe_patterns": [],
            "hardcoded_credentials": [],
            "command_type": "",
            "has_curl": False,
            "has_unquoted_vars": False,
        }

        command_match = re.search(r"^(shell|command|raw):\s*(.*)$", code_snippet.strip())
        if command_match:
            parts["command_type"] = command_match.group(1)
            parts["full_command"] = command_match.group(2).strip()

        parts["variables"] = self.extract_variables_from_code(parts["full_command"])

        if "curl" in parts["full_command"].lower():
            parts["has_curl"] = True
            parts["base_command"] = "curl"

        cred_patterns = [
            r'-u\s+["\']([^"\']*:[^"\']*)["\']',
            r'-u\s+([^"\s]+:[^"\s]+)',
            r'--user\s+["\']([^"\']*:[^"\']*)["\']',
        ]

        for pattern in cred_patterns:
            matches = re.findall(pattern, parts["full_command"])
            parts["hardcoded_credentials"].extend(matches)

        # Any `{{ var }}` not piped through the `quote` filter is a potential
        # shell-injection sink when interpolated into shell/command/raw.
        unquoted_var_pattern = r"\{\{[^}]*\}\}(?!\s*\|[^}]*quote)"
        if re.search(unquoted_var_pattern, parts["full_command"]):
            parts["has_unquoted_vars"] = True

        if "|" in parts["full_command"] and any(
            shell in parts["full_command"] for shell in ["sh", "bash", "zsh"]
        ):
            parts["unsafe_patterns"].append("pipe_to_shell")
        if any(pattern in parts["full_command"] for pattern in ["`", "$("]):
            parts["unsafe_patterns"].append("command_substitution")
        if any(pattern in parts["full_command"] for pattern in [";", "&&", "||"]):
            parts["unsafe_patterns"].append("command_chaining")
        if parts["hardcoded_credentials"]:
            parts["unsafe_patterns"].append("hardcoded_credentials")
        if "http://" in parts["full_command"].lower():
            parts["unsafe_patterns"].append("insecure_http")

        return parts

    def extract_task_context(self, lines: list[str], line_num: int) -> str:
        """Extract the full task context around a specific line for better remediation"""

        task_start = line_num - 1
        current_indent = len(lines[task_start]) - len(lines[task_start].lstrip())

        # Walk backwards: a line at ≤ our indent that carries `name:` is the
        # task header. A line at significantly *less* indent means we've
        # escaped the task entirely and should stop.
        for i in range(task_start - 1, -1, -1):
            line = lines[i].rstrip()
            if not line or line.strip().startswith("#"):
                continue

            line_indent = len(line) - len(line.lstrip())

            if line_indent <= current_indent and ("name:" in line or "- name:" in line):
                task_start = i
                break
            if line_indent < current_indent - 2:
                break

        task_end = line_num
        base_indent = len(lines[task_start]) - len(lines[task_start].lstrip())

        for i in range(line_num, len(lines)):
            line = lines[i].rstrip()
            if not line or line.strip().startswith("#"):
                continue

            line_indent = len(line) - len(line.lstrip())

            if (
                line_indent <= base_indent
                and i > task_start
                and ("name:" in line or "- name:" in line)
            ):
                task_end = i - 1
                break

            task_end = i

        task_lines = [lines[i].rstrip() for i in range(task_start, min(task_end + 1, len(lines)))]

        return "\n".join(task_lines)
