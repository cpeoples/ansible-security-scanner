#!/usr/bin/env python3
"""Remediations for callback/plugin/strategy risks."""

from .base import BaseRemediationGenerator


class CallbackPluginRiskRemediationGenerator(BaseRemediationGenerator):
    _FIX_MAP = {
        "action_plugin_shadow_core": "_fix_action_plugin",
        "callback_plugins_path_untrusted": "_fix_callback_path",
        "callback_whitelist_arbitrary": "_fix_callback_whitelist",
        "filter_plugins_path_untrusted": "_fix_filter_path",
        "strategy_plugin_custom": "_fix_strategy",
    }

    def generate_callback_plugin_risk_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._fix_generic)

    def _fix_callback_whitelist(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```ini
{snip}
```

**🚨 Arbitrary callback plugin enabled:**
Callback plugins run as Python code in the Ansible controller on every event (task_start, runner_on_ok, playbook_on_end). A malicious or vulnerable callback is effectively controller RCE.

**✅ Secure Fix - Enable only vetted callbacks:**
```ini
[defaults]
callbacks_enabled = ansible.posix.profile_tasks, ansible.posix.timer
stdout_callback = default
```

**🔐 Hardening:**
- Audit every enabled callback - review source, pin the collection version.
- Prefer `stdout_callback = default` or `yaml` in CI.
"""

    def _fix_callback_path(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```ini
{snip}
```

**🚨 callback_plugins path in writable location:**
Any Python file dropped into `/tmp`, `$HOME`, or a shared mount is loaded on the next play - classic local privilege escalation if another user can write there.

**✅ Secure Fix:**
```ini
[defaults]
callback_plugins = ./plugins/callback     # under the project, version-controlled
```

**🔐 Hardening:**
- Make the plugin directory root-owned and world-readable but not writable.
- CI grep: `rg -n 'callback_plugins\\s*=' ansible.cfg | rg '/tmp|~|\\$HOME'`
"""

    def _fix_strategy(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{snip}
```

**🚨 Custom strategy plugin:**
Strategy plugins control task dispatching - they run Python in the controller process and see every task and its vars. Third-party strategies should be reviewed as code.

**✅ Secure Fix - Use a core strategy:**
```yaml
- hosts: all
  strategy: linear      # default; also: free, host_pinned, debug
  tasks: []
```

**🔐 Hardening:**
- Reserve custom strategies for well-reviewed use cases (e.g. `mitogen`).
- Pin the collection version and review every update.
"""

    def _fix_filter_path(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```ini
{snip}
```

**🚨 filter/lookup/action plugin path untrusted:**
Same risk as callback_plugins: any Python file in a writable dir becomes controller code.

**✅ Secure Fix:**
```ini
[defaults]
filter_plugins   = ./plugins/filter
lookup_plugins   = ./plugins/lookup
action_plugins   = ./plugins/action
vars_plugins     = ./plugins/vars
```

**🔐 Hardening:**
- All plugin dirs must be under the project and read-only on the controller.
- Pre-commit hook rejects writable-location plugin paths.
"""

    def _fix_action_plugin(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```ini
{snip}
```

**🚨 action_plugins/ may shadow core modules:**
A file named `command.py`, `shell.py`, `copy.py`, etc. under your action_plugins path intercepts every task that uses that module. Attackers use this for quiet persistence - task syntax stays identical but arguments are logged, altered, or proxied.

**✅ Secure Fix - Audit the directory, prefix custom action names:**
```bash
ls -l ./plugins/action/            # review every file
mv ./plugins/action/shell.py ./plugins/action/acme_shell.py
```

**🔐 Hardening:**
- Namespace custom action plugins (`acme_*.py`) so shadowing is impossible.
- CI check: list files in action_plugins and reject any matching a core module name.
"""

    def _fix_generic(self, snip: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```
{snip}
```

**🚨 Callback/plugin/strategy risk detected.**

**✅ Secure Defaults:**
- Enable only vetted callbacks from trusted collections.
- All *_plugins paths must be project-local, read-only, root-owned.
- Use core strategies unless a custom one is documented and pinned.

**🔐 Hardening:**
- Treat every plugin path as a code-loading point that needs the same scrutiny as `pip install`.
"""
