#!/usr/bin/env python3
"""Tunneling / network-exposure remediation generator.

Two honest shapes:

* Pentest / C2 tunneling tools (chisel, ligolo, frp, revsocks, iodine,
  dnscat2, icmptunnel, rathole, bore) have no safe configuration. The fix
  removes the tool by its real name and routes any genuine need through an
  approved, reviewed connectivity path.
* Dual-use exposure tools (ngrok, cloudflared, localtunnel, serveo,
  tailscale, VPN, ssh forwards, socat) are legitimate only when approved.
  The fix replaces the ad-hoc tunnel with the sanctioned access method.

Both weave the detected tool/host/port from the finding into the output.
"""

from __future__ import annotations

from .base import BaseRemediationGenerator, _first, _render_from_metadata

# rule_id -> (binary/package name to remove, human label)
_TOOL_RULES: dict[str, tuple[str, str]] = {
    "chisel_tunnel": ("chisel", "Chisel"),
    "ligolo_tunnel": ("ligolo-ng", "Ligolo"),
    "frp_tunnel": ("frpc", "FRP"),
    "revsocks_tunnel": ("revsocks", "the reverse SOCKS proxy"),
    "iodine_dns_tunnel": ("iodine", "Iodine"),
    "dnscat2_tunnel": ("dnscat2", "dnscat2"),
    "icmptunnel_tunnel": ("icmptunnel", "icmptunnel"),
    "rathole_tunnel": ("rathole", "Rathole"),
    "bore_tunnel": ("bore", "Bore"),
}

# rule_id -> (human label, the approved alternative sentence)
_EXPOSURE_RULES: dict[str, tuple[str, str]] = {
    "ssh_socks_proxy": ("the SSH SOCKS proxy", "an approved corporate VPN or bastion host"),
    "ssh_remote_forward": (
        "the SSH remote port forward",
        "an approved reverse proxy with authentication",
    ),
    "ngrok_exposure": (
        "ngrok",
        "an approved ingress (load balancer + WAF) for any service that must be reachable",
    ),
    "cloudflared_tunnel": (
        "the Cloudflare Tunnel",
        "an approved Cloudflare Tunnel managed by the platform team with access policies",
    ),
    "vpn_setup_unauthorized": ("the VPN", "the corporate VPN approved by network security"),
    "localtunnel_exposure": (
        "LocalTunnel",
        "an approved ingress for any service that must be reachable",
    ),
    "serveo_tunnel": ("the Serveo tunnel", "an approved reverse proxy with authentication"),
    "socat_port_forward": (
        "the socat relay",
        "an explicit, reviewed firewall rule for the specific flow",
    ),
    "tailscale_unauthorized": (
        "Tailscale",
        "Tailscale enrolled through the sanctioned tailnet with ACLs, approved by network security",
    ),
}


class TunnelingRemediationGenerator(BaseRemediationGenerator):
    """Render dynamic fixes for tunnels, proxies and network exposure."""

    def generate_tunneling_fix(self, rule_id: str, code_snippet: str) -> str:
        if rule_id in _TOOL_RULES:
            return self._fix_tool(rule_id, code_snippet)
        if rule_id in _EXPOSURE_RULES:
            return self._fix_exposure(rule_id, code_snippet)
        return _render_from_metadata(rule_id, code_snippet)

    @staticmethod
    def _frame(rule_id: str, heading: str, code_snippet: str, why: str, secure_fix: str) -> str:
        return (
            f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
            f"\n**\U0001f50d {heading} ({rule_id}):**\n{why}\n"
            f"\n**\u2705 Secure Fix Example:**\n```yaml\n{secure_fix}\n```\n"
        )

    def _meta_heading(self, rule_id: str) -> tuple[str, str]:
        from . import _pattern_index

        meta = _pattern_index.get(rule_id)
        return meta.get("title") or rule_id, meta.get("recommendation") or ""

    def _fix_tool(self, rule_id: str, code_snippet: str) -> str:
        binary, label = _TOOL_RULES[rule_id]
        title, recommendation = self._meta_heading(rule_id)
        secure_fix = (
            f"# {label} is a tunneling tool with no safe production configuration.\n"
            f"# Remove the binary and its unit, then route any genuine remote-access\n"
            f"# need through an approved, reviewed path (corporate VPN or bastion).\n"
            f"- name: Ensure {binary} is stopped and removed\n"
            f"  block:\n"
            f"    - name: Stop and disable any {binary} service\n"
            f"      ansible.builtin.systemd:\n"
            f"        name: {binary}\n"
            f"        state: stopped\n"
            f"        enabled: false\n"
            f"      failed_when: false\n"
            f"\n"
            f"    - name: Remove the {binary} binary\n"
            f"      ansible.builtin.file:\n"
            f'        path: "/usr/local/bin/{binary}"\n'
            f"        state: absent\n"
            f"\n"
            f"- name: Provide sanctioned connectivity instead\n"
            f"  ansible.builtin.debug:\n"
            f"    msg: >-\n"
            f"      Use the approved corporate VPN or bastion host for remote access;\n"
            f"      {label} must not run on managed hosts."
        )
        return self._frame(
            rule_id,
            title,
            code_snippet,
            f"This task runs {label}. {recommendation}",
            secure_fix,
        )

    def _fix_exposure(self, rule_id: str, code_snippet: str) -> str:
        label, alternative = _EXPOSURE_RULES[rule_id]
        title, recommendation = self._meta_heading(rule_id)
        port = _first(
            code_snippet,
            r"-[DRL]\s+(?:0\.0\.0\.0:)?(\d+)",
            r"--port\s+(\d+)",
            r"TCP-LISTEN:(\d+)",
            r"\b(?:http|tcp|local|server)\s+(\d{2,5})\b",
        )
        port_note = f"\n# Detected exposed port: {port}" if port else ""
        secure_fix = (
            f"# {label} bypasses network controls and exposes internal services.{port_note}\n"
            f"# Do not open an ad-hoc tunnel; reach the service through the\n"
            f"# sanctioned path so access stays authenticated and auditable.\n"
            f"- name: Route access through the approved mechanism\n"
            f"  ansible.builtin.debug:\n"
            f"    msg: >-\n"
            f"      Reach this service via {alternative}.\n"
            f"      Any internet-facing exposure must be approved by network security\n"
            f"      and fronted by authentication and logging.\n"
            f"\n"
            f"- name: Confirm no ad-hoc tunnel remains enabled\n"
            f"  ansible.builtin.systemd:\n"
            f'    name: "{{{{ tunnel_service_name }}}}"\n'
            f"    state: stopped\n"
            f"    enabled: false\n"
            f"  failed_when: false\n"
            f"  when: tunnel_service_name is defined"
        )
        return self._frame(
            rule_id,
            title,
            code_snippet,
            f"This task uses {label} to expose internal services. {recommendation}",
            secure_fix,
        )
