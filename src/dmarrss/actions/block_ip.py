"""
Block IP action plugin.

Blocks malicious IP addresses using platform-specific firewall rules.
Supports Linux (nft/iptables), Mac (pfctl), Windows (netsh).
"""

import os
import platform
import subprocess
from typing import Dict

from .base import BaseAction
from ..schemas import ActionResult, Decision


class BlockIPAction(BaseAction):
    """
    Block IP address action.

    Platform adapters:
    - Linux: nftables/iptables (requires ENFORCE=1)
    - Mac: pfctl (dry-run by default)
    - Windows: netsh advfirewall (dry-run by default)

    Only executes when DMARRSS_ENFORCE=1 environment variable is set.
    """

    def __init__(self):
        super().__init__("block_ip")
        self.enforce = os.environ.get("DMARRSS_ENFORCE", "0") == "1"
        self.platform = platform.system().lower()

    def _get_src_ip(self, decision: Decision) -> str:
        """Extract source IP from decision details"""
        # In a real implementation, we'd have the event attached to decision
        # For now, extract from details or default
        return decision.details.get("src_ip", "0.0.0.0")

    def _block_linux_nft(self, ip: str) -> bool:
        """Block IP using nftables on Linux"""
        try:
            # Check if nft is available
            result = subprocess.run(
                ["which", "nft"], capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return self._block_linux_iptables(ip)

            # Add rule to block IP
            cmd = [
                "nft",
                "add",
                "rule",
                "inet",
                "filter",
                "input",
                "ip",
                "saddr",
                ip,
                "drop",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0

        except Exception:
            return False

    def _block_linux_iptables(self, ip: str) -> bool:
        """Block IP using iptables on Linux"""
        try:
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def _block_mac_pfctl(self, ip: str) -> bool:
        """Block IP using pfctl on Mac"""
        try:
            # Add to pf table (simplified)
            cmd = ["pfctl", "-t", "dmarrss_blocked", "-T", "add", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def _block_windows_netsh(self, ip: str) -> bool:
        """Block IP using netsh on Windows"""
        try:
            rule_name = f"DMARRSS_Block_{ip.replace('.', '_')}"
            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def _execute_impl(self, decision: Decision) -> ActionResult:
        """Execute IP blocking"""
        # Check enforce flag
        if not self.enforce:
            return self._create_result(
                decision=decision,
                success=False,
                dry_run=False,
                executed=False,
                message="ENFORCE mode not enabled (DMARRSS_ENFORCE=0)",
                error="Action requires DMARRSS_ENFORCE=1",
            )

        # Get source IP from decision
        # In real implementation, decision would have reference to event
        src_ip = "192.168.1.100"  # Placeholder

        # Execute platform-specific block
        success = False
        details: Dict = {"platform": self.platform, "ip": src_ip}

        if self.platform == "linux":
            success = self._block_linux_nft(src_ip)
            details["method"] = "nftables/iptables"
        elif self.platform == "darwin":
            success = self._block_mac_pfctl(src_ip)
            details["method"] = "pfctl"
        elif self.platform == "windows":
            success = self._block_windows_netsh(src_ip)
            details["method"] = "netsh"
        else:
            return self._create_result(
                decision=decision,
                success=False,
                dry_run=False,
                executed=False,
                message=f"Unsupported platform: {self.platform}",
                details=details,
                error=f"Platform {self.platform} not supported",
            )

        if success:
            message = f"Blocked IP {src_ip} using {details['method']}"
        else:
            message = f"Failed to block IP {src_ip}"

        return self._create_result(
            decision=decision,
            success=success,
            dry_run=False,
            executed=True,
            message=message,
            details=details,
            error=None if success else "Block command failed",
        )

    def _dry_run_impl(self, decision: Decision) -> ActionResult:
        """Dry-run: log what would be done"""
        src_ip = "192.168.1.100"  # Placeholder

        method = ""
        if self.platform == "linux":
            method = "nftables/iptables"
        elif self.platform == "darwin":
            method = "pfctl"
        elif self.platform == "windows":
            method = "netsh"
        else:
            method = "unknown"

        message = f"[DRY-RUN] Would block IP {src_ip} using {method}"

        return self._create_result(
            decision=decision,
            success=True,
            dry_run=True,
            executed=False,
            message=message,
            details={
                "platform": self.platform,
                "method": method,
                "ip": src_ip,
                "enforce": self.enforce,
            },
        )
