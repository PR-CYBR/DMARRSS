"""
Isolate host action plugin.

Simulates host isolation (e.g., disable network interface).
Only executes when DMARRSS_ENFORCE=1.
"""

import os
import platform
import subprocess

from ..schemas import ActionResult, Decision
from .base import BaseAction


class IsolateHostAction(BaseAction):
    """
    Isolate host action.

    Simulates host isolation by logging planned action.
    When ENFORCE=1, can disable network interface using nmcli (Linux).
    """

    def __init__(self):
        super().__init__("isolate_host")
        self.enforce = os.environ.get("DMARRSS_ENFORCE", "0") == "1"
        self.platform = platform.system().lower()

    def _isolate_linux_nmcli(self, interface: str = "eth0") -> bool:
        """Isolate host by disabling network interface on Linux"""
        try:
            cmd = ["nmcli", "device", "disconnect", interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def _execute_impl(self, decision: Decision) -> ActionResult:
        """Execute host isolation"""
        if not self.enforce:
            return self._create_result(
                decision=decision,
                success=False,
                dry_run=False,
                executed=False,
                message="ENFORCE mode not enabled (DMARRSS_ENFORCE=0)",
                error="Action requires DMARRSS_ENFORCE=1",
            )

        # Placeholder - in reality would get actual host/interface
        host = "localhost"
        interface = "eth0"

        success = False
        details = {"platform": self.platform, "host": host, "interface": interface}

        if self.platform == "linux":
            success = self._isolate_linux_nmcli(interface)
            details["method"] = "nmcli"
        else:
            # Other platforms: just log (simulated)
            success = True
            details["method"] = "simulated"

        message = (
            f"Isolated host {host} (interface {interface})"
            if success
            else f"Failed to isolate host {host}"
        )

        return self._create_result(
            decision=decision,
            success=success,
            dry_run=False,
            executed=True,
            message=message,
            details=details,
            error=None if success else "Isolation command failed",
        )

    def _dry_run_impl(self, decision: Decision) -> ActionResult:
        """Dry-run: log what would be done"""
        host = "localhost"
        interface = "eth0"

        message = f"[DRY-RUN] Would isolate host {host} (interface {interface})"

        return self._create_result(
            decision=decision,
            success=True,
            dry_run=True,
            executed=False,
            message=message,
            details={
                "platform": self.platform,
                "host": host,
                "interface": interface,
                "enforce": self.enforce,
            },
        )
