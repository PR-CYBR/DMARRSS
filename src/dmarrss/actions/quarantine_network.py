"""
Network Quarantine Action - Network Isolation

NIST CSF 2.0 Mapping: RS.MI (Mitigation)
"""

import logging
import platform
import subprocess

from ..actions.base import BaseAction
from ..schemas import ActionResult, Decision

logger = logging.getLogger(__name__)


class QuarantineNetworkAction(BaseAction):
    """
    Quarantine host by disabling network connectivity.

    Platform-specific implementation for network isolation.
    """

    def __init__(self):
        super().__init__("quarantine_network")

    def _execute_impl(self, decision: Decision) -> ActionResult:
        """Execute network quarantine"""
        system = platform.system()

        try:
            if system == "Linux":
                success = self._quarantine_linux()
            elif system == "Windows":
                success = self._quarantine_windows()
            elif system == "Darwin":
                success = self._quarantine_macos()
            else:
                return self._create_result(
                    decision=decision,
                    success=False,
                    dry_run=False,
                    executed=False,
                    message=f"Network quarantine not implemented for {system}",
                    error=f"Unsupported platform: {system}",
                )

            if success:
                message = f"Network quarantined on {system}"
                logger.warning(message)
                return self._create_result(
                    decision=decision,
                    success=True,
                    dry_run=False,
                    executed=True,
                    message=message,
                    details={
                        "platform": system,
                        "csf_function": "RESPOND",
                        "csf_category": "RS.MI - Mitigation",
                    },
                )
            else:
                return self._create_result(
                    decision=decision,
                    success=False,
                    dry_run=False,
                    executed=False,
                    message=f"Failed to quarantine network on {system}",
                    error="Command execution failed",
                )

        except Exception as e:
            logger.error(f"Error quarantining network: {e}")
            return self._create_result(
                decision=decision,
                success=False,
                dry_run=False,
                executed=False,
                message=f"Network quarantine failed: {e}",
                error=str(e),
            )

    def _quarantine_linux(self) -> bool:
        """Quarantine network on Linux using iptables"""
        try:
            # Drop all outbound traffic
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-j", "DROP"],
                capture_output=True,
                timeout=10,
                check=True,
            )
            logger.info("Linux network quarantined via iptables")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to quarantine Linux network: {e}")
            return False

    def _quarantine_windows(self) -> bool:
        """Quarantine network on Windows"""
        try:
            # First, try to get all network interfaces
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                logger.error("Failed to enumerate network interfaces")
                return False

            # Disable all active interfaces
            success_count = 0
            for line in result.stdout.split("\n"):
                # Look for lines with "Connected" status
                if "Connected" in line and "Enabled" in line:
                    # Extract interface name (typically after multiple spaces)
                    parts = line.split()
                    if len(parts) >= 4:
                        # Interface name is typically the last part
                        interface_name = " ".join(parts[3:])
                        disable_result = subprocess.run(
                            [
                                "netsh",
                                "interface",
                                "set",
                                "interface",
                                interface_name,
                                "admin=DISABLE",
                            ],
                            capture_output=True,
                            timeout=10,
                        )
                        if disable_result.returncode == 0:
                            success_count += 1
                            logger.info(f"Disabled interface: {interface_name}")

            if success_count > 0:
                logger.info(f"Windows network quarantined ({success_count} interfaces disabled)")
                return True
            else:
                logger.warning("No active interfaces found to disable")
                return False

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to quarantine Windows network: {e}")
            return False

    def _quarantine_macos(self) -> bool:
        """Quarantine network on macOS"""
        try:
            # Disable network interface
            subprocess.run(
                ["networksetup", "-setairportpower", "en0", "off"],
                capture_output=True,
                timeout=10,
                check=True,
            )
            logger.info("macOS network quarantined")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to quarantine macOS network: {e}")
            return False

    def _dry_run_impl(self, decision: Decision) -> ActionResult:
        """Dry-run: Log what would be done"""
        system = platform.system()
        message = f"[DRY-RUN] Would quarantine network on {system}"
        logger.info(message)

        return self._create_result(
            decision=decision,
            success=True,
            dry_run=True,
            executed=False,
            message=message,
            details={
                "platform": system,
                "csf_function": "RESPOND",
                "csf_category": "RS.MI - Mitigation",
            },
        )
