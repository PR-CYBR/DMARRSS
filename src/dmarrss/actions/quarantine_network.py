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
            # Disable all network adapters
            result = subprocess.run(
                ["netsh", "interface", "set", "interface", "name=\"Ethernet\"", "admin=DISABLE"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info("Windows network quarantined")
                return True
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
