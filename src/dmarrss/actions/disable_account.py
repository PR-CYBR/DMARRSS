"""
Account Disable Action - User Account Management

NIST CSF 2.0 Mapping: RS.MI (Mitigation)
"""

import logging
import platform
import subprocess

from ..actions.base import BaseAction
from ..schemas import ActionResult, Decision

logger = logging.getLogger(__name__)


class DisableAccountAction(BaseAction):
    """
    Disable a potentially compromised user account.
    
    Platform-specific implementation for account management.
    """

    def __init__(self):
        super().__init__("disable_account")

    def _execute_impl(self, decision: Decision) -> ActionResult:
        """Execute account disable"""
        # Extract account information from decision
        details = decision.score_components
        account_info = details.get("account_info", {})
        username = account_info.get("username", "")

        if not username:
            return self._create_result(
                decision=decision,
                success=False,
                dry_run=False,
                executed=False,
                message="No username specified",
                error="Missing username in decision",
            )

        system = platform.system()

        try:
            if system == "Linux":
                success = self._disable_linux_account(username)
            elif system == "Windows":
                success = self._disable_windows_account(username)
            elif system == "Darwin":
                success = self._disable_macos_account(username)
            else:
                return self._create_result(
                    decision=decision,
                    success=False,
                    dry_run=False,
                    executed=False,
                    message=f"Account disable not implemented for {system}",
                    error=f"Unsupported platform: {system}",
                )

            if success:
                message = f"Account {username} disabled on {system}"
                logger.warning(message)
                return self._create_result(
                    decision=decision,
                    success=True,
                    dry_run=False,
                    executed=True,
                    message=message,
                    details={
                        "username": username,
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
                    message=f"Failed to disable account {username}",
                    error="Command execution failed",
                )

        except Exception as e:
            logger.error(f"Error disabling account: {e}")
            return self._create_result(
                decision=decision,
                success=False,
                dry_run=False,
                executed=False,
                message=f"Account disable failed: {e}",
                error=str(e),
            )

    def _disable_linux_account(self, username: str) -> bool:
        """Disable account on Linux"""
        try:
            # Lock the account using passwd
            result = subprocess.run(
                ["passwd", "-l", username],
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info(f"Linux account {username} disabled")
                return True
            return False
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to disable Linux account: {e}")
            return False

    def _disable_windows_account(self, username: str) -> bool:
        """Disable account on Windows"""
        try:
            # Disable the user account
            result = subprocess.run(
                ["net", "user", username, "/active:no"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info(f"Windows account {username} disabled")
                return True
            return False
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to disable Windows account: {e}")
            return False

    def _disable_macos_account(self, username: str) -> bool:
        """Disable account on macOS"""
        try:
            # Disable the user account
            result = subprocess.run(
                ["dscl", ".", "-create", f"/Users/{username}", "AuthenticationAuthority", ";DisabledUser;"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info(f"macOS account {username} disabled")
                return True
            return False
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to disable macOS account: {e}")
            return False

    def _dry_run_impl(self, decision: Decision) -> ActionResult:
        """Dry-run: Log what would be done"""
        details = decision.score_components
        account_info = details.get("account_info", {})
        username = account_info.get("username", "UNKNOWN")
        system = platform.system()

        message = f"[DRY-RUN] Would disable account: {username} on {system}"
        logger.info(message)

        return self._create_result(
            decision=decision,
            success=True,
            dry_run=True,
            executed=False,
            message=message,
            details={
                "username": username,
                "platform": system,
                "csf_function": "RESPOND",
                "csf_category": "RS.MI - Mitigation",
            },
        )
