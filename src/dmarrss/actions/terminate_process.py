"""
Process Termination Action - Enhanced Process Control

NIST CSF 2.0 Mapping: RS.MI (Mitigation)
"""

import logging

from ..actions.base import BaseAction
from ..schemas import ActionResult, Decision

logger = logging.getLogger(__name__)


class TerminateProcessAction(BaseAction):
    """
    Terminate a malicious process.

    Enhanced version with better error handling and logging.
    """

    def __init__(self):
        super().__init__("terminate_process")

    def _execute_impl(self, decision: Decision) -> ActionResult:
        """Terminate the process"""
        # Extract process information from decision context
        details = decision.score_components
        process_info = details.get("process_info", {})

        if not process_info:
            return self._create_result(
                decision=decision,
                success=False,
                dry_run=False,
                executed=False,
                message="No process information available",
                error="Missing process_info in decision",
            )

        try:
            import psutil

            pid = process_info.get("pid")
            if not pid:
                return self._create_result(
                    decision=decision,
                    success=False,
                    dry_run=False,
                    executed=False,
                    message="No PID specified",
                    error="Missing PID",
                )

            # Terminate the process
            process = psutil.Process(pid)
            process_name = process.name()
            process.terminate()

            # Wait for process to terminate
            process.wait(timeout=5)

            logger.info(f"Process terminated: {process_name} (PID: {pid})")

            return self._create_result(
                decision=decision,
                success=True,
                dry_run=False,
                executed=True,
                message=f"Process {process_name} (PID: {pid}) terminated",
                details={
                    "pid": pid,
                    "process_name": process_name,
                    "csf_function": "RESPOND",
                    "csf_category": "RS.MI - Mitigation",
                },
            )

        except ImportError:
            return self._create_result(
                decision=decision,
                success=False,
                dry_run=False,
                executed=False,
                message="psutil not installed",
                error="psutil library required",
            )
        except Exception as e:
            logger.error(f"Error terminating process: {e}")
            return self._create_result(
                decision=decision,
                success=False,
                dry_run=False,
                executed=False,
                message=f"Failed to terminate process: {e}",
                error=str(e),
            )

    def _dry_run_impl(self, decision: Decision) -> ActionResult:
        """Dry-run: Log what would be done"""
        details = decision.score_components
        process_info = details.get("process_info", {})
        pid = process_info.get("pid", "UNKNOWN")
        process_name = process_info.get("name", "UNKNOWN")

        message = f"[DRY-RUN] Would terminate process: {process_name} (PID: {pid})"
        logger.info(message)

        return self._create_result(
            decision=decision,
            success=True,
            dry_run=True,
            executed=False,
            message=message,
            details={
                "pid": pid,
                "process_name": process_name,
                "csf_function": "RESPOND",
                "csf_category": "RS.MI - Mitigation",
            },
        )
