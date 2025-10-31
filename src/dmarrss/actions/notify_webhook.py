"""
Notify webhook action plugin.

Sends alert notifications via webhook or stdout.
"""

import os

from ..schemas import ActionResult, Decision
from .base import BaseAction


class NotifyWebhookAction(BaseAction):
    """
    Notify via webhook action.

    Posts decision to configured webhook URL.
    Falls back to stdout if no webhook configured.
    """

    def __init__(self):
        super().__init__("notify_webhook")
        self.webhook_url = os.environ.get("DMARRSS_WEBHOOK_URL", "")

    def _send_webhook(self, decision: Decision) -> tuple[bool, str | None]:
        """Send notification to webhook"""
        if not self.webhook_url:
            return False, "No webhook URL configured"

        try:
            import httpx

            payload = {
                "decision_id": decision.decision_id,
                "event_id": decision.event_id,
                "severity": decision.severity,
                "confidence": decision.confidence,
                "threat_score": decision.threat_score,
                "timestamp": decision.timestamp.isoformat(),
                "why": decision.why,
                "recommended_actions": decision.recommended_actions,
            }

            response = httpx.post(
                self.webhook_url,
                json=payload,
                timeout=10.0,
            )

            if response.status_code in [200, 201, 202]:
                return True, None
            else:
                return False, f"Webhook returned {response.status_code}"

        except Exception as e:
            return False, str(e)

    def _log_stdout(self, decision: Decision) -> None:
        """Log notification to stdout"""
        print("\n" + "=" * 60)
        print("DMARRSS ALERT")
        print("=" * 60)
        print(f"Decision ID: {decision.decision_id}")
        print(f"Event ID: {decision.event_id}")
        print(f"Severity: {decision.severity}")
        print(f"Confidence: {decision.confidence:.3f}")
        print(f"Threat Score: {decision.threat_score:.3f}")
        print(f"Timestamp: {decision.timestamp}")
        print(f"Reason: {decision.why}")
        print(f"Recommended Actions: {', '.join(decision.recommended_actions)}")
        print("=" * 60 + "\n")

    def _execute_impl(self, decision: Decision) -> ActionResult:
        """Execute notification"""
        details = {"webhook_url": self.webhook_url or "none"}

        # Try webhook first if configured
        if self.webhook_url:
            success, error = self._send_webhook(decision)
            if success:
                message = f"Notification sent to webhook: {self.webhook_url}"
                return self._create_result(
                    decision=decision,
                    success=True,
                    dry_run=False,
                    executed=True,
                    message=message,
                    details=details,
                )
            else:
                details["webhook_error"] = error

        # Fallback to stdout
        self._log_stdout(decision)
        message = "Notification logged to stdout (no webhook configured)"

        return self._create_result(
            decision=decision,
            success=True,
            dry_run=False,
            executed=True,
            message=message,
            details=details,
        )

    def _dry_run_impl(self, decision: Decision) -> ActionResult:
        """Dry-run: log what would be done"""
        if self.webhook_url:
            message = f"[DRY-RUN] Would send notification to {self.webhook_url}"
        else:
            message = "[DRY-RUN] Would log notification to stdout"

        return self._create_result(
            decision=decision,
            success=True,
            dry_run=True,
            executed=False,
            message=message,
            details={"webhook_url": self.webhook_url or "none"},
        )
