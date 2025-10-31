"""Tests for action plugins."""

import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dmarrss.actions import BlockIPAction, IsolateHostAction, NotifyWebhookAction
from dmarrss.schemas import Decision, Severity


class TestActionPlugins:
    """Tests for action plugins in dry-run mode"""

    def create_test_decision(self) -> Decision:
        """Create a test decision"""
        return Decision(
            decision_id="test_decision_1",
            event_id="test_event_1",
            severity=Severity.HIGH,
            confidence=0.85,
            threat_score=0.75,
            timestamp=datetime.utcnow(),
            recommended_actions=["block_ip", "notify_webhook"],
        )

    def test_block_ip_dry_run(self):
        """Test block IP in dry-run mode"""
        # Ensure dry-run mode
        os.environ["DMARRSS_ENFORCE"] = "0"

        action = BlockIPAction()
        decision = self.create_test_decision()

        result = action.execute(decision, dry_run=True)

        assert result is not None
        assert result.action_name == "block_ip"
        assert result.dry_run is True
        assert result.executed is False
        assert result.success is True
        assert "DRY-RUN" in result.message

    def test_block_ip_enforce_disabled(self):
        """Test block IP with enforce disabled"""
        os.environ["DMARRSS_ENFORCE"] = "0"

        action = BlockIPAction()
        decision = self.create_test_decision()

        # Try to execute (not dry-run) but enforce is disabled
        result = action.execute(decision, dry_run=False)

        assert result is not None
        assert result.executed is False
        assert result.success is False
        assert "ENFORCE" in result.message

    def test_isolate_host_dry_run(self):
        """Test isolate host in dry-run mode"""
        os.environ["DMARRSS_ENFORCE"] = "0"

        action = IsolateHostAction()
        decision = self.create_test_decision()

        result = action.execute(decision, dry_run=True)

        assert result is not None
        assert result.action_name == "isolate_host"
        assert result.dry_run is True
        assert result.executed is False
        assert result.success is True
        assert "DRY-RUN" in result.message

    def test_notify_webhook_dry_run(self):
        """Test notify webhook in dry-run mode"""
        # Clear webhook URL for test
        os.environ.pop("DMARRSS_WEBHOOK_URL", None)

        action = NotifyWebhookAction()
        decision = self.create_test_decision()

        result = action.execute(decision, dry_run=True)

        assert result is not None
        assert result.action_name == "notify_webhook"
        assert result.dry_run is True
        assert result.executed is False
        assert result.success is True

    def test_notify_webhook_execute(self):
        """Test notify webhook execution (falls back to stdout)"""
        os.environ.pop("DMARRSS_WEBHOOK_URL", None)

        action = NotifyWebhookAction()
        decision = self.create_test_decision()

        result = action.execute(decision, dry_run=False)

        assert result is not None
        assert result.action_name == "notify_webhook"
        assert result.dry_run is False
        assert result.executed is True
        assert result.success is True
        assert "stdout" in result.message.lower()
