"""End-to-end integration tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import yaml

from dmarrss.actions import BlockIPAction, NotifyWebhookAction
from dmarrss.decide.decision_node import DecisionNode
from dmarrss.models.inference import ThreatInference
from dmarrss.parsers import SnortParser
from dmarrss.scoring.threat_scorer import ThreatScorer
from dmarrss.store import Store


def load_test_config():
    """Load test configuration"""
    config_path = Path(__file__).parent.parent / "config" / "dmarrss_config.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)


class TestEndToEnd:
    """End-to-end integration tests"""

    def test_full_pipeline_snort(self):
        """Test complete pipeline from SNORT log to action"""
        config = load_test_config()

        # Initialize components
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)
        inference = ThreatInference()
        decision_node = DecisionNode(config, scorer, inference)

        # Parse event
        parser = SnortParser()
        log_line = "[**] [1:2024364:1] ET MALWARE Critical Ransomware [**] [Priority: 1] {TCP} 203.0.113.50:54321 -> 192.168.1.100:443"
        event = parser.parse(log_line)

        assert event is not None

        # Make decision
        decision = decision_node.decide(event)

        assert decision is not None
        assert decision.severity is not None
        assert decision.threat_score > 0

        # Store
        event.threat_score = decision.threat_score
        event.severity = decision.severity
        store.insert_event(event)
        store.insert_decision(decision)

        # Execute actions (dry-run)
        for action_name in decision.recommended_actions:
            if action_name == "notify_webhook":
                action = NotifyWebhookAction()
                result = action.execute(decision, dry_run=True)
                assert result.success
                store.insert_action(result)

        # Verify storage
        events = store.get_events(limit=10)
        assert len(events) >= 1

        decision_retrieved = store.get_decision(decision.decision_id)
        assert decision_retrieved is not None

    def test_batch_processing(self):
        """Test batch processing of multiple events"""
        config = load_test_config()

        store = Store(":memory:")
        scorer = ThreatScorer(config, store)
        inference = ThreatInference()
        decision_node = DecisionNode(config, scorer, inference)
        parser = SnortParser()

        # Multiple log lines
        log_lines = [
            "[**] [1:2024364:1] ET MALWARE Detected [**] [Priority: 1] {TCP} 10.0.0.1:12345 -> 192.168.1.100:443",
            "[**] [1:2013028:8] ET SCAN Port Scan [**] [Priority: 3] {TCP} 10.0.0.2:443 -> 192.168.1.50:22",
            "[**] [1:2019401:2] ET EXPLOIT Buffer Overflow [**] [Priority: 1] {TCP} 10.0.0.3:54321 -> 192.168.1.200:80",
        ]

        # Parse
        events = [parser.parse(line) for line in log_lines]
        events = [e for e in events if e]

        assert len(events) == 3

        # Make decisions
        decisions = decision_node.decide_batch(events)

        assert len(decisions) == 3

        # Store all
        for event, decision in zip(events, decisions):
            event.threat_score = decision.threat_score
            event.severity = decision.severity
            store.insert_event(event)
            store.insert_decision(decision)

        # Verify
        stored_events = store.get_events(limit=10)
        assert len(stored_events) == 3

    def test_in_memory_simulation(self):
        """Test complete in-memory simulation"""
        config = load_test_config()

        # Full pipeline
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)
        inference = ThreatInference()
        decision_node = DecisionNode(config, scorer, inference)
        parser = SnortParser()

        # Sample data
        log_line = "[**] [1:2024364:1] ET EXPLOIT Critical RCE [**] [Priority: 1] {TCP} 203.0.113.50:54321 -> 192.168.1.100:443"

        # Process
        event = parser.parse(log_line)
        assert event is not None

        decision = decision_node.decide(event)
        assert decision is not None

        # Verify decision quality
        assert decision.threat_score > 0
        assert decision.confidence > 0
        assert len(decision.score_components) > 0
        assert len(decision.recommended_actions) >= 0

        # Should have neural prediction (even if model not trained)
        assert decision.neural_prediction is not None
