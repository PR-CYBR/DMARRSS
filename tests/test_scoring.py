"""Tests for DMARRSS scoring and decision engine."""

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import yaml

from dmarrss.decide.decision_node import DecisionNode
from dmarrss.models.inference import ThreatInference
from dmarrss.schemas import Event, LogSource, Severity
from dmarrss.scoring.threat_scorer import ThreatScorer
from dmarrss.store import Store


def load_test_config():
    """Load test configuration"""
    config_path = Path(__file__).parent.parent / "config" / "dmarrss_config.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)


class TestThreatScorer:
    """Tests for threat scorer"""

    def test_pattern_score_exploit(self):
        """Test pattern scoring for exploit"""
        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)

        event = Event(
            source=LogSource.SNORT,
            ts=datetime.utcnow(),
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            signature="ET EXPLOIT Buffer Overflow Attempt",
        )

        score = scorer.calculate_pattern_score(event)
        assert score >= 0.7  # Should be high for exploit

    def test_context_relevance_internal(self):
        """Test context relevance for internal IPs"""
        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)

        event = Event(
            source=LogSource.SNORT,
            ts=datetime.utcnow(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            signature="Test",
        )

        score = scorer.calculate_context_relevance(event)
        assert score >= 0.7  # Both IPs in CIDR ranges

    def test_composite_score(self):
        """Test composite scoring"""
        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)

        event = Event(
            source=LogSource.SNORT,
            ts=datetime.utcnow(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            signature="ET EXPLOIT Critical RCE",
        )

        components = scorer.score_event(event)
        composite = scorer.calculate_composite_score(components)

        assert 0.0 <= composite <= 1.0
        assert composite > 0.5  # Should be elevated for exploit


class TestDecisionNode:
    """Tests for decision engine"""

    def test_decision_critical_threat(self):
        """Test decision for critical threat"""
        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)
        inference = ThreatInference()
        decision_node = DecisionNode(config, scorer, inference)

        event = Event(
            source=LogSource.SNORT,
            ts=datetime.utcnow(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=54321,
            dst_port=443,
            signature="ET EXPLOIT Critical Remote Code Execution",
            severity_hint="CRITICAL",
            event_id="test_event_1",
        )

        decision = decision_node.decide(event)

        assert decision is not None
        assert decision.event_id == "test_event_1"
        assert decision.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
        assert 0.0 <= decision.confidence <= 1.0
        assert 0.0 <= decision.threat_score <= 1.0
        assert len(decision.recommended_actions) >= 0

    def test_decision_low_threat(self):
        """Test decision for low threat"""
        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)
        inference = ThreatInference()
        decision_node = DecisionNode(config, scorer, inference)

        event = Event(
            source=LogSource.ZEEK,
            ts=datetime.utcnow(),
            src_ip="10.0.0.1",
            dst_ip="8.8.8.8",
            signature="DNS Query",
            severity_hint="LOW",
            event_id="test_event_2",
        )

        decision = decision_node.decide(event)

        assert decision is not None
        assert decision.event_id == "test_event_2"
        # Low severity events should get LOW or MEDIUM
        assert decision.severity in [Severity.LOW, Severity.MEDIUM]

    def test_decision_batch(self):
        """Test batch decision making"""
        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)
        inference = ThreatInference()
        decision_node = DecisionNode(config, scorer, inference)

        events = [
            Event(
                source=LogSource.SNORT,
                ts=datetime.utcnow(),
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                signature=f"Test Event {i}",
                event_id=f"test_{i}",
            )
            for i in range(5)
        ]

        decisions = decision_node.decide_batch(events)

        assert len(decisions) == 5
        assert all(d.event_id.startswith("test_") for d in decisions)
