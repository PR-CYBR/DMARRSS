"""
Decision engine for DMARRSS.

Combines threat scoring and neural classification to make severity decisions.
"""

import uuid

from ..models.inference import ThreatInference
from ..schemas import Decision, Event, Severity
from ..scoring.threat_scorer import ThreatScorer


class DecisionNode:
    """
    Decision engine that combines scoring and classification.

    Applies severity thresholds from config to produce final Decision objects.
    """

    def __init__(
        self,
        config: dict,
        scorer: ThreatScorer,
        inference: ThreatInference,
    ):
        """Initialize decision node"""
        self.config = config
        self.scorer = scorer
        self.inference = inference

        # Load severity thresholds
        self.severity_layers = config.get("severity_layers", {})
        self.layer1 = self.severity_layers.get("layer1", {})

        # Load response mapping
        self.responses = config.get("responses", {})

    def _apply_severity_layers(self, composite_score: float) -> Severity:
        """
        Apply severity layer thresholds to determine severity.

        Uses layer1 thresholds from config.
        """
        if composite_score >= self.layer1.get("critical", 0.9):
            return Severity.CRITICAL
        elif composite_score >= self.layer1.get("high", 0.7):
            return Severity.HIGH
        elif composite_score >= self.layer1.get("medium", 0.5):
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def decide(self, event: Event) -> Decision:
        """
        Make a decision for an event.

        Process:
        1. Calculate threat score components
        2. Calculate composite score
        3. Apply severity layers
        4. Run neural classifier (if available)
        5. Combine results
        6. Determine recommended actions

        Returns:
            Decision object with severity, confidence, and rationale
        """
        # Step 1: Calculate threat score components
        score_components = self.scorer.score_event(event)

        # Step 2: Calculate composite score
        composite_score = self.scorer.calculate_composite_score(score_components)

        # Step 3: Apply severity layers
        threshold_severity = self._apply_severity_layers(composite_score)

        # Step 4: Neural prediction
        neural_severity, neural_confidence = self.inference.predict(event, score_components)

        # Step 5: Combine results
        # Use threshold severity as primary, neural as confirmation
        # If neural agrees within 1 level, use threshold
        # If neural is more severe, use neural
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        threshold_idx = severity_order.index(threshold_severity)
        neural_idx = severity_order.index(neural_severity)

        if neural_idx > threshold_idx:
            # Neural is more severe, use it
            final_severity = neural_severity
            confidence = neural_confidence * 0.9  # Slightly reduce confidence
            why = "Neural model predicted higher severity than threshold"
        else:
            # Use threshold severity
            final_severity = threshold_severity
            confidence = composite_score
            why = "Threshold-based severity classification"

        # Step 6: Determine recommended actions
        recommended_actions = self.responses.get(final_severity, [])

        # Create decision
        decision = Decision(
            decision_id=str(uuid.uuid4()),
            event_id=event.event_id or str(uuid.uuid4()),
            severity=final_severity,
            confidence=confidence,
            threat_score=composite_score,
            score_components={
                "pattern_match": score_components.pattern_match,
                "context_relevance": score_components.context_relevance,
                "historical_severity": score_components.historical_severity,
                "source_reputation": score_components.source_reputation,
                "anomaly_score": score_components.anomaly_score,
            },
            neural_prediction=neural_severity,
            neural_confidence=neural_confidence,
            why=why,
            weights=self.scorer.weights,
            recommended_actions=recommended_actions,
        )

        return decision

    def decide_batch(self, events: list[Event]) -> list[Decision]:
        """Make decisions for a batch of events"""
        return [self.decide(event) for event in events]
