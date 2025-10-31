"""
Model inference for real-time threat classification.
"""

import json
import torch
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

from .neural import ThreatClassifierMLP, create_model
from ..schemas import Event, Severity, ThreatScoreComponents


class ThreatInference:
    """
    Real-time inference engine for threat classification.

    Loads trained model and provides predict() interface.
    """

    def __init__(self, model_dir: str = "data/models"):
        """Initialize inference engine"""
        self.model_dir = Path(model_dir)
        self.model: Optional[ThreatClassifierMLP] = None
        self.metadata: Optional[Dict] = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Severity mapping
        self.severity_classes = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]

        # Load model if available
        self._load_model()

    def _load_model(self) -> bool:
        """Load model and metadata from disk"""
        model_path = self.model_dir / "model.pt"
        manifest_path = self.model_dir / "manifest.json"

        if not model_path.exists():
            return False

        try:
            # Load metadata
            if manifest_path.exists():
                with open(manifest_path) as f:
                    self.metadata = json.load(f)

            # Load model
            checkpoint = torch.load(model_path, map_location=self.device)

            # Create model from architecture
            config = checkpoint.get("config", {})
            self.model = create_model(config)
            self.model.load_state_dict(checkpoint["model_state_dict"])
            self.model.to(self.device)
            self.model.eval()

            return True

        except Exception:
            return False

    def _extract_features(
        self, event: Event, score_components: ThreatScoreComponents
    ) -> torch.Tensor:
        """
        Extract feature vector from event and scoring components.

        Features (10 total):
        1-5: Scoring components
        6: src_port (normalized)
        7: dst_port (normalized)
        8: proto (encoded: TCP=1, UDP=2, ICMP=3, other=0)
        9: hour of day
        10: day of week
        """
        features = []

        # Scoring components
        features.append(score_components.pattern_match)
        features.append(score_components.context_relevance)
        features.append(score_components.historical_severity)
        features.append(score_components.source_reputation)
        features.append(score_components.anomaly_score)

        # Network features
        features.append((event.src_port or 0) / 65535.0)  # Normalize port
        features.append((event.dst_port or 0) / 65535.0)

        # Protocol encoding
        proto_map = {"TCP": 1, "UDP": 2, "ICMP": 3}
        proto_encoded = proto_map.get((event.proto or "").upper(), 0)
        features.append(proto_encoded / 3.0)  # Normalize

        # Time features
        features.append(event.ts.hour / 24.0)
        features.append(event.ts.weekday() / 7.0)

        return torch.tensor(features, dtype=torch.float32).unsqueeze(0).to(self.device)

    def predict(
        self, event: Event, score_components: ThreatScoreComponents
    ) -> Tuple[Severity, float]:
        """
        Predict severity class and confidence for an event.

        Args:
            event: Event to classify
            score_components: Pre-computed scoring components

        Returns:
            (predicted_severity, confidence)
        """
        # If model not loaded, use heuristic based on composite score
        if not self.model:
            # Simple threshold-based classification
            composite = (
                score_components.pattern_match * 0.3
                + score_components.context_relevance * 0.25
                + score_components.historical_severity * 0.2
                + score_components.source_reputation * 0.15
                + score_components.anomaly_score * 0.1
            )

            if composite >= 0.9:
                return Severity.CRITICAL, composite
            elif composite >= 0.7:
                return Severity.HIGH, composite
            elif composite >= 0.5:
                return Severity.MEDIUM, composite
            else:
                return Severity.LOW, composite

        # Use neural model
        try:
            features = self._extract_features(event, score_components)

            with torch.no_grad():
                probs = self.model.predict(features)
                probs_np = probs.cpu().numpy()[0]

                # Get highest probability class
                class_idx = int(probs_np.argmax())
                confidence = float(probs_np[class_idx])

                return self.severity_classes[class_idx], confidence

        except Exception:
            # Fallback to threshold-based
            composite = (
                score_components.pattern_match * 0.3
                + score_components.context_relevance * 0.25
                + score_components.historical_severity * 0.2
                + score_components.source_reputation * 0.15
                + score_components.anomaly_score * 0.1
            )

            if composite >= 0.9:
                return Severity.CRITICAL, composite
            elif composite >= 0.7:
                return Severity.HIGH, composite
            elif composite >= 0.5:
                return Severity.MEDIUM, composite
            else:
                return Severity.LOW, composite

    def is_model_loaded(self) -> bool:
        """Check if model is loaded"""
        return self.model is not None

    def get_metadata(self) -> Optional[Dict]:
        """Get model metadata"""
        return self.metadata
