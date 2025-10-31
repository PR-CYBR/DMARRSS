"""
Neural network model for threat classification.

Simple MLP for tabular threat features with PyTorch.
"""

import torch
import torch.nn as nn
from typing import List


class ThreatClassifierMLP(nn.Module):
    """
    Multi-layer perceptron for threat classification.

    Takes tabular features (threat scores, network info) and predicts severity class.
    """

    def __init__(
        self,
        input_dim: int = 10,
        hidden_layers: List[int] = [256, 128, 64],
        num_classes: int = 4,
        dropout_rate: float = 0.3,
    ):
        """
        Initialize MLP.

        Args:
            input_dim: Number of input features
            hidden_layers: List of hidden layer sizes
            num_classes: Number of output classes (CRITICAL, HIGH, MEDIUM, LOW)
            dropout_rate: Dropout probability
        """
        super().__init__()

        self.input_dim = input_dim
        self.num_classes = num_classes

        # Build layers
        layers = []
        prev_dim = input_dim

        for hidden_dim in hidden_layers:
            layers.append(nn.Linear(prev_dim, hidden_dim))
            layers.append(nn.ReLU())
            layers.append(nn.Dropout(dropout_rate))
            prev_dim = hidden_dim

        # Output layer
        layers.append(nn.Linear(prev_dim, num_classes))

        self.network = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass"""
        return self.network(x)

    def predict(self, x: torch.Tensor) -> torch.Tensor:
        """Predict with softmax"""
        logits = self.forward(x)
        return torch.softmax(logits, dim=-1)


def create_model(config: dict) -> ThreatClassifierMLP:
    """
    Create model from config.

    Expected config keys:
    - embedding_dim (not used for MLP, kept for compatibility)
    - hidden_layers: List[int]
    - dropout_rate: float
    """
    hidden_layers = config.get("hidden_layers", [256, 128, 64])
    dropout_rate = config.get("dropout_rate", 0.3)

    # Input features:
    # 5 scoring components + src_port + dst_port + proto_encoded + hour + day_of_week
    input_dim = 10

    # 4 severity classes: CRITICAL, HIGH, MEDIUM, LOW
    num_classes = 4

    model = ThreatClassifierMLP(
        input_dim=input_dim,
        hidden_layers=hidden_layers,
        num_classes=num_classes,
        dropout_rate=dropout_rate,
    )

    return model
