"""
Model training for threat classification.

Trains MLP on historical events from parquet files.
"""

import json
from datetime import datetime
from pathlib import Path

import torch

from ..schemas import ModelMetadata
from .neural import create_model


class ThreatModelTrainer:
    """
    Trainer for threat classification model.

    Loads training data from parquet, trains model, and saves with metadata.
    """

    def __init__(
        self,
        config: dict,
        data_dir: str = "data/training",
        model_dir: str = "data/models",
    ):
        """Initialize trainer"""
        self.config = config
        self.data_dir = Path(data_dir)
        self.model_dir = Path(model_dir)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Create directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.model_dir.mkdir(parents=True, exist_ok=True)

    def _check_if_training_needed(self) -> bool:
        """
        Check if training is needed.

        Returns True if:
        - No model exists
        - Model is older than 7 days
        - Training data is newer than model
        """
        model_path = self.model_dir / "model.pt"
        self.model_dir / "manifest.json"

        if not model_path.exists():
            return True

        # Check model age
        model_age = datetime.utcnow().timestamp() - model_path.stat().st_mtime
        if model_age > 7 * 24 * 3600:  # 7 days
            return True

        # Check if training data is newer
        training_file = self.data_dir / "events.parquet"
        if training_file.exists():
            data_age = training_file.stat().st_mtime
            if data_age > model_path.stat().st_mtime:
                return True

        return False

    def train(self, force: bool = False) -> bool:
        """
        Train or update model.

        Args:
            force: Force training even if not needed

        Returns:
            True if training was performed, False if skipped
        """
        # Check if training needed
        if not force and not self._check_if_training_needed():
            print("Model is up to date, skipping training")
            return False

        print("Starting model training...")

        # Check for training data
        training_file = self.data_dir / "events.parquet"
        if not training_file.exists():
            print(f"No training data found at {training_file}")
            print("Creating dummy model for cold start...")
            self._create_dummy_model()
            return True

        try:
            # Load training data (would use pandas/pyarrow here)
            # For now, create dummy model
            print("Training data loading not implemented yet")
            print("Creating dummy model...")
            self._create_dummy_model()
            return True

        except Exception as e:
            print(f"Training failed: {e}")
            return False

    def _create_dummy_model(self) -> None:
        """
        Create a dummy model for cold start.

        This creates an untrained model so inference can still work.
        """
        print("Creating untrained model for cold start...")

        neural_config = self.config.get("neural_config", {})
        model = create_model(neural_config)

        # Save model
        model_path = self.model_dir / "model.pt"
        torch.save(
            {
                "model_state_dict": model.state_dict(),
                "config": neural_config,
            },
            model_path,
        )

        # Save metadata
        metadata = ModelMetadata(
            model_version="1.0.0-untrained",
            trained_at=datetime.utcnow(),
            training_samples=0,
            validation_accuracy=0.0,
            features=[
                "pattern_match",
                "context_relevance",
                "historical_severity",
                "source_reputation",
                "anomaly_score",
                "src_port",
                "dst_port",
                "proto",
                "hour",
                "day_of_week",
            ],
            architecture={
                "type": "MLP",
                "input_dim": 10,
                "hidden_layers": neural_config.get("hidden_layers", [256, 128, 64]),
                "num_classes": 4,
            },
            hyperparameters=neural_config,
        )

        manifest_path = self.model_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(metadata.model_dump(), f, indent=2, default=str)

        print(f"Model saved to {model_path}")
        print(f"Manifest saved to {manifest_path}")


def train_model(config: dict, force: bool = False) -> bool:
    """
    Train threat classification model.

    Args:
        config: Configuration dict
        force: Force training even if not needed

    Returns:
        True if training was performed
    """
    trainer = ThreatModelTrainer(config)
    return trainer.train(force=force)
