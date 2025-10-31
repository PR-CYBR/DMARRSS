"""
DMARRSS Utility Module
Contains configuration loading and logging utilities
"""

import logging
import os
from pathlib import Path
from typing import Any

import yaml
from pythonjsonlogger import jsonlogger


class ConfigLoader:
    """Load and manage DMARRSS configuration"""

    def __init__(self, config_path: str = None):
        if config_path is None:
            # Default to config/dmarrss_config.yaml
            base_path = Path(__file__).parent.parent.parent
            config_path = base_path / "config" / "dmarrss_config.yaml"

        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path) as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing configuration file: {e}")

    def get(self, key: str, default=None) -> Any:
        """Get configuration value by key (supports nested keys with dot notation)"""
        keys = key.split(".")
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def get_severity_threshold(self, layer: str, level: str) -> float:
        """Get severity threshold for specific layer and level"""
        return self.get(f"severity_layers.{layer}.{level}", 0.5)

    def get_scoring_weights(self) -> dict[str, float]:
        """Get all scoring weights"""
        return self.get("scoring_weights", {})

    def get_response_action(self, severity: str) -> dict[str, Any]:
        """Get response action configuration for severity level"""
        return self.get(f"response_actions.{severity}", {})


class DMALogger:
    """Custom logger for DMARRSS with JSON formatting support"""

    def __init__(self, name: str, config: ConfigLoader = None):
        self.name = name
        self.config = config or ConfigLoader()
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Setup logger with JSON formatting"""
        logger = logging.getLogger(self.name)

        # Get log level from config
        log_level_str = self.config.get("logging.level", "INFO")
        log_level = getattr(logging, log_level_str.upper(), logging.INFO)
        logger.setLevel(log_level)

        # Avoid duplicate handlers
        if logger.handlers:
            return logger

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)

        # JSON formatter
        log_format = self.config.get("logging.format", "json")
        if log_format == "json":
            formatter = jsonlogger.JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")
        else:
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # File handler
        log_file = self.config.get("logging.file", "logs/dmarrss.log")
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger

    def info(self, message: str, **kwargs):
        """Log info message with optional extra fields"""
        self.logger.info(message, extra=kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message with optional extra fields"""
        self.logger.warning(message, extra=kwargs)

    def error(self, message: str, **kwargs):
        """Log error message with optional extra fields"""
        self.logger.error(message, extra=kwargs)

    def debug(self, message: str, **kwargs):
        """Log debug message with optional extra fields"""
        self.logger.debug(message, extra=kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message with optional extra fields"""
        self.logger.critical(message, extra=kwargs)


def ensure_directories():
    """Ensure required directories exist"""
    base_path = Path(__file__).parent.parent.parent
    dirs = [
        base_path / "logs",
        base_path / "data" / "raw",
        base_path / "data" / "processed",
        base_path / "data" / "models",
    ]

    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=True)
