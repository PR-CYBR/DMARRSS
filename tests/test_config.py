"""
Tests for DMARRSS configuration and utilities
"""

import pytest
import tempfile
import os
from pathlib import Path
from src.utils.config import ConfigLoader, DMALogger


def test_config_loader_default():
    """Test ConfigLoader with default config"""
    config = ConfigLoader()
    
    # Test system configuration
    assert config.get('system.name') == 'DMARRSS'
    assert config.get('system.version') == '1.0.0'
    
    # Test severity layers
    assert config.get_severity_threshold('layer1', 'critical') == 0.9
    assert config.get_severity_threshold('layer1', 'high') == 0.7
    
    # Test scoring weights
    weights = config.get_scoring_weights()
    assert 'pattern_match' in weights
    assert sum(weights.values()) == 1.0


def test_config_loader_nested_keys():
    """Test nested key access"""
    config = ConfigLoader()
    
    # Test nested access
    assert config.get('severity_layers.layer1.critical') == 0.9
    assert config.get('neural_config.embedding_dim') == 128
    
    # Test default values
    assert config.get('nonexistent.key', 'default') == 'default'


def test_config_loader_response_actions():
    """Test response action configuration"""
    config = ConfigLoader()
    
    critical_action = config.get_response_action('critical')
    assert critical_action['action'] == 'automated_response'
    assert critical_action['notify'] is True
    assert critical_action['block'] is True
    
    low_action = config.get_response_action('low')
    assert low_action['action'] == 'log_monitor'
    assert low_action['notify'] is False


def test_dma_logger_initialization():
    """Test DMALogger initialization"""
    logger = DMALogger('test_logger')
    
    assert logger.name == 'test_logger'
    assert logger.logger is not None


def test_dma_logger_logging_methods():
    """Test DMALogger logging methods"""
    logger = DMALogger('test_logger')
    
    # These should not raise exceptions
    logger.info("Test info message")
    logger.warning("Test warning message")
    logger.error("Test error message")
    logger.debug("Test debug message")
    logger.critical("Test critical message")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
