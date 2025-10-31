"""
Tests for DMARRSS threat scoring engine
"""

import pytest
from src.models import ThreatScorer
from src.utils import ConfigLoader


class TestThreatScorer:
    """Tests for ThreatScorer"""
    
    @pytest.fixture
    def scorer(self):
        """Create a ThreatScorer instance"""
        return ThreatScorer()
    
    @pytest.fixture
    def sample_event(self):
        """Create a sample event for testing"""
        return {
            'source': 'snort',
            'signature_id': 2024364,
            'message': 'ET MALWARE Win32/Emotet exploit detected',
            'priority': 1,
            'source_ip': '203.0.113.50',
            'destination_ip': '192.168.1.100',
            'destination_port': 443
        }
    
    def test_calculate_pattern_score(self, scorer, sample_event):
        """Test pattern matching score calculation"""
        score = scorer.calculate_pattern_score(sample_event)
        
        assert 0 <= score <= 1
        # Event contains 'malware' and 'exploit' keywords
        assert score >= 0.8  # Should be high
    
    def test_calculate_context_relevance(self, scorer, sample_event):
        """Test context relevance calculation"""
        score = scorer.calculate_context_relevance(sample_event)
        
        assert 0 <= score <= 1
        # Priority 1 should give high score
        assert score >= 0.8
    
    def test_calculate_historical_severity(self, scorer, sample_event):
        """Test historical severity calculation"""
        score = scorer.calculate_historical_severity(sample_event)
        
        assert 0 <= score <= 1
    
    def test_calculate_source_reputation(self, scorer, sample_event):
        """Test source reputation calculation"""
        score = scorer.calculate_source_reputation(sample_event)
        
        assert 0 <= score <= 1
        # External IP should have higher risk
        assert score >= 0.5
    
    def test_calculate_anomaly_score(self, scorer, sample_event):
        """Test anomaly score calculation"""
        score = scorer.calculate_anomaly_score(sample_event)
        
        assert 0 <= score <= 1
    
    def test_calculate_composite_score(self, scorer, sample_event):
        """Test composite score calculation"""
        final_score, components = scorer.calculate_composite_score(sample_event)
        
        # Check final score is in valid range
        assert 0 <= final_score <= 1
        
        # Check all components are present
        assert 'pattern_match' in components
        assert 'context_relevance' in components
        assert 'historical_severity' in components
        assert 'source_reputation' in components
        assert 'anomaly_score' in components
        
        # All component scores should be in range
        for score in components.values():
            assert 0 <= score <= 1
    
    def test_apply_severity_layers(self, scorer):
        """Test severity layer application"""
        # Test critical threshold
        severity, layers = scorer.apply_severity_layers(0.95)
        assert severity == 'critical'
        
        # Test high threshold
        severity, layers = scorer.apply_severity_layers(0.75)
        assert severity == 'high'
        
        # Test medium threshold
        severity, layers = scorer.apply_severity_layers(0.55)
        assert severity == 'medium'
        
        # Test low threshold
        severity, layers = scorer.apply_severity_layers(0.25)
        assert severity == 'low'
    
    def test_score_event(self, scorer, sample_event):
        """Test complete event scoring"""
        scored_event = scorer.score_event(sample_event)
        
        # Check that original event data is preserved
        assert scored_event['source'] == 'snort'
        assert scored_event['signature_id'] == 2024364
        
        # Check that scoring data is added
        assert 'threat_score' in scored_event
        assert 'severity' in scored_event
        assert 'score_components' in scored_event
        assert 'processing_timestamp' in scored_event
        
        # Check severity is valid
        assert scored_event['severity'] in ['critical', 'high', 'medium', 'low']
        
        # Check threat score is in range
        assert 0 <= scored_event['threat_score'] <= 1
    
    def test_score_batch(self, scorer):
        """Test batch scoring"""
        events = [
            {'source': 'snort', 'message': 'exploit detected', 'priority': 1, 'signature_id': 100},
            {'source': 'suricata', 'signature': 'scan detected', 'severity': 3, 'signature_id': 200}
        ]
        
        scored_events = scorer.score_batch(events)
        
        assert len(scored_events) == 2
        assert all('threat_score' in e for e in scored_events)
        assert all('severity' in e for e in scored_events)
    
    def test_prioritize_events(self, scorer):
        """Test event prioritization"""
        events = [
            {'severity': 'low', 'threat_score': 0.2},
            {'severity': 'critical', 'threat_score': 0.95},
            {'severity': 'high', 'threat_score': 0.75},
            {'severity': 'medium', 'threat_score': 0.5}
        ]
        
        prioritized = scorer.prioritize_events(events)
        
        # Check that critical is first
        assert prioritized[0]['severity'] == 'critical'
        
        # Check that low is last
        assert prioritized[-1]['severity'] == 'low'
        
        # Check ordering by severity
        severities = [e['severity'] for e in prioritized]
        assert severities == ['critical', 'high', 'medium', 'low']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
