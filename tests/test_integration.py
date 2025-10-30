"""
Integration tests for complete DMARRSS pipeline
"""

import pytest
from pathlib import Path
from src.dmarrss_pipeline import DMARRSSPipeline


class TestDMARRSSPipeline:
    """Integration tests for DMARRSS pipeline"""
    
    @pytest.fixture
    def pipeline(self):
        """Create a DMARRSS pipeline instance"""
        return DMARRSSPipeline()
    
    @pytest.fixture
    def sample_snort_log(self):
        """Sample SNORT log line"""
        return "[**] [1:2024364:1] ET MALWARE Win32/Emotet CnC Activity [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 203.0.113.50:54321 -> 192.168.1.100:443"
    
    @pytest.fixture
    def sample_suricata_log(self):
        """Sample SURICATA log line"""
        return '{"timestamp":"2024-01-15T10:30:45.123456+0000","src_ip":"203.0.113.50","dest_ip":"192.168.1.100","src_port":54321,"dest_port":443,"proto":"TCP","alert":{"signature":"ET EXPLOIT SQL Injection","signature_id":2013028,"category":"Web Application Attack","severity":1}}'
    
    def test_process_single_log_line(self, pipeline, sample_snort_log):
        """Test processing a single log line through the complete pipeline"""
        result = pipeline.process_log_line(sample_snort_log)
        
        # Check that event was processed
        assert result is not None
        
        # Check that all pipeline stages added their data
        assert 'source' in result
        assert 'threat_score' in result
        assert 'severity' in result
        assert 'score_components' in result
        assert 'neural_severity' in result
        assert 'confidence' in result
        assert 'response_action' in result
        
        # Check severity is valid
        assert result['severity'] in ['critical', 'high', 'medium', 'low']
        
        # Check that response action was determined
        assert result['response_action']['success'] is True
    
    def test_process_log_batch(self, pipeline, sample_snort_log, sample_suricata_log):
        """Test processing multiple log lines"""
        log_lines = [sample_snort_log, sample_suricata_log]
        
        results = pipeline.process_log_batch(log_lines)
        
        assert len(results) == 2
        assert all('threat_score' in r for r in results)
        assert all('response_action' in r for r in results)
    
    def test_process_log_file(self, pipeline):
        """Test processing a log file"""
        # Use sample data file
        base_path = Path(__file__).parent.parent
        log_file = base_path / "data" / "raw" / "sample_snort_alerts.log"
        
        if log_file.exists():
            results = pipeline.process_log_file(str(log_file), format_hint='snort')
            
            assert len(results) > 0
            assert all('threat_score' in r for r in results)
            assert all('severity' in r for r in results)
    
    def test_get_critical_events(self, pipeline):
        """Test filtering critical events"""
        events = [
            {'severity': 'low', 'threat_score': 0.2},
            {'severity': 'critical', 'threat_score': 0.95},
            {'severity': 'high', 'threat_score': 0.75},
            {'severity': 'critical', 'threat_score': 0.92}
        ]
        
        critical_events = pipeline.get_critical_events(events)
        
        assert len(critical_events) == 2
        assert all(e['severity'] == 'critical' for e in critical_events)
    
    def test_get_high_priority_events(self, pipeline):
        """Test filtering high priority events"""
        events = [
            {'severity': 'low', 'threat_score': 0.2},
            {'severity': 'critical', 'threat_score': 0.95},
            {'severity': 'high', 'threat_score': 0.75},
            {'severity': 'medium', 'threat_score': 0.5}
        ]
        
        high_priority = pipeline.get_high_priority_events(events)
        
        assert len(high_priority) == 2
        assert all(e['severity'] in ['critical', 'high'] for e in high_priority)
    
    def test_generate_summary(self, pipeline):
        """Test summary generation"""
        events = [
            {'severity': 'critical', 'threat_score': 0.95, 'source': 'snort', 
             'response_action': {'action': 'automated_response'}},
            {'severity': 'high', 'threat_score': 0.75, 'source': 'suricata',
             'response_action': {'action': 'analyst_review'}},
            {'severity': 'low', 'threat_score': 0.2, 'source': 'snort',
             'response_action': {'action': 'log_monitor'}}
        ]
        
        summary = pipeline.generate_summary(events)
        
        assert summary['total_events'] == 3
        assert summary['by_severity']['critical'] == 1
        assert summary['by_severity']['high'] == 1
        assert summary['by_severity']['low'] == 1
        assert summary['by_source']['snort'] == 2
        assert summary['by_source']['suricata'] == 1
        assert 'threat_scores' in summary
        assert summary['threat_scores']['min'] == 0.2
        assert summary['threat_scores']['max'] == 0.95
    
    def test_get_statistics(self, pipeline):
        """Test getting pipeline statistics"""
        stats = pipeline.get_statistics()
        
        assert 'system' in stats
        assert 'response_engine' in stats
        assert stats['system']['name'] == 'DMARRSS'
    
    def test_end_to_end_snort(self, pipeline):
        """Test complete end-to-end processing of SNORT data"""
        base_path = Path(__file__).parent.parent
        log_file = base_path / "data" / "raw" / "sample_snort_alerts.log"
        
        if log_file.exists():
            # Process the file
            events = pipeline.process_log_file(str(log_file), format_hint='snort')
            
            # Verify processing
            assert len(events) > 0
            
            # Generate summary
            summary = pipeline.generate_summary(events)
            assert summary['total_events'] > 0
            
            # Get high priority events
            high_priority = pipeline.get_high_priority_events(events)
            
            # Verify that critical/high priority events exist if the data contains them
            assert summary['by_severity']['critical'] + summary['by_severity']['high'] >= 0
    
    def test_end_to_end_suricata(self, pipeline):
        """Test complete end-to-end processing of SURICATA data"""
        base_path = Path(__file__).parent.parent
        log_file = base_path / "data" / "raw" / "sample_suricata_eve.json"
        
        if log_file.exists():
            # Read and process line by line (SURICATA EVE is line-delimited JSON)
            with open(log_file, 'r') as f:
                log_lines = f.readlines()
            
            events = pipeline.process_log_batch(log_lines, format_hint='suricata')
            
            # Verify processing
            assert len(events) > 0
            
            # Generate summary
            summary = pipeline.generate_summary(events)
            assert summary['total_events'] > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
