"""
Tests for DMARRSS log parsing functionality
"""

import pytest
from src.preprocessing import (
    SnortParser,
    SuricataParser,
    ZeekParser,
    UniversalLogParser
)


class TestSnortParser:
    """Tests for SNORT log parser"""
    
    def test_parse_snort_alert(self):
        """Test parsing a standard SNORT alert"""
        parser = SnortParser()
        log_line = "[**] [1:2013504:5] ET POLICY GNU/Linux APT User-Agent Outbound [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 192.168.1.100:45678 -> 93.184.216.34:80"
        
        event = parser.parse(log_line)
        
        assert event is not None
        assert event['source'] == 'snort'
        assert event['generator_id'] == 1
        assert event['signature_id'] == 2013504
        assert event['revision'] == 5
        assert event['priority'] == 1
        assert 'APT' in event['message']
        assert event['source_ip'] == '192.168.1.100'
        assert event['destination_ip'] == '93.184.216.34'
    
    def test_parse_snort_batch(self):
        """Test parsing multiple SNORT alerts"""
        parser = SnortParser()
        log_lines = [
            "[**] [1:2001219:20] ET SCAN Potential SSH Scan [**] [Priority: 2] {TCP} 203.0.113.45:54321 -> 192.168.1.10:22",
            "[**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Priority: 2] {TCP} 192.168.1.50:80 -> 198.51.100.23:49152"
        ]
        
        events = parser.parse_batch(log_lines)
        
        assert len(events) == 2
        assert all(e['source'] == 'snort' for e in events)


class TestSuricataParser:
    """Tests for SURICATA log parser"""
    
    def test_parse_suricata_json(self):
        """Test parsing SURICATA EVE JSON format"""
        parser = SuricataParser()
        log_line = '{"timestamp":"2024-01-15T10:30:45.123456+0000","src_ip":"203.0.113.50","dest_ip":"192.168.1.100","src_port":54321,"dest_port":443,"proto":"TCP","alert":{"signature":"ET MALWARE Win32/Emotet","signature_id":2024364,"category":"Trojan","severity":1}}'
        
        event = parser.parse(log_line)
        
        assert event is not None
        assert event['source'] == 'suricata'
        assert event['source_ip'] == '203.0.113.50'
        assert event['destination_ip'] == '192.168.1.100'
        assert event['signature_id'] == 2024364
        assert event['severity'] == 1
    
    def test_parse_suricata_batch(self):
        """Test parsing multiple SURICATA events"""
        parser = SuricataParser()
        log_lines = [
            '{"timestamp":"2024-01-15T10:30:45.123456+0000","src_ip":"203.0.113.50","dest_ip":"192.168.1.100","alert":{"signature":"Test","signature_id":1,"severity":1}}',
            '{"timestamp":"2024-01-15T10:31:12.456789+0000","src_ip":"198.51.100.75","dest_ip":"192.168.1.50","alert":{"signature":"Test2","signature_id":2,"severity":2}}'
        ]
        
        events = parser.parse_batch(log_lines)
        
        assert len(events) == 2
        assert all(e['source'] == 'suricata' for e in events)


class TestZeekParser:
    """Tests for ZEEK log parser"""
    
    def test_parse_zeek_with_headers(self):
        """Test parsing ZEEK logs with headers"""
        parser = ZeekParser()
        
        # Parse header first
        header_line = "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
        parser.parse(header_line)  # Sets up headers
        
        # Parse data line
        data_line = "1547545845.123456\t192.168.1.100\t54321\t203.0.113.50\t443\ttcp"
        event = parser.parse(data_line)
        
        assert event is not None
        assert event['source'] == 'zeek'
        assert event['source_ip'] == '192.168.1.100'
        assert event['destination_ip'] == '203.0.113.50'


class TestUniversalLogParser:
    """Tests for Universal log parser"""
    
    def test_detect_format_snort(self):
        """Test SNORT format detection"""
        parser = UniversalLogParser()
        log_line = "[**] [1:2013504:5] Test [**] [Priority: 1] {TCP} 192.168.1.1 -> 192.168.1.2"
        
        format_type = parser.detect_format(log_line)
        assert format_type == 'snort'
    
    def test_detect_format_suricata(self):
        """Test SURICATA format detection"""
        parser = UniversalLogParser()
        log_line = '{"timestamp":"2024-01-15T10:30:45.123456+0000","src_ip":"192.168.1.1"}'
        
        format_type = parser.detect_format(log_line)
        assert format_type == 'suricata'
    
    def test_detect_format_zeek(self):
        """Test ZEEK format detection"""
        parser = UniversalLogParser()
        log_line = "1547545845.123456\t192.168.1.100\t54321\t203.0.113.50\t443"
        
        format_type = parser.detect_format(log_line)
        assert format_type == 'zeek'
    
    def test_parse_with_format_hint(self):
        """Test parsing with format hint"""
        parser = UniversalLogParser()
        log_line = "[**] [1:2013504:5] Test [**] [Priority: 1] {TCP} 192.168.1.1:123 -> 192.168.1.2:80"
        
        event = parser.parse(log_line, format_hint='snort')
        
        assert event is not None
        assert event['source'] == 'snort'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
