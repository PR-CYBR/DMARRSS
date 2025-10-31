"""Tests for DMARRSS parsers."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dmarrss.parsers import SnortParser, SuricataParser, ZeekParser
from dmarrss.schemas import LogSource


class TestSnortParser:
    """Tests for SNORT parser"""

    def test_parse_snort_alert_with_priority(self):
        """Test parsing SNORT alert with priority"""
        parser = SnortParser()
        log_line = "[**] [1:2024364:1] ET MALWARE Detected [**] [Priority: 1] {TCP} 203.0.113.50:54321 -> 192.168.1.100:443"

        event = parser.parse(log_line)

        assert event is not None
        assert event.source == LogSource.SNORT
        assert event.src_ip == "203.0.113.50"
        assert event.src_port == 54321
        assert event.dst_ip == "192.168.1.100"
        assert event.dst_port == 443
        assert event.proto == "TCP"
        assert "MALWARE" in event.signature
        assert event.severity_hint == "CRITICAL"

    def test_parse_snort_without_ports(self):
        """Test parsing SNORT alert without ports"""
        parser = SnortParser()
        log_line = "[**] [1:123:1] Test Alert [**] {ICMP} 10.0.0.1 -> 10.0.0.2"

        event = parser.parse(log_line)

        assert event is not None
        assert event.src_ip == "10.0.0.1"
        assert event.src_port is None
        assert event.dst_ip == "10.0.0.2"
        assert event.dst_port is None

    def test_parse_invalid_line(self):
        """Test parsing invalid log line"""
        parser = SnortParser()
        log_line = "This is not a valid SNORT alert"

        event = parser.parse(log_line)

        assert event is None


class TestSuricataParser:
    """Tests for SURICATA parser"""

    def test_parse_suricata_eve_json(self):
        """Test parsing SURICATA EVE JSON"""
        parser = SuricataParser()
        log_line = '{"timestamp":"2024-01-15T10:30:45.123456+0000","src_ip":"192.168.1.100","src_port":54321,"dest_ip":"203.0.113.50","dest_port":443,"proto":"TCP","alert":{"signature":"ET EXPLOIT Critical RCE","category":"Exploit","severity":1}}'

        event = parser.parse(log_line)

        assert event is not None
        assert event.source == LogSource.SURICATA
        assert event.src_ip == "192.168.1.100"
        assert event.src_port == 54321
        assert event.dst_ip == "203.0.113.50"
        assert event.dst_port == 443
        assert event.proto == "TCP"
        assert "EXPLOIT" in event.signature
        assert event.severity_hint == "CRITICAL"

    def test_parse_suricata_without_alert(self):
        """Test parsing SURICATA event without alert"""
        parser = SuricataParser()
        log_line = '{"timestamp":"2024-01-15T10:30:45.123456+0000","src_ip":"192.168.1.100","src_port":54321,"dest_ip":"203.0.113.50","dest_port":443,"proto":"TCP"}'

        event = parser.parse(log_line)

        assert event is not None
        assert event.signature == ""

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON"""
        parser = SuricataParser()
        log_line = "This is not JSON"

        event = parser.parse(log_line)

        assert event is None


class TestZeekParser:
    """Tests for ZEEK parser"""

    def test_parse_zeek_with_fields_header(self):
        """Test parsing ZEEK log with #fields header"""
        parser = ZeekParser()

        # Set fields first
        header = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice"
        parser.set_fields(header)

        # Parse log line
        log_line = "1234567890.123\tCabcdef123\t10.0.0.1\t54321\t10.0.0.2\t80\tTCP\thttp"
        event = parser.parse(log_line)

        assert event is not None
        assert event.source == LogSource.ZEEK
        assert event.src_ip == "10.0.0.1"
        assert event.src_port == 54321
        assert event.dst_ip == "10.0.0.2"
        assert event.dst_port == 80
        assert event.proto == "TCP"

    def test_parse_zeek_comment_line(self):
        """Test parsing ZEEK comment line"""
        parser = ZeekParser()
        log_line = "#separator \\x09"

        event = parser.parse(log_line)

        assert event is None

    def test_parse_batch_with_header(self):
        """Test batch parsing with header"""
        parser = ZeekParser()
        log_lines = [
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto",
            "1234567890.123\tCabc\t10.0.0.1\t54321\t10.0.0.2\t80\tTCP",
            "1234567891.456\tCdef\t10.0.0.3\t12345\t10.0.0.4\t443\tTCP",
        ]

        events = parser.parse_batch(log_lines)

        assert len(events) == 2
        assert events[0].src_ip == "10.0.0.1"
        assert events[1].src_ip == "10.0.0.3"
