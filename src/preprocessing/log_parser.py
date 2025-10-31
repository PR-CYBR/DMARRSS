"""
DMARRSS Log Preprocessing Module
Parsers for SNORT, SURICATA, and ZEEK log formats
"""

import re
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from abc import ABC, abstractmethod


class LogParser(ABC):
    """Abstract base class for log parsers"""
    
    @abstractmethod
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse a single log line"""
        pass
    
    @abstractmethod
    def parse_batch(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """Parse multiple log lines"""
        pass


class SnortParser(LogParser):
    """Parser for SNORT alert logs"""
    
    def __init__(self):
        # SNORT alert pattern: [**] [gid:sid:rev] Message [**]
        self.alert_pattern = re.compile(
            r'\[\*\*\]\s*\[(\d+):(\d+):(\d+)\]\s*(.+?)\s*\[\*\*\]'
        )
        # Additional pattern for priority and classification
        self.priority_pattern = re.compile(r'\[Priority:\s*(\d+)\]')
        self.classification_pattern = re.compile(r'\[Classification:\s*(.+?)\]')
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse SNORT log line"""
        try:
            event = {
                'source': 'snort',
                'raw_log': log_line.strip(),
                'timestamp': datetime.now().isoformat()
            }
            
            # Parse alert signature
            alert_match = self.alert_pattern.search(log_line)
            if alert_match:
                event['generator_id'] = int(alert_match.group(1))
                event['signature_id'] = int(alert_match.group(2))
                event['revision'] = int(alert_match.group(3))
                event['message'] = alert_match.group(4).strip()
            
            # Parse priority
            priority_match = self.priority_pattern.search(log_line)
            if priority_match:
                event['priority'] = int(priority_match.group(1))
            else:
                event['priority'] = 3  # Default medium priority
            
            # Parse classification
            classification_match = self.classification_pattern.search(log_line)
            if classification_match:
                event['classification'] = classification_match.group(1).strip()
            
            # Extract IP addresses if present
            ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            ips = ip_pattern.findall(log_line)
            if len(ips) >= 2:
                event['source_ip'] = ips[0]
                event['destination_ip'] = ips[1]
            
            # Extract ports if present
            port_pattern = re.compile(r':(\d{1,5})\s*->')
            ports = port_pattern.findall(log_line)
            if ports:
                event['source_port'] = int(ports[0])
            
            return event
        
        except Exception as e:
            return None
    
    def parse_batch(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """Parse multiple SNORT log lines"""
        events = []
        for line in log_lines:
            event = self.parse(line)
            if event:
                events.append(event)
        return events


class SuricataParser(LogParser):
    """Parser for SURICATA EVE JSON logs"""
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse SURICATA JSON log line"""
        try:
            # SURICATA typically outputs JSON (EVE format)
            data = json.loads(log_line.strip())
            
            event = {
                'source': 'suricata',
                'raw_log': log_line.strip(),
                'timestamp': data.get('timestamp', datetime.now().isoformat())
            }
            
            # Extract alert information
            if 'alert' in data:
                alert = data['alert']
                event['signature'] = alert.get('signature', 'Unknown')
                event['signature_id'] = alert.get('signature_id', 0)
                event['category'] = alert.get('category', 'Unknown')
                event['severity'] = alert.get('severity', 3)
                event['gid'] = alert.get('gid', 1)
            
            # Extract network information
            if 'src_ip' in data:
                event['source_ip'] = data['src_ip']
            if 'dest_ip' in data:
                event['destination_ip'] = data['dest_ip']
            if 'src_port' in data:
                event['source_port'] = data['src_port']
            if 'dest_port' in data:
                event['destination_port'] = data['dest_port']
            if 'proto' in data:
                event['protocol'] = data['proto']
            
            # Extract flow information
            if 'flow' in data:
                event['flow_id'] = data['flow'].get('flow_id')
            
            return event
        
        except json.JSONDecodeError:
            # Fall back to text parsing if not JSON
            return self._parse_text_format(log_line)
        except Exception as e:
            return None
    
    def _parse_text_format(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse SURICATA text format (fallback)"""
        event = {
            'source': 'suricata',
            'raw_log': log_line.strip(),
            'timestamp': datetime.now().isoformat()
        }
        
        # Basic pattern matching for text format
        if '[**]' in log_line:
            parts = log_line.split('[**]')
            if len(parts) >= 2:
                event['signature'] = parts[1].strip()
        
        return event
    
    def parse_batch(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """Parse multiple SURICATA log lines"""
        events = []
        for line in log_lines:
            event = self.parse(line)
            if event:
                events.append(event)
        return events


class ZeekParser(LogParser):
    """Parser for ZEEK (Bro) TSV logs"""
    
    def __init__(self):
        self.headers = {}
        self.separator = '\t'
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse ZEEK log line"""
        try:
            line = log_line.strip()
            
            # Skip comments and directives
            if line.startswith('#'):
                # Parse header information
                if line.startswith('#fields'):
                    self.headers = line.split('\t')[1:]
                return None
            
            # Parse data line
            if not self.headers:
                # If no headers, use generic field names
                self.headers = ['field_' + str(i) for i in range(len(line.split('\t')))]
            
            values = line.split('\t')
            event = {
                'source': 'zeek',
                'raw_log': log_line.strip(),
                'timestamp': datetime.now().isoformat()
            }
            
            # Map values to headers
            for i, header in enumerate(self.headers):
                if i < len(values):
                    value = values[i]
                    # Convert common ZEEK placeholders
                    if value == '-':
                        value = None
                    event[header] = value
            
            # Normalize common field names
            if 'id.orig_h' in event:
                event['source_ip'] = event['id.orig_h']
            if 'id.resp_h' in event:
                event['destination_ip'] = event['id.resp_h']
            if 'id.orig_p' in event:
                event['source_port'] = event['id.orig_p']
            if 'id.resp_p' in event:
                event['destination_port'] = event['id.resp_p']
            
            return event
        
        except Exception as e:
            return None
    
    def parse_batch(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """Parse multiple ZEEK log lines"""
        events = []
        for line in log_lines:
            event = self.parse(line)
            if event:
                events.append(event)
        return events


class UniversalLogParser:
    """Universal parser that auto-detects log format"""
    
    def __init__(self):
        self.snort_parser = SnortParser()
        self.suricata_parser = SuricataParser()
        self.zeek_parser = ZeekParser()
    
    def detect_format(self, log_line: str) -> str:
        """Detect log format from line content"""
        if '[**]' in log_line and '[Priority:' in log_line:
            return 'snort'
        elif log_line.strip().startswith('{'):
            return 'suricata'
        elif '\t' in log_line or log_line.startswith('#'):
            return 'zeek'
        else:
            return 'unknown'
    
    def parse(self, log_line: str, format_hint: str = None) -> Optional[Dict[str, Any]]:
        """Parse log line with optional format hint"""
        if format_hint:
            parser_map = {
                'snort': self.snort_parser,
                'suricata': self.suricata_parser,
                'zeek': self.zeek_parser
            }
            parser = parser_map.get(format_hint)
            if parser:
                return parser.parse(log_line)
        
        # Auto-detect format
        detected_format = self.detect_format(log_line)
        parser_map = {
            'snort': self.snort_parser,
            'suricata': self.suricata_parser,
            'zeek': self.zeek_parser
        }
        
        parser = parser_map.get(detected_format)
        if parser:
            return parser.parse(log_line)
        
        return None
    
    def parse_batch(self, log_lines: List[str], format_hint: str = None) -> List[Dict[str, Any]]:
        """Parse multiple log lines"""
        events = []
        for line in log_lines:
            event = self.parse(line, format_hint)
            if event:
                events.append(event)
        return events
