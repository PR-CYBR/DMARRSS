"""
SNORT alert log parser.

Parses SNORT fast alert format to canonical Event schema.
"""

import re
from datetime import datetime
from typing import Optional

from ..schemas import Event, LogSource


class SnortParser:
    """
    Parser for SNORT alert logs (fast alert format).

    Example SNORT fast alert line:
    [**] [1:2024364:1] ET MALWARE Detected [**] [Priority: 1] {TCP} 203.0.113.50:54321 -> 192.168.1.100:443
    """

    def __init__(self):
        # Pattern for [**] [gid:sid:rev] Message [**]
        self.alert_pattern = re.compile(r"\[\*\*\]\s*\[(\d+):(\d+):(\d+)\]\s*(.+?)\s*\[\*\*\]")
        # Pattern for [Priority: N]
        self.priority_pattern = re.compile(r"\[Priority:\s*(\d+)\]")
        # Pattern for [Classification: X]
        self.classification_pattern = re.compile(r"\[Classification:\s*(.+?)\]")
        # Pattern for {PROTO}
        self.proto_pattern = re.compile(r"\{(\w+)\}")
        # Pattern for IP:PORT -> IP:PORT
        self.address_pattern = re.compile(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{1,5}))?\s*->\s*"
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{1,5}))?"
        )

    def parse(self, log_line: str) -> Optional[Event]:
        """
        Parse a single SNORT alert line into an Event.

        Returns None if parsing fails.
        """
        try:
            raw_data = {"raw_line": log_line.strip()}

            # Extract alert signature
            alert_match = self.alert_pattern.search(log_line)
            if not alert_match:
                return None

            gid = alert_match.group(1)
            sid = alert_match.group(2)
            rev = alert_match.group(3)
            signature = alert_match.group(4).strip()

            raw_data["gid"] = int(gid)
            raw_data["sid"] = int(sid)
            raw_data["rev"] = int(rev)

            # Extract priority
            priority_match = self.priority_pattern.search(log_line)
            priority = int(priority_match.group(1)) if priority_match else 3
            raw_data["priority"] = priority

            # Map priority to severity_hint
            severity_hint = "MEDIUM"
            if priority == 1:
                severity_hint = "CRITICAL"
            elif priority == 2:
                severity_hint = "HIGH"
            elif priority == 3:
                severity_hint = "MEDIUM"
            else:
                severity_hint = "LOW"

            # Extract classification
            classification = None
            classification_match = self.classification_pattern.search(log_line)
            if classification_match:
                classification = classification_match.group(1).strip()
                raw_data["classification"] = classification

            # Extract protocol
            proto = None
            proto_match = self.proto_pattern.search(log_line)
            if proto_match:
                proto = proto_match.group(1).upper()

            # Extract source and destination addresses
            addr_match = self.address_pattern.search(log_line)
            if not addr_match:
                return None

            src_ip = addr_match.group(1)
            src_port = int(addr_match.group(2)) if addr_match.group(2) else None
            dst_ip = addr_match.group(3)
            dst_port = int(addr_match.group(4)) if addr_match.group(4) else None

            # Build tags from classification
            tags = []
            if classification:
                tags.append(f"classification:{classification}")
            tags.append(f"priority:{priority}")

            return Event(
                source=LogSource.SNORT,
                ts=datetime.utcnow(),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                category=classification,
                signature=signature,
                severity_hint=severity_hint,
                raw=raw_data,
                tags=tags,
                event_id=f"snort_{gid}_{sid}_{int(datetime.utcnow().timestamp())}",
            )

        except Exception:
            return None
