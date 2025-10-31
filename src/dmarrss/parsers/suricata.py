"""
SURICATA EVE JSON log parser.

Parses SURICATA EVE (Extensible Event Format) JSON logs to canonical Event schema.
"""

import json
from datetime import datetime
from typing import Optional

from ..schemas import Event, LogSource


class SuricataParser:
    """
    Parser for SURICATA EVE JSON logs.

    EVE JSON is line-delimited JSON with fields like:
    - timestamp
    - src_ip, src_port, dest_ip, dest_port, proto
    - alert.signature, alert.category, alert.severity
    """

    def parse(self, log_line: str) -> Optional[Event]:
        """
        Parse a single SURICATA EVE JSON line into an Event.

        Returns None if parsing fails.
        """
        try:
            data = json.loads(log_line.strip())

            # Extract timestamp
            ts_str = data.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                ts = datetime.utcnow()

            # Extract network info
            src_ip = data.get("src_ip", "0.0.0.0")
            src_port = data.get("src_port")
            dst_ip = data.get("dest_ip", "0.0.0.0")
            dst_port = data.get("dest_port")
            proto = data.get("proto", "").upper()

            # Extract alert information
            alert = data.get("alert", {})
            signature = alert.get("signature", "")
            category = alert.get("category", "")
            severity = alert.get("severity")

            # Map severity to severity_hint
            severity_hint = "MEDIUM"
            if severity == 1:
                severity_hint = "CRITICAL"
            elif severity == 2:
                severity_hint = "HIGH"
            elif severity == 3:
                severity_hint = "MEDIUM"
            else:
                severity_hint = "LOW"

            # Build tags
            tags = []
            if category:
                tags.append(f"category:{category}")
            if severity:
                tags.append(f"severity:{severity}")
            event_type = data.get("event_type")
            if event_type:
                tags.append(f"event_type:{event_type}")

            # Build event_id
            flow_id = data.get("flow_id", "")
            event_id = f"suricata_{flow_id}_{int(ts.timestamp())}" if flow_id else None

            return Event(
                source=LogSource.SURICATA,
                ts=ts,
                event_id=event_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                category=category,
                signature=signature,
                severity_hint=severity_hint,
                raw=data,
                tags=tags,
            )

        except json.JSONDecodeError:
            return None
        except Exception:
            return None
