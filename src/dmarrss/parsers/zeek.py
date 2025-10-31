"""
ZEEK TSV log parser.

Parses ZEEK tab-separated value logs with #fields headers to canonical Event schema.
"""

from datetime import datetime

from ..schemas import Event, LogSource


class ZeekParser:
    """
    Parser for ZEEK TSV logs.

    ZEEK logs are tab-separated with a #fields header line defining column names.
    Example:
    #fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration
    """

    def __init__(self):
        self.fields: list[str] | None = None

    def set_fields(self, header_line: str) -> None:
        """
        Parse #fields header to set column mapping.

        Example: #fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto
        """
        if header_line.startswith("#fields"):
            parts = header_line.strip().split("\t")
            self.fields = [f.strip() for f in parts[1:]]  # Skip "#fields"

    def parse(self, log_line: str, fields: list[str] | None = None) -> Event | None:
        """
        Parse a single ZEEK TSV line into an Event.

        If fields is provided, use it; otherwise use self.fields.
        Returns None if parsing fails or if it's a comment line.
        """
        # Handle comment lines
        if log_line.startswith("#"):
            if log_line.startswith("#fields"):
                self.set_fields(log_line)
            return None

        try:
            # Use provided fields or stored fields
            field_names = fields if fields is not None else self.fields
            if not field_names:
                return None

            # Split on tabs
            values = log_line.strip().split("\t")
            if len(values) < len(field_names):
                # Pad with empty strings if needed
                values.extend([""] * (len(field_names) - len(values)))

            # Create field->value mapping
            data: dict[str, str] = dict(zip(field_names, values))

            # Extract timestamp (ZEEK uses Unix epoch)
            ts_str = data.get("ts", "")
            try:
                ts = datetime.fromtimestamp(float(ts_str))
            except Exception:
                ts = datetime.utcnow()

            # Extract network info
            # ZEEK uses id.orig_h, id.orig_p, id.resp_h, id.resp_p
            src_ip = data.get("id.orig_h", "0.0.0.0")
            src_port_str = data.get("id.orig_p", "")
            dst_ip = data.get("id.resp_h", "0.0.0.0")
            dst_port_str = data.get("id.resp_p", "")
            proto = data.get("proto", "").upper()

            src_port = int(src_port_str) if src_port_str and src_port_str != "-" else None
            dst_port = int(dst_port_str) if dst_port_str and dst_port_str != "-" else None

            # Extract service as category
            service = data.get("service", "")
            conn_state = data.get("conn_state", "")

            # Build tags
            tags = []
            if service and service != "-":
                tags.append(f"service:{service}")
            if conn_state and conn_state != "-":
                tags.append(f"conn_state:{conn_state}")

            # Build signature from available fields
            signature_parts = []
            if service and service != "-":
                signature_parts.append(f"service={service}")
            if conn_state and conn_state != "-":
                signature_parts.append(f"conn_state={conn_state}")
            signature = " ".join(signature_parts) if signature_parts else "ZEEK connection"

            # ZEEK logs don't have severity, default to LOW
            severity_hint = "LOW"

            # Build event_id from uid if available
            uid = data.get("uid", "")
            event_id = f"zeek_{uid}_{int(ts.timestamp())}" if uid else None

            return Event(
                source=LogSource.ZEEK,
                ts=ts,
                event_id=event_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                category=service if service != "-" else None,
                signature=signature,
                severity_hint=severity_hint,
                raw=data,
                tags=tags,
            )

        except Exception:
            return None

    def parse_batch(self, log_lines: list[str]) -> list[Event]:
        """
        Parse multiple ZEEK lines, handling #fields header automatically.

        Returns list of successfully parsed Events.
        """
        events = []
        for line in log_lines:
            event = self.parse(line)
            if event:
                events.append(event)
        return events
