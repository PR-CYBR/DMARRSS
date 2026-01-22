"""
Threat Intelligence Module - NIST CSF 2.0 Detect Function

This module integrates external threat intelligence feeds to detect known threats.

NIST CSF 2.0 Mapping: DE.CM (Continuous Monitoring), DE.DP (Detection Processes)
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ThreatMatch:
    """Represents a threat intelligence match"""

    def __init__(
        self,
        ioc_type: str,
        ioc_value: str,
        source: str,
        description: str,
        severity: str = "HIGH",
        context: dict[str, Any] | None = None,
    ):
        self.ioc_type = ioc_type  # ip, domain, hash, url
        self.ioc_value = ioc_value
        self.source = source
        self.description = description
        self.severity = severity
        self.context = context or {}
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "source": self.source,
            "description": self.description,
            "severity": self.severity,
            "context": self.context,
            "timestamp": self.timestamp,
            "csf_function": "DETECT",
            "csf_category": "DE.DP - Detection Processes",
        }


class ThreatIntelligence:
    """
    Threat intelligence feed integration.

    Implements NIST CSF 2.0 Detect function by:
    - Fetching IoCs from threat feeds
    - Comparing IoCs against system data
    - Maintaining feed freshness
    """

    def __init__(self, config: dict):
        """
        Initialize threat intelligence module.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.data_dir = Path(config.get("system", {}).get("data_dir", "data"))
        self.intel_dir = self.data_dir / "threat_intel"
        self.intel_dir.mkdir(parents=True, exist_ok=True)

        # Get threat intel configuration
        intel_config = config.get("threat_intel", {})
        self.feeds = intel_config.get("feeds", {})
        self.update_interval_hours = intel_config.get("update_interval_hours", 24)
        self.enabled = intel_config.get("enabled", True)

        self.iocs = {
            "ips": set(),
            "domains": set(),
            "hashes": set(),
            "urls": set(),
        }
        self.matches: list[ThreatMatch] = []

    def load_feeds(self) -> None:
        """Load threat intelligence feeds"""
        if not self.enabled:
            logger.info("Threat intelligence disabled in config")
            return

        logger.info("Loading threat intelligence feeds...")

        # Load built-in sample feeds
        self._load_builtin_feeds()

        # Load custom feeds if configured
        for feed_name, feed_config in self.feeds.items():
            if feed_config.get("enabled", False):
                self._load_feed(feed_name, feed_config)

        logger.info(
            f"Loaded {len(self.iocs['ips'])} IPs, "
            f"{len(self.iocs['domains'])} domains, "
            f"{len(self.iocs['hashes'])} hashes"
        )

    def _load_builtin_feeds(self) -> None:
        """Load built-in sample threat indicators"""
        # Sample malicious IPs (for demonstration)
        malicious_ips = [
            "198.51.100.1",  # Example malicious IP
            "203.0.113.50",  # Example from sample data
            "192.0.2.1",  # TEST-NET-1
        ]
        self.iocs["ips"].update(malicious_ips)

        # Sample malicious domains
        malicious_domains = [
            "evil.example.com",
            "malware-download.net",
            "phishing-site.org",
        ]
        self.iocs["domains"].update(malicious_domains)

        # Sample malicious file hashes (MD5)
        malicious_hashes = [
            "44d88612fea8a8f36de82e1278abb02f",  # Example malware hash
            "275a021bbfb6489e54d471899f7db9d1",  # Example malware hash
        ]
        self.iocs["hashes"].update(malicious_hashes)

    def _load_feed(self, feed_name: str, feed_config: dict) -> None:
        """
        Load a specific threat feed.

        Args:
            feed_name: Name of the feed
            feed_config: Feed configuration
        """
        feed_type = feed_config.get("type", "file")
        feed_path = feed_config.get("path", "")

        if feed_type == "file":
            self._load_file_feed(feed_name, feed_path)
        elif feed_type == "url":
            self._load_url_feed(feed_name, feed_path)
        else:
            logger.warning(f"Unknown feed type: {feed_type}")

    def _load_file_feed(self, feed_name: str, feed_path: str) -> None:
        """Load threat indicators from a file"""
        filepath = Path(feed_path)
        if not filepath.exists():
            logger.warning(f"Feed file not found: {feed_path}")
            return

        try:
            with open(filepath) as f:
                if filepath.suffix == ".json":
                    data = json.load(f)
                    self._parse_feed_data(data)
                else:
                    # Plain text file, one indicator per line
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self._add_indicator(line)

            logger.info(f"Loaded feed: {feed_name}")
        except Exception as e:
            logger.error(f"Error loading feed {feed_name}: {e}")

    def _load_url_feed(self, feed_name: str, feed_url: str) -> None:
        """Load threat indicators from a URL"""
        try:
            import httpx

            response = httpx.get(feed_url, timeout=30)
            response.raise_for_status()

            if "application/json" in response.headers.get("content-type", ""):
                data = response.json()
                self._parse_feed_data(data)
            else:
                # Plain text
                for line in response.text.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._add_indicator(line)

            logger.info(f"Loaded URL feed: {feed_name}")
        except Exception as e:
            logger.error(f"Error loading URL feed {feed_name}: {e}")

    def _parse_feed_data(self, data: dict) -> None:
        """Parse structured feed data"""
        if "indicators" in data:
            for indicator in data["indicators"]:
                ioc_type = indicator.get("type", "")
                ioc_value = indicator.get("value", "")
                if ioc_type and ioc_value:
                    if ioc_type == "ip":
                        self.iocs["ips"].add(ioc_value)
                    elif ioc_type == "domain":
                        self.iocs["domains"].add(ioc_value)
                    elif ioc_type == "hash":
                        self.iocs["hashes"].add(ioc_value.lower())
                    elif ioc_type == "url":
                        self.iocs["urls"].add(ioc_value)

    def _add_indicator(self, indicator: str) -> None:
        """Add an indicator, auto-detecting type"""
        indicator = indicator.strip()

        # Try to detect type
        if self._is_ip(indicator):
            self.iocs["ips"].add(indicator)
        elif self._is_domain(indicator):
            self.iocs["domains"].add(indicator)
        elif self._is_hash(indicator):
            self.iocs["hashes"].add(indicator.lower())
        elif indicator.startswith("http"):
            self.iocs["urls"].add(indicator)

    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address"""
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def _is_domain(self, value: str) -> bool:
        """Check if value is a domain"""
        return "." in value and not self._is_ip(value)

    def _is_hash(self, value: str) -> bool:
        """Check if value is a hash (MD5, SHA1, SHA256)"""
        if not value.isalnum():
            return False
        return len(value) in [32, 40, 64]  # MD5, SHA1, SHA256

    def check_ip(
        self, ip_address: str, context: dict[str, Any] | None = None
    ) -> ThreatMatch | None:
        """
        Check if an IP is in threat intel.

        Args:
            ip_address: IP address to check
            context: Additional context

        Returns:
            ThreatMatch if found, None otherwise
        """
        if ip_address in self.iocs["ips"]:
            return ThreatMatch(
                ioc_type="ip",
                ioc_value=ip_address,
                source="threat_intel",
                description=f"Malicious IP detected: {ip_address}",
                severity="HIGH",
                context=context or {},
            )
        return None

    def check_domain(
        self, domain: str, context: dict[str, Any] | None = None
    ) -> ThreatMatch | None:
        """
        Check if a domain is in threat intel.

        Args:
            domain: Domain to check
            context: Additional context

        Returns:
            ThreatMatch if found, None otherwise
        """
        if domain in self.iocs["domains"]:
            return ThreatMatch(
                ioc_type="domain",
                ioc_value=domain,
                source="threat_intel",
                description=f"Malicious domain detected: {domain}",
                severity="HIGH",
                context=context or {},
            )
        return None

    def check_file_hash(
        self, file_hash: str, context: dict[str, Any] | None = None
    ) -> ThreatMatch | None:
        """
        Check if a file hash is in threat intel.

        Args:
            file_hash: File hash to check (MD5, SHA1, or SHA256)
            context: Additional context

        Returns:
            ThreatMatch if found, None otherwise
        """
        file_hash = file_hash.lower()
        if file_hash in self.iocs["hashes"]:
            return ThreatMatch(
                ioc_type="hash",
                ioc_value=file_hash,
                source="threat_intel",
                description=f"Malicious file hash detected: {file_hash}",
                severity="CRITICAL",
                context=context or {},
            )
        return None

    def scan_event(self, event: dict[str, Any]) -> list[ThreatMatch]:
        """
        Scan an event for threat indicators.

        Args:
            event: Event dictionary to scan

        Returns:
            List of threat matches
        """
        if not self.iocs["ips"] and not self.iocs["domains"] and not self.iocs["hashes"]:
            self.load_feeds()

        matches = []

        # Check source IP
        src_ip = event.get("src_ip", "")
        if src_ip:
            match = self.check_ip(src_ip, {"event_field": "src_ip"})
            if match:
                matches.append(match)

        # Check destination IP
        dst_ip = event.get("dst_ip", "")
        if dst_ip:
            match = self.check_ip(dst_ip, {"event_field": "dst_ip"})
            if match:
                matches.append(match)

        # Check for domains in signature or raw data
        signature = event.get("signature", "")
        raw = str(event.get("raw", ""))
        text = f"{signature} {raw}"

        for domain in self.iocs["domains"]:
            if domain in text:
                match = self.check_domain(domain, {"found_in": "event_data"})
                if match:
                    matches.append(match)
                    break  # Avoid multiple matches for same event

        return matches

    def save_matches(self, matches: list[ThreatMatch] | None = None) -> Path:
        """
        Save threat matches to JSON file.

        Args:
            matches: List of matches (if None, uses self.matches)

        Returns:
            Path to saved matches file
        """
        if matches is None:
            matches = self.matches

        match_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "csf_function": "DETECT",
            "csf_category": "DE.DP - Detection Processes",
            "matches": [m.to_dict() for m in matches],
            "summary": {
                "total": len(matches),
                "critical": sum(1 for m in matches if m.severity == "CRITICAL"),
                "high": sum(1 for m in matches if m.severity == "HIGH"),
                "medium": sum(1 for m in matches if m.severity == "MEDIUM"),
            },
        }

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_matches_{timestamp}.json"
        filepath = self.intel_dir / filename

        with open(filepath, "w") as f:
            json.dump(match_data, f, indent=2)

        # Also save as latest.json
        latest_path = self.intel_dir / "latest.json"
        with open(latest_path, "w") as f:
            json.dump(match_data, f, indent=2)

        logger.info(f"Threat matches saved to {filepath}")
        return filepath

    def needs_update(self) -> bool:
        """Check if feeds need updating based on last update time"""
        last_update_file = self.intel_dir / "last_update.txt"

        if not last_update_file.exists():
            return True

        try:
            with open(last_update_file) as f:
                last_update_str = f.read().strip()
            last_update = datetime.fromisoformat(last_update_str)
            age = datetime.utcnow() - last_update
            return age > timedelta(hours=self.update_interval_hours)
        except Exception:
            return True

    def mark_updated(self) -> None:
        """Mark feeds as updated"""
        last_update_file = self.intel_dir / "last_update.txt"
        with open(last_update_file, "w") as f:
            f.write(datetime.utcnow().isoformat())
