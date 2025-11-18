"""
DMARRSS Threat Scoring Engine

Implements config-driven composite threat scoring with:
- Pattern matching
- Context relevance (CIDR matching)
- Historical severity tracking
- Source reputation
- Anomaly detection
- CVE/CVSS enrichment
"""

import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..enrichment import CVEEnricher
from ..schemas import Event, ThreatScoreComponents
from ..store import Store


class ThreatScorer:
    """
    Config-driven threat scorer with weighted composite scoring.

    Scoring components:
    1. Pattern match - signature/category keyword matching
    2. Context relevance - CIDR inclusion matching
    3. Historical severity - rolling window from store
    4. Source reputation - lookup from CSV
    5. Anomaly score - frequency-based z-score
    """

    def __init__(self, config: dict[str, Any], store: Store | None = None):
        """Initialize scorer with config and optional store"""
        self.config = config
        self.store = store

        # Load scoring weights
        scoring_config = config.get("scoring", {})
        self.weights = scoring_config.get("weights", {})
        self.cidr_include = [
            ipaddress.ip_network(c) for c in scoring_config.get("cidr_include", [])
        ]
        self.reputation_csv_path = scoring_config.get("reputation_csv", "")

        # Initialize CVE enricher
        cve_cache_file = scoring_config.get("cve_cache_file", "./data/cache/cve_cache.json")
        self.cve_enricher = CVEEnricher(
            cache_file=cve_cache_file,
            timeout=scoring_config.get("cve_timeout", 10.0),
            cache_ttl_hours=scoring_config.get("cve_cache_ttl_hours", 24),
        )

        # Load reputation data
        self.reputation_map: dict[str, float] = {}
        self._load_reputation()

        # Threat patterns for pattern matching
        self._init_threat_patterns()

        # Frequency tracking for anomaly detection
        self.event_counts: dict[str, int] = {}
        self.last_reset = datetime.utcnow()

    def _init_threat_patterns(self) -> None:
        """Initialize known threat patterns"""
        self.threat_patterns = {
            "exploit": {
                "keywords": ["exploit", "overflow", "injection", "shellcode", "RCE", "CVE"],
                "base_score": 0.9,
            },
            "malware": {
                "keywords": ["malware", "trojan", "virus", "ransomware", "backdoor", "botnet"],
                "base_score": 0.85,
            },
            "scan": {
                "keywords": ["scan", "probe", "reconnaissance", "enumeration", "discovery"],
                "base_score": 0.4,
            },
            "dos": {
                "keywords": ["dos", "ddos", "flood", "amplification", "denial"],
                "base_score": 0.7,
            },
            "intrusion": {
                "keywords": [
                    "intrusion",
                    "unauthorized",
                    "breach",
                    "compromise",
                    "penetration",
                ],
                "base_score": 0.8,
            },
            "suspicious": {
                "keywords": ["suspicious", "anomaly", "unusual", "abnormal", "irregular"],
                "base_score": 0.5,
            },
        }

    def _load_reputation(self) -> None:
        """Load reputation CSV if it exists"""
        if not self.reputation_csv_path:
            return

        csv_path = Path(self.reputation_csv_path)
        if not csv_path.exists():
            # Create default reputation file
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            with open(csv_path, "w") as f:
                f.write("ip,score,comment\n")
                f.write("0.0.0.0,0.1,Default\n")
            return

        # Parse CSV
        try:
            with open(csv_path) as f:
                lines = f.readlines()
                for line in lines[1:]:  # Skip header
                    parts = line.strip().split(",")
                    if len(parts) >= 2:
                        ip = parts[0].strip()
                        score = float(parts[1].strip())
                        self.reputation_map[ip] = score
        except Exception:
            pass

    def calculate_pattern_score(self, event: Event) -> float:
        """
        Calculate pattern matching score based on signature and category.

        Returns score 0.0-1.0 based on threat pattern keywords.
        """
        text = f"{event.signature or ''} {event.category or ''}".lower()

        max_score = 0.0
        for pattern_data in self.threat_patterns.values():
            for keyword in pattern_data["keywords"]:
                if keyword in text:
                    max_score = max(max_score, pattern_data["base_score"])

        # Boost score based on severity_hint
        if event.severity_hint:
            hint = event.severity_hint.upper()
            if hint == "CRITICAL":
                max_score = max(max_score, 0.9)
            elif hint == "HIGH":
                max_score = max(max_score, 0.7)
            elif hint == "MEDIUM":
                max_score = max(max_score, 0.5)

        return min(max_score, 1.0)

    def calculate_context_relevance(self, event: Event) -> float:
        """
        Calculate context relevance score.

        Checks if source/dest IPs are in configured CIDR ranges.
        Higher score if event involves internal/monitored networks.
        """
        if not self.cidr_include:
            return 0.5  # Default if no CIDRs configured

        try:
            src_ip = ipaddress.ip_address(event.src_ip)
            dst_ip = ipaddress.ip_address(event.dst_ip)

            src_match = any(src_ip in cidr for cidr in self.cidr_include)
            dst_match = any(dst_ip in cidr for cidr in self.cidr_include)

            # Both internal = high relevance
            if src_match and dst_match:
                return 0.9
            # One internal = medium relevance
            elif src_match or dst_match:
                return 0.7
            # Neither internal = lower relevance
            else:
                return 0.3

        except Exception:
            return 0.5

    def calculate_historical_severity(self, event: Event) -> float:
        """
        Calculate historical severity from recent similar events.

        Uses store to query recent events from same source IP.
        Returns average threat score from last 24h.
        """
        if not self.store:
            return 0.5  # Default if no store

        try:
            # Query recent events
            since = datetime.utcnow() - timedelta(hours=24)
            recent_events = self.store.get_events(limit=100, since=since)

            # Filter to same source IP
            src_events = [e for e in recent_events if e.get("src_ip") == event.src_ip]

            if not src_events:
                return 0.5

            # Calculate average threat score
            scores = [e.get("threat_score", 0.5) for e in src_events if e.get("threat_score")]
            if scores:
                return sum(scores) / len(scores)

        except Exception:
            pass

        return 0.5

    def calculate_source_reputation(self, event: Event) -> float:
        """
        Calculate source reputation score.

        Looks up source IP in reputation map.
        Returns reputation score or default.
        """
        src_ip = event.src_ip
        return self.reputation_map.get(src_ip, 0.5)

    def calculate_anomaly_score(self, event: Event) -> float:
        """
        Calculate anomaly score based on frequency.

        Simple frequency-based anomaly detection using z-score.
        Tracks event counts by signature and detects spikes.
        """
        # Reset counts every hour
        now = datetime.utcnow()
        if (now - self.last_reset).total_seconds() > 3600:
            self.event_counts.clear()
            self.last_reset = now

        # Count events by signature
        key = f"{event.source}:{event.signature}"
        self.event_counts[key] = self.event_counts.get(key, 0) + 1

        # Calculate z-score (simplified)
        counts = list(self.event_counts.values())
        if len(counts) < 2:
            return 0.2  # Not enough data

        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        std_dev = variance**0.5

        if std_dev == 0:
            return 0.2

        z_score = (self.event_counts[key] - mean) / std_dev

        # Map z-score to 0-1 range
        # z > 2 is anomalous
        anomaly_score = min(abs(z_score) / 3.0, 1.0)
        return anomaly_score

    def calculate_composite_score(self, components: ThreatScoreComponents) -> float:
        """
        Calculate weighted composite threat score from components.

        Uses config weights to combine component scores.
        """
        score = 0.0
        score += components.pattern_match * self.weights.get("pattern_match", 0.3)
        score += components.context_relevance * self.weights.get("context_relevance", 0.25)
        score += components.historical_severity * self.weights.get("historical_severity", 0.2)
        score += components.source_reputation * self.weights.get("source_reputation", 0.15)
        score += components.anomaly_score * self.weights.get("anomaly_score", 0.1)

        return min(score, 1.0)

    def score_event(self, event: Event) -> ThreatScoreComponents:
        """
        Score an event and return all components.

        This calculates all 5 scoring components and returns them.
        The composite score should be calculated separately.
        """
        components = ThreatScoreComponents(
            pattern_match=self.calculate_pattern_score(event),
            context_relevance=self.calculate_context_relevance(event),
            historical_severity=self.calculate_historical_severity(event),
            source_reputation=self.calculate_source_reputation(event),
            anomaly_score=self.calculate_anomaly_score(event),
        )

        return components

    def enrich_and_score_event(self, event: Event) -> tuple[Event, ThreatScoreComponents, float]:
        """
        Enrich event with CVE data and calculate threat score.

        This is the main entry point that:
        1. Enriches event with CVE/CVSS data
        2. Calculates baseline threat score components
        3. Augments score based on CVSS data
        4. Applies classification override for critical CVEs

        Args:
            event: Event to enrich and score

        Returns:
            Tuple of (enriched_event, score_components, final_score)
        """
        # Convert Event to dict for enrichment
        event_dict = event.model_dump()

        # Enrich with CVE data
        enriched_dict = self.cve_enricher.enrich_event(event_dict)

        # Calculate baseline score components
        components = self.score_event(event)

        # Calculate baseline composite score
        baseline_score = self.calculate_composite_score(components)

        # Apply CVSS score augmentation if CVE data present
        final_score = baseline_score
        cve_enrichment = enriched_dict.get("cve_enrichment")

        if cve_enrichment:
            max_cvss_score = cve_enrichment.get("max_cvss_score", 0.0)
            max_severity = cve_enrichment.get("max_severity", "UNKNOWN")

            # Get CVE weight from config (default 0.3)
            cve_weight = self.config.get("scoring", {}).get("cve_weight", 0.3)

            # Normalize CVSS score to 0-1 range and apply weight
            cvss_contribution = (max_cvss_score / 10.0) * cve_weight

            # Augment baseline score
            final_score = min(baseline_score + cvss_contribution, 1.0)

            # Classification override for critical/high CVEs
            if max_severity in ["CRITICAL", "HIGH"] and max_cvss_score >= 9.0:
                # Force score to critical threshold
                final_score = max(final_score, 0.9)

        # Update event with enrichment data
        if cve_enrichment:
            event.raw = enriched_dict.get("raw", event.raw)
            # Store CVE enrichment in event tags
            event.tags = event.tags or []
            for cve_data in cve_enrichment.get("cves", []):
                event.tags.append(f"cve:{cve_data['cve_id']}")

        # Set computed fields
        event.threat_score = final_score

        return event, components, final_score
