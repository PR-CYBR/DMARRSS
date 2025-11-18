"""
CVE Enricher for DMARRSS

Fetches vulnerability intelligence using CVE and CVSS data from NIST NVD API.
Integrates severity intelligence into threat scoring engine.
"""

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx


class CVEEnricher:
    """
    CVE Enricher that fetches CVSS data from NIST NVD API.

    Features:
    - Detects CVE identifiers in event data
    - Fetches CVSS v3.1 scores and severity
    - In-memory caching with optional persistence
    - Fault-tolerant with graceful degradation
    """

    CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d+\b")
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        cache_file: str | None = None,
        timeout: float = 10.0,
        cache_ttl_hours: int = 24,
    ):
        """
        Initialize CVE Enricher.

        Args:
            cache_file: Optional path to persistent cache file
            timeout: HTTP request timeout in seconds
            cache_ttl_hours: Time-to-live for cached entries in hours
        """
        self.cache_file = Path(cache_file) if cache_file else None
        self.timeout = timeout
        self.cache_ttl = timedelta(hours=cache_ttl_hours)

        # In-memory cache: {cve_id: (data, timestamp)}
        self.cache: dict[str, tuple[dict[str, Any], datetime]] = {}

        # Load persistent cache if configured
        if self.cache_file:
            self._load_cache()

    def _load_cache(self) -> None:
        """Load cache from persistent storage."""
        if not self.cache_file or not self.cache_file.exists():
            return

        try:
            with open(self.cache_file) as f:
                data = json.load(f)
                # Convert timestamp strings back to datetime
                for cve_id, entry in data.items():
                    timestamp = datetime.fromisoformat(entry["timestamp"])
                    self.cache[cve_id] = (entry["data"], timestamp)
        except Exception:
            # Silently fail - cache is optional
            pass

    def _save_cache(self) -> None:
        """Save cache to persistent storage."""
        if not self.cache_file:
            return

        try:
            # Ensure directory exists
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)

            # Convert cache to serializable format
            data = {}
            for cve_id, (entry_data, timestamp) in self.cache.items():
                data[cve_id] = {
                    "data": entry_data,
                    "timestamp": timestamp.isoformat(),
                }

            with open(self.cache_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            # Silently fail - cache is optional
            pass

    def _is_cache_valid(self, timestamp: datetime) -> bool:
        """Check if cached entry is still valid."""
        return datetime.now() - timestamp < self.cache_ttl

    def detect_cves(self, text: str) -> list[str]:
        """
        Detect CVE identifiers in text.

        Args:
            text: Text to scan for CVE identifiers

        Returns:
            List of unique CVE identifiers found
        """
        matches = self.CVE_PATTERN.findall(text)
        return list(set(matches))  # Return unique CVEs

    def fetch_cve_data(self, cve_id: str) -> dict[str, Any] | None:
        """
        Fetch CVE data from NVD API or cache.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-12345")

        Returns:
            Dictionary with CVSS data or None if not found/failed
        """
        # Check cache first
        if cve_id in self.cache:
            cached_data, timestamp = self.cache[cve_id]
            if self._is_cache_valid(timestamp):
                return cached_data
            # Cache expired, will refresh

        # Fetch from API
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    self.NVD_API_URL,
                    params={"cveId": cve_id},
                )
                response.raise_for_status()
                data = response.json()

                # Parse response
                if "vulnerabilities" not in data or not data["vulnerabilities"]:
                    return None

                vuln = data["vulnerabilities"][0]
                cve_data = vuln.get("cve", {})

                # Extract CVSS v3.1 data (preferred over v3.0 and v2)
                cvss_data = self._extract_cvss_data(cve_data)

                if cvss_data:
                    # Cache the result
                    self.cache[cve_id] = (cvss_data, datetime.now())
                    self._save_cache()

                return cvss_data

        except httpx.TimeoutException:
            # Timeout - return cached data if available even if expired
            if cve_id in self.cache:
                cached_data, _ = self.cache[cve_id]
                return cached_data
            return None
        except Exception:
            # Any other error - return cached data if available
            if cve_id in self.cache:
                cached_data, _ = self.cache[cve_id]
                return cached_data
            return None

    def _extract_cvss_data(self, cve_data: dict[str, Any]) -> dict[str, Any] | None:
        """
        Extract CVSS v3.1 data from CVE JSON.

        Args:
            cve_data: CVE data from NVD API

        Returns:
            Dictionary with extracted CVSS data or None
        """
        try:
            # Get metrics (CVSS scores)
            metrics = cve_data.get("metrics", {})

            # Try CVSS v3.1 first (preferred)
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])

            # Use v3.1 if available, otherwise v3.0
            cvss_list = cvss_v31 if cvss_v31 else cvss_v30

            if not cvss_list:
                return None

            # Get primary metric (usually from NVD)
            cvss_metric = cvss_list[0]
            cvss_data_obj = cvss_metric.get("cvssData", {})

            # Extract description (first English description)
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Build enrichment data
            result = {
                "base_score": cvss_data_obj.get("baseScore", 0.0),
                "severity": cvss_data_obj.get("baseSeverity", "UNKNOWN").upper(),
                "exploitability_score": cvss_metric.get("exploitabilityScore"),
                "impact_score": cvss_metric.get("impactScore"),
                "attack_vector": cvss_data_obj.get("attackVector"),
                "attack_complexity": cvss_data_obj.get("attackComplexity"),
                "privileges_required": cvss_data_obj.get("privilegesRequired"),
                "user_interaction": cvss_data_obj.get("userInteraction"),
                "scope": cvss_data_obj.get("scope"),
                "confidentiality_impact": cvss_data_obj.get("confidentialityImpact"),
                "integrity_impact": cvss_data_obj.get("integrityImpact"),
                "availability_impact": cvss_data_obj.get("availabilityImpact"),
                "description": (
                    description[:500] if description else None
                ),  # Truncate long descriptions
            }

            return result

        except Exception:
            return None

    def enrich_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich event with CVE and CVSS data.

        Scans event for CVE identifiers and fetches CVSS data for each.
        Updates event with enrichment data.

        Args:
            event: Event dictionary to enrich

        Returns:
            Enriched event dictionary with CVE data
        """
        # Scan event for CVE identifiers
        # Check signature, category, and raw data
        text_to_scan = " ".join(
            [
                str(event.get("signature", "")),
                str(event.get("category", "")),
                str(event.get("raw", "")),
            ]
        )

        cve_ids = self.detect_cves(text_to_scan)

        if not cve_ids:
            return event

        # Fetch data for each CVE
        cve_enrichments = []
        max_base_score = 0.0
        max_severity = "UNKNOWN"

        for cve_id in cve_ids:
            cve_data = self.fetch_cve_data(cve_id)
            if cve_data:
                enrichment = {
                    "cve_id": cve_id,
                    "cvss_base_score": cve_data["base_score"],
                    "cvss_severity": cve_data["severity"],
                    "cve_summary": cve_data.get("description"),
                }
                cve_enrichments.append(enrichment)

                # Track maximum severity
                if cve_data["base_score"] > max_base_score:
                    max_base_score = cve_data["base_score"]
                    max_severity = cve_data["severity"]

        # Add enrichment to event
        if cve_enrichments:
            event["cve_enrichment"] = {
                "cves": cve_enrichments,
                "max_cvss_score": max_base_score,
                "max_severity": max_severity,
                "enrichment_timestamp": datetime.now().isoformat(),
            }

        return event

    def get_severity_mapping(self, cvss_score: float) -> str:
        """
        Map CVSS base score to severity level.

        Args:
            cvss_score: CVSS base score (0.0-10.0)

        Returns:
            Severity level string
        """
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0.0:
            return "LOW"
        else:
            return "NONE"

    def clear_cache(self) -> None:
        """Clear in-memory cache."""
        self.cache.clear()
        if self.cache_file and self.cache_file.exists():
            self.cache_file.unlink()
