"""
Unit tests for CVE Enricher
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dmarrss.enrichment.cve_enricher import CVEEnricher


class TestCVEDetection:
    """Tests for CVE detection"""

    def test_detect_single_cve(self):
        """Test detection of single CVE"""
        enricher = CVEEnricher()
        text = "This is an exploit for CVE-2023-12345"
        cves = enricher.detect_cves(text)
        assert cves == ["CVE-2023-12345"]

    def test_detect_multiple_cves(self):
        """Test detection of multiple CVEs"""
        enricher = CVEEnricher()
        text = "CVE-2023-12345 and CVE-2024-67890 are critical"
        cves = enricher.detect_cves(text)
        assert set(cves) == {"CVE-2023-12345", "CVE-2024-67890"}

    def test_detect_no_cves(self):
        """Test detection when no CVEs present"""
        enricher = CVEEnricher()
        text = "No vulnerabilities here"
        cves = enricher.detect_cves(text)
        assert cves == []

    def test_detect_duplicate_cves(self):
        """Test detection with duplicates returns unique CVEs"""
        enricher = CVEEnricher()
        text = "CVE-2023-12345 mentioned twice: CVE-2023-12345"
        cves = enricher.detect_cves(text)
        assert cves == ["CVE-2023-12345"]

    def test_detect_invalid_format(self):
        """Test that invalid CVE formats are not matched"""
        enricher = CVEEnricher()
        text = "CVE-23-12345 CVE-2023-ABC CVE2023-12345"
        cves = enricher.detect_cves(text)
        assert cves == []


class TestCVEFetching:
    """Tests for CVE data fetching from API"""

    @patch("httpx.Client")
    def test_fetch_cve_success(self, mock_client_class):
        """Test successful CVE data fetch"""
        # Mock API response
        mock_response = Mock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                        "attackVector": "NETWORK",
                                    },
                                    "exploitabilityScore": 3.9,
                                    "impactScore": 5.9,
                                }
                            ]
                        },
                        "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                    }
                }
            ]
        }
        mock_response.raise_for_status = Mock()

        mock_client = Mock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        enricher = CVEEnricher()
        data = enricher.fetch_cve_data("CVE-2023-12345")

        assert data is not None
        assert data["base_score"] == 9.8
        assert data["severity"] == "CRITICAL"
        assert data["attack_vector"] == "NETWORK"
        assert "Test vulnerability" in data["description"]

    @patch("httpx.Client")
    def test_fetch_cve_not_found(self, mock_client_class):
        """Test fetching non-existent CVE"""
        mock_response = Mock()
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_response.raise_for_status = Mock()

        mock_client = Mock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        enricher = CVEEnricher()
        data = enricher.fetch_cve_data("CVE-9999-99999")

        assert data is None

    @patch("httpx.Client")
    def test_fetch_cve_timeout(self, mock_client_class):
        """Test handling of API timeout"""
        import httpx

        mock_client = Mock()
        mock_client.get.side_effect = httpx.TimeoutException("Timeout")
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        enricher = CVEEnricher()
        data = enricher.fetch_cve_data("CVE-2023-12345")

        # Should return None on timeout
        assert data is None

    @patch("httpx.Client")
    def test_fetch_cve_api_error(self, mock_client_class):
        """Test handling of API error"""
        mock_client = Mock()
        mock_client.get.side_effect = Exception("API Error")
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        enricher = CVEEnricher()
        data = enricher.fetch_cve_data("CVE-2023-12345")

        # Should return None on error
        assert data is None


class TestCVECaching:
    """Tests for CVE data caching"""

    @patch("httpx.Client")
    def test_cache_hit(self, mock_client_class):
        """Test cache hit on second fetch"""
        # Setup mock for first call only
        mock_response = Mock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                        "descriptions": [{"lang": "en", "value": "Test"}],
                    }
                }
            ]
        }
        mock_response.raise_for_status = Mock()

        mock_client = Mock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        enricher = CVEEnricher()

        # First fetch - should hit API
        data1 = enricher.fetch_cve_data("CVE-2023-12345")
        assert data1 is not None
        assert mock_client.get.call_count == 1

        # Second fetch - should use cache
        data2 = enricher.fetch_cve_data("CVE-2023-12345")
        assert data2 is not None
        assert data2 == data1
        assert mock_client.get.call_count == 1  # No additional API call

    def test_cache_expiry(self):
        """Test that expired cache entries are refreshed"""
        enricher = CVEEnricher(cache_ttl_hours=1)

        # Manually add expired cache entry
        old_timestamp = datetime.now() - timedelta(hours=2)
        enricher.cache["CVE-2023-12345"] = (
            {"base_score": 5.0, "severity": "MEDIUM"},
            old_timestamp,
        )

        # Check that cache is marked as invalid
        assert not enricher._is_cache_valid(old_timestamp)

    def test_persistent_cache(self, tmp_path):
        """Test persistent cache save and load"""
        cache_file = tmp_path / "test_cache.json"

        # Create enricher and populate cache
        enricher1 = CVEEnricher(cache_file=str(cache_file))
        test_data = {
            "base_score": 9.8,
            "severity": "CRITICAL",
            "description": "Test",
        }
        enricher1.cache["CVE-2023-12345"] = (test_data, datetime.now())
        enricher1._save_cache()

        # Verify cache file was created
        assert cache_file.exists()

        # Load cache in new enricher instance
        enricher2 = CVEEnricher(cache_file=str(cache_file))
        assert "CVE-2023-12345" in enricher2.cache
        cached_data, _ = enricher2.cache["CVE-2023-12345"]
        assert cached_data["base_score"] == 9.8

    def test_cache_clear(self, tmp_path):
        """Test cache clearing"""
        cache_file = tmp_path / "test_cache.json"
        enricher = CVEEnricher(cache_file=str(cache_file))

        # Add to cache
        enricher.cache["CVE-2023-12345"] = (
            {"base_score": 9.8, "severity": "CRITICAL"},
            datetime.now(),
        )
        enricher._save_cache()

        assert len(enricher.cache) > 0
        assert cache_file.exists()

        # Clear cache
        enricher.clear_cache()

        assert len(enricher.cache) == 0
        assert not cache_file.exists()


class TestEventEnrichment:
    """Tests for event enrichment"""

    @patch("httpx.Client")
    def test_enrich_event_with_cve(self, mock_client_class):
        """Test enriching event that contains CVE"""
        # Mock API response
        mock_response = Mock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                        "descriptions": [{"lang": "en", "value": "Critical vulnerability"}],
                    }
                }
            ]
        }
        mock_response.raise_for_status = Mock()

        mock_client = Mock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        enricher = CVEEnricher()

        event = {
            "signature": "Exploit attempt for CVE-2023-12345",
            "category": "exploit",
            "source_ip": "10.0.0.1",
        }

        enriched = enricher.enrich_event(event)

        # Check enrichment was added
        assert "cve_enrichment" in enriched
        assert enriched["cve_enrichment"]["max_cvss_score"] == 9.8
        assert enriched["cve_enrichment"]["max_severity"] == "CRITICAL"
        assert len(enriched["cve_enrichment"]["cves"]) == 1
        assert enriched["cve_enrichment"]["cves"][0]["cve_id"] == "CVE-2023-12345"

    def test_enrich_event_without_cve(self):
        """Test enriching event without CVE"""
        enricher = CVEEnricher()

        event = {
            "signature": "Generic suspicious activity",
            "category": "suspicious",
        }

        enriched = enricher.enrich_event(event)

        # Should not add enrichment
        assert "cve_enrichment" not in enriched

    @patch("httpx.Client")
    def test_enrich_event_multiple_cves(self, mock_client_class):
        """Test enriching event with multiple CVEs"""

        # Mock API responses
        def mock_get(url, params):
            cve_id = params["cveId"]
            if cve_id == "CVE-2023-11111":
                score = 9.8
                severity = "CRITICAL"
            else:
                score = 7.5
                severity = "HIGH"

            response = Mock()
            response.json.return_value = {
                "vulnerabilities": [
                    {
                        "cve": {
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": score,
                                            "baseSeverity": severity,
                                        }
                                    }
                                ]
                            },
                            "descriptions": [{"lang": "en", "value": "Test"}],
                        }
                    }
                ]
            }
            response.raise_for_status = Mock()
            return response

        mock_client = Mock()
        mock_client.get = mock_get
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        enricher = CVEEnricher()

        event = {
            "signature": "Exploits CVE-2023-11111 and CVE-2023-22222",
            "category": "exploit",
        }

        enriched = enricher.enrich_event(event)

        # Should have both CVEs
        assert len(enriched["cve_enrichment"]["cves"]) == 2
        # Should use max score
        assert enriched["cve_enrichment"]["max_cvss_score"] == 9.8
        assert enriched["cve_enrichment"]["max_severity"] == "CRITICAL"


class TestSeverityMapping:
    """Tests for CVSS to severity mapping"""

    def test_severity_critical(self):
        """Test critical severity mapping"""
        enricher = CVEEnricher()
        assert enricher.get_severity_mapping(10.0) == "CRITICAL"
        assert enricher.get_severity_mapping(9.5) == "CRITICAL"
        assert enricher.get_severity_mapping(9.0) == "CRITICAL"

    def test_severity_high(self):
        """Test high severity mapping"""
        enricher = CVEEnricher()
        assert enricher.get_severity_mapping(8.9) == "HIGH"
        assert enricher.get_severity_mapping(8.0) == "HIGH"
        assert enricher.get_severity_mapping(7.0) == "HIGH"

    def test_severity_medium(self):
        """Test medium severity mapping"""
        enricher = CVEEnricher()
        assert enricher.get_severity_mapping(6.9) == "MEDIUM"
        assert enricher.get_severity_mapping(5.0) == "MEDIUM"
        assert enricher.get_severity_mapping(4.0) == "MEDIUM"

    def test_severity_low(self):
        """Test low severity mapping"""
        enricher = CVEEnricher()
        assert enricher.get_severity_mapping(3.9) == "LOW"
        assert enricher.get_severity_mapping(2.0) == "LOW"
        assert enricher.get_severity_mapping(0.1) == "LOW"

    def test_severity_none(self):
        """Test none severity mapping"""
        enricher = CVEEnricher()
        assert enricher.get_severity_mapping(0.0) == "NONE"
