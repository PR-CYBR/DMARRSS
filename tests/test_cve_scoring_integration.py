"""
Integration tests for CVE enrichment in threat scoring
"""

from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import yaml

from dmarrss.enrichment.cve_enricher import CVEEnricher
from dmarrss.schemas import Event, LogSource
from dmarrss.scoring.threat_scorer import ThreatScorer
from dmarrss.store import Store


def load_test_config():
    """Load test configuration"""
    config_path = Path(__file__).parent.parent / "config" / "dmarrss_config.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)


class TestCVEScoringIntegration:
    """Tests for CVE enrichment integration with threat scoring"""

    @patch("httpx.Client")
    def test_scoring_with_cve_enrichment(self, mock_client_class):
        """Test that CVE enrichment augments threat score"""
        # Mock CVE API response
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
                                }
                            ]
                        },
                        "descriptions": [{"lang": "en", "value": "Critical RCE vulnerability"}],
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

        # Setup scorer with test config
        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)

        # Create event with CVE
        event = Event(
            source=LogSource.SNORT,
            ts=datetime.utcnow(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.10",
            signature="ET EXPLOIT CVE-2023-12345 Remote Code Execution",
            category="exploit",
            severity_hint="HIGH",
        )

        # Score event with enrichment
        enriched_event, components, final_score = scorer.enrich_and_score_event(event)

        # Verify enrichment was applied
        assert enriched_event.threat_score is not None
        assert enriched_event.threat_score == final_score

        # Verify CVE tag was added
        assert any("cve:" in tag for tag in enriched_event.tags)

        # Score should be augmented by CVSS data
        baseline_score = scorer.calculate_composite_score(components)
        assert final_score > baseline_score

    @patch("httpx.Client")
    def test_critical_cve_override(self, mock_client_class):
        """Test that critical CVE forces score to critical threshold"""
        # Mock critical CVE response
        mock_response = Mock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 10.0,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                        "descriptions": [{"lang": "en", "value": "Critical vuln"}],
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

        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)

        # Create low-severity event with critical CVE
        event = Event(
            source=LogSource.SNORT,
            ts=datetime.utcnow(),
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            signature="CVE-2023-99999 detected",
            severity_hint="LOW",
        )

        enriched_event, components, final_score = scorer.enrich_and_score_event(event)

        # Score should be forced to critical threshold (>= 0.9)
        assert final_score >= 0.9

    def test_scoring_without_cve(self):
        """Test scoring works normally without CVE"""
        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)

        event = Event(
            source=LogSource.SNORT,
            ts=datetime.utcnow(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            signature="Generic scan detected",
            category="scan",
        )

        enriched_event, components, final_score = scorer.enrich_and_score_event(event)

        # Should still work without enrichment
        assert enriched_event.threat_score is not None
        assert 0.0 <= final_score <= 1.0

    @patch("httpx.Client")
    def test_scoring_with_cve_timeout(self, mock_client_class):
        """Test scoring handles CVE API timeout gracefully"""
        import httpx

        # Mock timeout
        mock_client = Mock()
        mock_client.get.side_effect = httpx.TimeoutException("Timeout")
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=False)
        mock_client_class.return_value = mock_client

        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)

        event = Event(
            source=LogSource.SNORT,
            ts=datetime.utcnow(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            signature="CVE-2023-12345 exploit attempt",
        )

        # Should not raise exception, just use baseline score
        enriched_event, components, final_score = scorer.enrich_and_score_event(event)

        assert enriched_event.threat_score is not None
        assert 0.0 <= final_score <= 1.0

    @patch("httpx.Client")
    def test_multiple_cves_uses_max_score(self, mock_client_class):
        """Test that multiple CVEs use the maximum CVSS score"""

        def mock_get(url, params):
            cve_id = params["cveId"]
            if cve_id == "CVE-2023-11111":
                score = 9.8
                severity = "CRITICAL"
            else:
                score = 5.0
                severity = "MEDIUM"

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

        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)

        event = Event(
            source=LogSource.SNORT,
            ts=datetime.utcnow(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            signature="CVE-2023-11111 and CVE-2023-22222 detected",
        )

        enriched_event, components, final_score = scorer.enrich_and_score_event(event)

        # Score should reflect the higher CVE
        assert final_score >= 0.9  # Should be elevated by 9.8 CVSS score

    def test_cve_enricher_initialization(self):
        """Test that CVE enricher is properly initialized in scorer"""
        config = load_test_config()
        store = Store(":memory:")
        scorer = ThreatScorer(config, store)

        assert scorer.cve_enricher is not None
        assert isinstance(scorer.cve_enricher, CVEEnricher)
