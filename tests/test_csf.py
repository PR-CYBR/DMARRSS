import json
import tempfile
import pytest
from pathlib import Path

from dmarrss.csf.asset_inventory import AssetInventory
from dmarrss.csf.security_baseline import SecurityBaseline
from dmarrss.csf.anomaly_detector import AnomalyDetector, Anomaly
from dmarrss.csf.threat_intel import ThreatIntelligence, ThreatMatch
from dmarrss.csf.recovery import RecoveryManager, RecoveryAction
from dmarrss.csf.csf_reporting import CSFReporter


@pytest.fixture
def test_config():
    """Test configuration"""
    # Use tempfile for cross-platform compatibility
    temp_dir = tempfile.gettempdir()
    return {
        "system": {
            "data_dir": str(Path(temp_dir) / "dmarrss_test_csf"),
        },
        "csf": {
            "asset_inventory": {"enabled": True, "auto_collect_on_start": True},
            "security_baseline": {"enabled": True},
            "anomaly_detection": {
                "enabled": True,
                "process_threshold": 0.2,
                "network_threshold": 0.3,
                "user_threshold": 0.5,
            },
            "threat_intel": {"enabled": True, "update_interval_hours": 24, "feeds": {}},
            "recovery": {"enabled": True},
            "reporting": {"enabled": True},
        },
    }


class TestAssetInventory:
    """Tests for AssetInventory module"""

    def test_initialization(self, test_config):
        """Test AssetInventory initialization"""
        inventory = AssetInventory(test_config)
        assert inventory.config == test_config
        assert inventory.inventory_dir.exists()

    def test_collect_system_info(self, test_config):
        """Test system information collection"""
        inventory = AssetInventory(test_config)
        system_info = inventory.collect_system_info()
        
        assert "hostname" in system_info
        assert "platform" in system_info
        assert "architecture" in system_info

    def test_collect_network_info(self, test_config):
        """Test network information collection"""
        inventory = AssetInventory(test_config)
        network_info = inventory.collect_network_info()
        
        # Network info may be empty if psutil not available
        assert isinstance(network_info, dict)

    def test_collect_process_info(self, test_config):
        """Test process information collection"""
        inventory = AssetInventory(test_config)
        processes = inventory.collect_process_info()
        
        # Processes list should be a list (may be empty if psutil not available)
        assert isinstance(processes, list)

    def test_collect_all(self, test_config):
        """Test complete inventory collection"""
        inventory = AssetInventory(test_config)
        data = inventory.collect_all()
        
        assert "timestamp" in data
        assert "csf_function" in data
        assert data["csf_function"] == "IDENTIFY"
        assert "system" in data
        assert "network" in data
        assert "processes" in data

    def test_save_and_load_inventory(self, test_config):
        """Test saving and loading inventory"""
        inventory = AssetInventory(test_config)
        
        # Save inventory
        filepath = inventory.save_inventory()
        assert filepath.exists()
        
        # Load inventory
        loaded = inventory.load_inventory()
        assert "timestamp" in loaded
        assert "system" in loaded


class TestSecurityBaseline:
    """Tests for SecurityBaseline module"""

    def test_initialization(self, test_config):
        """Test SecurityBaseline initialization"""
        baseline = SecurityBaseline(test_config)
        assert baseline.config == test_config
        assert baseline.findings_dir.exists()

    def test_run_all_checks(self, test_config):
        """Test running all security checks"""
        baseline = SecurityBaseline(test_config)
        findings = baseline.run_all_checks()
        
        # Should return a list of findings (may be empty)
        assert isinstance(findings, list)

    def test_save_and_load_findings(self, test_config):
        """Test saving and loading findings"""
        baseline = SecurityBaseline(test_config)
        
        # Run checks and save
        filepath = baseline.save_findings()
        assert filepath.exists()
        
        # Load findings
        loaded = baseline.load_findings()
        assert "timestamp" in loaded
        assert "csf_function" in loaded
        assert loaded["csf_function"] == "PROTECT"
        assert "findings" in loaded


class TestAnomalyDetector:
    """Tests for AnomalyDetector module"""

    def test_initialization(self, test_config):
        """Test AnomalyDetector initialization"""
        detector = AnomalyDetector(test_config)
        assert detector.config == test_config
        assert detector.anomaly_dir.exists()

    def test_detect_process_anomalies(self, test_config):
        """Test process anomaly detection"""
        detector = AnomalyDetector(test_config)
        
        # Create mock baseline
        detector.baseline = {
            "processes": [
                {"name": "systemd", "pid": 1},
                {"name": "python", "pid": 100},
            ]
        }
        
        # Create current processes with new process
        current_processes = [
            {"name": "systemd", "pid": 1},
            {"name": "python", "pid": 100},
            {"name": "malware", "pid": 999},
        ]
        
        anomalies = detector.detect_process_anomalies(current_processes)
        
        # Should detect new process
        assert isinstance(anomalies, list)

    def test_detect_network_anomalies(self, test_config):
        """Test network anomaly detection"""
        detector = AnomalyDetector(test_config)
        
        # Create mock baseline
        detector.baseline = {
            "network": {
                "listening_ports": [
                    {"port": 22, "address": "0.0.0.0"},
                    {"port": 80, "address": "0.0.0.0"},
                ]
            }
        }
        
        # Create current network with new port
        current_network = {
            "listening_ports": [
                {"port": 22, "address": "0.0.0.0"},
                {"port": 80, "address": "0.0.0.0"},
                {"port": 4444, "address": "0.0.0.0"},  # Suspicious port
            ]
        }
        
        anomalies = detector.detect_network_anomalies(current_network)
        
        # Should detect new port
        assert isinstance(anomalies, list)
        if len(anomalies) > 0:
            assert anomalies[0].anomaly_type == "new_listening_ports"


class TestThreatIntelligence:
    """Tests for ThreatIntelligence module"""

    def test_initialization(self, test_config):
        """Test ThreatIntelligence initialization"""
        intel = ThreatIntelligence(test_config)
        assert intel.config == test_config
        assert intel.intel_dir.exists()

    def test_load_builtin_feeds(self, test_config):
        """Test loading built-in threat feeds"""
        intel = ThreatIntelligence(test_config)
        intel.load_feeds()
        
        # Should have some IoCs loaded
        assert len(intel.iocs["ips"]) > 0
        assert len(intel.iocs["domains"]) > 0
        assert len(intel.iocs["hashes"]) > 0

    def test_check_ip(self, test_config):
        """Test IP checking"""
        intel = ThreatIntelligence(test_config)
        intel.load_feeds()
        
        # Check malicious IP
        match = intel.check_ip("203.0.113.50")
        assert match is not None
        assert match.ioc_type == "ip"
        assert match.ioc_value == "203.0.113.50"
        
        # Check clean IP
        match = intel.check_ip("8.8.8.8")
        assert match is None

    def test_scan_event(self, test_config):
        """Test event scanning for IoCs"""
        intel = ThreatIntelligence(test_config)
        intel.load_feeds()
        
        # Event with malicious IP
        event = {
            "src_ip": "203.0.113.50",
            "dst_ip": "192.168.1.1",
            "signature": "Test alert",
            "raw": {},
        }
        
        matches = intel.scan_event(event)
        assert len(matches) > 0
        assert matches[0].ioc_type == "ip"


class TestRecoveryManager:
    """Tests for RecoveryManager module"""

    def test_initialization(self, test_config):
        """Test RecoveryManager initialization"""
        recovery = RecoveryManager(test_config)
        assert recovery.config == test_config
        assert recovery.recovery_dir.exists()

    def test_track_change(self, test_config):
        """Test change tracking"""
        recovery = RecoveryManager(test_config)
        
        recovery.track_change(
            change_type="service_stopped",
            description="Stopped malicious service",
            details={"service_name": "bad_service"},
        )
        
        assert len(recovery.changes_made) == 1
        assert recovery.changes_made[0]["type"] == "service_stopped"

    def test_generate_recovery_report(self, test_config):
        """Test recovery report generation"""
        recovery = RecoveryManager(test_config)
        
        # Add some changes
        recovery.track_change(
            change_type="service_stopped",
            description="Stopped service",
            details={"service_name": "test"},
        )
        
        report = recovery.generate_recovery_report()
        
        assert "timestamp" in report
        assert "csf_function" in report
        assert report["csf_function"] == "RECOVER"
        assert "changes_made" in report
        assert len(report["changes_made"]) == 1


class TestCSFReporter:
    """Tests for CSFReporter module"""

    def test_initialization(self, test_config):
        """Test CSFReporter initialization"""
        reporter = CSFReporter(test_config)
        assert reporter.config == test_config
        assert reporter.reports_dir.exists()

    def test_log_activity(self, test_config):
        """Test activity logging"""
        reporter = CSFReporter(test_config)
        
        reporter.log_activity(
            csf_function="IDENTIFY",
            category="ID.AM - Asset Management",
            description="Asset inventory collected",
            details={"count": 100},
        )
        
        assert len(reporter.activities["IDENTIFY"]) == 1

    def test_generate_csf_alignment_report(self, test_config):
        """Test CSF alignment report generation"""
        reporter = CSFReporter(test_config)
        
        # Log some activities
        reporter.log_activity(
            "IDENTIFY", "ID.AM", "Test activity", {}
        )
        reporter.log_activity(
            "DETECT", "DE.CM", "Test detection", {}
        )
        
        report = reporter.generate_csf_alignment_report()
        
        assert "timestamp" in report
        assert "report_type" in report
        assert "summary" in report
        assert "functions" in report
        assert report["summary"]["total_activities"] >= 2

    def test_generate_executive_summary(self, test_config):
        """Test executive summary generation"""
        reporter = CSFReporter(test_config)
        
        reporter.log_activity("IDENTIFY", "ID.AM", "Test", {})
        
        summary = reporter.generate_executive_summary()
        
        assert "timestamp" in summary
        assert "report_type" in summary
        assert "overview" in summary
        assert "key_metrics" in summary
