"""
Anomaly Detection Module - NIST CSF 2.0 Detect Function

This module detects deviations from baseline behavior to identify unknown threats.

NIST CSF 2.0 Mapping: DE.CM (Continuous Monitoring), DE.AE (Anomalies and Events)
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class Anomaly:
    """Represents a detected anomaly"""

    def __init__(
        self,
        anomaly_type: str,
        severity: str,
        description: str,
        baseline_value: Any,
        current_value: Any,
        deviation: float,
        details: dict[str, Any] | None = None,
    ):
        self.anomaly_type = anomaly_type
        self.severity = severity
        self.description = description
        self.baseline_value = baseline_value
        self.current_value = current_value
        self.deviation = deviation
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "deviation": self.deviation,
            "details": self.details,
            "timestamp": self.timestamp,
            "csf_function": "DETECT",
            "csf_category": "DE.AE - Anomalies and Events",
        }


class AnomalyDetector:
    """
    Anomaly detection using baseline comparison.
    
    Implements NIST CSF 2.0 Detect function by identifying:
    - New/unusual processes
    - Abnormal network connections
    - User activity pattern changes
    - Resource usage anomalies
    """

    def __init__(self, config: dict):
        """
        Initialize anomaly detector.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.data_dir = Path(config.get("system", {}).get("data_dir", "data"))
        self.anomaly_dir = self.data_dir / "anomalies"
        self.anomaly_dir.mkdir(parents=True, exist_ok=True)

        # Get anomaly detection thresholds from config
        anomaly_config = config.get("anomaly_detection", {})
        self.process_threshold = anomaly_config.get("process_threshold", 0.2)  # 20% deviation
        self.network_threshold = anomaly_config.get("network_threshold", 0.3)  # 30% deviation
        self.user_threshold = anomaly_config.get("user_threshold", 0.5)  # 50% deviation

        self.baseline = None
        self.anomalies: list[Anomaly] = []

    def load_baseline(self, baseline_data: dict[str, Any] | None = None) -> None:
        """
        Load baseline data for comparison.
        
        Args:
            baseline_data: Baseline inventory data (if None, loads from inventory/latest.json)
        """
        if baseline_data is None:
            baseline_file = self.data_dir / "inventory" / "latest.json"
            if baseline_file.exists():
                with open(baseline_file) as f:
                    baseline_data = json.load(f)
            else:
                logger.warning("No baseline inventory found")
                return

        self.baseline = baseline_data
        logger.info("Baseline data loaded for anomaly detection")

    def detect_process_anomalies(self, current_processes: list[dict[str, Any]]) -> list[Anomaly]:
        """
        Detect process anomalies compared to baseline.
        
        Args:
            current_processes: Current list of running processes
            
        Returns:
            List of detected anomalies
        """
        if not self.baseline:
            logger.warning("No baseline loaded, skipping process anomaly detection")
            return []

        anomalies = []
        baseline_processes = self.baseline.get("processes", [])

        # Create sets of process names
        baseline_names = {p.get("name", "").lower() for p in baseline_processes}
        current_names = {p.get("name", "").lower() for p in current_processes}

        # Detect new processes
        new_processes = current_names - baseline_names
        if new_processes:
            # Filter out common system processes
            significant_new = [p for p in new_processes if not self._is_common_process(p)]
            if significant_new:
                anomalies.append(
                    Anomaly(
                        anomaly_type="new_processes",
                        severity="MEDIUM",
                        description=f"{len(significant_new)} new process(es) detected",
                        baseline_value=len(baseline_names),
                        current_value=len(current_names),
                        deviation=len(significant_new) / max(len(baseline_names), 1),
                        details={"new_processes": list(significant_new)[:10]},
                    )
                )

        # Check for significant increase in process count
        baseline_count = len(baseline_processes)
        current_count = len(current_processes)
        if baseline_count > 0:
            deviation = (current_count - baseline_count) / baseline_count
            if deviation > self.process_threshold:
                anomalies.append(
                    Anomaly(
                        anomaly_type="process_count_increase",
                        severity="LOW",
                        description=f"Process count increased by {deviation*100:.1f}%",
                        baseline_value=baseline_count,
                        current_value=current_count,
                        deviation=deviation,
                        details={},
                    )
                )

        return anomalies

    def _is_common_process(self, process_name: str) -> bool:
        """Check if a process is commonly found on systems"""
        common_processes = {
            "systemd", "kthreadd", "rcu_sched", "bash", "sh", "sshd",
            "cron", "dbus-daemon", "systemd-journal", "python", "python3",
            "node", "java", "docker", "containerd", "nginx", "apache2",
        }
        return process_name.lower() in common_processes

    def detect_network_anomalies(self, current_network: dict[str, Any]) -> list[Anomaly]:
        """
        Detect network anomalies compared to baseline.
        
        Args:
            current_network: Current network information
            
        Returns:
            List of detected anomalies
        """
        if not self.baseline:
            logger.warning("No baseline loaded, skipping network anomaly detection")
            return []

        anomalies = []
        baseline_network = self.baseline.get("network", {})

        # Compare listening ports
        baseline_ports = {
            p.get("port") for p in baseline_network.get("listening_ports", [])
        }
        current_ports = {
            p.get("port") for p in current_network.get("listening_ports", [])
        }

        # Detect new listening ports
        new_ports = current_ports - baseline_ports
        if new_ports:
            anomalies.append(
                Anomaly(
                    anomaly_type="new_listening_ports",
                    severity="HIGH",
                    description=f"{len(new_ports)} new listening port(s) detected",
                    baseline_value=len(baseline_ports),
                    current_value=len(current_ports),
                    deviation=len(new_ports) / max(len(baseline_ports), 1),
                    details={"new_ports": sorted(list(new_ports))},
                )
            )

        # Detect closed ports (might indicate service failure)
        closed_ports = baseline_ports - current_ports
        if closed_ports and len(closed_ports) > 2:  # More than 2 ports closed
            anomalies.append(
                Anomaly(
                    anomaly_type="closed_listening_ports",
                    severity="MEDIUM",
                    description=f"{len(closed_ports)} listening port(s) closed",
                    baseline_value=len(baseline_ports),
                    current_value=len(current_ports),
                    deviation=len(closed_ports) / max(len(baseline_ports), 1),
                    details={"closed_ports": sorted(list(closed_ports))},
                )
            )

        return anomalies

    def detect_user_anomalies(self, current_users: list[dict[str, Any]]) -> list[Anomaly]:
        """
        Detect user account and activity anomalies.
        
        Args:
            current_users: Current user sessions
            
        Returns:
            List of detected anomalies
        """
        if not self.baseline:
            logger.warning("No baseline loaded, skipping user anomaly detection")
            return []

        anomalies = []
        baseline_users = self.baseline.get("users", [])

        # Create sets of usernames
        baseline_names = {u.get("name", "") for u in baseline_users}
        current_names = {u.get("name", "") for u in current_users}

        # Detect new user sessions
        new_users = current_names - baseline_names
        if new_users:
            anomalies.append(
                Anomaly(
                    anomaly_type="new_user_sessions",
                    severity="MEDIUM",
                    description=f"{len(new_users)} new user session(s) detected",
                    baseline_value=len(baseline_names),
                    current_value=len(current_names),
                    deviation=len(new_users) / max(len(baseline_names), 1),
                    details={"new_users": list(new_users)},
                )
            )

        # Check for unusual session count
        baseline_count = len(baseline_users)
        current_count = len(current_users)
        if baseline_count > 0:
            deviation = abs(current_count - baseline_count) / baseline_count
            if deviation > self.user_threshold:
                severity = "HIGH" if current_count > baseline_count else "LOW"
                anomalies.append(
                    Anomaly(
                        anomaly_type="unusual_session_count",
                        severity=severity,
                        description=f"User session count changed by {deviation*100:.1f}%",
                        baseline_value=baseline_count,
                        current_value=current_count,
                        deviation=deviation,
                        details={},
                    )
                )

        return anomalies

    def detect_all_anomalies(self, current_inventory: dict[str, Any]) -> list[Anomaly]:
        """
        Detect all types of anomalies.
        
        Args:
            current_inventory: Current system inventory
            
        Returns:
            List of all detected anomalies
        """
        if not self.baseline:
            self.load_baseline()

        if not self.baseline:
            logger.error("Cannot detect anomalies without baseline")
            return []

        logger.info("Detecting anomalies...")
        self.anomalies = []

        # Detect process anomalies
        if "processes" in current_inventory:
            self.anomalies.extend(
                self.detect_process_anomalies(current_inventory["processes"])
            )

        # Detect network anomalies
        if "network" in current_inventory:
            self.anomalies.extend(
                self.detect_network_anomalies(current_inventory["network"])
            )

        # Detect user anomalies
        if "users" in current_inventory:
            self.anomalies.extend(
                self.detect_user_anomalies(current_inventory["users"])
            )

        logger.info(f"Anomaly detection complete: {len(self.anomalies)} anomalies found")
        return self.anomalies

    def save_anomalies(self, anomalies: list[Anomaly] | None = None) -> Path:
        """
        Save anomalies to JSON file.
        
        Args:
            anomalies: List of anomalies (if None, uses self.anomalies)
            
        Returns:
            Path to saved anomalies file
        """
        if anomalies is None:
            anomalies = self.anomalies

        anomaly_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "csf_function": "DETECT",
            "csf_category": "DE.AE - Anomalies and Events",
            "anomalies": [a.to_dict() for a in anomalies],
            "summary": {
                "total": len(anomalies),
                "high": sum(1 for a in anomalies if a.severity == "HIGH"),
                "medium": sum(1 for a in anomalies if a.severity == "MEDIUM"),
                "low": sum(1 for a in anomalies if a.severity == "LOW"),
            },
        }

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"anomalies_{timestamp}.json"
        filepath = self.anomaly_dir / filename

        with open(filepath, 'w') as f:
            json.dump(anomaly_data, f, indent=2)

        # Also save as latest.json
        latest_path = self.anomaly_dir / "latest.json"
        with open(latest_path, 'w') as f:
            json.dump(anomaly_data, f, indent=2)

        logger.info(f"Anomalies saved to {filepath}")
        return filepath
