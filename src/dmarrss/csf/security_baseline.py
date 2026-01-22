"""
Security Baseline Module - NIST CSF 2.0 Protect Function

This module checks system security posture and configurations to identify
protective actions needed to harden the system.

NIST CSF 2.0 Mapping: PR.IP (Information Protection Processes and Procedures)
"""

import json
import logging
import platform
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SecurityFinding:
    """Represents a security finding"""

    def __init__(
        self,
        severity: str,
        category: str,
        title: str,
        description: str,
        recommendation: str,
        details: dict[str, Any] | None = None,
    ):
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.category = category
        self.title = title
        self.description = description
        self.recommendation = recommendation
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class SecurityBaseline:
    """
    Cross-platform security baseline checker.

    Implements NIST CSF 2.0 Protect function by checking:
    - Firewall status
    - Antivirus/security software presence
    - Security configurations
    - Logging status
    """

    def __init__(self, config: dict):
        """
        Initialize security baseline checker.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.data_dir = Path(config.get("system", {}).get("data_dir", "data"))
        self.findings_dir = self.data_dir / "findings"
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.findings: list[SecurityFinding] = []

    def check_firewall_status(self) -> None:
        """Check firewall status (platform-specific)"""
        system = platform.system()

        try:
            if system == "Linux":
                self._check_linux_firewall()
            elif system == "Windows":
                self._check_windows_firewall()
            elif system == "Darwin":
                self._check_macos_firewall()
        except Exception as e:
            logger.error(f"Error checking firewall status: {e}")
            self.findings.append(
                SecurityFinding(
                    severity="MEDIUM",
                    category="Firewall",
                    title="Unable to verify firewall status",
                    description=f"Error checking firewall: {e}",
                    recommendation="Manually verify firewall is enabled and configured",
                )
            )

    def _check_linux_firewall(self) -> None:
        """Check Linux firewall (iptables/ufw/firewalld)"""
        import subprocess

        # Check UFW
        try:
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "Status: inactive" in result.stdout:
                self.findings.append(
                    SecurityFinding(
                        severity="HIGH",
                        category="Firewall",
                        title="UFW firewall is disabled",
                        description="The UFW firewall is not active",
                        recommendation="Enable UFW with: sudo ufw enable",
                    )
                )
            elif "Status: active" in result.stdout:
                logger.info("UFW firewall is active")
            return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check firewalld
        try:
            result = subprocess.run(
                ["firewall-cmd", "--state"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "not running" in result.stdout.lower():
                self.findings.append(
                    SecurityFinding(
                        severity="HIGH",
                        category="Firewall",
                        title="firewalld is not running",
                        description="The firewalld service is not active",
                        recommendation="Start firewalld with: sudo systemctl start firewalld",
                    )
                )
            elif "running" in result.stdout.lower():
                logger.info("firewalld is running")
            return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check iptables
        try:
            result = subprocess.run(
                ["iptables", "-L", "-n"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Check if there are any rules
                lines = result.stdout.split("\n")
                if len(lines) < 10:  # Very few rules might indicate no firewall
                    self.findings.append(
                        SecurityFinding(
                            severity="MEDIUM",
                            category="Firewall",
                            title="Minimal iptables rules detected",
                            description="Firewall may not be properly configured",
                            recommendation="Review and configure iptables rules",
                        )
                    )
                else:
                    logger.info("iptables rules are configured")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.findings.append(
                SecurityFinding(
                    severity="MEDIUM",
                    category="Firewall",
                    title="Unable to detect firewall",
                    description="Could not find UFW, firewalld, or iptables",
                    recommendation="Install and configure a firewall",
                )
            )

    def _check_windows_firewall(self) -> None:
        """Check Windows Firewall"""
        import subprocess

        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "OFF" in result.stdout:
                self.findings.append(
                    SecurityFinding(
                        severity="CRITICAL",
                        category="Firewall",
                        title="Windows Firewall is disabled",
                        description="One or more firewall profiles are turned off",
                        recommendation="Enable Windows Firewall for all profiles",
                        details={"output": result.stdout},
                    )
                )
            elif "ON" in result.stdout:
                logger.info("Windows Firewall is enabled")
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.error(f"Error checking Windows Firewall: {e}")

    def _check_macos_firewall(self) -> None:
        """Check macOS Application Firewall"""
        import subprocess

        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            state = result.stdout.strip()
            if state == "0":
                self.findings.append(
                    SecurityFinding(
                        severity="HIGH",
                        category="Firewall",
                        title="macOS firewall is disabled",
                        description="The Application Firewall is not enabled",
                        recommendation="Enable firewall in System Preferences > Security & Privacy",
                    )
                )
            else:
                logger.info("macOS firewall is enabled")
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.error(f"Error checking macOS firewall: {e}")

    def check_antivirus_presence(self) -> None:
        """Check for antivirus/security software"""
        system = platform.system()

        try:
            if system == "Linux":
                self._check_linux_antivirus()
            elif system == "Windows":
                self._check_windows_defender()
            elif system == "Darwin":
                # macOS has built-in XProtect, less common to have AV
                logger.info("macOS XProtect is built-in")
        except Exception as e:
            logger.error(f"Error checking antivirus: {e}")

    def _check_linux_antivirus(self) -> None:
        """Check for Linux antivirus (ClamAV)"""
        import subprocess

        try:
            result = subprocess.run(
                ["which", "clamscan"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("ClamAV detected")
            else:
                self.findings.append(
                    SecurityFinding(
                        severity="INFO",
                        category="Antivirus",
                        title="No antivirus detected",
                        description="ClamAV or other antivirus not found",
                        recommendation="Consider installing ClamAV for malware scanning",
                    )
                )
        except subprocess.TimeoutExpired:
            pass

    def _check_windows_defender(self) -> None:
        """Check Windows Defender status"""
        import subprocess

        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled, AntivirusEnabled",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout
            if "False" in output:
                self.findings.append(
                    SecurityFinding(
                        severity="CRITICAL",
                        category="Antivirus",
                        title="Windows Defender protection disabled",
                        description="Real-time protection or antivirus is disabled",
                        recommendation="Enable Windows Defender real-time protection",
                        details={"output": output},
                    )
                )
            else:
                logger.info("Windows Defender is active")
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.error(f"Error checking Windows Defender: {e}")

    def check_logging_enabled(self) -> None:
        """Check if system logging is enabled"""
        system = platform.system()

        try:
            if system == "Linux":
                self._check_linux_logging()
            elif system == "Windows":
                self._check_windows_logging()
            elif system == "Darwin":
                # macOS has built-in logging via syslog/unified logging
                logger.info("macOS has built-in logging system")
        except Exception as e:
            logger.error(f"Error checking logging: {e}")

    def _check_linux_logging(self) -> None:
        """Check Linux syslog/rsyslog/systemd-journald"""
        import subprocess

        # Check for rsyslog
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "rsyslog"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "inactive" in result.stdout or "failed" in result.stdout:
                self.findings.append(
                    SecurityFinding(
                        severity="MEDIUM",
                        category="Logging",
                        title="rsyslog service is not active",
                        description="System logging service is not running",
                        recommendation="Start rsyslog: sudo systemctl start rsyslog",
                    )
                )
            else:
                logger.info("rsyslog is active")
            return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check for systemd-journald
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "systemd-journald"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "inactive" in result.stdout or "failed" in result.stdout:
                self.findings.append(
                    SecurityFinding(
                        severity="HIGH",
                        category="Logging",
                        title="systemd-journald is not active",
                        description="System logging service is not running",
                        recommendation="Check systemd-journald status",
                    )
                )
            else:
                logger.info("systemd-journald is active")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _check_windows_logging(self) -> None:
        """Check Windows Event Log service"""
        import subprocess

        try:
            result = subprocess.run(
                ["sc", "query", "eventlog"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "RUNNING" not in result.stdout:
                self.findings.append(
                    SecurityFinding(
                        severity="CRITICAL",
                        category="Logging",
                        title="Windows Event Log service not running",
                        description="The Event Log service is not active",
                        recommendation="Start the Windows Event Log service",
                    )
                )
            else:
                logger.info("Windows Event Log service is running")
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.error(f"Error checking Windows Event Log: {e}")

    def check_weak_configurations(self) -> None:
        """Check for weak configurations"""
        # Check for common security misconfigurations
        self._check_ssh_config()

    def _check_ssh_config(self) -> None:
        """Check SSH configuration for weak settings"""
        ssh_config_path = Path("/etc/ssh/sshd_config")

        if not ssh_config_path.exists():
            return  # SSH not installed or not Linux

        try:
            with open(ssh_config_path) as f:
                content = f.read()

            # Check for PermitRootLogin
            if "PermitRootLogin yes" in content:
                self.findings.append(
                    SecurityFinding(
                        severity="HIGH",
                        category="Configuration",
                        title="SSH root login enabled",
                        description="Root login via SSH is allowed",
                        recommendation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
                    )
                )

            # Check for PasswordAuthentication
            if "PasswordAuthentication yes" in content:
                self.findings.append(
                    SecurityFinding(
                        severity="MEDIUM",
                        category="Configuration",
                        title="SSH password authentication enabled",
                        description="Password-based SSH authentication is allowed",
                        recommendation="Consider using key-based authentication only",
                    )
                )

        except (OSError, PermissionError) as e:
            logger.warning(f"Cannot read SSH config: {e}")

    def run_all_checks(self) -> list[SecurityFinding]:
        """
        Run all security baseline checks.

        Returns:
            List of security findings
        """
        logger.info("Running security baseline checks...")
        self.findings = []

        self.check_firewall_status()
        self.check_antivirus_presence()
        self.check_logging_enabled()
        self.check_weak_configurations()

        logger.info(f"Security baseline check complete: {len(self.findings)} findings")
        return self.findings

    def save_findings(self, findings: list[SecurityFinding] | None = None) -> Path:
        """
        Save findings to JSON file.

        Args:
            findings: List of findings (if None, will run checks)

        Returns:
            Path to saved findings file
        """
        if findings is None:
            findings = self.run_all_checks()

        findings_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "csf_function": "PROTECT",
            "csf_category": "PR.IP - Information Protection Processes",
            "findings": [f.to_dict() for f in findings],
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
                "high": sum(1 for f in findings if f.severity == "HIGH"),
                "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
                "low": sum(1 for f in findings if f.severity == "LOW"),
                "info": sum(1 for f in findings if f.severity == "INFO"),
            },
        }

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"findings_{timestamp}.json"
        filepath = self.findings_dir / filename

        with open(filepath, "w") as f:
            json.dump(findings_data, f, indent=2)

        # Also save as latest.json
        latest_path = self.findings_dir / "latest.json"
        with open(latest_path, "w") as f:
            json.dump(findings_data, f, indent=2)

        logger.info(f"Findings saved to {filepath}")
        return filepath

    def load_findings(self, filepath: str | Path | None = None) -> dict[str, Any]:
        """
        Load findings from JSON file.

        Args:
            filepath: Path to findings file (defaults to latest.json)

        Returns:
            Findings dictionary
        """
        if filepath is None:
            filepath = self.findings_dir / "latest.json"
        else:
            filepath = Path(filepath)

        if not filepath.exists():
            logger.warning(f"Findings file not found: {filepath}")
            return {}

        with open(filepath) as f:
            return json.load(f)
