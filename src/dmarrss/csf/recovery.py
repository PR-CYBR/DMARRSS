"""
Recovery Manager Module - NIST CSF 2.0 Recover Function

This module facilitates system recovery post-incident.

NIST CSF 2.0 Mapping: RC.RP (Recovery Planning), RC.CO (Recovery Communications)
"""

import json
import logging
import platform
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class RecoveryAction:
    """Represents a recovery action"""

    def __init__(
        self,
        action_type: str,
        description: str,
        status: str = "pending",
        details: dict[str, Any] | None = None,
    ):
        self.action_type = action_type
        self.description = description
        self.status = status  # pending, completed, failed
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {
            "action_type": self.action_type,
            "description": self.description,
            "status": self.status,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class RecoveryManager:
    """
    Recovery management and guidance.

    Implements NIST CSF 2.0 Recover function by:
    - Creating backups before changes
    - Tracking changes for reversion
    - Generating recovery reports
    - Providing recovery guidance
    """

    def __init__(self, config: dict):
        """
        Initialize recovery manager.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.data_dir = Path(config.get("system", {}).get("data_dir", "data"))
        self.recovery_dir = self.data_dir / "recovery"
        self.backup_dir = self.recovery_dir / "backups"
        self.recovery_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        self.changes_made: list[dict[str, Any]] = []
        self.recovery_actions: list[RecoveryAction] = []

    def create_backup(self, filepath: str | Path, description: str = "") -> Path | None:
        """
        Create a backup of a file before modification.

        Args:
            filepath: Path to file to backup
            description: Description of why backup is being made

        Returns:
            Path to backup file or None if backup failed
        """
        filepath = Path(filepath)

        if not filepath.exists():
            logger.warning(f"Cannot backup non-existent file: {filepath}")
            return None

        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{filepath.name}.{timestamp}.bak"
            backup_path = self.backup_dir / backup_name

            shutil.copy2(filepath, backup_path)

            self.changes_made.append(
                {
                    "type": "file_backup",
                    "original_path": str(filepath),
                    "backup_path": str(backup_path),
                    "description": description,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

            logger.info(f"Backup created: {backup_path}")
            return backup_path

        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return None

    def restore_from_backup(self, backup_path: str | Path) -> bool:
        """
        Restore a file from backup.

        Args:
            backup_path: Path to backup file

        Returns:
            True if successful, False otherwise
        """
        backup_path = Path(backup_path)

        if not backup_path.exists():
            logger.error(f"Backup file not found: {backup_path}")
            return False

        try:
            # Find original path from changes_made
            original_path = None
            for change in self.changes_made:
                if change.get("backup_path") == str(backup_path):
                    original_path = Path(change.get("original_path", ""))
                    break

            if not original_path:
                logger.error("Cannot determine original path for restore")
                return False

            shutil.copy2(backup_path, original_path)

            self.recovery_actions.append(
                RecoveryAction(
                    action_type="file_restore",
                    description=f"Restored {original_path} from backup",
                    status="completed",
                    details={
                        "original_path": str(original_path),
                        "backup_path": str(backup_path),
                    },
                )
            )

            logger.info(f"File restored from backup: {original_path}")
            return True

        except Exception as e:
            logger.error(f"Error restoring from backup: {e}")
            return False

    def track_change(self, change_type: str, description: str, details: dict[str, Any]) -> None:
        """
        Track a change made during response.

        Args:
            change_type: Type of change (service_stopped, firewall_rule, etc.)
            description: Human-readable description
            details: Detailed information about the change
        """
        change = {
            "type": change_type,
            "description": description,
            "details": details,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.changes_made.append(change)
        logger.info(f"Change tracked: {description}")

    def revert_change(self, change: dict[str, Any]) -> bool:
        """
        Attempt to revert a tracked change.

        Args:
            change: Change dictionary to revert

        Returns:
            True if successful, False otherwise
        """
        change_type = change.get("type", "")
        details = change.get("details", {})

        try:
            if change_type == "service_stopped":
                return self._restart_service(details.get("service_name", ""))
            elif change_type == "firewall_rule_added":
                return self._remove_firewall_rule(details.get("rule_id", ""))
            elif change_type == "file_backup":
                return self.restore_from_backup(details.get("backup_path", ""))
            else:
                logger.warning(f"Unknown change type for reversion: {change_type}")
                return False
        except Exception as e:
            logger.error(f"Error reverting change: {e}")
            return False

    def _restart_service(self, service_name: str) -> bool:
        """Restart a service (platform-specific)"""
        import subprocess

        system = platform.system()

        try:
            if system == "Linux":
                result = subprocess.run(
                    ["systemctl", "start", service_name],
                    capture_output=True,
                    timeout=30,
                )
                success = result.returncode == 0
            elif system == "Windows":
                result = subprocess.run(
                    ["sc", "start", service_name],
                    capture_output=True,
                    timeout=30,
                )
                success = result.returncode == 0
            else:
                logger.warning(f"Service restart not implemented for {system}")
                return False

            if success:
                self.recovery_actions.append(
                    RecoveryAction(
                        action_type="service_restart",
                        description=f"Restarted service: {service_name}",
                        status="completed",
                        details={"service_name": service_name},
                    )
                )
                logger.info(f"Service restarted: {service_name}")
            return success

        except Exception as e:
            logger.error(f"Error restarting service {service_name}: {e}")
            return False

    def _remove_firewall_rule(self, rule_id: str) -> bool:
        """Remove a firewall rule (platform-specific)"""
        # This would contain platform-specific firewall rule removal
        # For now, just log it
        logger.info(f"Would remove firewall rule: {rule_id}")
        return True

    def create_system_restore_point(self) -> bool:
        """
        Create a system restore point (Windows only).

        Returns:
            True if successful, False otherwise
        """
        system = platform.system()

        if system != "Windows":
            logger.info(f"System restore points not available on {system}")
            return False

        try:
            import subprocess

            # Create restore point using PowerShell
            ps_command = (
                'Checkpoint-Computer -Description "DMARRSS Pre-Response Backup" '
                '-RestorePointType "MODIFY_SETTINGS"'
            )

            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                timeout=60,
            )

            if result.returncode == 0:
                logger.info("System restore point created")
                self.track_change(
                    change_type="restore_point",
                    description="Created Windows System Restore point",
                    details={"timestamp": datetime.utcnow().isoformat()},
                )
                return True
            else:
                logger.error(f"Failed to create restore point: {result.stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Error creating system restore point: {e}")
            return False

    def generate_recovery_report(self) -> dict[str, Any]:
        """
        Generate a comprehensive recovery report.

        Returns:
            Recovery report dictionary
        """
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "csf_function": "RECOVER",
            "csf_category": "RC.RP - Recovery Planning",
            "changes_made": self.changes_made,
            "recovery_actions": [a.to_dict() for a in self.recovery_actions],
            "recommendations": self._generate_recommendations(),
            "summary": {
                "total_changes": len(self.changes_made),
                "recovery_actions_completed": sum(
                    1 for a in self.recovery_actions if a.status == "completed"
                ),
                "recovery_actions_pending": sum(
                    1 for a in self.recovery_actions if a.status == "pending"
                ),
            },
        }

        return report

    def _generate_recommendations(self) -> list[str]:
        """Generate recovery recommendations based on changes made"""
        recommendations = []

        # Check for stopped services
        stopped_services = [c for c in self.changes_made if c.get("type") == "service_stopped"]
        if stopped_services:
            recommendations.append(
                f"Verify {len(stopped_services)} stopped service(s) can be safely restarted"
            )

        # Check for firewall changes
        firewall_changes = [
            c for c in self.changes_made if c.get("type", "").startswith("firewall")
        ]
        if firewall_changes:
            recommendations.append("Review firewall changes and test network connectivity")

        # Check for file modifications
        file_changes = [
            c for c in self.changes_made if c.get("type") in ["file_backup", "file_modified"]
        ]
        if file_changes:
            recommendations.append(
                f"Review {len(file_changes)} file modification(s) and verify functionality"
            )

        # General recommendations
        recommendations.extend(
            [
                "Change all passwords for potentially compromised accounts",
                "Apply security patches to prevent re-exploitation",
                "Review and update security policies based on incident findings",
                "Schedule a post-incident review meeting",
            ]
        )

        return recommendations

    def save_recovery_report(self, report: dict[str, Any] | None = None) -> Path:
        """
        Save recovery report to JSON file.

        Args:
            report: Recovery report (if None, will generate)

        Returns:
            Path to saved report file
        """
        if report is None:
            report = self.generate_recovery_report()

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"recovery_report_{timestamp}.json"
        filepath = self.recovery_dir / filename

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        # Also save as latest.json
        latest_path = self.recovery_dir / "latest.json"
        with open(latest_path, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Recovery report saved to {filepath}")
        return filepath
