"""
CSF Reporting Module - NIST CSF 2.0 Govern Function

This module provides governance reporting and CSF alignment tracking.

NIST CSF 2.0 Mapping: GV.OC (Organizational Context), GV.RM (Risk Management)
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class CSFReporter:
    """
    NIST CSF 2.0 alignment reporting.

    Implements NIST CSF 2.0 Govern function by:
    - Tracking activities by CSF function
    - Generating compliance reports
    - Providing management-friendly summaries
    """

    def __init__(self, config: dict):
        """
        Initialize CSF reporter.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.data_dir = Path(config.get("system", {}).get("data_dir", "data"))
        self.reports_dir = self.data_dir / "csf_reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # Initialize activity counters
        self.activities = {
            "IDENTIFY": [],
            "PROTECT": [],
            "DETECT": [],
            "RESPOND": [],
            "RECOVER": [],
            "GOVERN": [],
        }

    def log_activity(
        self,
        csf_function: str,
        category: str,
        description: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Log an activity for CSF reporting.

        Args:
            csf_function: NIST CSF function (IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER, GOVERN)
            category: CSF category (e.g., ID.AM, DE.CM)
            description: Human-readable description
            details: Additional details
        """
        activity = {
            "csf_function": csf_function,
            "category": category,
            "description": description,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat(),
        }

        if csf_function in self.activities:
            self.activities[csf_function].append(activity)
            logger.debug(f"CSF activity logged: {csf_function} - {description}")
        else:
            logger.warning(f"Unknown CSF function: {csf_function}")

    def load_activities_from_data(self) -> None:
        """Load activities from various data sources"""
        logger.info("Loading CSF activities from data files...")

        # Load asset inventory activities
        self._load_inventory_activities()

        # Load security findings
        self._load_security_findings()

        # Load anomaly detections
        self._load_anomaly_activities()

        # Load threat intelligence matches
        self._load_threat_intel_activities()

        # Load recovery actions
        self._load_recovery_activities()

        logger.info("CSF activities loaded")

    def _load_inventory_activities(self) -> None:
        """Load activities from asset inventory"""
        inventory_file = self.data_dir / "inventory" / "latest.json"
        if not inventory_file.exists():
            return

        try:
            with open(inventory_file) as f:
                data = json.load(f)

            self.log_activity(
                csf_function="IDENTIFY",
                category="ID.AM - Asset Management",
                description="Asset inventory collected",
                details={
                    "process_count": len(data.get("processes", [])),
                    "software_count": len(data.get("software", [])),
                    "network_interfaces": len(data.get("network", {}).get("interfaces", {})),
                },
            )
        except Exception as e:
            logger.error(f"Error loading inventory activities: {e}")

    def _load_security_findings(self) -> None:
        """Load activities from security findings"""
        findings_file = self.data_dir / "findings" / "latest.json"
        if not findings_file.exists():
            return

        try:
            with open(findings_file) as f:
                data = json.load(f)

            summary = data.get("summary", {})
            self.log_activity(
                csf_function="PROTECT",
                category="PR.IP - Information Protection",
                description="Security baseline check completed",
                details={
                    "total_findings": summary.get("total", 0),
                    "critical": summary.get("critical", 0),
                    "high": summary.get("high", 0),
                    "medium": summary.get("medium", 0),
                },
            )
        except Exception as e:
            logger.error(f"Error loading security findings: {e}")

    def _load_anomaly_activities(self) -> None:
        """Load activities from anomaly detection"""
        anomaly_file = self.data_dir / "anomalies" / "latest.json"
        if not anomaly_file.exists():
            return

        try:
            with open(anomaly_file) as f:
                data = json.load(f)

            summary = data.get("summary", {})
            self.log_activity(
                csf_function="DETECT",
                category="DE.AE - Anomalies and Events",
                description="Anomaly detection completed",
                details={
                    "total_anomalies": summary.get("total", 0),
                    "high": summary.get("high", 0),
                    "medium": summary.get("medium", 0),
                    "low": summary.get("low", 0),
                },
            )
        except Exception as e:
            logger.error(f"Error loading anomaly activities: {e}")

    def _load_threat_intel_activities(self) -> None:
        """Load activities from threat intelligence"""
        intel_file = self.data_dir / "threat_intel" / "latest.json"
        if not intel_file.exists():
            return

        try:
            with open(intel_file) as f:
                data = json.load(f)

            summary = data.get("summary", {})
            self.log_activity(
                csf_function="DETECT",
                category="DE.DP - Detection Processes",
                description="Threat intelligence scan completed",
                details={
                    "total_matches": summary.get("total", 0),
                    "critical": summary.get("critical", 0),
                    "high": summary.get("high", 0),
                },
            )
        except Exception as e:
            logger.error(f"Error loading threat intel activities: {e}")

    def _load_recovery_activities(self) -> None:
        """Load activities from recovery manager"""
        recovery_file = self.data_dir / "recovery" / "latest.json"
        if not recovery_file.exists():
            return

        try:
            with open(recovery_file) as f:
                data = json.load(f)

            summary = data.get("summary", {})
            self.log_activity(
                csf_function="RECOVER",
                category="RC.RP - Recovery Planning",
                description="Recovery actions completed",
                details={
                    "total_changes": summary.get("total_changes", 0),
                    "actions_completed": summary.get("recovery_actions_completed", 0),
                    "actions_pending": summary.get("recovery_actions_pending", 0),
                },
            )
        except Exception as e:
            logger.error(f"Error loading recovery activities: {e}")

    def generate_csf_alignment_report(self) -> dict[str, Any]:
        """
        Generate comprehensive CSF alignment report.

        Returns:
            CSF alignment report dictionary
        """
        # Load activities from data files
        self.load_activities_from_data()

        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "report_type": "NIST CSF 2.0 Alignment Report",
            "summary": {
                "total_activities": sum(len(acts) for acts in self.activities.values()),
                "by_function": {func: len(acts) for func, acts in self.activities.items()},
            },
            "functions": {
                "IDENTIFY": {
                    "description": "Asset management and risk assessment",
                    "activities": self.activities["IDENTIFY"],
                    "count": len(self.activities["IDENTIFY"]),
                },
                "PROTECT": {
                    "description": "Protective measures and safeguards",
                    "activities": self.activities["PROTECT"],
                    "count": len(self.activities["PROTECT"]),
                },
                "DETECT": {
                    "description": "Threat detection and monitoring",
                    "activities": self.activities["DETECT"],
                    "count": len(self.activities["DETECT"]),
                },
                "RESPOND": {
                    "description": "Incident response actions",
                    "activities": self.activities["RESPOND"],
                    "count": len(self.activities["RESPOND"]),
                },
                "RECOVER": {
                    "description": "Recovery and restoration",
                    "activities": self.activities["RECOVER"],
                    "count": len(self.activities["RECOVER"]),
                },
                "GOVERN": {
                    "description": "Governance and oversight",
                    "activities": self.activities["GOVERN"],
                    "count": len(self.activities["GOVERN"]),
                },
            },
            "compliance_status": self._calculate_compliance_status(),
            "recommendations": self._generate_governance_recommendations(),
        }

        return report

    def _calculate_compliance_status(self) -> dict[str, Any]:
        """Calculate compliance status based on activities"""
        # Simple compliance calculation based on whether functions are being performed
        compliance = {}

        for func, activities in self.activities.items():
            if len(activities) > 0:
                compliance[func] = "ACTIVE"
            else:
                compliance[func] = "NOT_IMPLEMENTED"

        # Overall status
        active_count = sum(1 for status in compliance.values() if status == "ACTIVE")
        total_functions = len(compliance)

        if active_count == total_functions:
            overall_status = "FULLY_ALIGNED"
        elif active_count >= total_functions * 0.75:
            overall_status = "MOSTLY_ALIGNED"
        elif active_count >= total_functions * 0.5:
            overall_status = "PARTIALLY_ALIGNED"
        else:
            overall_status = "LIMITED_ALIGNMENT"

        return {
            "overall": overall_status,
            "by_function": compliance,
            "coverage": f"{(active_count/total_functions)*100:.1f}%",
        }

    def _generate_governance_recommendations(self) -> list[str]:
        """Generate governance recommendations"""
        recommendations = []

        # Check for missing functions
        for func, activities in self.activities.items():
            if len(activities) == 0:
                recommendations.append(f"Implement {func} function to improve CSF alignment")

        # General recommendations
        recommendations.extend(
            [
                "Review and update security policies regularly",
                "Conduct periodic CSF alignment assessments",
                "Integrate DMARRSS with SIEM for centralized monitoring",
                "Provide security awareness training to staff",
                "Document incident response procedures",
            ]
        )

        return recommendations

    def generate_executive_summary(self) -> dict[str, Any]:
        """
        Generate executive-friendly summary.

        Returns:
            Executive summary dictionary
        """
        full_report = self.generate_csf_alignment_report()

        summary = {
            "timestamp": datetime.utcnow().isoformat(),
            "report_type": "Executive Summary - NIST CSF 2.0",
            "overview": {
                "total_activities": full_report["summary"]["total_activities"],
                "compliance_status": full_report["compliance_status"]["overall"],
                "coverage": full_report["compliance_status"]["coverage"],
            },
            "key_metrics": {
                "assets_identified": len(full_report["functions"]["IDENTIFY"]["activities"]),
                "security_findings": len(full_report["functions"]["PROTECT"]["activities"]),
                "threats_detected": len(full_report["functions"]["DETECT"]["activities"]),
                "incidents_responded": len(full_report["functions"]["RESPOND"]["activities"]),
                "recovery_actions": len(full_report["functions"]["RECOVER"]["activities"]),
            },
            "top_recommendations": full_report["recommendations"][:5],
            "next_steps": [
                "Review security findings and remediate high-priority issues",
                "Continue monitoring for anomalies and threats",
                "Update incident response procedures based on lessons learned",
                "Schedule next CSF assessment",
            ],
        }

        return summary

    def save_csf_report(self, report: dict[str, Any] | None = None) -> Path:
        """
        Save CSF alignment report to JSON file.

        Args:
            report: Report data (if None, will generate)

        Returns:
            Path to saved report file
        """
        if report is None:
            report = self.generate_csf_alignment_report()

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"csf_report_{timestamp}.json"
        filepath = self.reports_dir / filename

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        # Also save as latest.json
        latest_path = self.reports_dir / "latest.json"
        with open(latest_path, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"CSF report saved to {filepath}")
        return filepath

    def save_executive_summary(self, summary: dict[str, Any] | None = None) -> Path:
        """
        Save executive summary to JSON file.

        Args:
            summary: Summary data (if None, will generate)

        Returns:
            Path to saved summary file
        """
        if summary is None:
            summary = self.generate_executive_summary()

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"executive_summary_{timestamp}.json"
        filepath = self.reports_dir / filename

        with open(filepath, "w") as f:
            json.dump(summary, f, indent=2)

        # Also save as latest_summary.json
        latest_path = self.reports_dir / "latest_summary.json"
        with open(latest_path, "w") as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Executive summary saved to {filepath}")
        return filepath
