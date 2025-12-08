"""
Artifact Collection Action - Forensic Evidence Collection

NIST CSF 2.0 Mapping: RS.AN (Analysis)
"""

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path

from ..actions.base import BaseAction
from ..schemas import ActionResult, Decision

logger = logging.getLogger(__name__)


class CollectArtifactsAction(BaseAction):
    """
    Collect forensic artifacts before remediation.
    
    Preserves evidence for post-incident analysis.
    """

    def __init__(self, config: dict | None = None):
        super().__init__("collect_artifacts")
        self.config = config or {}
        data_dir = self.config.get("system", {}).get("data_dir", "data")
        self.artifacts_dir = Path(data_dir) / "artifacts"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    def _execute_impl(self, decision: Decision) -> ActionResult:
        """Collect artifacts"""
        try:
            # Create timestamped directory for this incident
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            incident_dir = self.artifacts_dir / f"incident_{decision.decision_id}_{timestamp}"
            incident_dir.mkdir(parents=True, exist_ok=True)

            artifacts_collected = []

            # Collect decision details
            decision_file = incident_dir / "decision.json"
            with open(decision_file, 'w') as f:
                json.dump({
                    "decision_id": decision.decision_id,
                    "event_id": decision.event_id,
                    "severity": decision.severity,
                    "threat_score": decision.threat_score,
                    "score_components": decision.score_components,
                    "timestamp": decision.timestamp.isoformat() if hasattr(decision.timestamp, 'isoformat') else str(decision.timestamp),
                    "why": decision.why,
                }, f, indent=2)
            artifacts_collected.append(str(decision_file))

            # Collect event details if available
            if hasattr(decision, 'event_data') and decision.event_data:
                event_file = incident_dir / "event.json"
                with open(event_file, 'w') as f:
                    json.dump(decision.event_data, f, indent=2)
                artifacts_collected.append(str(event_file))

            # Collect system snapshot if available
            details = decision.score_components
            if "process_info" in details:
                process_file = incident_dir / "process_info.json"
                with open(process_file, 'w') as f:
                    json.dump(details["process_info"], f, indent=2)
                artifacts_collected.append(str(process_file))

            if "network_info" in details:
                network_file = incident_dir / "network_info.json"
                with open(network_file, 'w') as f:
                    json.dump(details["network_info"], f, indent=2)
                artifacts_collected.append(str(network_file))

            # Create collection manifest
            manifest = {
                "incident_id": decision.decision_id,
                "collection_time": datetime.utcnow().isoformat(),
                "artifacts": artifacts_collected,
                "csf_function": "RESPOND",
                "csf_category": "RS.AN - Analysis",
            }

            manifest_file = incident_dir / "manifest.json"
            with open(manifest_file, 'w') as f:
                json.dump(manifest, f, indent=2)

            message = f"Artifacts collected to {incident_dir}"
            logger.info(message)

            return self._create_result(
                decision=decision,
                success=True,
                dry_run=False,
                executed=True,
                message=message,
                details={
                    "incident_dir": str(incident_dir),
                    "artifacts_count": len(artifacts_collected),
                    "artifacts": artifacts_collected,
                    "csf_function": "RESPOND",
                    "csf_category": "RS.AN - Analysis",
                },
            )

        except Exception as e:
            logger.error(f"Error collecting artifacts: {e}")
            return self._create_result(
                decision=decision,
                success=False,
                dry_run=False,
                executed=False,
                message=f"Artifact collection failed: {e}",
                error=str(e),
            )

    def _dry_run_impl(self, decision: Decision) -> ActionResult:
        """Dry-run: Log what would be done"""
        message = f"[DRY-RUN] Would collect artifacts for decision {decision.decision_id}"
        logger.info(message)

        return self._create_result(
            decision=decision,
            success=True,
            dry_run=True,
            executed=False,
            message=message,
            details={
                "decision_id": decision.decision_id,
                "csf_function": "RESPOND",
                "csf_category": "RS.AN - Analysis",
            },
        )
