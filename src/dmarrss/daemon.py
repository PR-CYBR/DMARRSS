"""
DMARRSS Daemon Supervisor

Runs continuous log processing pipeline with:
- Log tailers
- Event parsing
- Scoring and classification
- Decision making
- Action execution
- NIST CSF 2.0 functions integration
"""

import logging
import sys
from pathlib import Path

from .actions import (
    BlockIPAction,
    CollectArtifactsAction,
    DisableAccountAction,
    IsolateHostAction,
    NotifyWebhookAction,
    QuarantineNetworkAction,
    TerminateProcessAction,
)
from .csf import (
    AnomalyDetector,
    AssetInventory,
    CSFReporter,
    RecoveryManager,
    SecurityBaseline,
    ThreatIntelligence,
)
from .decide.decision_node import DecisionNode
from .models.inference import ThreatInference
from .parsers import SnortParser, SuricataParser, ZeekParser
from .scoring.threat_scorer import ThreatScorer
from .store import Store

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("dmarrss.daemon")


class DMADaemon:
    """
    DMARRSS daemon supervisor.

    Manages continuous processing of security events with NIST CSF 2.0 integration.
    """

    def __init__(self, config: dict):
        """Initialize daemon with config"""
        self.config = config
        self.running = False

        # Initialize components
        data_dir = config.get("system", {}).get("data_dir", "data")
        self.store = Store(f"{data_dir}/state/dmarrss.db")
        self.scorer = ThreatScorer(config, self.store)
        self.inference = ThreatInference()
        self.decision_node = DecisionNode(config, self.scorer, self.inference)

        # Initialize parsers
        self.parsers = {
            "SNORT": SnortParser(),
            "SURICATA": SuricataParser(),
            "ZEEK": ZeekParser(),
        }

        # Initialize action plugins (including new CSF actions)
        self.actions = {
            "block_ip": BlockIPAction(),
            "isolate_host": IsolateHostAction(),
            "notify_webhook": NotifyWebhookAction(),
            "terminate_process": TerminateProcessAction(),
            "quarantine_network": QuarantineNetworkAction(),
            "disable_account": DisableAccountAction(),
            "collect_artifacts": CollectArtifactsAction(config),
        }

        # Initialize CSF modules
        csf_config = config.get("csf", {})
        self.asset_inventory = (
            AssetInventory(config)
            if csf_config.get("asset_inventory", {}).get("enabled", True)
            else None
        )
        self.security_baseline = (
            SecurityBaseline(config)
            if csf_config.get("security_baseline", {}).get("enabled", True)
            else None
        )
        self.anomaly_detector = (
            AnomalyDetector(config)
            if csf_config.get("anomaly_detection", {}).get("enabled", True)
            else None
        )
        self.threat_intel = (
            ThreatIntelligence(config)
            if csf_config.get("threat_intel", {}).get("enabled", True)
            else None
        )
        self.recovery_manager = (
            RecoveryManager(config) if csf_config.get("recovery", {}).get("enabled", True) else None
        )
        self.csf_reporter = (
            CSFReporter(config) if csf_config.get("reporting", {}).get("enabled", True) else None
        )

        # Get dry-run mode
        self.dry_run = not config.get("system", {}).get("enforce", False)

        logger.info(f"DMARRSS daemon initialized (dry_run={self.dry_run})")
        logger.info(
            f"CSF modules enabled: {sum(1 for m in [self.asset_inventory, self.security_baseline, self.anomaly_detector, self.threat_intel, self.recovery_manager, self.csf_reporter] if m is not None)}/6"
        )

    def run_csf_initialization(self) -> None:
        """
        Run NIST CSF initialization functions.

        This runs at daemon start to establish baseline and security posture.
        """
        csf_config = self.config.get("csf", {})

        # IDENTIFY: Collect asset inventory
        if self.asset_inventory and csf_config.get("asset_inventory", {}).get(
            "auto_collect_on_start", True
        ):
            logger.info("Running asset inventory collection (NIST CSF Identify)...")
            try:
                self.asset_inventory.save_inventory()
                if self.csf_reporter:
                    self.csf_reporter.log_activity(
                        "IDENTIFY",
                        "ID.AM - Asset Management",
                        "Asset inventory collected at daemon start",
                    )
            except Exception as e:
                logger.error(f"Error collecting asset inventory: {e}")

        # PROTECT: Run security baseline checks
        if self.security_baseline and csf_config.get("security_baseline", {}).get(
            "auto_check_on_start", False
        ):
            logger.info("Running security baseline checks (NIST CSF Protect)...")
            try:
                self.security_baseline.save_findings()
                if self.csf_reporter:
                    self.csf_reporter.log_activity(
                        "PROTECT",
                        "PR.IP - Information Protection",
                        "Security baseline check completed at daemon start",
                    )
            except Exception as e:
                logger.error(f"Error checking security baseline: {e}")

        # DETECT: Update threat intelligence
        if self.threat_intel:
            if self.threat_intel.needs_update():
                logger.info("Updating threat intelligence feeds (NIST CSF Detect)...")
                try:
                    self.threat_intel.load_feeds()
                    self.threat_intel.mark_updated()
                    if self.csf_reporter:
                        self.csf_reporter.log_activity(
                            "DETECT",
                            "DE.DP - Detection Processes",
                            "Threat intelligence feeds updated",
                        )
                except Exception as e:
                    logger.error(f"Error updating threat intelligence: {e}")

        # DETECT: Load baseline for anomaly detection
        if self.anomaly_detector:
            try:
                self.anomaly_detector.load_baseline()
                logger.info("Anomaly detector baseline loaded")
            except Exception as e:
                logger.error(f"Error loading anomaly baseline: {e}")

    def process_log_file(self, file_path: str, source: str) -> int:
        """
        Process a log file.

        Args:
            file_path: Path to log file
            source: Source type (SNORT, SURICATA, ZEEK)

        Returns:
            Number of events processed
        """
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"Log file not found: {file_path}")
            return 0

        parser = self.parsers.get(source.upper())
        if not parser:
            logger.error(f"Unknown parser: {source}")
            return 0

        logger.info(f"Processing {source} log: {file_path}")

        events_processed = 0

        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Parse event
                    event = parser.parse(line)
                    if not event:
                        continue

                    # DETECT: Check threat intelligence for IoC matches
                    if self.threat_intel:
                        try:
                            # Convert event to dict for scanning
                            event_dict = {
                                "src_ip": event.src_ip,
                                "dst_ip": event.dst_ip,
                                "signature": event.signature,
                                "raw": event.raw,
                            }
                            matches = self.threat_intel.scan_event(event_dict)
                            if matches:
                                logger.warning(
                                    f"Threat intelligence match: {len(matches)} IoC(s) detected"
                                )
                                self.threat_intel.matches.extend(matches)
                                if self.csf_reporter:
                                    self.csf_reporter.log_activity(
                                        "DETECT",
                                        "DE.DP - Detection Processes",
                                        f"Threat intelligence match detected: {matches[0].ioc_value}",
                                        {"ioc_type": matches[0].ioc_type},
                                    )
                        except Exception as e:
                            logger.error(f"Error scanning threat intelligence: {e}")

                    # Make decision
                    decision = self.decision_node.decide(event)

                    # Update event with decision
                    event.threat_score = decision.threat_score
                    event.severity = decision.severity

                    # Store event and decision
                    self.store.insert_event(event)
                    self.store.insert_decision(decision)

                    # RESPOND: Log CSF activity
                    if self.csf_reporter:
                        self.csf_reporter.log_activity(
                            "RESPOND",
                            "RS.AN - Analysis",
                            f"Threat detected and classified as {decision.severity}",
                            {"threat_score": decision.threat_score},
                        )

                    # RESPOND: Collect artifacts for critical threats
                    if decision.severity == "CRITICAL" and "collect_artifacts" in self.actions:
                        artifacts_action = self.actions["collect_artifacts"]
                        result = artifacts_action.execute(decision, dry_run=self.dry_run)
                        self.store.insert_action(result)
                        logger.info(f"Artifacts collected: {result.message}")

                    # Execute actions
                    for action_name in decision.recommended_actions:
                        action = self.actions.get(action_name)
                        if action:
                            result = action.execute(decision, dry_run=self.dry_run)
                            self.store.insert_action(result)

                            # Track changes for recovery
                            if self.recovery_manager and result.executed:
                                self.recovery_manager.track_change(
                                    change_type=action_name,
                                    description=result.message,
                                    details=result.details,
                                )

                            # Log action result
                            logger.info(
                                f"Action {action_name}: {result.message} "
                                f"(dry_run={result.dry_run}, executed={result.executed})"
                            )

                    events_processed += 1

                    # Log decision
                    logger.info(
                        f"Event {event.event_id}: {event.severity} "
                        f"(score={decision.threat_score:.3f}, "
                        f"confidence={decision.confidence:.3f})"
                    )

        except Exception as e:
            logger.error(f"Error processing log file {file_path}: {e}")

        logger.info(f"Processed {events_processed} events from {file_path}")
        return events_processed

    def run_once(self) -> int:
        """
        Run one processing iteration.

        Processes all configured log files once.

        Returns:
            Total number of events processed
        """
        total_events = 0

        # Process SNORT logs
        ingest_config = self.config.get("ingest", {})

        if ingest_config.get("snort", {}).get("enabled", False):
            for file_path in ingest_config["snort"].get("files", []):
                total_events += self.process_log_file(file_path, "SNORT")

        # Process SURICATA logs
        if ingest_config.get("suricata", {}).get("enabled", False):
            for file_path in ingest_config["suricata"].get("files", []):
                total_events += self.process_log_file(file_path, "SURICATA")

        # Process ZEEK logs
        if ingest_config.get("zeek", {}).get("enabled", False):
            for file_path in ingest_config["zeek"].get("files", []):
                total_events += self.process_log_file(file_path, "ZEEK")

        return total_events

    def run(self):
        """
        Run daemon in continuous mode with NIST CSF integration.

        Executes:
        1. CSF initialization (Identify, Protect baseline)
        2. Event processing loop (Detect, Respond)
        3. CSF completion tasks (Recover, Govern reporting)
        """
        self.running = True

        logger.info("Starting DMARRSS daemon...")
        logger.info(f"Mode: {'ENFORCE' if not self.dry_run else 'DRY-RUN'}")

        try:
            # NIST CSF Initialization
            self.run_csf_initialization()

            # Run one iteration (process all logs)
            total = self.run_once()

            logger.info(f"Processed {total} total events")

            # NIST CSF Completion Tasks
            self.run_csf_completion()

            logger.info("Processing complete. In continuous mode, daemon would keep running.")

        except KeyboardInterrupt:
            logger.info("Shutting down...")
        except Exception as e:
            logger.error(f"Daemon error: {e}")
            raise
        finally:
            self.running = False
            logger.info("Daemon stopped")

    def run_csf_completion(self) -> None:
        """
        Run NIST CSF completion tasks after event processing.

        This runs recovery and governance functions at the end.
        """
        csf_config = self.config.get("csf", {})

        # DETECT: Save threat intelligence matches
        if self.threat_intel and self.threat_intel.matches:
            try:
                self.threat_intel.save_matches()
                logger.info(f"Saved {len(self.threat_intel.matches)} threat intelligence matches")
            except Exception as e:
                logger.error(f"Error saving threat matches: {e}")

        # DETECT: Run anomaly detection
        if self.anomaly_detector and self.asset_inventory:
            try:
                logger.info("Running anomaly detection (NIST CSF Detect)...")
                current_inventory = self.asset_inventory.collect_all()
                anomalies = self.anomaly_detector.detect_all_anomalies(current_inventory)
                if anomalies:
                    self.anomaly_detector.save_anomalies(anomalies)
                    logger.info(f"Detected {len(anomalies)} anomalies")
                    if self.csf_reporter:
                        self.csf_reporter.log_activity(
                            "DETECT",
                            "DE.AE - Anomalies and Events",
                            f"Anomaly detection completed: {len(anomalies)} anomalies found",
                        )
            except Exception as e:
                logger.error(f"Error detecting anomalies: {e}")

        # RECOVER: Generate recovery report
        if self.recovery_manager and self.recovery_manager.changes_made:
            try:
                logger.info("Generating recovery report (NIST CSF Recover)...")
                self.recovery_manager.save_recovery_report()
                if self.csf_reporter:
                    self.csf_reporter.log_activity(
                        "RECOVER",
                        "RC.RP - Recovery Planning",
                        f"Recovery report generated: {len(self.recovery_manager.changes_made)} changes tracked",
                    )
            except Exception as e:
                logger.error(f"Error generating recovery report: {e}")

        # GOVERN: Generate CSF alignment report
        if self.csf_reporter and csf_config.get("reporting", {}).get(
            "auto_generate_on_complete", True
        ):
            try:
                logger.info("Generating CSF alignment report (NIST CSF Govern)...")
                self.csf_reporter.save_csf_report()
                self.csf_reporter.save_executive_summary()
                logger.info("CSF reports generated")
            except Exception as e:
                logger.error(f"Error generating CSF reports: {e}")


def run_daemon(config: dict):
    """
    Run DMARRSS daemon.

    Args:
        config: Configuration dictionary
    """
    daemon = DMADaemon(config)
    daemon.run()
