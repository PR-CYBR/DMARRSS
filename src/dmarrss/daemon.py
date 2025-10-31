"""
DMARRSS Daemon Supervisor

Runs continuous log processing pipeline with:
- Log tailers
- Event parsing
- Scoring and classification
- Decision making
- Action execution
"""

import logging
import sys
from pathlib import Path

from .actions import BlockIPAction, IsolateHostAction, NotifyWebhookAction
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

    Manages continuous processing of security events.
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

        # Initialize action plugins
        self.actions = {
            "block_ip": BlockIPAction(),
            "isolate_host": IsolateHostAction(),
            "notify_webhook": NotifyWebhookAction(),
        }

        # Get dry-run mode
        self.dry_run = not config.get("system", {}).get("enforce", False)

        logger.info(f"DMARRSS daemon initialized (dry_run={self.dry_run})")

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

                    # Make decision
                    decision = self.decision_node.decide(event)

                    # Update event with decision
                    event.threat_score = decision.threat_score
                    event.severity = decision.severity

                    # Store event and decision
                    self.store.insert_event(event)
                    self.store.insert_decision(decision)

                    # Execute actions
                    for action_name in decision.recommended_actions:
                        action = self.actions.get(action_name)
                        if action:
                            result = action.execute(decision, dry_run=self.dry_run)
                            self.store.insert_action(result)

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
        Run daemon in continuous mode.

        For now, this just processes files once and exits.
        In a full implementation, this would:
        - Use watchdog to tail log files
        - Run periodic model retraining
        - Implement crash recovery with exponential backoff
        """
        self.running = True

        logger.info("Starting DMARRSS daemon...")
        logger.info(f"Mode: {'ENFORCE' if not self.dry_run else 'DRY-RUN'}")

        try:
            # Run one iteration
            total = self.run_once()

            logger.info(f"Processed {total} total events")
            logger.info("Processing complete. In continuous mode, daemon would keep running.")

        except KeyboardInterrupt:
            logger.info("Shutting down...")
        except Exception as e:
            logger.error(f"Daemon error: {e}")
            raise
        finally:
            self.running = False
            logger.info("Daemon stopped")


def run_daemon(config: dict):
    """
    Run DMARRSS daemon.

    Args:
        config: Configuration dictionary
    """
    daemon = DMADaemon(config)
    daemon.run()
