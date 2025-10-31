"""
DMARRSS Main Pipeline
Integrates all components: parsing, scoring, neural processing, and response
"""

from typing import Any

from .models import NeuralThreatProcessor, ResponseEngine, ThreatScorer
from .preprocessing import UniversalLogParser
from .utils import ConfigLoader, DMALogger, ensure_directories


class DMARRSSPipeline:
    """
    Main DMARRSS pipeline that orchestrates the complete threat detection
    and response workflow.

    Pipeline flow:
    1. Input: Security log data (SNORT, SURICATA, ZEEK)
    2. Parse: Extract structured events from logs
    3. Score: Calculate threat scores with Context Aware Severity Layers
    4. Classify: Apply LLM-inspired neural processing
    5. Prioritize: Order events by threat level
    6. Respond: Execute appropriate actions based on severity
    """

    def __init__(self, config_path: str | None = None):
        """Initialize DMARRSS pipeline with configuration"""
        # Ensure required directories exist
        ensure_directories()

        # Load configuration
        self.config = ConfigLoader(config_path)
        self.logger = DMALogger("DMARRSS", self.config)

        # Initialize pipeline components
        self.parser = UniversalLogParser()
        self.scorer = ThreatScorer(self.config)
        self.neural_processor = NeuralThreatProcessor(self.config)
        self.response_engine = ResponseEngine(self.config)

        self.logger.info("DMARRSS pipeline initialized", mode=self.config.get("system.mode"))

    def process_log_line(
        self, log_line: str, format_hint: str | None = None
    ) -> dict[str, Any] | None:
        """
        Process a single log line through the complete pipeline.

        Args:
            log_line: Raw log line string
            format_hint: Optional format hint ('snort', 'suricata', 'zeek')

        Returns:
            Processed event with threat score, classification, and response action
        """
        # Step 1: Parse log line
        event = self.parser.parse(log_line, format_hint)
        if not event:
            self.logger.warning("Failed to parse log line", log_sample=log_line[:100])
            return None

        # Step 2: Score event
        scored_event = self.scorer.score_event(event)

        # Step 3: Apply neural processing
        neural_event = self.neural_processor.process_event(scored_event)

        # Step 4: Determine and execute response
        final_event = self.response_engine.process_event(neural_event)

        return final_event

    def process_log_batch(
        self, log_lines: list[str], format_hint: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Process multiple log lines through the pipeline.

        Args:
            log_lines: List of raw log line strings
            format_hint: Optional format hint ('snort', 'suricata', 'zeek')

        Returns:
            List of processed events
        """
        self.logger.info(f"Processing batch of {len(log_lines)} log lines")

        # Step 1: Parse all logs
        events = self.parser.parse_batch(log_lines, format_hint)
        self.logger.info(f"Parsed {len(events)} events from {len(log_lines)} log lines")

        if not events:
            return []

        # Step 2: Score all events
        scored_events = self.scorer.score_batch(events)

        # Step 3: Apply neural processing
        neural_events = self.neural_processor.process_batch(scored_events)

        # Step 4: Prioritize events
        prioritized_events = self.scorer.prioritize_events(neural_events)

        # Step 5: Execute responses
        final_events = self.response_engine.process_batch(prioritized_events)

        self.logger.info(
            f"Pipeline complete: processed {len(final_events)} events",
            critical=sum(1 for e in final_events if e.get("severity") == "critical"),
            high=sum(1 for e in final_events if e.get("severity") == "high"),
            medium=sum(1 for e in final_events if e.get("severity") == "medium"),
            low=sum(1 for e in final_events if e.get("severity") == "low"),
        )

        return final_events

    def process_log_file(
        self, file_path: str, format_hint: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Process an entire log file through the pipeline.

        Args:
            file_path: Path to log file
            format_hint: Optional format hint ('snort', 'suricata', 'zeek')

        Returns:
            List of processed events
        """
        self.logger.info(f"Processing log file: {file_path}")

        try:
            with open(file_path) as f:
                log_lines = f.readlines()

            return self.process_log_batch(log_lines, format_hint)

        except FileNotFoundError:
            self.logger.error(f"Log file not found: {file_path}")
            return []
        except Exception as e:
            self.logger.error(f"Error processing log file: {e}")
            return []

    def get_critical_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter and return only critical severity events"""
        return [e for e in events if e.get("severity") == "critical"]

    def get_high_priority_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter and return critical and high severity events"""
        return [e for e in events if e.get("severity") in ["critical", "high"]]

    def generate_summary(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Generate summary statistics for processed events.

        Args:
            events: List of processed events

        Returns:
            Summary dictionary with statistics
        """
        if not events:
            return {
                "total_events": 0,
                "by_severity": {},
                "by_source": {},
                "average_threat_score": 0,
                "response_actions": {},
            }

        summary = {
            "total_events": len(events),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_source": {},
            "threat_scores": {"min": 1.0, "max": 0.0, "average": 0.0},
            "response_actions": {},
        }

        total_score = 0
        for event in events:
            # Count by severity
            severity = event.get("severity", "low")
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

            # Count by source
            source = event.get("source", "unknown")
            summary["by_source"][source] = summary["by_source"].get(source, 0) + 1

            # Track threat scores
            score = event.get("threat_score", 0)
            total_score += score
            summary["threat_scores"]["min"] = min(summary["threat_scores"]["min"], score)
            summary["threat_scores"]["max"] = max(summary["threat_scores"]["max"], score)

            # Count response actions
            response = event.get("response_action", {})
            action = response.get("action", "unknown")
            summary["response_actions"][action] = summary["response_actions"].get(action, 0) + 1

        summary["threat_scores"]["average"] = round(total_score / len(events), 3)

        return summary

    def get_statistics(self) -> dict[str, Any]:
        """Get overall pipeline statistics"""
        return {
            "system": {
                "name": self.config.get("system.name"),
                "version": self.config.get("system.version"),
                "mode": self.config.get("system.mode"),
            },
            "response_engine": self.response_engine.get_action_statistics(),
        }
