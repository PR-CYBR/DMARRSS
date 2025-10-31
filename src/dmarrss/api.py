"""
DMARRSS REST API Server

Provides HTTP endpoints for:
- Event ingestion (POST /ingest)
- Status queries (GET /status, GET /events)
- Decision details (GET /decisions/:id)
- Action testing (POST /actions/test)
- Prometheus metrics (GET /metrics)
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import yaml
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from . import __version__
from .decide.decision_node import DecisionNode
from .models.inference import ThreatInference
from .parsers import SnortParser, SuricataParser, ZeekParser
from .schemas import Decision, Event, Severity
from .scoring.threat_scorer import ThreatScorer
from .store import Store

# Prometheus metrics
try:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest

    METRICS_AVAILABLE = True

    # Define metrics
    events_ingested = Counter(
        "dmarrss_events_ingested_total", "Total events ingested", ["source"]
    )
    decisions_made = Counter(
        "dmarrss_decisions_total", "Total decisions made", ["severity"]
    )
    actions_executed = Counter(
        "dmarrss_actions_total", "Total actions executed", ["action_name", "dry_run"]
    )
    processing_time = Histogram(
        "dmarrss_processing_seconds", "Event processing time", ["stage"]
    )
    active_events = Gauge("dmarrss_active_events", "Currently active events")

except ImportError:
    METRICS_AVAILABLE = False


class EventIngestRequest(BaseModel):
    """Request body for event ingestion"""

    source: str  # SNORT, SURICATA, ZEEK
    log_line: str


class EventIngestBatchRequest(BaseModel):
    """Request body for batch event ingestion"""

    source: str
    log_lines: List[str]


class ActionTestRequest(BaseModel):
    """Request body for testing actions"""

    decision_id: str
    action_name: str
    dry_run: bool = True


def create_app(config: Dict[str, Any]) -> FastAPI:
    """
    Create FastAPI application with DMARRSS endpoints.

    Args:
        config: Configuration dictionary

    Returns:
        FastAPI application instance
    """
    app = FastAPI(
        title="DMARRSS API",
        description="Decentralized Machine Assisted Rapid Response Security System",
        version=__version__,
    )

    # Initialize components
    store = Store(config.get("system", {}).get("data_dir", "data") + "/state/dmarrss.db")
    scorer = ThreatScorer(config, store)
    inference = ThreatInference()
    decision_node = DecisionNode(config, scorer, inference)

    # Initialize parsers
    parsers = {
        "SNORT": SnortParser(),
        "SURICATA": SuricataParser(),
        "ZEEK": ZeekParser(),
    }

    @app.get("/")
    async def root():
        """Root endpoint"""
        return {
            "service": "DMARRSS",
            "version": __version__,
            "status": "operational",
            "endpoints": [
                "/status",
                "/ingest",
                "/events",
                "/decisions/{id}",
                "/actions/test",
                "/metrics",
            ],
        }

    @app.get("/status")
    async def get_status():
        """Get system status"""
        return {
            "status": "operational",
            "version": __version__,
            "mode": config.get("system", {}).get("mode", "decentralized"),
            "enforce": config.get("system", {}).get("enforce", False),
            "model_loaded": inference.is_model_loaded(),
            "model_metadata": inference.get_metadata(),
        }

    @app.post("/ingest")
    async def ingest_event(request: EventIngestRequest) -> Dict[str, Any]:
        """
        Ingest a single event for processing.

        Returns decision and recommended actions.
        """
        source = request.source.upper()
        if source not in parsers:
            raise HTTPException(
                status_code=400, detail=f"Unsupported source: {request.source}"
            )

        # Parse event
        parser = parsers[source]
        event = parser.parse(request.log_line)

        if not event:
            raise HTTPException(status_code=400, detail="Failed to parse log line")

        # Update metrics
        if METRICS_AVAILABLE:
            events_ingested.labels(source=source).inc()

        # Make decision
        decision = decision_node.decide(event)

        # Store event and decision
        event.threat_score = decision.threat_score
        event.severity = decision.severity
        store.insert_event(event)
        store.insert_decision(decision)

        # Update metrics
        if METRICS_AVAILABLE:
            decisions_made.labels(severity=decision.severity).inc()

        return {
            "event_id": event.event_id,
            "decision_id": decision.decision_id,
            "severity": decision.severity,
            "confidence": decision.confidence,
            "threat_score": decision.threat_score,
            "recommended_actions": decision.recommended_actions,
        }

    @app.post("/ingest/batch")
    async def ingest_batch(request: EventIngestBatchRequest) -> Dict[str, Any]:
        """
        Ingest multiple events for batch processing.

        Returns summary of decisions.
        """
        source = request.source.upper()
        if source not in parsers:
            raise HTTPException(
                status_code=400, detail=f"Unsupported source: {request.source}"
            )

        parser = parsers[source]
        events = []

        # Parse all events
        for log_line in request.log_lines:
            event = parser.parse(log_line)
            if event:
                events.append(event)

        if not events:
            raise HTTPException(status_code=400, detail="No valid events in batch")

        # Make decisions
        decisions = decision_node.decide_batch(events)

        # Store events and decisions
        for event, decision in zip(events, decisions):
            event.threat_score = decision.threat_score
            event.severity = decision.severity
            store.insert_event(event)
            store.insert_decision(decision)

            # Update metrics
            if METRICS_AVAILABLE:
                events_ingested.labels(source=source).inc()
                decisions_made.labels(severity=decision.severity).inc()

        # Generate summary
        severity_counts = {}
        for decision in decisions:
            sev = decision.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_events": len(events),
            "severity_counts": severity_counts,
            "decisions": [
                {
                    "decision_id": d.decision_id,
                    "severity": d.severity,
                    "confidence": d.confidence,
                }
                for d in decisions
            ],
        }

    @app.get("/events")
    async def get_events(
        limit: int = Query(100, ge=1, le=1000),
        severity: Optional[str] = Query(None),
        since: Optional[str] = Query(None),
    ):
        """
        Query events with filters.

        Args:
            limit: Max number of events to return
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            since: ISO timestamp to filter events after
        """
        since_dt = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid since timestamp")

        events = store.get_events(limit=limit, severity=severity, since=since_dt)

        return {"total": len(events), "events": events}

    @app.get("/decisions/{decision_id}")
    async def get_decision(decision_id: str):
        """Get decision details by ID"""
        decision = store.get_decision(decision_id)

        if not decision:
            raise HTTPException(status_code=404, detail="Decision not found")

        # Parse JSON data field
        decision_data = json.loads(decision["data"])

        return decision_data

    @app.post("/actions/test")
    async def test_action(request: ActionTestRequest):
        """
        Test an action in dry-run mode.

        Useful for validating action plugins without executing.
        """
        # Get decision from store
        decision_dict = store.get_decision(request.decision_id)

        if not decision_dict:
            raise HTTPException(status_code=404, detail="Decision not found")

        # Parse decision
        decision_data = json.loads(decision_dict["data"])
        decision = Decision(**decision_data)

        # Load action plugin
        from .actions import BlockIPAction, IsolateHostAction, NotifyWebhookAction

        action_map = {
            "block_ip": BlockIPAction(),
            "isolate_host": IsolateHostAction(),
            "notify_webhook": NotifyWebhookAction(),
        }

        action = action_map.get(request.action_name)
        if not action:
            raise HTTPException(status_code=400, detail=f"Unknown action: {request.action_name}")

        # Execute action
        result = action.execute(decision, dry_run=request.dry_run)

        # Store action result
        store.insert_action(result)

        # Update metrics
        if METRICS_AVAILABLE:
            actions_executed.labels(
                action_name=request.action_name, dry_run=str(request.dry_run)
            ).inc()

        return {
            "action_id": result.action_id,
            "action_name": result.action_name,
            "success": result.success,
            "dry_run": result.dry_run,
            "executed": result.executed,
            "message": result.message,
            "details": result.details,
        }

    @app.get("/metrics", response_class=PlainTextResponse)
    async def get_metrics():
        """
        Get Prometheus metrics.

        Returns metrics in Prometheus text format.
        """
        if not METRICS_AVAILABLE:
            raise HTTPException(status_code=503, detail="Metrics not available")

        return generate_latest()

    return app
