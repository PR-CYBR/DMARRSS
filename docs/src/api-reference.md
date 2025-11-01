# API Reference

DMARRSS provides both a REST API and a Python API for integration with your security infrastructure.

## REST API

The REST API is built with FastAPI and provides endpoints for event ingestion, querying, and monitoring.

### Starting the API Server

```bash
# Start with default settings (localhost:8080)
dmarrss api

# Specify host and port
dmarrss api --host 0.0.0.0 --port 8080

# With custom config
dmarrss api --config /path/to/config.yaml
```

### Base URL

When running locally: `http://localhost:8080`

### Endpoints

#### GET `/`

Get API information and available endpoints.

**Response:**
```json
{
  "name": "DMARRSS API",
  "version": "1.0.0",
  "description": "Decentralized Machine Assisted Rapid Response Security System",
  "endpoints": ["/status", "/ingest", "/events", "/decisions", "/metrics"]
}
```

#### GET `/status`

Get system status and model information.

**Response:**
```json
{
  "status": "running",
  "mode": "decentralized",
  "enforce_mode": false,
  "model_loaded": true,
  "model_version": "v1.0.0",
  "uptime_seconds": 3600,
  "events_processed": 1234
}
```

#### POST `/ingest`

Ingest a single security event.

**Request Body:**
```json
{
  "source": "SNORT",
  "log_line": "[**] [1:2024364:1] ET MALWARE Detected [**] [Priority: 1] {TCP} 203.0.113.50:54321 -> 192.168.1.100:443"
}
```

**Response:**
```json
{
  "event_id": "evt_1234567890",
  "severity": "HIGH",
  "threat_score": 0.750,
  "neural_severity": "MEDIUM",
  "neural_confidence": 0.276,
  "recommended_actions": ["notify_webhook"],
  "dry_run": true
}
```

#### POST `/ingest/batch`

Ingest multiple security events at once.

**Request Body:**
```json
{
  "events": [
    {
      "source": "SNORT",
      "log_line": "[**] [1:2024364:1] ET MALWARE..."
    },
    {
      "source": "SURICATA",
      "log_line": "{\"timestamp\":\"2024-01-15T12:00:00\"...}"
    }
  ]
}
```

**Response:**
```json
{
  "processed": 2,
  "results": [
    {
      "event_id": "evt_1234567890",
      "severity": "HIGH",
      "threat_score": 0.750
    },
    {
      "event_id": "evt_1234567891",
      "severity": "CRITICAL",
      "threat_score": 0.950
    }
  ]
}
```

#### GET `/events`

Query processed events with optional filters.

**Query Parameters:**
- `severity`: Filter by severity level (CRITICAL, HIGH, MEDIUM, LOW)
- `source`: Filter by log source (SNORT, SURICATA, ZEEK)
- `limit`: Maximum number of results (default: 100)
- `offset`: Pagination offset (default: 0)
- `start_time`: ISO timestamp for range start
- `end_time`: ISO timestamp for range end

**Example:**
```bash
curl "http://localhost:8080/events?severity=HIGH&limit=50"
```

**Response:**
```json
{
  "count": 50,
  "events": [
    {
      "event_id": "evt_1234567890",
      "timestamp": "2024-01-15T12:00:00Z",
      "source": "SNORT",
      "severity": "HIGH",
      "threat_score": 0.750,
      "src_ip": "203.0.113.50",
      "dst_ip": "192.168.1.100",
      "classification": "ET MALWARE"
    }
  ]
}
```

#### GET `/decisions/{id}`

Get detailed decision information for a specific event.

**Example:**
```bash
curl http://localhost:8080/decisions/evt_1234567890
```

**Response:**
```json
{
  "event_id": "evt_1234567890",
  "timestamp": "2024-01-15T12:00:00Z",
  "severity": "HIGH",
  "threat_score": 0.750,
  "score_components": {
    "pattern_match": 0.900,
    "context_relevance": 0.900,
    "historical_severity": 0.400,
    "source_reputation": 0.700,
    "anomaly_score": 0.200
  },
  "neural_severity": "MEDIUM",
  "neural_confidence": 0.276,
  "recommended_actions": ["notify_webhook"],
  "executed_actions": [],
  "dry_run": true
}
```

#### POST `/actions/test`

Test action plugins without executing them.

**Request Body:**
```json
{
  "action": "block_ip",
  "parameters": {
    "ip_address": "203.0.113.50",
    "duration": 3600
  }
}
```

**Response:**
```json
{
  "action": "block_ip",
  "status": "success",
  "dry_run": true,
  "message": "Would block IP 203.0.113.50 for 3600 seconds"
}
```

#### GET `/metrics`

Get Prometheus-compatible metrics.

**Response:**
```
# HELP dmarrss_events_total Total number of events processed
# TYPE dmarrss_events_total counter
dmarrss_events_total{source="SNORT"} 1234
dmarrss_events_total{source="SURICATA"} 567
dmarrss_events_total{source="ZEEK"} 890

# HELP dmarrss_events_by_severity Events by severity level
# TYPE dmarrss_events_by_severity gauge
dmarrss_events_by_severity{severity="CRITICAL"} 45
dmarrss_events_by_severity{severity="HIGH"} 123
dmarrss_events_by_severity{severity="MEDIUM"} 456
dmarrss_events_by_severity{severity="LOW"} 610

# HELP dmarrss_processing_time_seconds Time spent processing events
# TYPE dmarrss_processing_time_seconds histogram
dmarrss_processing_time_seconds_bucket{le="0.001"} 567
dmarrss_processing_time_seconds_bucket{le="0.01"} 1234
```

## Python API

Use DMARRSS components directly in your Python code.

### Basic Usage

```python
from dmarrss.parsers import SnortParser
from dmarrss.scoring.threat_scorer import ThreatScorer
from dmarrss.models.inference import ThreatInference
from dmarrss.decide.decision_node import DecisionNode
from dmarrss.store import Store
import yaml

# Load configuration
with open('config/dmarrss_config.yaml') as f:
    config = yaml.safe_load(f)

# Initialize components
store = Store("data/state/dmarrss.db")
scorer = ThreatScorer(config, store)
inference = ThreatInference()
decision_node = DecisionNode(config, scorer, inference)

# Parse event
parser = SnortParser()
log_line = "[**] [1:2024364:1] ET MALWARE Detected [**] [Priority: 1] {TCP} 203.0.113.50:54321 -> 192.168.1.100:443"
event = parser.parse(log_line)

# Make decision
decision = decision_node.decide(event)

print(f"Severity: {decision.severity}")
print(f"Threat Score: {decision.threat_score:.3f}")
print(f"Recommended Actions: {decision.recommended_actions}")
```

### Parsers

```python
from dmarrss.parsers import SnortParser, SuricataParser, ZeekParser

# SNORT
snort_parser = SnortParser()
event = snort_parser.parse(snort_log_line)

# SURICATA
suricata_parser = SuricataParser()
event = suricata_parser.parse(suricata_json_line)

# ZEEK
zeek_parser = ZeekParser()
event = zeek_parser.parse(zeek_log_line)

# Event fields
print(f"Source: {event.source}")
print(f"Timestamp: {event.timestamp}")
print(f"Source IP: {event.src_ip}")
print(f"Destination IP: {event.dst_ip}")
print(f"Classification: {event.classification}")
```

### Threat Scoring

```python
from dmarrss.scoring.threat_scorer import ThreatScorer

scorer = ThreatScorer(config, store)

# Get composite threat score
score = scorer.score_event(event)
print(f"Threat Score: {score:.3f}")

# Get component scores
components = scorer.get_score_components(event)
for component, value in components.items():
    print(f"{component}: {value:.3f}")
```

### Neural Inference

```python
from dmarrss.models.inference import ThreatInference

inference = ThreatInference()

# Load model
inference.load_model("data/models/threat_classifier_v1.0.0.pt")

# Get prediction
features = scorer.extract_features(event)
prediction = inference.predict(features)

print(f"Neural Severity: {prediction.severity}")
print(f"Confidence: {prediction.confidence:.3f}")
```

### Decision Making

```python
from dmarrss.decide.decision_node import DecisionNode

decision_node = DecisionNode(config, scorer, inference)

# Make decision
decision = decision_node.decide(event)

# Decision fields
print(f"Severity: {decision.severity}")
print(f"Threat Score: {decision.threat_score:.3f}")
print(f"Neural Severity: {decision.neural_severity}")
print(f"Recommended Actions: {decision.recommended_actions}")
print(f"Executed Actions: {decision.executed_actions}")
```

### Storage

```python
from dmarrss.store import Store

store = Store("data/state/dmarrss.db")

# Store event
event_id = store.store_event(event)

# Store decision
store.store_decision(decision)

# Query events
events = store.query_events(
    severity="HIGH",
    limit=100,
    start_time="2024-01-01T00:00:00Z"
)

# Get statistics
stats = store.get_statistics()
print(f"Total events: {stats['total_events']}")
print(f"By severity: {stats['by_severity']}")
```

## Command-Line Interface

DMARRSS provides a comprehensive CLI powered by Typer.

### Available Commands

```bash
# Show help
dmarrss --help

# Show version
dmarrss version

# Run daemon in dry-run mode (default)
dmarrss run

# Run daemon with enforcement (executes actions)
dmarrss run --enforce

# Train/update neural model
dmarrss train
dmarrss train --force  # Force retraining

# Generate and process synthetic events
dmarrss simulate --count 20

# Start REST API server
dmarrss api --host 0.0.0.0 --port 8080
```

### Configuration

Override config file location:

```bash
dmarrss run --config /path/to/config.yaml
```

### Environment Variables

- `DMARRSS_ENFORCE`: Enable action execution (0=dry-run, 1=execute)
- `DMARRSS_WEBHOOK_URL`: Webhook URL for notifications

## Integration Examples

### cURL

```bash
# Ingest event
curl -X POST http://localhost:8080/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "SNORT",
    "log_line": "[**] [1:2024364:1] ET MALWARE Detected [**]"
  }'

# Query events
curl "http://localhost:8080/events?severity=CRITICAL&limit=10"

# Get metrics
curl http://localhost:8080/metrics
```

### Python Requests

```python
import requests

# Ingest event
response = requests.post(
    "http://localhost:8080/ingest",
    json={
        "source": "SNORT",
        "log_line": "[**] [1:2024364:1] ET MALWARE Detected [**]"
    }
)
decision = response.json()

# Query events
response = requests.get(
    "http://localhost:8080/events",
    params={"severity": "HIGH", "limit": 50}
)
events = response.json()
```

### Prometheus Scraping

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'dmarrss'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

## Next Steps

- Review the [Architecture](./architecture.md) for system design
- Follow the [Deployment Guide](./deployment.md) for production setup
- Check the [GitHub Repository](https://github.com/PR-CYBR/DMARRSS) for code examples
