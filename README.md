# DMARRSS - Decentralized Machine Assisted Rapid Response Security System

[![Tests](https://img.shields.io/badge/tests-73%20passing-brightgreen)]() [![Python](https://img.shields.io/badge/python-3.10%2B-blue)]() [![License](https://img.shields.io/badge/license-MIT-blue)]() [![NIST CSF 2.0](https://img.shields.io/badge/NIST%20CSF-2.0-blue)]()

DMARRSS is an advanced threat detection and response system that leverages **LLM-inspired architecture**, **neural networks**, and **NIST CSF 2.0 framework** to intelligently detect, classify, and prioritize security threats in distributed systems. The system processes logs from industry-standard security tools (SNORT, SURICATA, ZEEK) and applies sophisticated scoring algorithms with Context Aware Event Severity Layers to identify critical threats and automate response actions.

## 🎯 Key Features

### Core Capabilities
- **LLM-Inspired Pattern Recognition**: Neural network architecture inspired by transformer models for advanced threat pattern detection
- **Context-Aware Event Severity Layers**: Dual-layer severity assessment system for precise threat classification
- **Multi-Source Log Ingestion**: Native support for SNORT, SURICATA, and ZEEK log formats
- **Neural Threat Prioritization**: Deep learning-based classification with confidence scoring
- **Automated Response Actions**: Intelligent response system with configurable severity-based actions
- **Modular Architecture**: Clean, extensible design with separate components for parsing, scoring, classification, and response
- **Real-time Processing**: High-performance pipeline capable of processing thousands of events per second

### NIST CSF 2.0 Integration 🆕
DMARRSS now includes comprehensive NIST Cybersecurity Framework 2.0 support:

- **IDENTIFY** 🔍
  - **Asset Inventory**: Automated collection of system assets (OS, processes, network, users, software)
  - Cross-platform support (Windows, Linux, macOS)
  - Baseline establishment for anomaly detection

- **PROTECT** 🛡️
  - **Security Baseline Checks**: Firewall, antivirus, logging status verification
  - Weak configuration detection (SSH, default passwords)
  - Vulnerability assessment and recommendations

- **DETECT** 🎯
  - **Anomaly Detection**: Behavioral baseline comparison for processes, network, and users
  - **Threat Intelligence Integration**: IoC matching against malicious IPs, domains, and file hashes
  - Real-time threat feed updates with extensible feed framework
  - Automatic IoC scanning during event processing

- **RESPOND** ⚡
  - **Enhanced Response Actions**: Process termination, network quarantine, account disable
  - **Artifact Collection**: Automatic forensic evidence collection for critical threats
  - Recovery tracking for all response actions
  - Policy-based action configuration

- **RECOVER** 🔄
  - **Change Tracking**: Complete audit trail of all modifications
  - **File Backup**: Automatic backup before critical changes
  - **Recovery Reports**: Detailed remediation and restoration guidance
  - Service restoration tracking

- **GOVERN** 📊
  - **CSF Alignment Reports**: Comprehensive activity mapping to CSF functions
  - **Executive Summaries**: Management-friendly compliance reports
  - **Activity Logging**: Structured JSON logs with CSF function tags
  - Compliance status tracking

## 🗺️ Live Codebase Mindmap

Auto-generated on each push: **repo-map.html** (via GitHub Pages and CI artifact).

When Pages is enabled, it will be served at: `https://<owner>.github.io/<repo>/repo-map.html`

The mindmap provides an interactive visualization of the entire codebase structure, including:
- Language distribution and file statistics
- Directory hierarchy with expandable/collapsible nodes
- Quick navigation to understand project organization

## 🏗️ Architecture

DMARRSS implements a multi-stage pipeline that transforms raw security logs into actionable threat intelligence:

```mermaid
graph TD
    A[Threat Data Sources] --> B{Universal Log Parser}
    B -->|SNORT| C[Event Extraction]
    B -->|SURICATA| C
    B -->|ZEEK| C
    
    C --> D[Threat Scoring Engine]
    D --> E[Context Aware Severity Layer 1]
    E --> F[Context Aware Severity Layer 2]
    
    F --> G[LLM-Inspired Neural Processor]
    G --> H[Pattern Recognition]
    G --> I[Context Attention]
    
    H --> J[Threat Classification]
    I --> J
    
    J --> K{Severity Decision Node}
    
    K -->|Critical 0.9+| L[Automated Response]
    K -->|High 0.7-0.9| M[Analyst Review Queue]
    K -->|Medium 0.5-0.7| N[Reassessment Queue]
    K -->|Low 0-0.5| O[Log & Monitor]
    
    L --> P[Block IP/Isolate System]
    L --> Q[Send Alerts]
    L --> R[Escalate to SOC]
    
    M --> S[Human Review Required]
    N --> T[Scheduled Reassessment]
    O --> U[Monitoring Dashboard]
    
    style K fill:#ff6b6b
    style L fill:#ff0000
    style M fill:#ffa500
    style N fill:#ffff00
    style O fill:#90ee90
    style G fill:#4ecdc4
    style D fill:#95e1d3
```

### Pipeline Stages

1. **Input Layer**: Multi-format log ingestion with auto-detection
2. **Parsing Layer**: Structured event extraction from security logs
3. **Scoring Layer**: Composite threat scoring using weighted components:
   - Pattern matching (30%)
   - Context relevance (25%)
   - Historical severity (20%)
   - Source reputation (15%)
   - Anomaly detection (10%)
4. **Neural Processing Layer**: LLM-inspired classification with attention mechanisms
5. **Severity Assessment**: Dual-layer context-aware severity determination
6. **Response Layer**: Automated action execution based on threat level

## 📋 Requirements

- Python 3.8 or higher
- PyTorch 2.0+
- NumPy, Pandas, scikit-learn
- PyYAML for configuration management

## 🚀 Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/PR-CYBR/DMARRSS.git
cd DMARRSS

# Install dependencies with development tools
pip install -e ".[dev]"

# Or production install
pip install -e .

# Train the neural model (creates dummy model for cold start)
dmarrss train

# Run the demo with synthetic events
dmarrss simulate --count 10
```

### Development Setup

```bash
# Install with pre-commit hooks
make setup

# Run tests
make test

# Run with coverage
make test-cov

# Lint and format code
make lint
make format
```

## 💻 Usage

### Command-Line Interface

DMARRSS provides a comprehensive CLI powered by Typer:

```bash
# Show help
dmarrss --help

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

# Show version
dmarrss version

# NIST CSF 2.0 Commands
dmarrss collect-inventory          # Collect asset inventory (Identify)
dmarrss check-baseline             # Run security baseline checks (Protect)
dmarrss detect-anomalies           # Detect anomalies from baseline (Detect)
dmarrss update-threat-intel        # Update threat intelligence feeds (Detect)
dmarrss generate-csf-report        # Generate CSF alignment report (Govern)
dmarrss generate-csf-report --executive  # Generate executive summary
```

### NIST CSF Workflow

Complete CSF workflow example:

```bash
# 1. IDENTIFY: Establish baseline
dmarrss collect-inventory

# 2. PROTECT: Check security posture
dmarrss check-baseline

# 3. DETECT & RESPOND: Run threat hunting
dmarrss run

# 4. DETECT: Check for anomalies
dmarrss detect-anomalies

# 5. GOVERN: Generate compliance reports
dmarrss generate-csf-report --executive

# Generate and process synthetic events
dmarrss simulate --count 20

# Start REST API server
dmarrss api --host 0.0.0.0 --port 8080

# Show version
dmarrss version
```

### Python API

```python
from dmarrss.parsers import SnortParser
from dmarrss.scoring.threat_scorer import ThreatScorer
from dmarrss.models.inference import ThreatInference
from dmarrss.decide.decision_node import DecisionNode
from dmarrss.store import Store
import yaml

# Load config
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

### REST API

Start the API server:

```bash
dmarrss api
```

API endpoints:

- `GET /` - API info and available endpoints
- `GET /status` - System status and model info
- `POST /ingest` - Ingest single event
- `POST /ingest/batch` - Ingest multiple events
- `GET /events` - Query events (with filters)
- `GET /decisions/{id}` - Get decision details
- `POST /actions/test` - Test action plugins
- `GET /metrics` - Prometheus metrics

Example API usage:

```bash
# Check status
curl http://localhost:8080/status

# Ingest event
curl -X POST http://localhost:8080/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "SNORT",
    "log_line": "[**] [1:2024364:1] ET MALWARE Detected [**] [Priority: 1] {TCP} 203.0.113.50:54321 -> 192.168.1.100:443"
  }'

# Get metrics
curl http://localhost:8080/metrics
```

## ⚙️ Configuration

DMARRSS is highly configurable through `config/dmarrss_config.yaml`:

### System Configuration

```yaml
system:
  mode: "decentralized"  # decentralized, centralized_cloud, centralized_onprem
  enforce: false          # Enable action execution (can override with DMARRSS_ENFORCE env var)
  data_dir: "./data"
```

### Log Ingestion

```yaml
ingest:
  snort:
    enabled: true
    files: ["./data/raw/sample_snort_alerts.log"]
  suricata:
    enabled: true
    files: ["./data/raw/sample_suricata_eve.json"]
  zeek:
    enabled: true
    files: ["./data/raw/sample_zeek_conn.log"]
```

### Threat Scoring

```yaml
scoring:
  weights:
    pattern_match: 0.30
    context_relevance: 0.25
    historical_severity: 0.20
    source_reputation: 0.15
    anomaly_score: 0.10
  cidr_include: ["10.0.0.0/8", "192.168.0.0/16"]
  reputation_csv: "./data/reputation/reputation.csv"
```

### Severity Thresholds

```yaml
severity_layers:
  layer1:
    critical: 0.90
    high: 0.70
    medium: 0.50
    low: 0.30
```

### Response Actions

```yaml
responses:
  CRITICAL: ["block_ip", "notify_webhook", "collect_artifacts"]
  HIGH: ["notify_webhook"]
  MEDIUM: ["notify_webhook"]
  LOW: []
```

### NIST CSF Configuration 🆕

```yaml
csf:
  # Asset Inventory (IDENTIFY function)
  asset_inventory:
    enabled: true
    auto_collect_on_start: true
    
  # Security Baseline (PROTECT function)
  security_baseline:
    enabled: true
    auto_check_on_start: false
    
  # Anomaly Detection (DETECT function)
  anomaly_detection:
    enabled: true
    process_threshold: 0.2  # 20% deviation threshold
    network_threshold: 0.3  # 30% deviation threshold
    user_threshold: 0.5     # 50% deviation threshold
    
  # Threat Intelligence (DETECT function)
  threat_intel:
    enabled: true
    update_interval_hours: 24
    
  # Recovery (RECOVER function)
  recovery:
    enabled: true
    auto_backup_before_changes: true
    
  # CSF Reporting (GOVERN function)
  reporting:
    enabled: true
    auto_generate_on_complete: true
```

### Environment Variables

- `DMARRSS_ENFORCE` - Enable action execution (0=dry-run, 1=execute)
- `DMARRSS_WEBHOOK_URL` - Webhook URL for notifications

## 🐳 Docker Deployment

### Docker Compose (Recommended)

The easiest way to deploy DMARRSS with all services:

```bash
# Start all services (daemon, API, Prometheus, Grafana)
make docker-up

# Or manually
docker-compose up -d

# View logs
docker-compose logs -f dmarrss-daemon
docker-compose logs -f dmarrss-api

# Stop services
make docker-down
```

Services:
- **dmarrss-daemon**: Event processing daemon
- **dmarrss-api**: REST API server (port 8080)
- **prometheus**: Metrics collection (port 9090)
- **grafana**: Metrics visualization (port 3000)

### Docker Build

```bash
# Build image
make docker-build

# Or manually
docker build -t dmarrss:latest -f docker/Dockerfile .

# Run daemon
docker run -v $(pwd)/data:/app/data dmarrss:latest dmarrss run

# Run API
docker run -p 8080:8080 -v $(pwd)/data:/app/data dmarrss:latest dmarrss api
```

### Environment Variables for Docker

```bash
# Enable enforcement mode
docker run -e DMARRSS_ENFORCE=1 dmarrss:latest dmarrss run

# Set webhook URL
docker run -e DMARRSS_WEBHOOK_URL=https://hooks.example.com/webhook dmarrss:latest
```

## 🚀 Production Deployment

### Systemd Service

For Linux servers, a systemd service template is provided:

```bash
# Install service
sudo cp deploy/systemd/dmarrss.service /etc/systemd/system/
sudo systemctl daemon-reload

# Start service
sudo systemctl start dmarrss
sudo systemctl enable dmarrss

# Check status
sudo systemctl status dmarrss

# View logs
sudo journalctl -u dmarrss -f
```

**Note**: Edit the service file to set correct paths and user before installing.

## 🧪 Testing

DMARRSS includes comprehensive test coverage:

```bash
# Run all tests
make test

# Run with coverage report
make test-cov

# Run specific test file
pytest tests/test_parsers.py -v

# Run specific test
pytest tests/test_parsers.py::TestSnortParser::test_parse_snort_alert_with_priority -v
```

### Test Results

Current test coverage: **73 tests passing** (50 original + 23 CSF tests)

#### Core Tests
- ✅ Parser tests: SNORT, SURICATA, ZEEK format parsing
- ✅ Scoring tests: Threat scoring components and composite scores
- ✅ Decision tests: Severity classification and batch processing
- ✅ Action tests: Dry-run mode for all action plugins
- ✅ Integration tests: End-to-end pipeline with in-memory storage
- ✅ CVE enrichment: CVE detection, fetching, caching

#### NIST CSF Tests 🆕
- ✅ Asset Inventory: System info, network, processes collection
- ✅ Security Baseline: Firewall, antivirus, logging checks
- ✅ Anomaly Detection: Process, network, user anomalies
- ✅ Threat Intelligence: IoC loading, matching, event scanning
- ✅ Recovery Manager: Change tracking, backups, reporting
- ✅ CSF Reporter: Activity logging, alignment reports, summaries

### CI/CD

GitHub Actions workflows automatically:
- Run tests on Python 3.10, 3.11, 3.12
- Check code formatting (black, ruff)
- Run type checking (mypy)
- Build Docker images
- Publish releases to GHCR on tags

## 📊 Sample Data

Sample security logs are included for testing and demonstration:

- `data/raw/sample_snort_alerts.log` - SNORT alert examples
- `data/raw/sample_suricata_eve.json` - SURICATA EVE JSON format

## 🔍 Components

### Core Modules

- **`src/dmarrss/parsers/`**: Log parsers for SNORT, SURICATA, and ZEEK
  - Unified Event schema with Pydantic validation
  - Streaming-capable parsers
- **`src/dmarrss/scoring/threat_scorer.py`**: Config-driven composite threat scoring
  - Pattern matching, context relevance, historical severity
  - Source reputation, anomaly detection
- **`src/dmarrss/models/`**: Neural network threat classification
  - PyTorch MLP for tabular features
  - Model training and inference pipelines
  - Versioned model storage with metadata
- **`src/dmarrss/decide/decision_node.py`**: Decision engine
  - Combines scoring and neural predictions
  - Severity classification with confidence scores
- **`src/dmarrss/actions/`**: Action plugins with dry-run support
  - `block_ip.py`: Platform-specific firewall rules (Linux/Mac/Windows)
  - `isolate_host.py`: Network isolation
  - `notify_webhook.py`: Webhook notifications
  - `terminate_process.py`: Enhanced process control
  - `quarantine_network.py`: Network quarantine
  - `disable_account.py`: Account management
  - `collect_artifacts.py`: Forensic artifact collection
- **`src/dmarrss/csf/`**: NIST CSF 2.0 modules 🆕
  - `asset_inventory.py`: Asset catalog and baseline (IDENTIFY)
  - `security_baseline.py`: Security posture checks (PROTECT)
  - `anomaly_detector.py`: Behavioral anomaly detection (DETECT)
  - `threat_intel.py`: IoC feed integration (DETECT)
  - `recovery.py`: Recovery and restoration (RECOVER)
  - `csf_reporting.py`: Governance and reporting (GOVERN)
- **`src/dmarrss/store.py`**: SQLite persistence layer
  - Events, decisions, actions, statistics
  - File position tracking for log tailers
- **`src/dmarrss/api.py`**: FastAPI REST server with Prometheus metrics
- **`src/dmarrss/cli.py`**: Typer-based command-line interface
- **`src/dmarrss/daemon.py`**: Autonomous daemon supervisor with CSF integration

## 🎓 Example Output

```
Event: ET EXPLOIT Critical Remote Code Execution Attempt
────────────────────────────────────────────────────────
  Source:          SNORT
  Source IP:       203.0.113.50
  Dest IP:         192.168.1.100
  Threat Score:    0.700
  Severity:        HIGH
  Neural Severity: MEDIUM (conf: 0.276)
  Response:        analyst_review

Score Components:
  pattern_match        : 0.900
  context_relevance    : 0.900
  historical_severity  : 0.400
  source_reputation    : 0.700
  anomaly_score        : 0.200
```

## 🛠️ Development Roadmap

### Completed ✅
- [x] Core pipeline implementation
- [x] Multi-format log parsing (SNORT, SURICATA, ZEEK)
- [x] Threat scoring with Context Aware Severity Layers
- [x] Neural network threat classification
- [x] Automated response system with dry-run
- [x] REST API with Prometheus metrics
- [x] Command-line interface
- [x] Docker and Docker Compose support
- [x] CI/CD with GitHub Actions
- [x] Comprehensive test suite (73 tests passing)
- [x] **NIST CSF 2.0 Integration** 🆕
  - [x] Asset inventory (IDENTIFY)
  - [x] Security baseline checks (PROTECT)
  - [x] Anomaly detection (DETECT)
  - [x] Threat intelligence integration (DETECT)
  - [x] Enhanced response actions (RESPOND)
  - [x] Recovery mechanisms (RECOVER)
  - [x] Governance reporting (GOVERN)

### In Progress 🚧
- [ ] Async log tailers with watchdog
- [ ] Continuous monitoring mode with scheduling
- [ ] Email alerting (SMTP integration)
- [ ] SIEM integration support

### Planned 📋
- [ ] Fine-tuning on domain-specific cybersecurity datasets
- [ ] Distributed agent deployment
- [ ] Web-based visualization dashboard
- [ ] Advanced threat intelligence feed sources
- [ ] Increase test coverage to ≥85%

## 📖 Documentation

- **Architecture Details**: See `docs/phase-breakdown.md`
- **Project Roadmap**: See `docs/roadmap.md`
- **API Reference**: See inline code documentation

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by Large Language Model architectures and transformer-based pattern recognition
- Built for compatibility with industry-standard security tools (SNORT, SURICATA, ZEEK)
- Designed for deployment in distributed security operations centers

## 📧 Contact

For questions, issues, or contributions, please open an issue on GitHub or contact the development team.

---

**DMARRSS** - Intelligent, automated threat detection and response for modern distributed systems.
