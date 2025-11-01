# Deployment Guide

This guide covers different deployment options for DMARRSS, from local development to production environments.

## Prerequisites

- Python 3.10 or higher
- Docker and Docker Compose (for containerized deployment)
- Git
- Linux/macOS/Windows (with WSL)

## Local Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/PR-CYBR/DMARRSS.git
cd DMARRSS
```

### 2. Install Dependencies

```bash
# Install with development tools
pip install -e ".[dev]"

# Or production install only
pip install -e .
```

### 3. Initialize Data Directories

```bash
mkdir -p data/raw data/state data/models data/training data/reputation logs
```

### 4. Train the Neural Model

```bash
# Create initial model (uses dummy data for cold start)
dmarrss train
```

### 5. Test the Installation

```bash
# Run tests
pytest tests/ -v

# Generate and process synthetic events
dmarrss simulate --count 10

# Start the API server
dmarrss api --host 127.0.0.1 --port 8080
```

## Docker Deployment

### Using Docker Compose (Recommended)

The easiest way to deploy DMARRSS with all services.

#### 1. Start All Services

```bash
# Start daemon, API, Prometheus, and Grafana
docker-compose up -d
```

Services available:
- **dmarrss-daemon**: Event processing daemon
- **dmarrss-api**: REST API server (port 8080)
- **prometheus**: Metrics collection (port 9090)
- **grafana**: Metrics visualization (port 3000)

#### 2. View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f dmarrss-daemon
docker-compose logs -f dmarrss-api
```

#### 3. Stop Services

```bash
docker-compose down
```

#### 4. Update Services

```bash
# Rebuild and restart
docker-compose up -d --build
```

### Using Docker Directly

#### 1. Build the Image

```bash
# Using Makefile
make docker-build

# Or manually
docker build -t dmarrss:latest -f docker/Dockerfile .
```

#### 2. Run the Daemon

```bash
docker run -d \
  --name dmarrss-daemon \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config:/app/config \
  dmarrss:latest dmarrss run
```

#### 3. Run the API Server

```bash
docker run -d \
  --name dmarrss-api \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config:/app/config \
  dmarrss:latest dmarrss api --host 0.0.0.0 --port 8080
```

#### 4. Enable Enforcement Mode

```bash
docker run -d \
  --name dmarrss-daemon \
  -e DMARRSS_ENFORCE=1 \
  -v $(pwd)/data:/app/data \
  dmarrss:latest dmarrss run
```

## Production Deployment

### Systemd Service (Linux)

For production Linux servers, use systemd for process management.

#### 1. Create Service File

```bash
sudo nano /etc/systemd/system/dmarrss.service
```

Example service file:

```ini
[Unit]
Description=DMARRSS - Decentralized Machine Assisted Rapid Response Security System
After=network.target

[Service]
Type=simple
User=dmarrss
Group=dmarrss
WorkingDirectory=/opt/dmarrss
Environment="PATH=/opt/dmarrss/venv/bin"
Environment="DMARRSS_ENFORCE=0"
ExecStart=/opt/dmarrss/venv/bin/dmarrss run --config /etc/dmarrss/config.yaml
Restart=always
RestartSec=10
StandardOutput=append:/var/log/dmarrss/daemon.log
StandardError=append:/var/log/dmarrss/error.log

[Install]
WantedBy=multi-user.target
```

#### 2. Install DMARRSS

```bash
# Create user and directories
sudo useradd -r -s /bin/false dmarrss
sudo mkdir -p /opt/dmarrss /etc/dmarrss /var/log/dmarrss
sudo chown dmarrss:dmarrss /opt/dmarrss /var/log/dmarrss

# Clone and install
cd /opt/dmarrss
sudo -u dmarrss git clone https://github.com/PR-CYBR/DMARRSS.git .
sudo -u dmarrss python3 -m venv venv
sudo -u dmarrss venv/bin/pip install -e .

# Copy configuration
sudo cp config/dmarrss_config.yaml /etc/dmarrss/config.yaml
sudo chown dmarrss:dmarrss /etc/dmarrss/config.yaml

# Train model
sudo -u dmarrss venv/bin/dmarrss train
```

#### 3. Start and Enable Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Start service
sudo systemctl start dmarrss

# Enable on boot
sudo systemctl enable dmarrss

# Check status
sudo systemctl status dmarrss

# View logs
sudo journalctl -u dmarrss -f
```

#### 4. Manage the Service

```bash
# Stop service
sudo systemctl stop dmarrss

# Restart service
sudo systemctl restart dmarrss

# View logs
sudo tail -f /var/log/dmarrss/daemon.log
```

### API Service with Systemd

Create a separate service for the API:

```bash
sudo nano /etc/systemd/system/dmarrss-api.service
```

```ini
[Unit]
Description=DMARRSS API Server
After=network.target

[Service]
Type=simple
User=dmarrss
Group=dmarrss
WorkingDirectory=/opt/dmarrss
Environment="PATH=/opt/dmarrss/venv/bin"
ExecStart=/opt/dmarrss/venv/bin/dmarrss api --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10
StandardOutput=append:/var/log/dmarrss/api.log
StandardError=append:/var/log/dmarrss/api-error.log

[Install]
WantedBy=multi-user.target
```

Start the API service:

```bash
sudo systemctl daemon-reload
sudo systemctl start dmarrss-api
sudo systemctl enable dmarrss-api
sudo systemctl status dmarrss-api
```

## Kubernetes Deployment

### 1. Create Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: dmarrss
```

### 2. Create ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: dmarrss-config
  namespace: dmarrss
data:
  dmarrss_config.yaml: |
    system:
      mode: "decentralized"
      enforce: false
      data_dir: "/app/data"
    # ... rest of config
```

### 3. Create PersistentVolumeClaim

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: dmarrss-data
  namespace: dmarrss
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### 4. Create Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dmarrss-daemon
  namespace: dmarrss
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dmarrss-daemon
  template:
    metadata:
      labels:
        app: dmarrss-daemon
    spec:
      containers:
      - name: dmarrss
        image: ghcr.io/pr-cybr/dmarrss:latest
        command: ["dmarrss", "run"]
        env:
        - name: DMARRSS_ENFORCE
          value: "0"
        volumeMounts:
        - name: data
          mountPath: /app/data
        - name: config
          mountPath: /app/config
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: dmarrss-data
      - name: config
        configMap:
          name: dmarrss-config
```

### 5. Create API Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: dmarrss-api
  namespace: dmarrss
spec:
  selector:
    app: dmarrss-api
  ports:
  - port: 8080
    targetPort: 8080
  type: LoadBalancer
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dmarrss-api
  namespace: dmarrss
spec:
  replicas: 3
  selector:
    matchLabels:
      app: dmarrss-api
  template:
    metadata:
      labels:
        app: dmarrss-api
    spec:
      containers:
      - name: dmarrss
        image: ghcr.io/pr-cybr/dmarrss:latest
        command: ["dmarrss", "api", "--host", "0.0.0.0", "--port", "8080"]
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: data
          mountPath: /app/data
        - name: config
          mountPath: /app/config
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: dmarrss-data
      - name: config
        configMap:
          name: dmarrss-config
```

### 6. Apply Configurations

```bash
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f pvc.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

## Configuration

### System Configuration

Edit `config/dmarrss_config.yaml`:

```yaml
system:
  mode: "decentralized"  # or "centralized_cloud", "centralized_onprem"
  enforce: false          # Set to true to execute actions
  data_dir: "./data"

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

scoring:
  weights:
    pattern_match: 0.30
    context_relevance: 0.25
    historical_severity: 0.20
    source_reputation: 0.15
    anomaly_score: 0.10
  cidr_include: ["10.0.0.0/8", "192.168.0.0/16"]
  reputation_csv: "./data/reputation/reputation.csv"

severity_layers:
  layer1:
    critical: 0.90
    high: 0.70
    medium: 0.50
    low: 0.30

responses:
  CRITICAL: ["block_ip", "notify_webhook"]
  HIGH: ["notify_webhook"]
  MEDIUM: ["notify_webhook"]
  LOW: []
```

### Environment Variables

- `DMARRSS_ENFORCE`: Enable action execution (0=dry-run, 1=execute)
- `DMARRSS_WEBHOOK_URL`: Webhook URL for notifications
- `DMARRSS_CONFIG`: Path to config file

## Monitoring

### Prometheus

DMARRSS exposes metrics at `/metrics` endpoint.

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'dmarrss'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Grafana

Import the DMARRSS dashboard (coming soon) or create custom dashboards using Prometheus metrics.

Key metrics:
- `dmarrss_events_total`: Total events processed
- `dmarrss_events_by_severity`: Events by severity level
- `dmarrss_processing_time_seconds`: Processing time histogram
- `dmarrss_actions_executed`: Actions executed by type

### Logging

Logs are written to:
- Daemon: `logs/daemon.log`
- API: stdout/stderr (captured by Docker/systemd)
- Actions: `logs/actions.log`

Configure log level via environment:

```bash
export LOG_LEVEL=DEBUG
dmarrss run
```

## Security Considerations

1. **Firewall Configuration**: Restrict API access to trusted networks
2. **TLS/SSL**: Use reverse proxy (nginx, Traefik) for HTTPS
3. **Authentication**: Implement API authentication in production
4. **Action Execution**: Start with `enforce: false` and validate decisions
5. **Network Segmentation**: Deploy in isolated security network
6. **Secrets Management**: Use environment variables or secrets manager
7. **Regular Updates**: Keep dependencies and models up to date

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u dmarrss -n 50

# Check permissions
ls -la /opt/dmarrss/data

# Verify Python environment
/opt/dmarrss/venv/bin/python --version
```

### High Memory Usage

```bash
# Monitor memory
docker stats dmarrss-daemon

# Reduce batch size in config
# Increase swap space
# Use smaller neural network model
```

### Events Not Processing

```bash
# Check file paths in config
# Verify log file permissions
# Check parser compatibility
# Review daemon logs
```

### API Not Responding

```bash
# Check if service is running
sudo systemctl status dmarrss-api

# Verify port is open
sudo netstat -tlnp | grep 8080

# Check firewall rules
sudo ufw status
```

## Performance Tuning

### For High Throughput

1. Use decentralized mode
2. Increase worker processes
3. Use SSD storage for database
4. Tune database indices
5. Enable connection pooling

### For Low Latency

1. Pre-load models in memory
2. Use local database (SQLite)
3. Optimize severity thresholds
4. Reduce logging verbosity
5. Use compiled Python (PyPy)

## Backup and Recovery

### Backup Data

```bash
# Backup database
cp data/state/dmarrss.db backups/dmarrss.db.$(date +%Y%m%d)

# Backup configuration
cp config/dmarrss_config.yaml backups/config.yaml.$(date +%Y%m%d)

# Backup models
tar -czf backups/models.$(date +%Y%m%d).tar.gz data/models/
```

### Restore Data

```bash
# Restore database
cp backups/dmarrss.db.20240115 data/state/dmarrss.db

# Restore configuration
cp backups/config.yaml.20240115 config/dmarrss_config.yaml

# Restore models
tar -xzf backups/models.20240115.tar.gz -C data/
```

## Next Steps

- Review the [API Reference](./api-reference.md) for integration
- Check the [Architecture](./architecture.md) for system design
- Explore the [Roadmap](./roadmap.md) for upcoming features
- Join the community on [GitHub](https://github.com/PR-CYBR/DMARRSS)
