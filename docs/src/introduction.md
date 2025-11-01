# Introduction

![DMARRSS Logo](https://pr-cybr.github.io/DMARRSS/assets/logo.svg)

**DMARRSS** - Decentralized Machine Assisted Rapid Response Security System

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)]() [![Python](https://img.shields.io/badge/python-3.8%2B-blue)]() [![License](https://img.shields.io/badge/license-MIT-blue)]()

## Overview

DMARRSS is an advanced threat detection and response system that leverages **LLM-inspired architecture** and **neural networks** to intelligently detect, classify, and prioritize security threats in distributed systems. The system processes logs from industry-standard security tools (SNORT, SURICATA, ZEEK) and applies sophisticated scoring algorithms with Context Aware Event Severity Layers to identify critical threats and automate response actions.

## Key Features

- **LLM-Inspired Pattern Recognition**: Neural network architecture inspired by transformer models for advanced threat pattern detection
- **Context-Aware Event Severity Layers**: Dual-layer severity assessment system for precise threat classification
- **Multi-Source Log Ingestion**: Native support for SNORT, SURICATA, and ZEEK log formats
- **Neural Threat Prioritization**: Deep learning-based classification with confidence scoring
- **Automated Response Actions**: Intelligent response system with configurable severity-based actions
- **Modular Architecture**: Clean, extensible design with separate components for parsing, scoring, classification, and response
- **Real-time Processing**: High-performance pipeline capable of processing thousands of events per second

## Quick Start

### Installation

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

### Run the API Server

```bash
# Start REST API server
dmarrss api --host 0.0.0.0 --port 8080

# Check status
curl http://localhost:8080/status

# View metrics
curl http://localhost:8080/metrics
```

### Docker Deployment

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Requirements

- Python 3.8 or higher
- PyTorch 2.0+
- NumPy, Pandas, scikit-learn
- PyYAML for configuration management

## Getting Help

- [GitHub Repository](https://github.com/PR-CYBR/DMARRSS)
- [Issue Tracker](https://github.com/PR-CYBR/DMARRSS/issues)
- [API Reference](./api-reference.md)
- [Deployment Guide](./deployment.md)

## What's Next?

- Learn about the [Architecture](./architecture.md) and how DMARRSS processes threats
- Explore the [API Reference](./api-reference.md) for integration options
- Follow the [Deployment Guide](./deployment.md) for production setup
- Check out the [Roadmap](./roadmap.md) for upcoming features

