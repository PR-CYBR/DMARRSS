# Roadmap

This page outlines the development roadmap for DMARRSS with milestones and estimated timelines.

## Current Status

### Completed Features ✅

- [x] Core pipeline implementation
- [x] Multi-format log parsing (SNORT, SURICATA, ZEEK)
- [x] Threat scoring with Context Aware Severity Layers
- [x] Neural network threat classification
- [x] Automated response system with dry-run mode
- [x] REST API with Prometheus metrics
- [x] Command-line interface
- [x] Docker and Docker Compose support
- [x] CI/CD with GitHub Actions
- [x] Comprehensive test suite (49% coverage)

## Development Phases

### Phase 1: AI Controlled Data Source Processing ✅

**Status: Completed**

1. ✅ Preselection of Data Sources/Inputs to process:
   - System Logs
   - System Scans
   - System Properties
   - Custom System Properties

2. ✅ Categorizing events in the data source (input)

3. ✅ Calculating severity level for every event

4. ✅ Defining final weights/confidence values

5. ✅ Defining values for:
   - Context Aware Event Severity Risk Layer 1
   - Context Aware Event Severity Risk Layer 2

6. ✅ Localization of the system:
   - Centralized Cloud
   - Centralized On Premises
   - Decentralized (every agent calculates scores)

### Phase 2: AI Controlled Response 🚧

**Status: In Progress**

1. ✅ Defining actions to perform for every event based on the score
   - ✅ Developing LLM Specific (Transformers) Model for security data
   - 🚧 Developing Set Of Complementary Rules for AI Decision Process

2. 🚧 Engineering actions (AI Control Over Infrastructure)
   - ✅ Basic action plugins (block_ip, notify_webhook, isolate_host)
   - 🚧 Advanced orchestration capabilities
   - 🚧 Multi-cloud support

## Detailed Milestones

### 1. Data Collection and Preprocessing ✅

**Timeline: Completed** | **Duration: 1-2 weeks**

- [x] Finalized list of relevant cybersecurity datasets, logs, and threat intelligence feeds
- [x] Completed preprocessing scripts to clean, format, and normalize data
- [x] Successfully split preprocessed data into training, validation, and test sets

### 2. Model Development and Fine-tuning ✅

**Timeline: Completed** | **Duration: 3-4 weeks**

- [x] Chosen appropriate LLM-inspired architecture and neural network technologies
- [x] Completed implementation and fine-tuning of models on preprocessed datasets
- [x] Successfully incorporated context-aware and risk-sensitive mechanisms

### 3. System Integration and Evaluation ✅

**Timeline: Completed** | **Duration: 2-3 weeks**

- [x] Developed scripts for combining Context Aware Event Severity Layers
- [x] Completed integration with SNORT, SURICATA, and ZEEK
- [x] Evaluated system performance using standard metrics

### 4. Visualization and Frontend Development 🚧

**Timeline: Q2 2024** | **Duration: 2-3 weeks**

- [ ] Design user-friendly frontend interface for visualizing threat event table
- [ ] Implement frontend with support for different log formats
- [ ] Test frontend integration with DMARRSS system

### 5. Testing and Validation 🚧

**Timeline: Ongoing** | **Duration: 1-2 weeks per iteration**

- [x] Comprehensive testing (unit, integration, end-to-end)
- [ ] Increase test coverage to ≥85%
- [ ] Validate system accuracy in real-world scenarios
- [ ] Performance benchmarking

### 6. Documentation and Deployment ✅

**Timeline: Completed** | **Duration: 1-2 weeks**

- [x] Comprehensive documentation covering architecture and usage
- [x] Package system for deployment
- [x] Docker and systemd deployment options
- [x] CI/CD pipeline with automated testing

## Upcoming Features

### Q1 2024

#### Async Log Tailers 🎯

**Priority: High**

Implement asynchronous log file monitoring with watchdog:
- Real-time log file watching
- Automatic position tracking
- Graceful restart with state preservation
- Support for log rotation

#### Enhanced Testing 🎯

**Priority: High**

Increase test coverage and quality:
- Target: 85% code coverage
- Integration tests for all components
- Performance benchmarks
- Load testing scenarios

### Q2 2024

#### Fine-tuning on Domain-Specific Datasets 🎯

**Priority: Medium**

Improve neural network accuracy:
- Collect domain-specific cybersecurity datasets
- Fine-tune transformer models
- Implement transfer learning
- Continuous model updates

#### Web-based Visualization Dashboard 🎯

**Priority: Medium**

Interactive dashboard for monitoring:
- Real-time threat visualization
- Historical trend analysis
- Custom alert configurations
- Multi-user support with RBAC

### Q3 2024

#### Distributed Agent Deployment 🎯

**Priority: High**

Scale to multiple agents:
- Agent coordination protocol
- Centralized threat intelligence sharing
- Distributed model updates
- High availability configuration

#### Threat Intelligence Feed Integration 🎯

**Priority: Medium**

Integrate external threat feeds:
- MISP integration
- STIX/TAXII support
- Commercial threat feed APIs
- Automated IOC ingestion

### Q4 2024

#### Advanced Features 🎯

**Priority: Low-Medium**

Additional capabilities:
- Multi-language support
- Advanced ML models (ensemble, deep learning)
- Custom rule engine
- Automated model retraining

## Long-term Vision

### 2025 and Beyond

#### Machine Learning Enhancements

- Federated learning across distributed agents
- AutoML for model optimization
- Explainable AI for decision transparency
- Adversarial attack resistance

#### Enterprise Features

- Multi-tenancy support
- Advanced RBAC and audit logging
- Compliance reporting (SOC 2, ISO 27001)
- SLA monitoring and guarantees

#### Integration Ecosystem

- SIEM integrations (Splunk, ELK, QRadar)
- SOAR platform connectors
- Cloud-native deployments (AWS, Azure, GCP)
- Serverless architecture support

#### Performance and Scale

- Horizontal scaling improvements
- Real-time streaming with Kafka/Redis
- Time-series database support
- Edge computing optimizations

## Community Contributions

We welcome contributions in these areas:

### High Priority

- [ ] Additional log parser implementations
- [ ] New action plugins for different platforms
- [ ] Performance optimizations
- [ ] Test coverage improvements
- [ ] Documentation enhancements

### Medium Priority

- [ ] Web dashboard implementation
- [ ] Additional deployment options (Ansible, Terraform)
- [ ] Integration examples and tutorials
- [ ] Localization and i18n

### Low Priority

- [ ] Alternative ML models
- [ ] Custom visualization plugins
- [ ] Additional metric exporters
- [ ] Community-contributed configs

## Versioning Strategy

DMARRSS follows [Semantic Versioning](https://semver.org/):

- **Major version** (X.0.0): Breaking changes, major features
- **Minor version** (0.X.0): New features, backward compatible
- **Patch version** (0.0.X): Bug fixes, minor improvements

### Release Schedule

- **Patch releases**: Monthly or as needed for critical fixes
- **Minor releases**: Quarterly with new features
- **Major releases**: Yearly or when breaking changes are necessary

## Current Version: 1.0.0

### Recent Releases

- **v1.0.0** (Current): Initial stable release with core features
- **v0.9.0**: Beta release with API and CLI
- **v0.8.0**: Alpha release with basic pipeline

### Next Release: v1.1.0 (Planned Q1 2024)

Planned features:
- Async log tailers with watchdog
- Improved test coverage (target: 85%)
- Performance optimizations
- Additional action plugins
- Documentation improvements

## How to Contribute

1. Check the [GitHub Issues](https://github.com/PR-CYBR/DMARRSS/issues) for open tasks
2. Review the [Contributing Guidelines](https://github.com/PR-CYBR/DMARRSS/blob/main/CONTRIBUTING.md)
3. Fork the repository and create a feature branch
4. Submit a Pull Request with your changes
5. Participate in code review and testing

## Feedback and Suggestions

We value your input! Share your ideas:

- [Open a GitHub Issue](https://github.com/PR-CYBR/DMARRSS/issues/new)
- [Start a Discussion](https://github.com/PR-CYBR/DMARRSS/discussions)
- [Join our Community](https://github.com/PR-CYBR)

## Support

For questions and support:

- **Documentation**: [GitHub Repository](https://github.com/PR-CYBR/DMARRSS#readme)
- **Issues**: [GitHub Issues](https://github.com/PR-CYBR/DMARRSS/issues)
- **Email**: info@pr-cybr.com

---

*Last updated: January 2024*

*This roadmap is subject to change based on community feedback and project priorities.*
