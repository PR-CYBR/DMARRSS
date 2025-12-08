# DMARRSS Data Directories

This directory contains structured data organized by NIST CSF 2.0 functions.

## Directory Structure

### inventory/
Asset inventory data (NIST CSF Identify function)
- Contains system information, processes, network, users, and software inventories
- Files: `inventory_<timestamp>.json`, `latest.json`

### findings/
Security baseline findings (NIST CSF Protect function)
- Contains security posture checks and vulnerability assessments
- Files: `findings_<timestamp>.json`, `latest.json`

### anomalies/
Anomaly detection results (NIST CSF Detect function)
- Contains detected deviations from baseline behavior
- Files: `anomalies_<timestamp>.json`, `latest.json`

### threat_intel/
Threat intelligence data (NIST CSF Detect function)
- Contains IoCs and threat matches from feeds
- Files: `threat_matches_<timestamp>.json`, `latest.json`, `last_update.txt`

### recovery/
Recovery and restoration data (NIST CSF Recover function)
- Contains backups, change tracking, and recovery reports
- Subdirectories: `backups/`
- Files: `recovery_report_<timestamp>.json`, `latest.json`

### csf_reports/
CSF alignment and governance reports (NIST CSF Govern function)
- Contains NIST CSF 2.0 alignment reports and executive summaries
- Files: `csf_report_<timestamp>.json`, `executive_summary_<timestamp>.json`

### artifacts/
Forensic artifacts collected during incident response
- Contains evidence collected before remediation actions
- Subdirectories: `incident_<id>_<timestamp>/`

### state/
System state database
- Contains SQLite database for events, decisions, and actions
- Files: `dmarrss.db`

### cache/
Cached data for performance
- CVE enrichment cache
- Files: `cve_cache.json`

## File Naming Convention

- Timestamped files: `<type>_YYYYMMDD_HHMMSS.json`
- Latest files: `latest.json` (always points to most recent data)
- Manifests: `manifest.json` (metadata about collections)
