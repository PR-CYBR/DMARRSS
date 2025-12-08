"""
DMARRSS Command-Line Interface

Provides commands: run, train, simulate, api
"""

import os
import sys
from pathlib import Path

import typer
import yaml

app = typer.Typer(
    name="dmarrss",
    help="DMARRSS - Decentralized Machine Assisted Rapid Response Security System",
)


def load_config(config_path: str = "config/dmarrss_config.yaml") -> dict:
    """Load configuration from YAML"""
    path = Path(config_path)
    if not path.exists():
        typer.echo(f"Config file not found: {config_path}", err=True)
        raise typer.Exit(1)

    with open(path) as f:
        return yaml.safe_load(f)


@app.command()
def run(
    config: str = typer.Option(
        "config/dmarrss_config.yaml", "--config", "-c", help="Path to config file"
    ),
    enforce: bool = typer.Option(
        False, "--enforce", help="Enable enforcement mode (execute actions)"
    ),
):
    """
    Run DMARRSS daemon in continuous mode.

    Starts log tailers, scoring, classification, and response pipeline.
    """
    typer.echo("Starting DMARRSS daemon...")

    # Set enforce env var
    if enforce:
        os.environ["DMARRSS_ENFORCE"] = "1"
        typer.echo("⚠️  ENFORCE MODE ENABLED - Actions will be executed!")
    else:
        os.environ["DMARRSS_ENFORCE"] = "0"
        typer.echo("ℹ️  Dry-run mode (use --enforce to execute actions)")

    try:
        # Import here to avoid circular imports
        from .daemon import run_daemon

        config_data = load_config(config)
        run_daemon(config_data)

    except KeyboardInterrupt:
        typer.echo("\nShutting down DMARRSS daemon...")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def train(
    config: str = typer.Option(
        "config/dmarrss_config.yaml", "--config", "-c", help="Path to config file"
    ),
    force: bool = typer.Option(False, "--force", help="Force training even if not needed"),
):
    """
    Train or update neural threat classification model.

    Loads training data from data/training/events.parquet and trains/updates model.
    """
    typer.echo("Training neural threat classifier...")

    try:
        from .models.train import train_model

        config_data = load_config(config)
        success = train_model(config_data, force=force)

        if success:
            typer.echo("✓ Training complete!")
        else:
            typer.echo("ℹ️  Training skipped (model up to date)")

    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def simulate(
    config: str = typer.Option(
        "config/dmarrss_config.yaml", "--config", "-c", help="Path to config file"
    ),
    count: int = typer.Option(10, "--count", "-n", help="Number of events to generate"),
):
    """
    Generate and process synthetic security events for testing.

    Useful for testing the pipeline without real log data.
    """
    typer.echo(f"Generating {count} synthetic events...")

    try:
        # Import demo script
        sys.path.insert(0, "scripts")
        from demo import generate_synthetic_events, process_events

        config_data = load_config(config)

        # Generate events
        events = generate_synthetic_events(count)
        typer.echo(f"Generated {len(events)} events")

        # Process events
        results = process_events(events, config_data)

        # Print summary
        typer.echo("\nProcessing Summary:")
        severities = {}
        for result in results:
            sev = result.get("severity", "UNKNOWN")
            severities[sev] = severities.get(sev, 0) + 1

        for sev, count in sorted(severities.items()):
            typer.echo(f"  {sev}: {count}")

    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def api(
    config: str = typer.Option(
        "config/dmarrss_config.yaml", "--config", "-c", help="Path to config file"
    ),
    host: str = typer.Option("0.0.0.0", "--host", help="API host"),
    port: int = typer.Option(8080, "--port", "-p", help="API port"),
):
    """
    Start DMARRSS REST API server.

    Provides HTTP endpoints for event ingestion, status, and metrics.
    """
    typer.echo(f"Starting DMARRSS API server on {host}:{port}...")

    try:
        import uvicorn

        config_data = load_config(config)

        # Update API config
        config_data.setdefault("api", {})
        config_data["api"]["host"] = host
        config_data["api"]["port"] = port

        # Run API server
        from .api import create_app

        app_instance = create_app(config_data)
        uvicorn.run(app_instance, host=host, port=port)

    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def version():
    """Show DMARRSS version"""
    from . import __version__

    typer.echo(f"DMARRSS version {__version__}")


@app.command()
def collect_inventory(
    config: str = typer.Option(
        "config/dmarrss_config.yaml", "--config", "-c", help="Path to config file"
    ),
):
    """
    Collect system asset inventory (NIST CSF Identify function).
    
    Catalogs OS info, processes, network, users, and software.
    """
    typer.echo("Collecting asset inventory...")

    try:
        from .csf.asset_inventory import AssetInventory

        config_data = load_config(config)
        inventory = AssetInventory(config_data)
        
        # Collect and save inventory
        filepath = inventory.save_inventory()
        
        typer.echo(f"✓ Asset inventory saved to {filepath}")

    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def check_baseline(
    config: str = typer.Option(
        "config/dmarrss_config.yaml", "--config", "-c", help="Path to config file"
    ),
):
    """
    Check security baseline (NIST CSF Protect function).
    
    Verifies firewall, antivirus, logging, and configurations.
    """
    typer.echo("Checking security baseline...")

    try:
        from .csf.security_baseline import SecurityBaseline

        config_data = load_config(config)
        baseline = SecurityBaseline(config_data)
        
        # Run checks and save findings
        filepath = baseline.save_findings()
        
        # Load and display summary
        findings_data = baseline.load_findings()
        summary = findings_data.get("summary", {})
        
        typer.echo(f"\n✓ Security baseline check complete")
        typer.echo(f"  Total findings: {summary.get('total', 0)}")
        typer.echo(f"  Critical: {summary.get('critical', 0)}")
        typer.echo(f"  High: {summary.get('high', 0)}")
        typer.echo(f"  Medium: {summary.get('medium', 0)}")
        typer.echo(f"  Low: {summary.get('low', 0)}")
        typer.echo(f"\n  Report saved to {filepath}")

    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def detect_anomalies(
    config: str = typer.Option(
        "config/dmarrss_config.yaml", "--config", "-c", help="Path to config file"
    ),
):
    """
    Detect anomalies from baseline (NIST CSF Detect function).
    
    Compares current state against baseline inventory.
    """
    typer.echo("Detecting anomalies...")

    try:
        from .csf.asset_inventory import AssetInventory
        from .csf.anomaly_detector import AnomalyDetector

        config_data = load_config(config)
        
        # Collect current inventory
        inventory = AssetInventory(config_data)
        current = inventory.collect_all()
        
        # Detect anomalies
        detector = AnomalyDetector(config_data)
        detector.load_baseline()
        anomalies = detector.detect_all_anomalies(current)
        filepath = detector.save_anomalies(anomalies)
        
        # Display summary
        typer.echo(f"\n✓ Anomaly detection complete")
        typer.echo(f"  Total anomalies: {len(anomalies)}")
        high_count = sum(1 for a in anomalies if a.severity == "HIGH")
        medium_count = sum(1 for a in anomalies if a.severity == "MEDIUM")
        low_count = sum(1 for a in anomalies if a.severity == "LOW")
        typer.echo(f"  High: {high_count}")
        typer.echo(f"  Medium: {medium_count}")
        typer.echo(f"  Low: {low_count}")
        typer.echo(f"\n  Report saved to {filepath}")

    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def update_threat_intel(
    config: str = typer.Option(
        "config/dmarrss_config.yaml", "--config", "-c", help="Path to config file"
    ),
):
    """
    Update threat intelligence feeds (NIST CSF Detect function).
    
    Loads IoCs from configured threat feeds.
    """
    typer.echo("Updating threat intelligence feeds...")

    try:
        from .csf.threat_intel import ThreatIntelligence

        config_data = load_config(config)
        intel = ThreatIntelligence(config_data)
        
        # Load feeds
        intel.load_feeds()
        intel.mark_updated()
        
        typer.echo(f"✓ Threat intelligence updated")
        typer.echo(f"  IPs: {len(intel.iocs['ips'])}")
        typer.echo(f"  Domains: {len(intel.iocs['domains'])}")
        typer.echo(f"  Hashes: {len(intel.iocs['hashes'])}")

    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def generate_csf_report(
    config: str = typer.Option(
        "config/dmarrss_config.yaml", "--config", "-c", help="Path to config file"
    ),
    executive: bool = typer.Option(False, "--executive", help="Generate executive summary"),
):
    """
    Generate NIST CSF alignment report (NIST CSF Govern function).
    
    Provides governance and compliance reporting.
    """
    typer.echo("Generating CSF report...")

    try:
        from .csf.csf_reporting import CSFReporter

        config_data = load_config(config)
        reporter = CSFReporter(config_data)
        
        if executive:
            filepath = reporter.save_executive_summary()
            typer.echo(f"✓ Executive summary saved to {filepath}")
        else:
            filepath = reporter.save_csf_report()
            
            # Load and display summary
            report = reporter.load_activities_from_data()
            
            typer.echo(f"✓ CSF alignment report generated")
            typer.echo(f"  Report saved to {filepath}")

    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
