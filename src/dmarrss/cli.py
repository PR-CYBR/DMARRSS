"""
DMARRSS Command-Line Interface

Provides commands: run, train, simulate, api
"""

import os
import sys
from pathlib import Path
from typing import Optional

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


if __name__ == "__main__":
    app()
