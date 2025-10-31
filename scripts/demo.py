#!/usr/bin/env python3
"""
DMARRSS Demo Script
Demonstrates the complete DMARRSS threat detection and response pipeline
"""

import random
import sys
import yaml
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dmarrss.parsers import SnortParser, SuricataParser
from dmarrss.schemas import Event, LogSource


def generate_synthetic_events(count: int = 10) -> list:
    """Generate synthetic security events for testing"""
    events = []

    templates = [
        "[**] [1:2024364:1] ET MALWARE Critical Ransomware Detected [**] [Priority: 1] {TCP} 203.0.113.50:54321 -> 192.168.1.100:443",
        "[**] [1:2019401:2] ET EXPLOIT Buffer Overflow Attempt [**] [Priority: 1] {TCP} 10.0.0.50:12345 -> 192.168.1.200:80",
        "[**] [1:2013028:8] ET SCAN Port Scan Detected [**] [Priority: 3] {TCP} 203.0.113.100:443 -> 192.168.1.50:22",
        "[**] [1:2001219:19] ET DOS Possible DDoS Attack [**] [Priority: 2] {UDP} 203.0.113.200:53 -> 192.168.1.1:53",
    ]

    for i in range(count):
        # Pick random template
        template = random.choice(templates)
        # Randomize IP for variety
        src_ip = f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        template = template.replace("203.0.113.50", src_ip)
        events.append(template)

    return events


def process_events(events: list, config: dict) -> list:
    """Process events through DMARRSS pipeline"""
    from dmarrss.scoring.threat_scorer import ThreatScorer
    from dmarrss.models.inference import ThreatInference
    from dmarrss.decide.decision_node import DecisionNode
    from dmarrss.store import Store

    # Initialize components
    store = Store(":memory:")  # In-memory for demo
    scorer = ThreatScorer(config, store)
    inference = ThreatInference()
    decision_node = DecisionNode(config, scorer, inference)

    # Parse and process
    parser = SnortParser()
    results = []

    for log_line in events:
        event = parser.parse(log_line)
        if event:
            decision = decision_node.decide(event)
            event.threat_score = decision.threat_score
            event.severity = decision.severity

            results.append({
                "event_id": event.event_id,
                "source": event.source,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "signature": event.signature,
                "severity": decision.severity,
                "threat_score": decision.threat_score,
                "confidence": decision.confidence,
                "actions": decision.recommended_actions,
            })

    return results


def main():
    """Main demo"""
    print("=" * 80)
    print("DMARRSS - Decentralized Machine Assisted Rapid Response Security System")
    print("Demo Script - Synthetic Event Processing")
    print("=" * 80)
    print()

    # Load config
    config_path = Path(__file__).parent.parent / "config" / "dmarrss_config.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f)

    # Generate synthetic events
    print("Generating 10 synthetic security events...")
    events = generate_synthetic_events(10)

    # Process events
    print(f"Processing {len(events)} events through DMARRSS pipeline...")
    results = process_events(events, config)

    # Print results
    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)

    severity_counts = {}
    for result in results:
        sev = result["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        print(f"\n{result['signature'][:60]}")
        print(f"  Severity: {sev} | Score: {result['threat_score']:.3f} | Confidence: {result['confidence']:.3f}")
        print(f"  Source: {result['src_ip']} -> {result['dst_ip']}")
        if result['actions']:
            print(f"  Actions: {', '.join(result['actions'])}")

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total Events: {len(results)}")
    for sev, count in sorted(severity_counts.items()):
        print(f"  {sev}: {count}")
    print()


if __name__ == "__main__":
    main()
