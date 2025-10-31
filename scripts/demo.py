#!/usr/bin/env python3
"""
DMARRSS Demo Script
Demonstrates the complete DMARRSS threat detection and response pipeline
"""

import sys
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.dmarrss_pipeline import DMARRSSPipeline


def print_banner():
    """Print DMARRSS banner"""
    print("=" * 80)
    print("DMARRSS - Decentralized Machine Assisted Rapid Response Security System")
    print("Version 1.0.0")
    print("=" * 80)
    print()


def print_event_summary(event):
    """Print a summary of a processed event"""
    print(f"\n{'─' * 80}")
    print(f"Event: {event.get('message', event.get('signature', 'Unknown'))[:60]}")
    print(f"{'─' * 80}")
    print(f"  Source:          {event.get('source', 'unknown').upper()}")
    print(f"  Source IP:       {event.get('source_ip', 'N/A')}")
    print(f"  Dest IP:         {event.get('destination_ip', 'N/A')}")
    print(f"  Threat Score:    {event.get('threat_score', 0):.3f}")
    print(f"  Severity:        {event.get('severity', 'unknown').upper()}")
    print(f"  Neural Severity: {event.get('neural_severity', 'unknown').upper()} (conf: {event.get('confidence', 0):.3f})")
    print(f"  Response:        {event.get('response_action', {}).get('action', 'unknown')}")
    print()


def demo_snort_processing():
    """Demonstrate SNORT log processing"""
    print("\n" + "=" * 80)
    print("DEMO 1: Processing SNORT Alerts")
    print("=" * 80)
    
    pipeline = DMARRSSPipeline()
    
    # Get sample SNORT log file
    base_path = Path(__file__).parent.parent
    log_file = base_path / "data" / "raw" / "sample_snort_alerts.log"
    
    if not log_file.exists():
        print(f"Sample log file not found: {log_file}")
        return
    
    print(f"\nProcessing: {log_file}")
    
    # Process the file
    events = pipeline.process_log_file(str(log_file), format_hint='snort')
    
    print(f"\nTotal events processed: {len(events)}")
    
    # Show high priority events
    high_priority = pipeline.get_high_priority_events(events)
    print(f"High priority events: {len(high_priority)}")
    
    # Display first few events
    print("\nTop 5 Events by Priority:")
    for i, event in enumerate(events[:5], 1):
        print(f"\n{i}.", end="")
        print_event_summary(event)
    
    # Generate and display summary
    summary = pipeline.generate_summary(events)
    print("\n" + "=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    print(f"Total Events:        {summary['total_events']}")
    print(f"Critical:            {summary['by_severity']['critical']}")
    print(f"High:                {summary['by_severity']['high']}")
    print(f"Medium:              {summary['by_severity']['medium']}")
    print(f"Low:                 {summary['by_severity']['low']}")
    print(f"\nThreat Score Range:  {summary['threat_scores']['min']:.3f} - {summary['threat_scores']['max']:.3f}")
    print(f"Average Score:       {summary['threat_scores']['average']:.3f}")
    
    print("\nResponse Actions:")
    for action, count in summary['response_actions'].items():
        print(f"  {action:25s}: {count}")


def demo_suricata_processing():
    """Demonstrate SURICATA log processing"""
    print("\n\n" + "=" * 80)
    print("DEMO 2: Processing SURICATA EVE JSON Logs")
    print("=" * 80)
    
    pipeline = DMARRSSPipeline()
    
    # Get sample SURICATA log file
    base_path = Path(__file__).parent.parent
    log_file = base_path / "data" / "raw" / "sample_suricata_eve.json"
    
    if not log_file.exists():
        print(f"Sample log file not found: {log_file}")
        return
    
    print(f"\nProcessing: {log_file}")
    
    # Read line-delimited JSON
    with open(log_file, 'r') as f:
        log_lines = f.readlines()
    
    # Process the events
    events = pipeline.process_log_batch(log_lines, format_hint='suricata')
    
    print(f"\nTotal events processed: {len(events)}")
    
    # Get critical events
    critical = pipeline.get_critical_events(events)
    print(f"Critical events: {len(critical)}")
    
    # Display critical events
    if critical:
        print("\nCritical Events:")
        for i, event in enumerate(critical, 1):
            print(f"\n{i}.", end="")
            print_event_summary(event)
    
    # Generate summary
    summary = pipeline.generate_summary(events)
    print("\n" + "=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    print(f"Total Events:        {summary['total_events']}")
    print(f"Critical:            {summary['by_severity']['critical']}")
    print(f"High:                {summary['by_severity']['high']}")
    print(f"Medium:              {summary['by_severity']['medium']}")
    print(f"Low:                 {summary['by_severity']['low']}")


def demo_single_event():
    """Demonstrate processing a single log entry"""
    print("\n\n" + "=" * 80)
    print("DEMO 3: Processing Single Threat Event")
    print("=" * 80)
    
    pipeline = DMARRSSPipeline()
    
    # Process a critical event
    log_line = "[**] [1:2024364:1] ET EXPLOIT Critical Remote Code Execution Attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 203.0.113.50:54321 -> 192.168.1.100:443"
    
    print(f"\nInput: {log_line}")
    
    result = pipeline.process_log_line(log_line)
    
    if result:
        print("\nProcessing Result:")
        print_event_summary(result)
        
        print("Detailed Score Components:")
        for component, score in result.get('score_components', {}).items():
            print(f"  {component:25s}: {score:.3f}")
        
        print("\nNeural Confidence Scores:")
        for severity, confidence in result.get('confidence_scores', {}).items():
            print(f"  {severity:10s}: {confidence:.3f}")


def main():
    """Run all demonstrations"""
    print_banner()
    
    try:
        demo_snort_processing()
        demo_suricata_processing()
        demo_single_event()
        
        print("\n" + "=" * 80)
        print("DEMO COMPLETE")
        print("=" * 80)
        print("\nDMARRSS successfully processed threat events through:")
        print("  ✓ Log parsing (SNORT, SURICATA formats)")
        print("  ✓ Threat scoring with Context Aware Severity Layers")
        print("  ✓ LLM-inspired neural classification")
        print("  ✓ Automated response action determination")
        print("\nThe system is ready for production deployment!")
        print("=" * 80)
        
    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
