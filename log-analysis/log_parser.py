#!/usr/bin/env python3
"""
Log Parser & Aggregator
Parse firewall and system logs to find security events.
Beginner-friendly version.
"""

import re
import json
from collections import defaultdict
from datetime import datetime

def parse_firewall_log(log_content):
    """Parse firewall log and extract blocked connections"""
    events = []
    
    # Pattern for firewall blocks: DROP from 192.168.1.100 to 10.0.0.1 port 443
    pattern = r'DROP.*from\s+(\d+\.\d+\.\d+\.\d+).*to\s+(\d+\.\d+\.\d+\.\d+).*port\s+(\d+)'
    
    for line in log_content.split('\n'):
        match = re.search(pattern, line)
        if match:
            events.append({
                'type': 'Blocked Connection',
                'source_ip': match.group(1),
                'dest_ip': match.group(2),
                'port': match.group(3),
                'raw': line[:100]
            })
    
    return events

def parse_proxy_log(log_content):
    """Parse proxy log and extract blocked domains"""
    events = []
    
    # Pattern for blocked access: BLOCKED domain=example.com user=admin
    pattern = r'BLOCKED.*domain=(\S+).*user=(\S+)'
    
    for line in log_content.split('\n'):
        match = re.search(pattern, line)
        if match:
            events.append({
                'type': 'Blocked Access',
                'domain': match.group(1),
                'user': match.group(2),
                'raw': line[:100]
            })
    
    return events

def parse_system_log(log_content):
    """Parse system log for errors and warnings"""
    events = []
    
    for line in log_content.split('\n'):
        # Look for ERROR or WARNING
        if 'ERROR' in line.upper() or 'FAIL' in line.upper():
            events.append({
                'type': 'System Error',
                'severity': 'High',
                'message': line[:150]
            })
        elif 'WARNING' in line.upper():
            events.append({
                'type': 'System Warning',
                'severity': 'Medium',
                'message': line[:150]
            })
    
    return events

def aggregate_events(events):
    """Group events by type"""
    aggregated = defaultdict(list)
    
    for event in events:
        event_type = event.get('type', 'Unknown')
        aggregated[event_type].append(event)
    
    return aggregated

def generate_report(aggregated_events):
    """Create a formatted report"""
    print("\n" + "="*70)
    print(" SECURITY LOG REPORT")
    print("="*70)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    total_events = sum(len(events) for events in aggregated_events.values())
    print(f"\n Total Events Found: {total_events}\n")
    
    for event_type, events in aggregated_events.items():
        print(f"\n{'='*70}")
        print(f" {event_type.upper()}: {len(events)} events")
        print(f"{'='*70}")
        
        # Show first 5 events of this type
        for i, event in enumerate(events[:5], 1):
            print(f"\n  [{i}] {event}")
        
        if len(events) > 5:
            print(f"\n  ... and {len(events) - 5} more events")
    
    print("\n" + "="*70 + "\n")

def save_json_report(aggregated_events, filename='security_report.json'):
    """Save report as JSON file"""
    try:
        # Convert to JSON-serializable format
        report_data = {}
        for event_type, events in aggregated_events.items():
            report_data[event_type] = events
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"✓ JSON report saved to {filename}")
    except Exception as e:
        print(f"✗ Error saving JSON: {str(e)}")

def main():
    """Run the log parser"""
    print("\n" + "="*70)
    print(" LOG PARSER & AGGREGATOR")
    print("="*70)
    
    # Sample log data - replace with real logs
    sample_firewall = """
    Oct 22 10:15:23 firewall DROP from 192.168.1.100 to 10.0.0.1 port 443
    Oct 22 10:15:24 firewall DROP from 192.168.1.101 to 10.0.0.2 port 22
    Oct 22 10:15:25 firewall DROP from 192.168.1.102 to 8.8.8.8 port 53
    Oct 22 10:15:26 firewall ALLOW from 192.168.1.50 to 1.1.1.1 port 443
    """
    
    sample_proxy = """
    Oct 22 10:20:11 proxy BLOCKED domain=malicious.com user=admin
    Oct 22 10:20:12 proxy BLOCKED domain=phishing.com user=john
    Oct 22 10:20:13 proxy ALLOW domain=google.com user=jane
    """
    
    sample_system = """
    Oct 22 10:30:00 syslog ERROR: Database connection failed
    Oct 22 10:30:05 syslog WARNING: Low disk space on /var
    Oct 22 10:30:10 syslog ERROR: Authentication timeout
    Oct 22 10:30:15 syslog INFO: System backup completed
    """
    
    print("\n Parsing logs...\n")
    
    # Parse all logs
    firewall_events = parse_firewall_log(sample_firewall)
    print(f"✓ Found {len(firewall_events)} firewall events")
    
    proxy_events = parse_proxy_log(sample_proxy)
    print(f"✓ Found {len(proxy_events)} proxy events")
    
    system_events = parse_system_log(sample_system)
    print(f"✓ Found {len(system_events)} system events")
    
    # Combine all events
    all_events = firewall_events + proxy_events + system_events
    
    # Aggregate by type
    aggregated = aggregate_events(all_events)
    
    # Generate and display report
    generate_report(aggregated)
    
    # Save as JSON
    save_json_report(aggregated)

if __name__ == "__main__":
    main()
