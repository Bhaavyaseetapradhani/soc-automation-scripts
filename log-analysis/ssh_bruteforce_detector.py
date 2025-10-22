#!/usr/bin/env python3
"""
SSH Brute Force Detector
Detects multiple failed SSH login attempts from the same IP address.
Easy to understand for beginners.
"""

import re
from collections import defaultdict

def read_log_file(log_path):
    """Read SSH log file"""
    try:
        with open(log_path, 'r') as file:
            lines = file.readlines()
        print(f"✓ Read {len(lines)} lines from {log_path}")
        return lines
    except FileNotFoundError:
        print(f"✗ Error: File not found at {log_path}")
        return []
    except PermissionError:
        print(f"✗ Error: Need permission. Try: sudo python3 ssh_bruteforce_detector.py")
        return []

def extract_failed_attempts(lines):
    """Extract failed SSH login attempts"""
    failed_attempts = []
    
    # Pattern for: Failed password for admin from 192.168.1.100
    failed_password = r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)'
    
    # Pattern for: Invalid user admin from 192.168.1.100
    invalid_user = r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)'
    
    for line in lines:
        if 'Failed password' in line:
            match = re.search(failed_password, line)
            if match:
                ip = match.group(1)
                failed_attempts.append((line[:15], ip, 'Failed password'))
        
        elif 'Invalid user' in line:
            match = re.search(invalid_user, line)
            if match:
                ip = match.group(1)
                failed_attempts.append((line[:15], ip, 'Invalid user'))
    
    print(f"✓ Found {len(failed_attempts)} failed attempts")
    return failed_attempts

def group_by_ip(failed_attempts):
    """Group attempts by IP address"""
    attempts_by_ip = defaultdict(list)
    
    for timestamp, ip, reason in failed_attempts:
        attempts_by_ip[ip].append({
            'timestamp': timestamp,
            'reason': reason
        })
    
    return attempts_by_ip

def detect_brute_force(attempts_by_ip, threshold=5):
    """Find IPs with suspicious activity"""
    suspicious_ips = {}
    
    for ip, attempts in attempts_by_ip.items():
        if len(attempts) >= threshold:
            suspicious_ips[ip] = {
                'total_attempts': len(attempts),
                'attempts': attempts
            }
    
    return suspicious_ips

def print_report(suspicious_ips):
    """Print the report"""
    if not suspicious_ips:
        print("\n✓ No brute force attempts detected!")
        return
    
    print("\n" + "="*70)
    print("  BRUTE FORCE ALERT")
    print("="*70)
    
    for ip, data in sorted(suspicious_ips.items(), 
                          key=lambda x: x[1]['total_attempts'], 
                          reverse=True):
        print(f"\n IP: {ip}")
        print(f"   Failed Attempts: {data['total_attempts']}")
        
        for attempt in data['attempts'][-3:]:
            print(f"   {attempt['timestamp']} - {attempt['reason']}")
    
    print("\n" + "="*70)
    print(f"Total Suspicious IPs: {len(suspicious_ips)}")
    print("="*70 + "\n")

def main():
    """Run the detector"""
    print("\n SSH Brute Force Detector\n")
    
    LOG_FILE = '/var/log/auth.log'
    THRESHOLD = 5
    
    print(f"Log File: {LOG_FILE}")
    print(f"Threshold: {THRESHOLD} attempts\n")
    
    lines = read_log_file(LOG_FILE)
    if not lines:
        return
    
    print()
    failed_attempts = extract_failed_attempts(lines)
    if not failed_attempts:
        print("✓ No failed attempts found!")
        return
    
    print()
    attempts_by_ip = group_by_ip(failed_attempts)
    print(f"✓ Found {len(attempts_by_ip)} unique IPs\n")
    
    suspicious_ips = detect_brute_force(attempts_by_ip, THRESHOLD)
    print_report(suspicious_ips)

if __name__ == "__main__":
    main()
