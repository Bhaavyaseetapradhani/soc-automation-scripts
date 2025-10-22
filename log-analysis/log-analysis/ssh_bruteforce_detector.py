#!/usr/bin/env python3
"""
SSH Brute Force Detector
Detects multiple failed SSH login attempts from the same IP address.
Beginner-friendly version with detailed comments.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta

def read_log_file(log_path):
    """
    Read the SSH log file and return all lines.
    
    Args:
        log_path (str): Path to the SSH log file (usually /var/log/auth.log)
    
    Returns:
        list: List of lines from the log file
    """
    try:
        with open(log_path, 'r') as file:
            lines = file.readlines()
        print(f"✓ Successfully read {len(lines)} lines from {log_path}")
        return lines
    except FileNotFoundError:
        print(f"✗ Error: Log file not found at {log_path}")
        print("  Make sure you have read permission and the path is correct")
        return []
    except PermissionError:
        print(f"✗ Error: Permission denied reading {log_path}")
        print("  Try running with sudo: sudo python3 ssh_bruteforce_detector.py")
        return []

def extract_failed_attempts(lines):
    """
    Extract failed SSH login attempts from log lines.
    Looks for "Failed password" or "Invalid user" messages.
    
    Args:
        lines (list): List of log file lines
    
    Returns:
        list: List of tuples (timestamp, ip_address, failure_reason)
    """
    failed_attempts = []
    
    # Pattern to match failed password attempts
    # Example: "Oct 22 14:32:15 server sshd[1234]: Failed password for admin from 192.168.1.100 port 12345 ssh2"
    failed_password_pattern = r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)'
    
    # Pattern to match invalid user attempts
    # Example: "Oct 22 14:32:15 server sshd[1234]: Invalid user admin from 192.168.1.100 port 12345"
    invalid_user_pattern = r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)'
    
    for line in lines:
        # Check for failed password attempts
        if 'Failed password' in line:
            match = re.search(failed_password_pattern, line)
            if match:
                ip = match.group(1)
                failed_attempts.append((line[:15], ip, 'Failed password'))
        
        # Check for invalid user attempts
        elif 'Invalid user' in line:
            match = re.search(invalid_user_pattern, line)
            if match:
                ip = match.group(1)
                failed_attempts.append((line[:15], ip, 'Invalid user'))
    
    print(f"✓ Found {len(failed_attempts)} failed login attempts")
    return failed_attempts

def group_by_ip(failed_attempts):
    """
    Group failed attempts by IP address to find suspicious IPs.
    
    Args:
        failed_attempts (list): List of tuples with failed attempts
    
    Returns:
        dict: Dictionary with IP addresses as keys and list of attempts as values
    """
    attempts_by_ip = defaultdict(list)
    
    for timestamp, ip, reason in failed_attempts:
        attempts_by_ip[ip].append({
            'timestamp': timestamp,
            'reason': reason
        })
    
    return attempts_by_ip

def detect_brute_force(attempts_by_ip, threshold=5):
    """
    Detect brute force attempts based on threshold.
    If an IP has more failed attempts than threshold, it's flagged.
    
    Args:
        attempts_by_ip (dict): Dictionary of IP addresses with their attempts
        threshold (int): Minimum number of failed attempts to flag as suspicious
    
    Returns:
        dict: Dictionary of suspicious IPs and their attempt counts
    """
    suspicious_ips = {}
    
    for ip, attempts in attempts_by_ip.items():
        # Count total attempts from this IP
        attempt_count = len(attempts)
        
        # If attempts exceed threshold, flag as suspicious
        if attempt_count >= threshold:
            suspicious_ips[ip] = {
                'total_attempts': attempt_count,
                'attempts': attempts
            }
    
    return suspicious_ips

def print_report(suspicious_ips):
    """
    Print a formatted report of suspicious IPs and their activities.
    
    Args:
        suspicious_ips (dict): Dictionary of suspicious IPs
    """
    if not suspicious_ips:
        print("\n✓ No brute force attempts detected!")
        return
    
    print("\n" + "="*70)
    print("  BRUTE FORCE ALERT - Suspicious IPs Detected")
    print("="*70)
    
    for ip, data in sorted(suspicious_ips.items(), 
                          key=lambda x: x[1]['total_attempts'], 
                          reverse=True):
        print(f"\n IP Address: {ip}")
        print(f"   Total Failed Attempts: {data['total_attempts']}")
        print(f"   Recent Activity:")
        
        # Show the last 3 attempts from this IP
        for attempt in data['attempts'][-3:]:
            print(f"     - {attempt['timestamp']} - {attempt['reason']}")
    
    print("\n" + "="*70)
    print(f"  Total Suspicious IPs: {len(suspicious_ips)}")
    print("="*70)

def main():
    """
    Main function that runs the SSH brute force detector.
    """
    print("\n SSH Brute Force Detector")
    print("-" * 70)
    
    # Configuration - You can change these values
    LOG_FILE = '/var/log/auth.log'  # Path to SSH log file
    THRESHOLD = 5                    # Number of failed attempts to flag as suspicious
    
    print(f" Configuration:")
    print(f"   Log File: {LOG_FILE}")
    print(f"   Threshold: {THRESHOLD} failed attempts")
    print(f"   Detecting IPs with {THRESHOLD}+ failed login attempts...\n")
    
    # Step 1: Read the log file
    lines = read_log_file(LOG_FILE)
    if not lines:
        return
    
    # Step 2: Extract failed SSH attempts
    print()
    failed_attempts = extract_failed_attempts(lines)
    if not failed_attempts:
        print("✓ No failed attempts found - All SSH logins successful!")
        return
    
    # Step 3: Group attempts by IP address
    print()
    attempts_by_ip = group_by_ip(failed_attempts)
    print(f"✓ Found {len(attempts_by_ip)} unique IP addresses")
    
    # Step 4: Detect brute force attempts
    print()
    suspicious_ips = detect_brute_force(attempts_by_ip, THRESHOLD)
    
    # Step 5: Print the report
    print_report(suspicious_ips)

if __name__ == "__main__":
    main()
