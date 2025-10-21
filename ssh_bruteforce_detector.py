#!/usr/bin/env python3
"""
SSH Brute Force Attack Detector
Analyzes authentication logs to detect potential brute force attacks
Author: Bhaavya Seeta Pradhani
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta

class SSHBruteForceDetector:
    def __init__(self, log_file='/var/log/auth.log', threshold=5, time_window=5):
        """
        Initialize the SSH brute force detector
        
        Args:
            log_file (str): Path to authentication log file
            threshold (int): Number of failed attempts to trigger alert
            time_window (int): Time window in minutes to check for attacks
        """
        self.log_file = log_file
        self.threshold = threshold
        self.time_window = time_window
        self.failed_attempts = defaultdict(list)
        
    def parse_log_line(self, line):
        """
        Parse a single log line for failed SSH attempts
        
        Returns:
            tuple: (timestamp, source_ip, username) or None
        """
        # Pattern for failed password attempts
        pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\w+) from ([\d.]+)'
        
        match = re.search(pattern, line)
        if match:
            timestamp_str = match.group(1)
            username = match.group(2)
            source_ip = match.group(3)
            
            # Parse timestamp (assuming current year)
            current_year = datetime.now().year
            timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            
            return (timestamp, source_ip, username)
        return None
    
    def analyze_logs(self):
        """
        Analyze authentication logs for brute force patterns
        
        Returns:
            list: List of detected attacks with details
        """
        attacks = []
        
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    parsed = self.parse_log_line(line)
                    if parsed:
                        timestamp, source_ip, username = parsed
                        self.failed_attempts[source_ip].append({
                            'timestamp': timestamp,
                            'username': username
                        })
            
            # Check for brute force patterns
            for ip, attempts in self.failed_attempts.items():
                if len(attempts) >= self.threshold:
                    # Sort by timestamp
                    attempts.sort(key=lambda x: x['timestamp'])
                    
                    # Check if attempts occurred within time window
                    first_attempt = attempts[0]['timestamp']
                    last_attempt = attempts[-1]['timestamp']
                    time_diff = (last_attempt - first_attempt).total_seconds() / 60
                    
                    if time_diff <= self.time_window:
                        attacks.append({
                            'source_ip': ip,
                            'attempt_count': len(attempts),
                            'first_attempt': first_attempt,
                            'last_attempt': last_attempt,
                            'targeted_users': list(set([a['username'] for a in attempts])),
                            'severity': 'HIGH' if len(attempts) > 10 else 'MEDIUM'
                        })
        
        except FileNotFoundError:
            print(f"Error: Log file {self.log_file} not found")
        except Exception as e:
            print(f"Error analyzing logs: {str(e)}")
        
        return attacks
    
    def generate_report(self, attacks):
        """
        Generate a formatted security report
        
        Args:
            attacks (list): List of detected attacks
        """
        print("\n" + "="*70)
        print("SSH BRUTE FORCE DETECTION REPORT")
        print("="*70)
        print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Detection Threshold: {self.threshold} failed attempts in {self.time_window} minutes")
        print(f"Total Attacks Detected: {len(attacks)}")
        print("="*70 + "\n")
        
        if not attacks:
            print("✓ No brute force attacks detected")
            return
        
        for idx, attack in enumerate(attacks, 1):
            print(f"Attack #{idx}")
            print(f"  Source IP: {attack['source_ip']}")
            print(f"  Severity: {attack['severity']}")
            print(f"  Failed Attempts: {attack['attempt_count']}")
            print(f"  First Attempt: {attack['first_attempt']}")
            print(f"  Last Attempt: {attack['last_attempt']}")
            print(f"  Targeted Users: {', '.join(attack['targeted_users'])}")
            print(f"  Recommendation: Block IP {attack['source_ip']} in firewall")
            print("-"*70)

def main():
    """
    Main execution function
    """
    # Example usage with sample log file
    detector = SSHBruteForceDetector(
        log_file='/var/log/auth.log',  # Change to your log file path
        threshold=5,
        time_window=5
    )
    
    print("Analyzing SSH authentication logs...")
    attacks = detector.analyze_logs()
    detector.generate_report(attacks)
    
    # Return exit code based on findings
    return 1 if attacks else 0

if __name__ == "__main__":
    exit(main())
