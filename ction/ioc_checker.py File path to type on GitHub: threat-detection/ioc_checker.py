#!/usr/bin/env python3
"""
IOC Threat Intelligence Checker
Check IPs, domains, and hashes against VirusTotal and AbuseIPDB.
Beginner-friendly version.
"""

import requests
import re
import json

# You can get free API keys from:
# VirusTotal: https://www.virustotal.com/gui/home/upload
# AbuseIPDB: https://www.abuseipdb.com/api

VIRUSTOTAL_API_KEY = "your_virustotal_api_key_here"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key_here"

def is_valid_ip(ip):
    """Check if string is a valid IP address"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False

def is_valid_domain(domain):
    """Check if string is a valid domain"""
    pattern = r'^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$'
    return re.match(pattern, domain.lower()) is not None

def is_valid_hash(hash_str):
    """Check if string is a valid hash (MD5, SHA1, or SHA256)"""
    hash_str = hash_str.upper()
    if len(hash_str) == 32 or len(hash_str) == 40 or len(hash_str) == 64:
        return all(c in '0123456789ABCDEF' for c in hash_str)
    return False

def check_ip_abuseipdb(ip):
    """Check IP on AbuseIPDB"""
    print(f"\n Checking IP on AbuseIPDB: {ip}")
    
    if ABUSEIPDB_API_KEY == "your_abuseipdb_api_key_here":
        print("  AbuseIPDB API key not set. Skipping...")
        return None
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            abuse_score = data['data']['abuseConfidenceScore']
            
            if abuse_score > 0:
                print(f" Abuse Score: {abuse_score}%")
                print(f"   Total Reports: {data['data']['totalReports']}")
            else:
                print(f"✓ Clean - Abuse Score: {abuse_score}%")
            
            return data
        else:
            print(f"✗ Error: {response.status_code}")
            return None
    
    except requests.exceptions.Timeout:
        print("✗ Request timed out")
        return None
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        return None

def check_ip_virustotal(ip):
    """Check IP on VirusTotal"""
    print(f"\n Checking IP on VirusTotal: {ip}")
    
    if VIRUSTOTAL_API_KEY == "your_virustotal_api_key_here":
        print("  VirusTotal API key not set. Skipping...")
        return None
    
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            malicious = stats['malicious']
            undetected = stats['undetected']
            
            if malicious > 0:
                print(f" Malicious: {malicious} vendor(s)")
                print(f"   Undetected: {undetected}")
            else:
                print(f"✓ Clean - No malicious detections")
            
            return data
        else:
            print(f"✗ Error: {response.status_code}")
            return None
    
    except requests.exceptions.Timeout:
        print("✗ Request timed out")
        return None
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        return None

def check_domain_virustotal(domain):
    """Check domain on VirusTotal"""
    print(f"\n Checking domain on VirusTotal: {domain}")
    
    if VIRUSTOTAL_API_KEY == "your_virustotal_api_key_here":
        print("  VirusTotal API key not set. Skipping...")
        return None
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            malicious = stats['malicious']
            
            if malicious > 0:
                print(f" Malicious: {malicious} vendor(s)")
            else:
                print(f"✓ Clean - No malicious detections")
            
            return data
        else:
            print(f"✗ Error: {response.status_code}")
            return None
    
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        return None

def check_hash_virustotal(hash_str):
    """Check file hash on VirusTotal"""
    print(f"\n Checking hash on VirusTotal: {hash_str}")
    
    if VIRUSTOTAL_API_KEY == "your_virustotal_api_key_here":
        print("  VirusTotal API key not set. Skipping...")
        return None
    
    try:
        url = f"https://www.virustotal.com/api/v3/files/{hash_str}"
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            malicious = stats['malicious']
            
            if malicious > 0:
                print(f" Malicious: {malicious} vendor(s)")
            else:
                print(f"✓ Clean - No malicious detections")
            
            return data
        else:
            print(f"✗ Not found in VirusTotal database")
            return None
    
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        return None

def check_ioc(ioc_value):
    """Main function to check any IOC"""
    print("\n" + "="*70)
    print("Threat Intelligence IOC Checker")
    print("="*70)
    
    print(f"\nChecking: {ioc_value}")
    
    if is_valid_ip(ioc_value):
        print("Type: IP Address")
        check_ip_virustotal(ioc_value)
        check_ip_abuseipdb(ioc_value)
    
    elif is_valid_domain(ioc_value):
        print("Type: Domain")
        check_domain_virustotal(ioc_value)
    
    elif is_valid_hash(ioc_value):
        print("Type: File Hash")
        check_hash_virustotal(ioc_value)
    
    else:
        print("✗ Invalid IOC format!")
        print("   Supported: IP addresses, domains, MD5/SHA1/SHA256 hashes")
    
    print("\n" + "="*70 + "\n")

def main():
    """Run the checker"""
    print("\n" + "="*70)
    print(" IOC Threat Intelligence Checker")
    print("="*70)
    print("\n SETUP INSTRUCTIONS:")
    print("1. Get free API keys:")
    print("   - VirusTotal: https://www.virustotal.com")
    print("   - AbuseIPDB: https://www.abuseipdb.com")
    print("2. Replace API keys in this script")
    print("3. Run: python3 ioc_checker.py")
    print("\n" + "="*70)
    
    # Example usage - change these values
    test_iocs = [
        "8.8.8.8",           # Google DNS
        "example.com",       # Example domain
    ]
    
    for ioc in test_iocs:
        check_ioc(ioc)

if __name__ == "__main__":
    main()
