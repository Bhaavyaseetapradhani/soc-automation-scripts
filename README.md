## # SOC Automation Scripts

A comprehensive collection of **Python and Bash scripts** designed to automate essential Security Operations Center (SOC) tasks, including log analysis, threat detection, and incident response. These tools help streamline security workflows and significantly reduce manual effort in cybersecurity operations.

##  Project Overview

This repository provides automation tools for common SOC workflows:
- **Log Analysis**: Parse and extract security events from firewall, proxy, and system logs
- **Threat Detection**: Automated threat hunting and IOC (Indicator of Compromise) validation
- **Incident Response**: Rapid forensic data collection and IR automation
- **Compliance**: Security auditing and CIS benchmark validation

##  Project Structure
```
soc-automation-scripts/
├── log-analysis/           # Scripts for parsing and analyzing security logs
├── threat-detection/       # Automated threat hunting and IOC checking
├── incident-response/      # IR automation and forensic tools
├── compliance-checks/      # Security audit and compliance scripts
├── logs/                   # Sample log files for testing scripts
├── config/                 # Configuration files (API keys, templates)
├── requirements.txt        # Python dependencies
└── README.md
```

##  Tools & Scripts

### 1. SSH Brute Force Detector
Automatically identifies suspicious SSH activity by detecting multiple failed login attempts from the same IP address within a configurable time window. This helps prevent unauthorized access and credential compromise.

- **Location**: `log-analysis/ssh_bruteforce_detector.py`
- **Tech**: Python, Regex
- **Key Features**:
  - Real-time log monitoring
  - Configurable failure threshold
  - IP-based grouping and analysis
  - Alert generation

### 2. IOC Threat Intelligence Checker
Validates IP addresses, domains, and file hashes against public threat intelligence databases (VirusTotal and AbuseIPDB). Enables rapid identification of known malicious indicators without manual lookups.

- **Location**: `threat-detection/ioc_checker.py`
- **Tech**: Python, Requests library
- **Key Features**:
  - Multi-indicator support (IPs, domains, hashes)
  - Integration with VirusTotal and AbuseIPDB
  - Batch processing capabilities
  - Detailed threat reports

### 3. Log Parser & Aggregator
Processes firewall, proxy, and system logs to extract and correlate security events. Generates clear, actionable summaries for SOC analysts to review and respond to incidents more efficiently.

- **Location**: `log-analysis/log_parser.py`
- **Tech**: Python, Pandas, Regex
- **Key Features**:
  - Multi-format log support
  - Anomaly extraction and flagging
  - HTML and JSON report generation
  - Filtering and sorting capabilities

### 4. Automated Compliance Auditor
Performs systematic security audits against CIS benchmarks and industry standards. Validates patch levels, permission settings, and other critical security configurations on Linux systems.

- **Location**: `compliance-checks/compliance_audit.sh`
- **Tech**: Bash scripting
- **Key Features**:
  - CIS benchmark validation
  - Patch level verification
  - Security configuration audits
  - Compliance report generation

##  Quick Start

### Prerequisites

Ensure you have the following installed on your system:
- **Python**: 3.8 or higher
- **Bash**: 4.0 or higher
- **OS**: Linux/Unix environment (macOS compatible)

### Installation
```bash
# Clone the repository
git clone https://github.com/Bhaavyaseetapradhani/soc-automation-scripts.git
cd soc-automation-scripts

# Install Python dependencies
pip install -r requirements.txt
```

### Running Scripts

**SSH Brute Force Detector:**
```bash
cd log-analysis
python3 ssh_bruteforce_detector.py
```

**IOC Threat Intelligence Checker:**
```bash
cd threat-detection
python3 ioc_checker.py
```

**Log Parser & Aggregator:**
```bash
cd log-analysis
python3 log_parser.py
```

**Compliance Auditor:**
```bash
cd compliance-checks
sudo bash compliance_audit.sh
```

##  Dependencies

All required Python packages are listed in `requirements.txt`. Install them using:
```bash
pip install -r requirements.txt
```

Common dependencies include:
- `requests`: API calls for threat intelligence
- `pandas`: Data processing and log analysis
- `pyyaml`: Configuration file parsing

##  Security Considerations

- **API Keys**: Store API keys in `.env` files or secure vaults—never commit them to version control
- **Permissions**: Run scripts with appropriate privilege levels (some require `sudo`)
- **Log Files**: Ensure proper access controls on log files and reports
- **Data Sensitivity**: Handle security logs and reports as sensitive information

##  Configuration

Configuration files are located in the `config/` directory:
- `api_keys.conf`: API credentials for threat intelligence services
- `log_sources.conf`: Log file paths and parsing rules
- `thresholds.conf`: Alert thresholds and sensitivity settings

Update these files before running scripts for the first time.

##  Sample Data

Sample log files are provided in the `logs/` directory for testing and development:
- `sample_auth.log`: Sample SSH authentication logs
- `sample_firewall.log`: Sample firewall events

Use these to test scripts without requiring production data.

##  Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Test your changes thoroughly
4. Submit a pull request with clear documentation

##  License

This project is licensed under the MIT License. See the LICENSE file for details.

##  Support & Issues

For bug reports, feature requests, or questions, please open an issue on the GitHub repository. Provide as much detail as possible about the issue you're experiencing.

##  Roadmap

Future enhancements planned for this project:
- SIEM integration (Splunk, ELK Stack)
- Machine learning-based anomaly detection
- Automated incident ticket creation
- Real-time dashboard for SOC monitoring
- Integration with Slack and email notifications

---

**Last Updated**: October 2025  
**Maintainer**: Bhaavya Seetapradhani Project Structure
