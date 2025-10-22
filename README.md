# SOC Automation Scripts

A collection of **Python and Bash scripts** for automating common Security Operations Center (SOC) tasks, such as log analysis, threat detection, and incident response.  
Designed to help streamline workflows and reduce manual work in cybersecurity operations.

--

##  Project Structure
soc-automation-scripts/
├── log-analysis/ # Scripts for parsing and analyzing security logs
├── threat-detection/ # Automated threat hunting and IOC checking
├── incident-response/ # IR automation and forensic tools
├── compliance-checks/ # Security audit and compliance scripts
├── logs/ # Sample log files for testing scripts
├── config/ # Configuration files (API keys, templates)
├── requirements.txt # Python dependencies
└── README.md

---

## 🛠 Tools & Scripts

### 1. SSH Brute Force Detector
- Detects multiple failed SSH login attempts from the same IP within a short time.
- Helps prevent unauthorized access.
- **Tech:** Bash, Regex

### 2. IOC Threat Intelligence Checker
- Checks IP addresses, domains, and file hashes against VirusTotal and AbuseIPDB.
- Helps identify known threats automatically.
- **Tech:** Python, Requests library

### 3. Log Parser & Aggregator
- Parses firewall, proxy, and system logs to extract security events and anomalies.
- Generates easy-to-read summaries for SOC analysts.
- **Tech:** Python, Pandas, Regex

### 4. Automated Compliance Auditor
- Checks Linux systems against **CIS benchmarks**.
- Validates patch levels and security settings to maintain compliance.
- **Tech:** Bash scripting

---

## Quick Start

### Prerequisites
- Python 3.8+
- Bash 4.0+
- Linux/Unix environment

### Installation & Running Scripts
```bash
# Clone the repository
git clone https://github.com/Bhaavyaseetapradhani/soc-automation-scripts.git
cd soc-automation-scripts

# Install Python dependencies
pip install -r requirements.txt

# Run the SSH brute force detector (example)
cd log-analysis
python3 ssh_bruteforce_detector.py

# Run the compliance check (example)
cd ../compliance-checks
bash compliance_check.sh

