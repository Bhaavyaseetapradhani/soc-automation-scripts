# 🛡️ SOC Automation Scripts

Collection of Python and Bash security automation scripts for Security Operations Center (SOC) analysts. These tools help streamline log analysis, threat detection, and incident response workflows.

---

## 📁 Project Structure
```
soc-automation-scripts/
├── log-analysis/          # Scripts for parsing and analyzing security logs
├── threat-detection/      # Automated threat hunting and IOC checking
├── incident-response/     # IR automation and forensic tools
└── compliance-checks/     # Security audit and compliance scripts
```

---

## 🔧 Tools & Scripts

### 1. **SSH Brute Force Detector**
- Analyzes `/var/log/auth.log` for failed login attempts
- Alerts on 5+ failed attempts from same IP within 5 minutes
- **Tech:** Bash, Regex

### 2. **IOC Threat Intelligence Checker**
- Queries VirusTotal and AbuseIPDB APIs for IP reputation
- Automated hash and domain lookups
- **Tech:** Python, Requests library

### 3. **Log Parser & Aggregator**
- Parses firewall, proxy, and system logs
- Extracts key security events and anomalies
- **Tech:** Python, Pandas, Regex

### 4. **Automated Compliance Auditor**
- Checks Linux systems against CIS benchmarks
- Validates patch levels and security configurations
- **Tech:** Bash scripting

---

## 📊 Impact

- ⚡ Reduced manual log analysis time by **60%**
- 🎯 Automated daily security checks across **25+ systems**
- 🔍 Enabled real-time threat detection and alerting

---

## 🚀 Coming Soon

- [ ] Windows Event Log analyzer
- [ ] SIEM integration scripts (Splunk/ELK)
- [ ] Automated incident report generator
- [ ] Network traffic anomaly detector

---

## 🛠️ Tech Stack

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)

**Libraries:** Requests • Pandas • Regex • JSON

---

## 📫 Contact

**Bhaavya Seeta Pradhani**  
SOC Analyst | SIEM & Threat Detection Specialist  
📧 pradhaniseeta@gmail.com  
💼 [LinkedIn](https://linkedin.com/in/bhaavya-seeta-pradhani-576067361)

---

*This repository showcases security automation capabilities developed through hands-on SOC operations and cybersecurity projects.*
