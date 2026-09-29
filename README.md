# Security Log SIEM & Automated Threat Detection

A lightweight Python security automation script that inspects Linux authentication logs (`/var/log/auth.log`) to identify brute-force SSH attacks, track threat actor IPs, and automatically generate dynamic firewall blocking rules (`ufw`).

## Features
- **Regex Log Parsing**: Extracts authentication attempts, source IP addresses, and targeted usernames.
- **Incident Threshold Detection**: Flags IPs exceeding defined failed login thresholds.
- **Automated Mitigation**: Generates host-level firewall block commands (`ufw deny`).

## Quick Start
```bash
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -v
```