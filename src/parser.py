import re
from collections import defaultdict

SSH_FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\w+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)

def analyze_auth_log(log_filepath, threshold=3):
    """Scans log files for repeated authentication failures indicating brute-force attacks."""
    suspicious_ips = defaultdict(int)
    attack_details = []

    with open(log_filepath, "r", encoding="utf-8") as file:
        for line in file:
            match = SSH_FAILED_PATTERN.search(line)
            if match:
                username, ip = match.groups()
                suspicious_ips[ip] += 1
                attack_details.append({"ip": ip, "target_user": username})

    flagged_threats = {
        ip: count for ip, count in suspicious_ips.items() if count >= threshold
    }

    # Generate mitigation commands
    remediations = [f"sudo ufw deny from {ip}" for ip in flagged_threats.keys()]

    return {
        "total_failures": len(attack_details),
        "threats_detected": flagged_threats,
        "mitigation_firewall_rules": remediations
    }