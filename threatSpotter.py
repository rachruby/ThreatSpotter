import re
import json
import os
from collections import defaultdict
from datetime import datetime

# Ensure output folder exists
os.makedirs("output", exist_ok=True)

# MITRE ATT&CK mapping
MITRE_MAPPING = {
    "BRUTE_FORCE": {
        "technique": "T1110",
        "name": "Brute Force"
    },
    "SUSPICIOUS_LOGIN": {
        "technique": "T1078",
        "name": "Valid Accounts"
    }
}

# Regex patterns for SSH log events
FAILED_LOGIN = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
SUCCESS_LOGIN = re.compile(r"Accepted password for .* from (\d+\.\d+\.\d+\.\d+)")

def parse_log(file_path, threshold=5):
    detections = []
    failed_attempts = defaultdict(int)

    try:
        with open(file_path, "r") as log_file:
            for line in log_file:
                line = line.strip()
                
                # Detect failed login
                failed_match = FAILED_LOGIN.search(line)
                if failed_match:
                    ip = failed_match.group(1)
                    failed_attempts[ip] += 1
                    if failed_attempts[ip] == threshold:  # Trigger once at threshold
                        detections.append({
                            "timestamp": str(datetime.now()),
                            "ip": ip,
                            "event": f"{threshold} failed login attempts",
                            "mitre": MITRE_MAPPING["BRUTE_FORCE"]
                        })

                # Detect suspicious successful login (after failures)
                success_match = SUCCESS_LOGIN.search(line)
                if success_match:
                    ip = success_match.group(1)
                    if failed_attempts[ip] > 0:
                        detections.append({
                            "timestamp": str(datetime.now()),
                            "ip": ip,
                            "event": "Suspicious successful login after failures",
                            "mitre": MITRE_MAPPING["SUSPICIOUS_LOGIN"]
                        })
    except FileNotFoundError:
        print(f"Log file not found: {file_path}")
        return []

    return detections


if __name__ == "__main__":
    log_file = "sample_logs/auth.log"  # Update path if needed
    findings = parse_log(log_file)

    # Save detections to JSON
    with open("output/detections.json", "w") as f:
        json.dump(findings, f, indent=4)

    print(f"Detections saved to output/detections.json ({len(findings)} alerts)")

    if len(findings) == 0:
        print("No detections found. Make sure your auth.log has failed or suspicious login attempts.")
