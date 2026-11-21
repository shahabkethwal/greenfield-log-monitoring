import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

DEFAULT_INPUT = "data/simulated_attack_logs.jsonl"
DEFAULT_OUTPUT = "output/alerts_triggered.json"


def load_logs(filepath):
    if not filepath or not filepath.strip():
        print("[ERROR] Log file path cannot be empty.")
        sys.exit(1)

    if not os.path.exists(filepath):
        print(f"[ERROR] Log file not found: '{filepath}'.")
        print("Run 'python scripts/simulate_attacks.py all' first to generate attack logs.")
        sys.exit(1)

    if os.path.getsize(filepath) == 0:
        print(f"[ERROR] Log file '{filepath}' is empty. Nothing to analyze.")
        sys.exit(1)

    valid_events = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line_num, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("JSON root is not an object")
                    valid_events.append(event)
                except (json.JSONDecodeError, ValueError) as parse_err:
                    print(f"[WARNING] Skipping malformed log on line {line_num}: {parse_err}")
    except OSError as io_err:
        print(f"[ERROR] Unable to read '{filepath}': {io_err}")
        sys.exit(1)

    if not valid_events:
        print(f"[ERROR] No valid JSON log records found in '{filepath}'.")
        sys.exit(1)

    return valid_events


def evaluate_rules(events):
    alerts = []
    failed_logins = defaultdict(list)

    for event in events:
        user = event.get("user", "unknown")
        host = event.get("host", "unknown")
        src_ip = event.get("source_ip", "unknown")
        event_type = event.get("event_type", "")
        action = event.get("action", "")
        status = event.get("status", "")
        details = event.get("details", "")
        ts = event.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

        # Track failed logins per (user, source_ip) for Rule 1
        if event_type == "auth_failure" and status == "FAILED":
            failed_logins[(user, src_ip)].append(ts)

        # Rule 1: Credential Brute-Force (5+ failures followed by success or threshold breach)
        if event_type == "auth_success" and status == "SUCCESS":
            prior_failures = len(failed_logins[(user, src_ip)])
            if prior_failures >= 5:
                alerts.append({
                    "rule_id": "GF-RULE-001",
                    "rule_name": "Brute-Force Login Followed by Account Compromise",
                    "severity": "HIGH",
                    "timestamp": ts,
                    "user": user,
                    "host": host,
                    "source_ip": src_ip,
                    "evidence": f"{prior_failures} consecutive failed logins before successful login ({details})"
                })

        # Rule 2: Service Account Performing Bulk Database Export
        if event_type == "db_export" and action == "EXPORT_TABLE" and user.startswith("svc_"):
            alerts.append({
                "rule_id": "GF-RULE-002",
                "rule_name": "Unauthorized Bulk Export by IoT Service Account",
                "severity": "CRITICAL",
                "timestamp": ts,
                "user": user,
                "host": host,
                "source_ip": src_ip,
                "evidence": details
            })

        # Rule 3: Rogue Administrator Account Creation
        if event_type == "account_mgmt" and action == "USER_ADD_ADMIN":
            alerts.append({
                "rule_id": "GF-RULE-003",
                "rule_name": "Unauthorized Privilege Escalation / Admin Account Created",
                "severity": "HIGH",
                "timestamp": ts,
                "user": user,
                "host": host,
                "source_ip": src_ip,
                "evidence": details
            })

        # Rule 4: Ransomware File Encryption Pattern (.locked extension)
        if event_type == "file_modify" and ".locked" in details:
            alerts.append({
                "rule_id": "GF-RULE-004",
                "rule_name": "Suspected Ransomware File Encryption on Co-op Storage",
                "severity": "CRITICAL",
                "timestamp": ts,
                "user": user,
                "host": host,
                "source_ip": src_ip,
                "evidence": details
            })

    return alerts


def main():
    input_path = sys.argv[1] if len(sys.argv) >= 2 else DEFAULT_INPUT
    output_path = sys.argv[2] if len(sys.argv) >= 3 else DEFAULT_OUTPUT

    events = load_logs(input_path)
    alerts = evaluate_rules(events)

    try:
        parent_dir = os.path.dirname(output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2)
    except OSError as err:
        print(f"[ERROR] Failed to save alerts to '{output_path}': {err}")
        sys.exit(1)

    print(f"[SUCCESS] Analyzed {len(events)} log events from '{input_path}'.")
    print(f"[ALERTS] Triggered {len(alerts)} security alert(s) -> saved to '{output_path}'.")
    for alert in alerts:
        print(f"  - [{alert['severity']}] {alert['rule_id']}: {alert['rule_name']} (Host: {alert['host']}, User: {alert['user']})")


if __name__ == "__main__":
    main()
