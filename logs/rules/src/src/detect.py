import json
import os
import sys

def load_json_safely(file_path, label):
    if not os.path.exists(file_path):
        print(f"[ERROR] {label} file not found at: {file_path}")
        return None
    if os.path.getsize(file_path) == 0:
        print(f"[ERROR] {label} file is empty: {file_path}")
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not data:
                print(f"[ERROR] {label} contains no usable records.")
                return None
            return data
    except json.JSONDecodeError:
        print(f"[ERROR] {label} is corrupted or invalid JSON: {file_path}")
        return None

def run_detection(triage_path, rules_path, alert_output_path):
    triaged_data = load_json_safely(triage_path, "Triaged log")
    rules = load_json_safely(rules_path, "Detection rules")

    if triaged_data is None or rules is None:
        return

    # Combine HIGH, MEDIUM, and LOW events produced by Task 1
    all_events = (
        triaged_data.get("HIGH", []) +
        triaged_data.get("MEDIUM", []) +
        triaged_data.get("LOW", [])
    )

    if not all_events:
        print("[INFO] No valid triaged events found to scan.")
        return

    triggered_alerts = []

    for rule in rules:
        keyword = rule.get("match_keyword", "")
        threshold = rule.get("threshold", 1)
        matched_logs = [log for log in all_events if keyword in log]

        if len(matched_logs) >= threshold:
            triggered_alerts.append({
                "rule_id": rule["rule_id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "description": rule["description"],
                "match_count": len(matched_logs),
                "evidence": matched_logs
            })

    os.makedirs(os.path.dirname(alert_output_path), exist_ok=True)
    with open(alert_output_path, "w", encoding="utf-8") as out:
        json.dump(triggered_alerts, out, indent=4)

    print(f"[SUCCESS] Detection complete. {len(triggered_alerts)} security alert(s) triggered and saved to {alert_output_path}.")

if __name__ == "__main__":
    triage_file = sys.argv[1] if len(sys.argv) > 1 else "output/triage_report.json"
    rules_file = sys.argv[2] if len(sys.argv) > 2 else "rules/coop_detection_rules.json"
    run_detection(triage_file, rules_file, "output/alerts.json")
