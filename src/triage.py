import json
import os
import sys

def triage_logs(log_path, output_path):
    # 1. Validate file existence and non-empty content
    if not os.path.exists(log_path):
        print(f"[ERROR] Log file not found at: {log_path}")
        return
    if os.path.getsize(log_path) == 0:
        print(f"[ERROR] Log file is empty: {log_path}. Nothing to triage.")
        return

    triaged_events = {"HIGH": [], "MEDIUM": [], "LOW": [], "MALFORMED": []}

    with open(log_path, "r", encoding="utf-8") as file:
        for line_num, line in enumerate(file, start=1):
            clean_line = line.strip()
            if not clean_line:
                continue

            parts = clean_line.split(" ")
            # Basic format validation (Timestamp + Date + Level + Service)
            if len(parts) < 5 or parts[2] not in ["INFO", "WARN", "ERROR", "CRITICAL"]:
                triaged_events["MALFORMED"].append(f"Line {line_num}: {clean_line}")
                continue

            level = parts[2]
            if level in ["CRITICAL", "ERROR"]:
                triaged_events["HIGH"].append(clean_line)
            elif level == "WARN":
                triaged_events["MEDIUM"].append(clean_line)
            else:
                triaged_events["LOW"].append(clean_line)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as out:
        json.dump(triaged_events, out, indent=4)

    print(f"[SUCCESS] Triage complete. High: {len(triaged_events['HIGH'])}, Medium: {len(triaged_events['MEDIUM'])}, Low: {len(triaged_events['LOW'])}, Malformed: {len(triaged_events['MALFORMED'])}")

if __name__ == "__main__":
    input_file = sys.argv[1] if len(sys.argv) > 1 else "logs/coop_system_logs.log"
    triage_logs(input_file, "output/triage_report.json")
