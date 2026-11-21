import json
import os
import sys
from datetime import datetime, timezone

VALID_ATTACKS = ["brute_force", "data_exfil", "priv_esc", "ransomware", "all"]
DEFAULT_OUTPUT = "data/simulated_attack_logs.jsonl"


def build_event(event_type, user, role, host, source_ip, action, status, details):
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "organization": "GreenField Farmers Co-op",
        "event_type": event_type,
        "user": user,
        "role": role,
        "host": host,
        "source_ip": source_ip,
        "action": action,
        "status": status,
        "details": details,
    }


def generate_simulations(attack_type):
    events = []

    # Scenario 1: Credential Brute-Force on Member Payout Portal
    if attack_type in ("brute_force", "all"):
        for attempt in range(1, 11):
            events.append(
                build_event(
                    "auth_failure",
                    "d.chen",
                    "Finance & Member Payouts",
                    "member-payout-portal",
                    "185.220.101.44",
                    "LOGIN",
                    "FAILED",
                    f"Failed login attempt #{attempt} for Finance payout portal from untrusted external IP",
                )
            )
        events.append(
            build_event(
                "auth_success",
                "d.chen",
                "Finance & Member Payouts",
                "member-payout-portal",
                "185.220.101.44",
                "LOGIN",
                "SUCCESS",
                "Account compromised after 10 consecutive failed login attempts",
            )
        )

    # Scenario 2: Bulk Data Exfiltration via IoT Service Account
    if attack_type in ("data_exfil", "all"):
        events.append(
            build_event(
                "db_export",
                "svc_iot_silo",
                "Service Account",
                "silo-telemetry-db",
                "10.24.8.19",
                "EXPORT_TABLE",
                "SUCCESS",
                "Anomalous bulk export of Member_Dividend_Batch_Q4 (14,200 rows) by silo sensor account",
            )
        )

    # Scenario 3: Unauthorized Privilege Escalation on Inventory ERP
    if attack_type in ("priv_esc", "all"):
        events.append(
            build_event(
                "account_mgmt",
                "h.singh",
                "Warehouse Manager",
                "erp-inventory-01",
                "10.24.4.12",
                "USER_ADD_ADMIN",
                "SUCCESS",
                "Created rogue administrator account 'coop_vendor_tmp' with sudo privileges at 02:14 AM",
            )
        )

    # Scenario 4: Ransomware File Encryption on Cold Storage Schedules
    if attack_type in ("ransomware", "all"):
        locked_files = [
            "ColdStorage_ZoneA_Schedule.csv.locked",
            "ColdStorage_ZoneB_TempLog.csv.locked",
            "Dairy_Dispatch_Manifest_Nov2026.xlsx.locked",
        ]
        for fname in locked_files:
            events.append(
                build_event(
                    "file_modify",
                    "m.alvarez",
                    "Procurement Lead",
                    "cold-storage-gateway",
                    "10.24.4.18",
                    "FILE_RENAME_ENCRYPT",
                    "SUCCESS",
                    f"Rapid file modification detected: renamed to {fname}",
                )
            )

    return events


def main():
    # Validation 1: Check for missing CLI argument
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        print("[ERROR] Missing or empty attack scenario argument.")
        print(f"Usage: python scripts/simulate_attacks.py <{'|'.join(VALID_ATTACKS)}> [output_path]")
        sys.exit(1)

    attack_type = sys.argv[1].strip().lower()

    # Validation 2: Check for invalid scenario name
    if attack_type not in VALID_ATTACKS:
        print(f"[ERROR] Unknown attack scenario: '{attack_type}'.")
        print(f"Allowed options: {', '.join(VALID_ATTACKS)}")
        sys.exit(1)

    # Optional custom output path with validation
    output_path = sys.argv[2].strip() if len(sys.argv) >= 3 else DEFAULT_OUTPUT
    if not output_path:
        print("[ERROR] Output file path cannot be empty.")
        sys.exit(1)

    events = generate_simulations(attack_type)

    # Validation 3: Safe file writing so permission/path errors never crash
    try:
        parent_dir = os.path.dirname(output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        print(f"[SUCCESS] Simulated '{attack_type}' ({len(events)} log events) -> '{output_path}'")
    except OSError as err:
        print(f"[ERROR] Could not write log file '{output_path}': {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
