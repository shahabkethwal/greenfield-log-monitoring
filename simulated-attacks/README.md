# Task 3: Simulated Attacks in the Lab — GreenField Farmers Co-op

## Overview
This module builds on Tasks 1 and 2 of the **GreenField Farmers Co-op** log monitoring and incident detection system. It provides a safe lab attack simulator and a detection runner using realistic cooperative staff accounts (`h.singh`, `m.alvarez`, `d.chen`, `svc_iot_silo`), internal servers (`erp-inventory-01`, `member-payout-portal`, `silo-telemetry-db`, `cold-storage-gateway`), and agricultural operations data.

## Directory Structure
- `data/sample_co_op_logs.jsonl` — Normal baseline operational logs (fertilizer receipts, wheat seed POs, silo telemetry, member dividend approvals).
- `scripts/simulate_attacks.py` — Generates realistic attack log streams with strict CLI and file validation.
- `scripts/run_detection.py` — Evaluates log files against Co-op detection rules and outputs JSON alerts.
- `output/alerts_triggered.json` — Sample alert output generated from a full lab simulation run.

## Simulated Attack Scenarios
1. **Credential Brute-Force (`brute_force`)**: 10 consecutive failed logins followed by a successful compromise on `d.chen` (`member-payout-portal`) from external IP `185.220.101.44`.
2. **Bulk Data Exfiltration (`data_exfil`)**: Service account `svc_iot_silo` exporting `Member_Dividend_Batch_Q4` (14,200 rows) from `silo-telemetry-db`.
3. **Privilege Escalation (`priv_esc`)**: Warehouse user `h.singh` creating rogue admin account `coop_vendor_tmp` on `erp-inventory-01`.
4. **Ransomware Activity (`ransomware`)**: Rapid `.locked` file renaming of cold-storage and dairy dispatch schedules on `cold-storage-gateway`.

## How to Run & Verify (Requires Python 3.8+)

Navigate into the `task-3-simulated-attacks` directory:
```bash
cd task-3-simulated-attacks
