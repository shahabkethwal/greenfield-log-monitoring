# greenfield-log-monitoring
---

## Task 2: Detection Rules

### Overview
Building on the triaged output from Task 1 (`output/triage_report.json`), `src/detect.py` scans GreenField Farmers Co-op logs against custom security rules defined in `rules/coop_detection_rules.json` and writes triggered security alerts to `output/alerts.json`.

### Active Co-op Detection Rules
* **GF-RULE-001 (Brute Force Login Attempt):** Triggers if 3 or more failed logins (`LOGIN_FAILED`) occur on a co-op staff account.
* **GF-RULE-002 (Unauthorized Subsidy Export):** Triggers immediately on any `UNAUTHORIZED_EXPORT` from `farmer_subsidy_payouts`.
* **GF-RULE-003 (Grain Silo IoT Tampering):** Triggers immediately on `FIRMWARE_TAMPER_ALERT` from cold storage sensors.
* **GF-RULE-004 (Suspicious POS Discount Override):** Flags unauthorized `BULK_DISCOUNT_OVERRIDE` events on fertilizer or seed inventory.

### How to Run & Check (Task 2)
1. **Run detection on triaged logs:**
   ```bash
   python src/detect.py output/triage_report.json rules/coop_detection_rules.json
   ```
   *Expected result:* Generates `output/alerts.json` with 4 triggered security alerts.

2. **Test missing input handling:**
   ```bash
   python src/detect.py output/missing.json rules/coop_detection_rules.json
   ```
   *Expected result:* Prints `[ERROR] Triaged log file not found` without crashing.

3. **Test empty input handling:**
   ```bash
   python src/detect.py logs/empty.log rules/coop_detection_rules.json
   ```
   *Expected result:* Prints `[ERROR] Triaged log file is empty` without crashing.

### Handover Note (Task 2)
* **What was built:** A JSON-based rule engine (`src/detect.py` and `rules/coop_detection_rules.json`) tailored to GreenField Farmers Co-op operations (staff logins, subsidy payouts, grain silo IoT, and warehouse POS).
* **Why:** Separating rules into a JSON configuration file allows security analysts to add or adjust thresholds without modifying the Python detection code, preparing the system for **Task 3 (Simulated Attacks)**.
