## How to Run & Check

1. **Run normal log triage (GreenField Co-op logs):**
   ```bash
   python src/triage.py logs/coop_system_logs.log
   ```
   *Expected result:* Generates `output/triage_report.json` and prints the count of High, Medium, and Low severity events.

2. **Check missing file handling:**
   ```bash
   python src/triage.py logs/fake_file.log
   ```
   *Expected result:* Displays `[ERROR] Log file not found` without crashing.

3. **Check empty file handling:**
   ```bash
   python src/triage.py logs/empty.log
   ```
   *Expected result:* Displays `[ERROR] Log file is empty` without crashing.
