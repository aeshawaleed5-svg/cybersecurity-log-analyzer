from datetime import datetime, timedelta
from collections import defaultdict
import csv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "data" / "auth.log"
REPORT_FILE = BASE_DIR / "reports" / "alerts.csv"

THRESHOLD = 5
TIME_WINDOW_MINUTES = 5
HIGH_SEVERITY_THRESHOLD = 10

# Read logs
with open(LOG_FILE, "r", encoding="utf-8") as file:
    logs = file.readlines()

events = []

# Parse failed login events
for log in logs:
    if "FAILED_LOGIN" not in log:
        continue

    try:
        timestamp_text = log.split(" FAILED_LOGIN")[0]
        timestamp = datetime.strptime(
            timestamp_text, "%Y-%m-%d %H:%M:%S"
        )

        username = log.split("user=")[1].split()[0]
        ip = log.split("ip=")[1].split()[0]

        events.append({
            "timestamp": timestamp,
            "username": username,
            "ip": ip
        })

    except (ValueError, IndexError):
        print(f"Skipping invalid log: {log.strip()}")

events.sort(key=lambda event: event["timestamp"])

# Group events by IP
events_by_ip = defaultdict(list)

for event in events:
    events_by_ip[event["ip"]].append(event)

# Detect brute-force-like activity
alerts = []
window = timedelta(minutes=TIME_WINDOW_MINUTES)

for ip, ip_events in events_by_ip.items():
    best_window = []

    for index, event in enumerate(ip_events):
        end_time = event["timestamp"] + window

        matching_events = [
            item for item in ip_events[index:]
            if event["timestamp"] <= item["timestamp"] <= end_time
        ]

        if len(matching_events) > len(best_window):
            best_window = matching_events

    attempts = len(best_window)

    if attempts >= THRESHOLD:
        severity = (
            "HIGH"
            if attempts >= HIGH_SEVERITY_THRESHOLD
            else "MEDIUM"
        )

        alerts.append({
            "Attack Type": "Possible Brute Force",
            "IP Address": ip,
            "Target User": best_window[0]["username"],
            "Attempts": attempts,
            "First Seen": best_window[0]["timestamp"],
            "Last Seen": best_window[-1]["timestamp"],
            "Severity": severity
        })

# Save CSV report
columns = [
    "Attack Type",
    "IP Address",
    "Target User",
    "Attempts",
    "First Seen",
    "Last Seen",
    "Severity"
]

REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

with open(REPORT_FILE, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=columns)
    writer.writeheader()
    writer.writerows(alerts)

# Print results
print(f"Analysis complete. Alerts found: {len(alerts)}")

for alert in alerts:
    print("\n========================================")
    print("             SECURITY ALERT")
    print("========================================")

    for key, value in alert.items():
        print(f"{key:<15}: {value}")

    print("Recommendation: Investigate this IP")
    print("========================================")

print(f"Report saved to {REPORT_FILE}")