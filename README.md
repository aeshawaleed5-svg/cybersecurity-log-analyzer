# Cybersecurity Log Analyzer

A Python-based security monitoring project that analyzes
authentication logs and detects possible brute-force activity.

## Features

- Parses authentication log entries.
- Detects repeated failed logins from the same IP.
- Uses a configurable five-minute detection window.
- Classifies alerts by severity.
- Exports alerts to a CSV report.
- Includes a Streamlit dashboard.

## Technologies

- Python
- Pandas
- Streamlit
- CSV

## Detection Rules

- Minimum 5 failed login attempts within 5 minutes:
  Medium severity.
- 10 or more failed attempts within 5 minutes:
  High severity.
- Fewer than 5 attempts in every five-minute window:
  No alert.

## How to Run

Install dependencies:

    pip install -r requirements.txt

Run the analyzer from the project root:

    python src/analyzer.py

Run the dashboard:

    streamlit run src/dashboard.py

## Testing

Tested with sample log data for:
- Five failed attempts within five minutes.
- Two failed attempts.
- Five attempts spread across more than five minutes,
  with no five attempts inside any five-minute window.

## Disclaimer

This project is an educational prototype using sample log data.
Alerts indicate potentially suspicious activity and are not
proof of a confirmed attack.