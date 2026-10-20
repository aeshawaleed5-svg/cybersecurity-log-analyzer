
import unittest
from datetime import datetime, timedelta

from src.analyzer import detect_alerts


class TestBruteForceDetection(unittest.TestCase):

    def make_events(self, count, interval_seconds=20):
        start = datetime(2026, 10, 7, 10, 15, 0)

        return [
            {
                "timestamp": start + timedelta(
                    seconds=i * interval_seconds
                ),
                "username": "admin",
                "ip": "192.168.1.10"
            }
            for i in range(count)
        ]

    def test_five_attempts_create_medium_alert(self):
        events = self.make_events(5)

        alerts = detect_alerts(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["Severity"], "MEDIUM")
        self.assertEqual(alerts[0]["Attempts"], 5)

    def test_two_attempts_create_no_alert(self):
        events = self.make_events(2)

        alerts = detect_alerts(events)

        self.assertEqual(len(alerts), 0)

    def test_ten_attempts_create_high_alert(self):
        events = self.make_events(10, interval_seconds=20)

        alerts = detect_alerts(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["Severity"], "HIGH")
        self.assertEqual(alerts[0]["Attempts"], 10)


if __name__ == "__main__":
    unittest.main()
