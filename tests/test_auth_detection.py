
import unittest

from tools.log_analyzer import detect_success_after_failures


class TestSuccessfulLoginAfterFailures(unittest.TestCase):

    def make_evidence(self, failed, successful):
        return {
            "failed_logins": failed,
            "successful_logins": successful
        }

    def make_failed_logins(self, username="admin", ip="10.0.0.5"):
        return [
            {
                "timestamp": f"Nov 17 02:0{i}:00",
                "username": username,
                "source_ip": ip
            }
            for i in range(3)
        ]

    def make_success(self, username="admin", ip="10.0.0.5",
                     timestamp="Nov 17 02:03:00"):
        return {
            "timestamp": timestamp,
            "username": username,
            "source_ip": ip
        }

    def test_same_account_and_ip_generates_alert(self):
        evidence = self.make_evidence(
            self.make_failed_logins(),
            [self.make_success()]
        )

        alerts = detect_success_after_failures(evidence)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "DET-002")
        self.assertEqual(alerts[0]["failed_attempts"], 3)

    def test_different_username_does_not_generate_alert(self):
        evidence = self.make_evidence(
            self.make_failed_logins(username="admin"),
            [self.make_success(username="kelvin")]
        )

        alerts = detect_success_after_failures(evidence)

        self.assertEqual(len(alerts), 0)

    def test_different_source_ip_does_not_generate_alert(self):
        evidence = self.make_evidence(
            self.make_failed_logins(ip="10.0.0.5"),
            [self.make_success(ip="10.0.0.9")]
        )

        alerts = detect_success_after_failures(evidence)

        self.assertEqual(len(alerts), 0)

    def test_outside_detection_window_does_not_generate_alert(self):
        evidence = self.make_evidence(
            self.make_failed_logins(),
            [
                self.make_success(
                    timestamp="Nov 17 02:08:00"
                )
            ]
        )

        alerts = detect_success_after_failures(evidence)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
