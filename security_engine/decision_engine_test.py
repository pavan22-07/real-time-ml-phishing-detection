
import unittest

from decision_engine import determine_decision


class DecisionEngineTests(unittest.TestCase):

    def create_assessment(self, score, findings=None):

        return {
            "risk_score": score,
            "risk_level": (
                "CRITICAL" if score >= 70
                else "HIGH" if score >= 45
                else "MEDIUM" if score >= 20
                else "LOW"
            ),
            "confirmed_threat": False,
            "findings": findings or []
        }

    def test_low_risk_allows(self):

        result = determine_decision(
            self.create_assessment(10),
            {
                "threat_intelligence": {
                    "available": True,
                    "feed_status": "FRESH",
                    "matched": False
                },
                "redirect_analysis": {}
            }
        )

        self.assertEqual(result["decision"], "ALLOW")

    def test_medium_risk_warns(self):

        result = determine_decision(
            self.create_assessment(30),
            {}
        )

        self.assertEqual(result["decision"], "WARN")

    def test_high_risk_warns(self):

        result = determine_decision(
            self.create_assessment(50),
            {}
        )

        self.assertEqual(result["decision"], "WARN")

    def test_critical_risk_blocks(self):

        result = determine_decision(
            self.create_assessment(80),
            {}
        )

        self.assertEqual(result["decision"], "BLOCK")

    def test_fresh_threat_match_blocks(self):

        result = determine_decision(
            self.create_assessment(0),
            {
                "threat_intelligence": {
                    "available": True,
                    "feed_status": "FRESH",
                    "matched": True
                }
            }
        )

        self.assertEqual(result["decision"], "BLOCK")

    def test_failed_redirect_inspection_warns(self):

        result = determine_decision(
            self.create_assessment(0),
            {
                "threat_intelligence": {
                    "available": True,
                    "feed_status": "FRESH",
                    "matched": False
                },
                "redirect_analysis": {
                    "error": "DNS resolution failed"
                }
            }
        )

        self.assertEqual(result["decision"], "WARN")
        self.assertEqual(result["inspection_status"], "INCOMPLETE")

    def test_unavailable_feed_warns(self):

        result = determine_decision(
            self.create_assessment(0),
            {
                "threat_intelligence": {
                    "available": False,
                    "feed_status": "UNAVAILABLE"
                }
            }
        )

        self.assertEqual(result["decision"], "WARN")

    def test_stale_feed_match_not_confirmed(self):

        result = determine_decision(
            self.create_assessment(39),
            {
                "threat_intelligence": {
                    "available": True,
                    "feed_status": "STALE",
                    "matched": True
                }
            }
        )

        self.assertNotEqual(result["decision"], "BLOCK")

    def test_findings_explanations(self):

        findings = [{
            "rule": "IP_ADDRESS",
            "detected": True,
            "severity": "MEDIUM",
            "reason": "URL uses an IP address"
        }]

        result = determine_decision(
            self.create_assessment(20, findings),
            {}
        )

        self.assertEqual(len(result["explanations"]), 1)
        self.assertEqual(
            result["explanations"][0]["rule"],
            "IP_ADDRESS"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)


    def test_ip_address_url_cannot_receive_allow(self):

        findings = [{
            "rule": "IP_ADDRESS",
            "detected": True,
            "severity": "MEDIUM",
            "confidence": 0.75,
            "reason": "URL uses an IP address"
        }]

        result = determine_decision(
            self.create_assessment(11, findings),
            {
                "threat_intelligence": {
                    "available": True,
                    "feed_status": "FRESH",
                    "matched": False
                }
            }
        )

        self.assertEqual(result["decision"], "WARN")

    def test_url_credentials_cannot_receive_allow(self):

        findings = [{
            "rule": "AT_SYMBOL",
            "detected": True,
            "severity": "MEDIUM",
            "confidence": 0.75,
            "reason": "URL contains user information"
        }]

        result = determine_decision(
            self.create_assessment(11, findings),
            {
                "threat_intelligence": {
                    "available": True,
                    "feed_status": "FRESH",
                    "matched": False
                }
            }
        )

        self.assertEqual(result["decision"], "WARN")
