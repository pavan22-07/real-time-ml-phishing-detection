
import unittest

if __package__:
    from .decision_engine import determine_decision
else:
    from decision_engine import determine_decision


class DecisionPolicyTests(unittest.TestCase):

    def make_assessment(self, findings, score=4):
        return {
            "risk_score": score,
            "risk_level": "LOW",
            "confirmed_threat": False,
            "findings": findings
        }

    def test_high_severity_finding_causes_warning(self):
        assessment = self.make_assessment([
            {
                "rule": "URL_ENCODING",
                "detected": True,
                "severity": "HIGH",
                "reason": "Nested encoding detected"
            }
        ])

        result = determine_decision(assessment, {})

        self.assertEqual(result["decision"], "WARN")

    def test_malformed_encoding_causes_warning(self):
        assessment = self.make_assessment([
            {
                "rule": "URL_ENCODING",
                "detected": True,
                "severity": "HIGH",
                "reason": "Malformed encoding detected"
            }
        ])

        result = determine_decision(assessment, {})

        self.assertEqual(result["decision"], "WARN")

    def test_low_severity_finding_can_remain_allowed(self):
        assessment = self.make_assessment([
            {
                "rule": "SUSPICIOUS_KEYWORDS",
                "detected": True,
                "severity": "LOW",
                "reason": "One suspicious keyword"
            }
        ])

        result = determine_decision(assessment, {})

        self.assertEqual(result["decision"], "ALLOW")

    def test_fresh_threat_intelligence_still_blocks(self):
        assessment = self.make_assessment([], score=4)

        features = {
            "threat_intelligence": {
                "matched": True,
                "feed_status": "FRESH"
            }
        }

        result = determine_decision(assessment, features)

        self.assertEqual(result["decision"], "BLOCK")

    def test_high_score_still_blocks(self):
        assessment = self.make_assessment([], score=75)

        result = determine_decision(assessment, {})

        self.assertEqual(result["decision"], "BLOCK")


if __name__ == "__main__":
    unittest.main(verbosity=2)
