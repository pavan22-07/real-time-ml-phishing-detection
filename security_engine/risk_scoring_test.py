
import unittest

if __package__:
    from .risk_scoring import (
        calculate_risk_score,
        get_risk_level,
        get_security_action,
        assess_risk
    )
else:
    from risk_scoring import (
        calculate_risk_score,
        get_risk_level,
        get_security_action,
        assess_risk
    )


class RiskScoringTests(unittest.TestCase):

    def test_empty_findings(self):

        result = assess_risk([])

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["action"], "ALLOW")

    def test_score_never_exceeds_100(self):

        findings = [
            {
                "rule": "THREAT_INTELLIGENCE",
                "detected": True,
                "confidence": 1.0,
                "evidence_group": "threat_reputation"
            },
            {
                "rule": "BRAND_IMPERSONATION",
                "detected": True,
                "confidence": 1.0,
                "evidence_group": "brand_identity"
            },
            {
                "rule": "IP_ADDRESS",
                "detected": True,
                "confidence": 1.0,
                "evidence_group": "url_structure"
            }
        ]

        result = calculate_risk_score(findings)

        self.assertLessEqual(result["risk_score"], 100)

    def test_correlated_findings_are_capped(self):

        findings = [
            {
                "rule": "DOMAIN_SIMILARITY",
                "detected": True,
                "confidence": 1.0,
                "evidence_group": "brand_identity"
            },
            {
                "rule": "BRAND_IMPERSONATION",
                "detected": True,
                "confidence": 1.0,
                "evidence_group": "brand_identity"
            },
            {
                "rule": "IDN_HOMOGRAPH",
                "detected": True,
                "confidence": 1.0,
                "evidence_group": "brand_identity"
            }
        ]

        result = calculate_risk_score(findings)

        self.assertEqual(result["risk_score"], 35)

    def test_duplicate_rule_not_counted_twice(self):

        finding = {
            "rule": "IP_ADDRESS",
            "detected": True,
            "confidence": 1.0,
            "evidence_group": "url_structure"
        }

        result = calculate_risk_score([finding, finding])

        self.assertEqual(result["risk_score"], 15)

    def test_confidence_adjustment(self):

        findings = [{
            "rule": "IP_ADDRESS",
            "detected": True,
            "confidence": 0.5,
            "evidence_group": "url_structure"
        }]

        result = calculate_risk_score(findings)

        self.assertEqual(result["risk_score"], 8)

    def test_risk_levels(self):

        self.assertEqual(get_risk_level(10), "LOW")
        self.assertEqual(get_risk_level(20), "MEDIUM")
        self.assertEqual(get_risk_level(45), "HIGH")
        self.assertEqual(get_risk_level(70), "CRITICAL")

    def test_security_actions(self):

        self.assertEqual(get_security_action("LOW"), "ALLOW")
        self.assertEqual(get_security_action("MEDIUM"), "WARN")
        self.assertEqual(get_security_action("HIGH"), "BLOCK")
        self.assertEqual(get_security_action("CRITICAL"), "BLOCK")

    def test_confirmed_threat_is_blocked(self):

        findings = [{
            "rule": "THREAT_INTELLIGENCE",
            "detected": True,
            "confidence": 0.98,
            "evidence_group": "threat_reputation"
        }]

        result = assess_risk(findings)

        self.assertTrue(result["confirmed_threat"])
        self.assertEqual(result["action"], "BLOCK")


if __name__ == "__main__":
    unittest.main(verbosity=2)
