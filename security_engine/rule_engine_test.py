
import unittest

from rule_engine import (
    evaluate_security_rules,
    run_security_rules,
    check_brand_impersonation,
    check_idn_homograph,
    check_redirect_behavior
)


class RuleEngineTests(unittest.TestCase):

    def test_legitimate_domain(self):

        features = {
            "hostname": "google.com",
            "registered_domain": "google.com",
            "has_ip": False,
            "has_at_symbol": False,
            "suspicious_keywords": [],
            "has_encoding": False,
            "subdomain_count": 0,
            "url_length": 25,
            "idn_analysis": {}
        }

        findings = run_security_rules(features)

        self.assertEqual(findings, [])

    def test_brand_impersonation(self):

        features = {
            "hostname": "paypal.com.evil-site.com",
            "registered_domain": "evil-site.com"
        }

        result = check_brand_impersonation(features)

        self.assertTrue(result["detected"])

    def test_legitimate_paypal(self):

        features = {
            "hostname": "paypal.com",
            "registered_domain": "paypal.com"
        }

        result = check_brand_impersonation(features)

        self.assertFalse(result["detected"])

    def test_idn_homograph(self):

        features = {
            "idn_analysis": {
                "mixed_script_labels": [
                    {
                        "label": "раypal",
                        "scripts": ["CYRILLIC", "LATIN"]
                    }
                ],
                "has_suspicious_confusables": True,
                "invalid_idn": False,
                "requires_idn_review": True
            }
        }

        result = check_idn_homograph(features)

        self.assertTrue(result["detected"])

    def test_normal_idn(self):

        features = {
            "idn_analysis": {
                "mixed_script_labels": [],
                "has_suspicious_confusables": False,
                "invalid_idn": False,
                "requires_idn_review": True
            }
        }

        result = check_idn_homograph(features)

        self.assertFalse(result["detected"])

    def test_redirect_loop(self):

        features = {
            "redirect_analysis": {
                "loop_detected": True,
                "https_downgrade": False
            }
        }

        result = check_redirect_behavior(features)

        self.assertTrue(result["detected"])

    def test_https_downgrade(self):

        features = {
            "redirect_analysis": {
                "loop_detected": False,
                "https_downgrade": True
            }
        }

        result = check_redirect_behavior(features)

        self.assertTrue(result["detected"])

    def test_redirect_inspection_failure(self):

        features = {
            "redirect_analysis": {
                "error": "DNS resolution failed"
            }
        }

        result = check_redirect_behavior(features)

        self.assertFalse(result["detected"])

    def test_unavailable_threat_intelligence(self):

        features = {
            "threat_intelligence": {
                "available": False,
                "reason": "Feed unavailable"
            }
        }

        results = evaluate_security_rules(features)

        ti_result = next(
            item for item in results
            if item["rule"] == "THREAT_INTELLIGENCE"
        )

        self.assertFalse(ti_result["detected"])

    def test_duplicate_rules_removed(self):

        features = {
            "hostname": "google.com",
            "registered_domain": "google.com",
            "has_ip": False,
            "has_at_symbol": False,
            "suspicious_keywords": [],
            "has_encoding": False,
            "subdomain_count": 0,
            "url_length": 25,
            "idn_analysis": {}
        }

        results = evaluate_security_rules(features)

        rule_names = [item["rule"] for item in results]

        self.assertEqual(len(rule_names), len(set(rule_names)))


if __name__ == "__main__":
    unittest.main(verbosity=2)


    def test_example_domain_is_not_apple_impersonation(self):

        features = {
            "hostname": "example.com",
            "registered_domain": "example.com"
        }

        result = check_brand_impersonation(features)

        self.assertFalse(result["detected"])

    def test_legitimate_keyword_path_is_not_brand_impersonation(self):

        features = {
            "hostname": "example.com",
            "registered_domain": "example.com"
        }

        result = check_brand_impersonation(features)

        self.assertFalse(result["detected"])

    def test_paypal_subdomain_impersonation(self):

        features = {
            "hostname": "paypal.com.evil-site.com",
            "registered_domain": "evil-site.com"
        }

        result = check_brand_impersonation(features)

        self.assertTrue(result["detected"])

    def test_paypal_login_domain_impersonation(self):

        features = {
            "hostname": "paypal-login.com",
            "registered_domain": "paypal-login.com"
        }

        result = check_brand_impersonation(features)

        self.assertTrue(result["detected"])

    def test_google_numeric_lookalike(self):

        features = {
            "hostname": "g00gle.com",
            "registered_domain": "g00gle.com"
        }

        result = check_brand_impersonation(features)

        self.assertTrue(result["detected"])
