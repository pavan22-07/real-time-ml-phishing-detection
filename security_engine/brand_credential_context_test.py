import unittest
from unittest.mock import patch

from .url_analyzer import analyze_url
from .rule_engine import run_security_rules
from .risk_scoring import assess_risk
from .decision_engine import determine_decision


FRESH_CLEAN_THREAT_INTEL = {
    "available": True,
    "feed_status": "FRESH",
    "matched": False,
    "match_type": None,
    "matched_indicator": None,
}


class BrandCredentialContextTests(unittest.TestCase):
    def scan(self, url):
        features = analyze_url(url)
        features["threat_intelligence"] = dict(FRESH_CLEAN_THREAT_INTEL)
        features["redirect_analysis"] = {}
        findings = run_security_rules(features)
        assessment = assess_risk(findings)
        decision = determine_decision(assessment, features)
        return features, findings, assessment, decision

    def test_paypal_brand_spoof_with_login_and_payment_context_blocks(self):
        url = (
            "https://paypal.com.example.test/login/verify-account/"
            "secure-payment?redirect=signin"
        )
        features, findings, assessment, decision = self.scan(url)
        detected = {item["rule"] for item in findings}

        self.assertEqual(features["registered_domain"], "example.test")
        self.assertIn("BRAND_IMPERSONATION", detected)
        self.assertIn("BRAND_CREDENTIAL_CONTEXT", detected)
        self.assertTrue(assessment["high_confidence_brand_attack"])
        self.assertEqual(assessment["action"], "BLOCK")
        self.assertEqual(decision["decision"], "BLOCK")

    def test_paypal_subdomain_account_generic_remains_warn(self):
        _, findings, assessment, decision = self.scan(
            "https://paypal.com.example.test/account"
        )
        detected = {item["rule"] for item in findings}
        self.assertIn("BRAND_IMPERSONATION", detected)
        self.assertNotIn("BRAND_CREDENTIAL_CONTEXT", detected)
        self.assertFalse(assessment["high_confidence_brand_attack"])
        self.assertEqual(decision["decision"], "WARN")

    def test_paypal_subdomain_secure_update_generic_remains_warn(self):
        _, findings, assessment, decision = self.scan(
            "https://paypal.com.example.test/secure-update"
        )
        detected = {item["rule"] for item in findings}
        self.assertIn("BRAND_IMPERSONATION", detected)
        self.assertNotIn("BRAND_CREDENTIAL_CONTEXT", detected)
        self.assertFalse(assessment["high_confidence_brand_attack"])
        self.assertEqual(decision["decision"], "WARN")

    def test_paypal_subdomain_login_generic_remains_warn(self):
        _, findings, assessment, decision = self.scan(
            "https://paypal.com.example.test/login"
        )
        detected = {item["rule"] for item in findings}
        self.assertIn("BRAND_IMPERSONATION", detected)
        self.assertNotIn("BRAND_CREDENTIAL_CONTEXT", detected)
        self.assertFalse(assessment["high_confidence_brand_attack"])
        self.assertEqual(decision["decision"], "WARN")

    def test_paypal_subdomain_login_password_reset_strong_blocks(self):
        _, findings, assessment, decision = self.scan(
            "https://paypal.com.example.test/login/password-reset"
        )
        detected = {item["rule"] for item in findings}
        self.assertIn("BRAND_IMPERSONATION", detected)
        self.assertIn("BRAND_CREDENTIAL_CONTEXT", detected)
        self.assertTrue(assessment["high_confidence_brand_attack"])
        self.assertEqual(assessment["action"], "BLOCK")
        self.assertEqual(decision["decision"], "BLOCK")

    def test_paypal_subdomain_checkout_payment_strong_blocks(self):
        _, findings, assessment, decision = self.scan(
            "https://paypal.com.example.test/checkout/payment"
        )
        detected = {item["rule"] for item in findings}
        self.assertIn("BRAND_IMPERSONATION", detected)
        self.assertIn("BRAND_CREDENTIAL_CONTEXT", detected)
        self.assertTrue(assessment["high_confidence_brand_attack"])
        self.assertEqual(assessment["action"], "BLOCK")
        self.assertEqual(decision["decision"], "BLOCK")

    def test_brand_impersonation_without_credential_context_remains_warning(self):
        _, findings, assessment, decision = self.scan(
            "https://paypal.com.example.test/about"
        )
        detected = {item["rule"] for item in findings}

        self.assertIn("BRAND_IMPERSONATION", detected)
        self.assertNotIn("BRAND_CREDENTIAL_CONTEXT", detected)
        self.assertFalse(assessment["high_confidence_brand_attack"])
        self.assertEqual(decision["decision"], "WARN")

    def test_credential_context_on_unrelated_domain_does_not_trigger_compound_rule(self):
        _, findings, assessment, decision = self.scan(
            "https://example.test/login/password-reset"
        )
        detected = {item["rule"] for item in findings}

        self.assertNotIn("BRAND_IMPERSONATION", detected)
        self.assertNotIn("BRAND_CREDENTIAL_CONTEXT", detected)
        self.assertFalse(assessment["high_confidence_brand_attack"])
        self.assertNotEqual(decision["decision"], "BLOCK")

    def test_legitimate_paypal_domain_is_not_blocked(self):
        _, findings, _, decision = self.scan(
            "https://www.paypal.com/login"
        )
        detected = {item["rule"] for item in findings}

        self.assertNotIn("BRAND_IMPERSONATION", detected)
        self.assertNotIn("BRAND_CREDENTIAL_CONTEXT", detected)
        self.assertNotEqual(decision["decision"], "BLOCK")


if __name__ == "__main__":
    unittest.main(verbosity=2)
