"""
Comprehensive Cybersecurity Audit Regression Test Suite.
Validates all requirements specified in the SecureLens Cybersecurity Audit:
- Section 10.A: Legitimate domains
- Section 10.B: Synthetic phishing domains
- Section 10.C: Credential and payment attacks
- Section 10.D: URL parsing edge cases
- Section 10.E: Threat intelligence states
- Section 10.F: SSRF and redirect security protections
- Section 10.G: Unified decision policy combinations
"""

import socket
import unittest
from unittest.mock import MagicMock, patch

from security_engine.url_analyzer import analyze_url
from security_engine.rule_engine import (
    evaluate_security_rules,
    run_security_rules,
    check_brand_impersonation,
    check_brand_credential_context,
    check_private_ip,
    check_suspicious_port,
    check_suspicious_extension,
    check_ip_address,
    check_at_symbol,
    check_url_encoding,
    check_subdomains,
    check_idn_homograph,
)
from security_engine.risk_scoring import assess_risk
from security_engine.decision_engine import determine_decision
from security_engine.security_engine import analyze_url_security
from security_engine.redirect_analyzer import (
    validate_and_resolve_destination,
    is_public_ip,
    SSRFPinnedAdapter,
    analyze_redirects,
)
from unified_engine.contracts import (
    ENGINE_ML,
    ENGINE_SECURITY,
    ENGINE_STATUS_DEGRADED,
    ENGINE_STATUS_ERROR,
    ENGINE_STATUS_OK,
    SCORE_SCALE_PROB,
    SCORE_SCALE_RISK,
    SCORE_TYPE_ML_PROB,
    SCORE_TYPE_RISK,
    VERDICT_BENIGN,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    build_engine_result,
    build_error_result,
)
from unified_engine.policy import evaluate_combined_policy
from unified_engine.detector import scan_url


FRESH_CLEAN_THREAT_INTEL = {
    "available": True,
    "feed_status": "FRESH",
    "matched": False,
    "match_type": None,
    "matched_indicator": None,
    "source": "OpenPhish Community",
    "reason": "No matching indicator found in local feed",
}


class SectionA_LegitimateDomainsTests(unittest.TestCase):
    """10.A: Legitimate domains must never be blocked."""

    DOMAINS = [
        "https://www.wikipedia.org/",
        "https://python.org/",
        "https://www.google.com/",
        "https://www.paypal.com/",
        "https://www.microsoft.com/",
        "https://www.apple.com/",
        "https://www.amazon.com/",
    ]

    def test_all_legitimate_domains_are_allowed(self):
        for url in self.DOMAINS:
            with self.subTest(url=url):
                features = analyze_url(url)
                features["threat_intelligence"] = dict(FRESH_CLEAN_THREAT_INTEL)
                features["redirect_analysis"] = {}

                findings = run_security_rules(features)
                assessment = assess_risk(findings)
                decision = determine_decision(assessment, features)

                self.assertEqual(decision["decision"], "ALLOW", msg=f"Failed for {url}")
                self.assertEqual(assessment["risk_score"], 0)
                self.assertNotIn("BRAND_IMPERSONATION", [f["rule"] for f in findings])

    def test_legitimate_domains_with_login_paths_are_not_blocked(self):
        login_urls = [
            "https://www.paypal.com/signin",
            "https://www.google.com/accounts/login",
            "https://appleid.apple.com/sign-in",
            "https://login.microsoftonline.com/",
            "https://www.amazon.com/ap/signin",
        ]
        for url in login_urls:
            with self.subTest(url=url):
                features = analyze_url(url)
                features["threat_intelligence"] = dict(FRESH_CLEAN_THREAT_INTEL)
                features["redirect_analysis"] = {}

                findings = run_security_rules(features)
                assessment = assess_risk(findings)
                decision = determine_decision(assessment, features)

                self.assertNotEqual(decision["decision"], "BLOCK", msg=f"Wrongly blocked: {url}")
                self.assertFalse(assessment["high_confidence_brand_attack"])


class SectionB_SyntheticPhishingDomainsTests(unittest.TestCase):
    """10.B: Synthetic phishing domains must be detected as brand impersonation."""

    SYNTHETIC_DOMAINS = [
        ("https://paypal.com.example.test/", "paypal"),
        ("https://google.com.example.test/", "google"),
        ("https://microsoft.com.example.test/", "microsoft"),
        ("https://apple.com.example.test/", "apple"),
        ("https://amazon.com.example.test/", "amazon"),
    ]

    def test_synthetic_domains_registered_domain_and_impersonation(self):
        for url, brand in self.SYNTHETIC_DOMAINS:
            with self.subTest(url=url, brand=brand):
                features = analyze_url(url)
                self.assertEqual(features["registered_domain"], "example.test")
                self.assertEqual(features["subdomain"], f"{brand}.com")

                finding = check_brand_impersonation(features)
                self.assertTrue(finding["detected"], msg=f"Brand impersonation missed for {url}")
                self.assertIn(brand, finding["reason"])


class SectionC_CredentialAttacksTests(unittest.TestCase):
    """10.C: Strong credential/payment attacks paired with brand spoof trigger BLOCK, generic words WARN."""

    STRONG_ATTACKS = [
        "/password-reset",
        "/payment",
        "/billing",
        "/checkout",
        "/login/password-reset",
        "/checkout/payment",
    ]

    GENERIC_ATTACKS = [
        "/account",
        "/secure-update",
        "/login",
        "/signin",
        "/verify",
    ]

    BRANDS = ["paypal", "google", "microsoft", "apple", "amazon"]

    def test_compound_brand_and_strong_credential_context_triggers_block(self):
        for brand in self.BRANDS:
            for attack in self.STRONG_ATTACKS:
                url = f"https://{brand}.com.example.test{attack}"
                with self.subTest(url=url):
                    features = analyze_url(url)
                    features["threat_intelligence"] = dict(FRESH_CLEAN_THREAT_INTEL)
                    features["redirect_analysis"] = {}

                    findings = run_security_rules(features)
                    assessment = assess_risk(findings)
                    decision = determine_decision(assessment, features)

                    rules = {f["rule"] for f in findings}
                    self.assertIn("BRAND_IMPERSONATION", rules)
                    self.assertIn("BRAND_CREDENTIAL_CONTEXT", rules)
                    self.assertTrue(assessment["high_confidence_brand_attack"])
                    self.assertEqual(assessment["action"], "BLOCK")
                    self.assertEqual(decision["decision"], "BLOCK")

    def test_generic_words_on_brand_spoof_remain_warn(self):
        for brand in self.BRANDS:
            for attack in self.GENERIC_ATTACKS:
                url = f"https://{brand}.com.example.test{attack}"
                with self.subTest(url=url):
                    features = analyze_url(url)
                    features["threat_intelligence"] = dict(FRESH_CLEAN_THREAT_INTEL)
                    features["redirect_analysis"] = {}

                    findings = run_security_rules(features)
                    assessment = assess_risk(findings)
                    decision = determine_decision(assessment, features)

                    rules = {f["rule"] for f in findings}
                    self.assertIn("BRAND_IMPERSONATION", rules)
                    self.assertNotIn("BRAND_CREDENTIAL_CONTEXT", rules)
                    self.assertFalse(assessment["high_confidence_brand_attack"])
                    self.assertEqual(decision["decision"], "WARN")

    def test_credential_paths_alone_on_generic_domain_never_block(self):
        all_attacks = self.STRONG_ATTACKS + self.GENERIC_ATTACKS
        for attack in all_attacks:
            url = f"https://example.test{attack}"
            with self.subTest(url=url):
                features = analyze_url(url)
                features["threat_intelligence"] = dict(FRESH_CLEAN_THREAT_INTEL)
                features["redirect_analysis"] = {}

                findings = run_security_rules(features)
                assessment = assess_risk(findings)
                decision = determine_decision(assessment, features)

                rules = {f["rule"] for f in findings}
                self.assertNotIn("BRAND_CREDENTIAL_CONTEXT", rules)
                self.assertNotEqual(decision["decision"], "BLOCK")


class SectionD_URLParsingEdgeCasesTests(unittest.TestCase):
    """10.D: Comprehensive URL parsing edge cases."""

    def test_userinfo_and_at_symbol(self):
        cred_url = "https://user:password@evil-site.com/login"
        feat = analyze_url(cred_url)
        self.assertTrue(feat["has_url_credentials"])
        self.assertTrue(check_at_symbol(feat)["detected"])

        at_domain_url = "https://paypal.com@evil-site.com/login"
        feat2 = analyze_url(at_domain_url)
        self.assertTrue(feat2["has_url_credentials"])
        self.assertTrue(check_at_symbol(feat2)["detected"])

        path_at_url = "https://example.com/user@company/profile"
        feat3 = analyze_url(path_at_url)
        self.assertFalse(feat3["has_url_credentials"])

    def test_ip_based_urls(self):
        # Public IP
        feat_pub = analyze_url("http://93.184.216.34/index.html")
        self.assertTrue(feat_pub["has_ip"])
        self.assertFalse(feat_pub["has_private_ip"])
        self.assertTrue(check_ip_address(feat_pub)["detected"])
        self.assertFalse(check_private_ip(feat_pub)["detected"])

        # Private IPv4
        for priv_ip in ["10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"]:
            with self.subTest(ip=priv_ip):
                feat_priv = analyze_url(f"http://{priv_ip}/admin")
                self.assertTrue(feat_priv["has_ip"])
                self.assertTrue(feat_priv["has_private_ip"])
                self.assertTrue(check_private_ip(feat_priv)["detected"])

    def test_encoded_and_nested_encoded_characters(self):
        normal_enc = analyze_url("https://example.com/search?q=%20test")
        self.assertTrue(normal_enc["has_encoding"])
        self.assertFalse(normal_enc["encoding_analysis"]["nested_encoding"])

        nested_enc = analyze_url("https://example.com/%256c%256f%2567%2569%256e")
        self.assertTrue(nested_enc["encoding_analysis"]["nested_encoding"])
        finding = check_url_encoding(nested_enc)
        self.assertTrue(finding["detected"])
        self.assertEqual(finding["severity"], "HIGH")

        malformed_enc = analyze_url("https://example.com/%ZZtest")
        self.assertTrue(malformed_enc["encoding_analysis"]["malformed_encoding"])

    def test_punycode_and_unicode_homographs(self):
        puny_paypal = analyze_url("https://xn--ypal-43d9g.com/")
        self.assertTrue(puny_paypal["idn_analysis"]["is_punycode"])
        self.assertTrue(check_idn_homograph(puny_paypal)["detected"])

        cyrillic_paypal = analyze_url("https://раypal.com/")
        self.assertTrue(cyrillic_paypal["idn_analysis"]["has_suspicious_confusables"])
        self.assertTrue(check_idn_homograph(cyrillic_paypal)["detected"])

    def test_trailing_dots_normalization(self):
        feat = analyze_url("https://www.paypal.com./login")
        self.assertEqual(feat["hostname"], "www.paypal.com")
        self.assertEqual(feat["registered_domain"], "paypal.com")
        self.assertTrue(feat["has_trailing_dot"])

        attack_feat = analyze_url("https://paypal.com.example.test./login")
        self.assertEqual(attack_feat["hostname"], "paypal.com.example.test")
        self.assertEqual(attack_feat["registered_domain"], "example.test")
        self.assertTrue(check_brand_impersonation(attack_feat)["detected"])

    def test_unusual_ports(self):
        feat_std_http = analyze_url("http://example.com:80/")
        self.assertFalse(feat_std_http["has_unusual_port"])
        self.assertFalse(check_suspicious_port(feat_std_http)["detected"])

        feat_std_https = analyze_url("https://example.com:443/")
        self.assertFalse(feat_std_https["has_unusual_port"])
        self.assertFalse(check_suspicious_port(feat_std_https)["detected"])

        feat_unusual = analyze_url("http://example.com:8080/login")
        self.assertTrue(feat_unusual["has_unusual_port"])
        finding = check_suspicious_port(feat_unusual)
        self.assertTrue(finding["detected"])
        self.assertEqual(finding["severity"], "MEDIUM")

    def test_excessive_subdomains(self):
        feat_sub = analyze_url("https://a.b.c.d.example.com/")
        self.assertGreaterEqual(feat_sub["subdomain_count"], 3)
        self.assertTrue(check_subdomains(feat_sub)["detected"])

    def test_suspicious_file_extensions(self):
        feat_exe = analyze_url("https://example.com/download/invoice.exe")
        self.assertTrue(feat_exe["has_suspicious_extension"])
        finding = check_suspicious_extension(feat_exe)
        self.assertTrue(finding["detected"])
        self.assertEqual(finding["severity"], "HIGH")

        feat_html = analyze_url("https://example.com/index.html")
        self.assertFalse(feat_html["has_suspicious_extension"])
        self.assertFalse(check_suspicious_extension(feat_html)["detected"])


class SectionE_ThreatIntelligenceStatesTests(unittest.TestCase):
    """10.E: Threat intelligence verification states."""

    def test_fresh_feed_confirmed_match_blocks(self):
        matched_intel = {
            "available": True,
            "feed_status": "FRESH",
            "matched": True,
            "match_type": "EXACT_URL",
            "matched_indicator": "https://malicious.example.com/phish",
            "source": "OpenPhish Community",
            "reason": "Exact URL match found in phishing feed",
        }
        with patch("security_engine.security_engine.check_threat_intelligence", return_value=matched_intel):
            result = analyze_url_security("https://malicious.example.com/phish", inspect_redirects=False)
            self.assertEqual(result["final_decision"]["decision"], "BLOCK")
            self.assertEqual(result["engine_status"], "COMPLETED")

    def test_stale_feed_never_produces_unverified_allow(self):
        stale_intel = {
            "available": True,
            "feed_status": "STALE",
            "matched": False,
            "match_type": None,
            "matched_indicator": None,
            "source": "OpenPhish Community",
            "reason": "No matching indicator found in local feed",
        }
        with patch("security_engine.security_engine.check_threat_intelligence", return_value=stale_intel):
            result = analyze_url_security("https://www.wikipedia.org/", inspect_redirects=False)
            self.assertEqual(result["final_decision"]["decision"], "WARN")
            self.assertEqual(result["engine_status"], "INCOMPLETE")

    def test_unavailable_feed_warns_and_marks_incomplete(self):
        unavail_intel = {
            "available": False,
            "feed_status": "UNAVAILABLE",
            "matched": False,
            "match_type": None,
            "matched_indicator": None,
            "source": "OpenPhish Community",
            "reason": "Threat intelligence feed file does not exist",
        }
        with patch("security_engine.security_engine.check_threat_intelligence", return_value=unavail_intel):
            result = analyze_url_security("https://www.wikipedia.org/", inspect_redirects=False)
            self.assertEqual(result["final_decision"]["decision"], "WARN")
            self.assertEqual(result["engine_status"], "INCOMPLETE")

    def test_malformed_metadata_warns_and_marks_incomplete(self):
        malformed_intel = {
            "available": False,
            "feed_status": "MALFORMED",
            "matched": False,
            "match_type": None,
            "matched_indicator": None,
            "source": "OpenPhish Community",
            "reason": "Threat feed metadata missing or invalid",
        }
        with patch("security_engine.security_engine.check_threat_intelligence", return_value=malformed_intel):
            result = analyze_url_security("https://www.wikipedia.org/", inspect_redirects=False)
            self.assertEqual(result["final_decision"]["decision"], "WARN")
            self.assertEqual(result["engine_status"], "INCOMPLETE")


class SectionF_SSRFAndRedirectTests(unittest.TestCase):
    """10.F: SSRF, DNS rebinding, and redirect security protections."""

    def test_localhost_and_cloud_metadata_rejected(self):
        for dest in [
            "http://localhost/",
            "http://app.localhost/",
            "http://metadata.google.internal/",
            "http://instance-data/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
        ]:
            with self.subTest(dest=dest):
                valid, _, err, _ = validate_and_resolve_destination(dest)
                self.assertFalse(valid)
                self.assertIsNotNone(err)

    def test_private_ipv4_and_ipv6_destinations_rejected(self):
        private_destinations = [
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[fc00::1]/",
            "http://[::ffff:127.0.0.1]/",
        ]
        for dest in private_destinations:
            with self.subTest(dest=dest):
                valid, _, err, _ = validate_and_resolve_destination(dest)
                self.assertFalse(valid)
                self.assertIsNotNone(err)

    def test_ssrf_pinned_adapter_rejects_proxies(self):
        adapter = SSRFPinnedAdapter("93.184.216.34")
        with self.assertRaises(ValueError) as cm:
            adapter.proxy_manager_for("http://127.0.0.1:8080")
        self.assertIn("Proxy configuration is disabled", str(cm.exception))

    def test_redirect_loop_detected(self):
        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "http://example.com/loop"}

        with patch("requests.Session.get", return_value=mock_resp):
            result = analyze_redirects("http://example.com/loop", resolver=fake_resolver)
            self.assertTrue(result["loop_detected"])
            self.assertEqual(result["stop_reason"], "Redirect loop detected")


class SectionG_UnifiedDecisionPolicyTests(unittest.TestCase):
    """10.G: All combinations in the Unified Phishing Detection policy matrix."""

    def _build_sec(self, status, verdict, raw_decision=None):
        if status == ENGINE_STATUS_ERROR:
            return build_error_result(
                engine=ENGINE_SECURITY,
                url="https://test.com",
                score_type=SCORE_TYPE_RISK,
                score_scale=SCORE_SCALE_RISK,
                error="Cybersecurity failure",
            )
        raw_result = {"final_decision": {"decision": raw_decision or "ALLOW"}}
        return build_engine_result(
            engine=ENGINE_SECURITY,
            url="https://test.com",
            status=status,
            verdict=verdict,
            score=0.0 if verdict == VERDICT_BENIGN else 50.0,
            score_type=SCORE_TYPE_RISK,
            score_scale=SCORE_SCALE_RISK,
            risk_score=0.0 if verdict == VERDICT_BENIGN else 50.0,
            raw_result=raw_result,
        )

    def _build_ml(self, status, verdict):
        if status == ENGINE_STATUS_ERROR:
            return build_error_result(
                engine=ENGINE_ML,
                url="https://test.com",
                score_type=SCORE_TYPE_ML_PROB,
                score_scale=SCORE_SCALE_PROB,
                error="ML failure",
            )
        prob = 0.05 if verdict == VERDICT_BENIGN else 0.85
        return build_engine_result(
            engine=ENGINE_ML,
            url="https://test.com",
            status=status,
            verdict=verdict,
            score=prob,
            score_type=SCORE_TYPE_ML_PROB,
            score_scale=SCORE_SCALE_PROB,
            raw_phishing_probability=prob,
        )

    def test_benign_plus_legitimate_yields_allow(self):
        sec = self._build_sec(ENGINE_STATUS_OK, VERDICT_BENIGN, "ALLOW")
        ml = self._build_ml(ENGINE_STATUS_OK, VERDICT_BENIGN)
        out = evaluate_combined_policy(sec, ml)
        self.assertEqual(out["final_decision"], "ALLOW")
        self.assertFalse(out["degraded_mode"])

    def test_suspicious_plus_legitimate_yields_warn(self):
        sec = self._build_sec(ENGINE_STATUS_OK, VERDICT_SUSPICIOUS, "WARN")
        ml = self._build_ml(ENGINE_STATUS_OK, VERDICT_BENIGN)
        out = evaluate_combined_policy(sec, ml)
        self.assertEqual(out["final_decision"], "WARN")

    def test_benign_plus_phishing_yields_warn_never_block(self):
        sec = self._build_sec(ENGINE_STATUS_OK, VERDICT_BENIGN, "ALLOW")
        ml = self._build_ml(ENGINE_STATUS_OK, VERDICT_SUSPICIOUS)
        out = evaluate_combined_policy(sec, ml)
        self.assertEqual(out["final_decision"], "WARN")

    def test_malicious_plus_legitimate_yields_block(self):
        sec = self._build_sec(ENGINE_STATUS_OK, VERDICT_MALICIOUS, "BLOCK")
        ml = self._build_ml(ENGINE_STATUS_OK, VERDICT_BENIGN)
        out = evaluate_combined_policy(sec, ml)
        self.assertEqual(out["final_decision"], "BLOCK")

    def test_malicious_plus_phishing_yields_block(self):
        sec = self._build_sec(ENGINE_STATUS_OK, VERDICT_MALICIOUS, "BLOCK")
        ml = self._build_ml(ENGINE_STATUS_OK, VERDICT_SUSPICIOUS)
        out = evaluate_combined_policy(sec, ml)
        self.assertEqual(out["final_decision"], "BLOCK")

    def test_error_plus_legitimate_yields_warn_degraded(self):
        sec = self._build_sec(ENGINE_STATUS_ERROR, VERDICT_UNKNOWN)
        ml = self._build_ml(ENGINE_STATUS_OK, VERDICT_BENIGN)
        out = evaluate_combined_policy(sec, ml)
        self.assertEqual(out["final_decision"], "WARN")
        self.assertTrue(out["degraded_mode"])

    def test_benign_plus_error_yields_warn_degraded(self):
        sec = self._build_sec(ENGINE_STATUS_OK, VERDICT_BENIGN, "ALLOW")
        ml = self._build_ml(ENGINE_STATUS_ERROR, VERDICT_UNKNOWN)
        out = evaluate_combined_policy(sec, ml)
        self.assertEqual(out["final_decision"], "WARN")
        self.assertTrue(out["degraded_mode"])

    def test_error_plus_error_yields_error(self):
        sec = self._build_sec(ENGINE_STATUS_ERROR, VERDICT_UNKNOWN)
        ml = self._build_ml(ENGINE_STATUS_ERROR, VERDICT_UNKNOWN)
        out = evaluate_combined_policy(sec, ml)
        self.assertEqual(out["final_decision"], "ERROR")

    def test_cybersecurity_block_cannot_be_downgraded_by_ml_error(self):
        sec = self._build_sec(ENGINE_STATUS_OK, VERDICT_MALICIOUS, "BLOCK")
        ml = self._build_ml(ENGINE_STATUS_ERROR, VERDICT_UNKNOWN)
        out = evaluate_combined_policy(sec, ml)
        self.assertEqual(out["final_decision"], "BLOCK")
        self.assertTrue(out["degraded_mode"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
