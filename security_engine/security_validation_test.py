
import csv
import unittest
from pathlib import Path

if __package__:
    from .url_analyzer import analyze_url
    from .rule_engine import run_security_rules
    from .risk_scoring import assess_risk
    from .decision_engine import determine_decision
else:
    from url_analyzer import analyze_url
    from rule_engine import run_security_rules
    from risk_scoring import assess_risk
    from decision_engine import determine_decision


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = PROJECT_ROOT / "data" / "cybersecurity_test_urls.csv"


def scan_static_url(url):
    """
    Run the static cybersecurity pipeline.
    No submitted URL is opened or fetched.
    """

    features = analyze_url(url)

    # Simulated feed status for deterministic testing.
    # Existing threat-intelligence tests cover real feed lookup.
    features["threat_intelligence"] = {
        "available": True,
        "feed_status": "FRESH",
        "matched": False,
        "match_type": None,
        "matched_indicator": None
    }

    # Redirect inspection is intentionally not performed here.
    features["redirect_analysis"] = {}

    findings = run_security_rules(features)
    assessment = assess_risk(findings)

    decision = determine_decision(
        assessment,
        features
    )

    return {
        "features": features,
        "findings": findings,
        "assessment": assessment,
        "decision": decision
    }


class CybersecurityValidationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with DATASET_PATH.open(
            "r",
            encoding="utf-8-sig",
            newline=""
        ) as file:
            reader = csv.DictReader(file, skipinitialspace=True)

            print("\nCSV PATH:", DATASET_PATH)
            print("CSV HEADERS:", repr(reader.fieldnames))

            cls.cases = list(reader)

            if cls.cases:
                print("FIRST ROW KEYS:", repr(list(cls.cases[0].keys())))
                print("FIRST ROW:", repr(cls.cases[0]))

    def test_dataset_has_both_classes(self):
        labels = {case["label"] for case in self.cases}

        self.assertIn("legitimate", labels)
        self.assertIn("phishing", labels)

    def test_all_dataset_urls_are_analyzed(self):
        for case in self.cases:
            with self.subTest(url=case["url"]):
                result = scan_static_url(case["url"])

                self.assertIn(
                    result["decision"]["decision"],
                    {"ALLOW", "WARN", "BLOCK"}
                )

                self.assertGreaterEqual(
                    result["assessment"]["risk_score"], 0
                )

                self.assertLessEqual(
                    result["assessment"]["risk_score"], 100
                )

    def test_legitimate_domains_are_not_blocked(self):
        legitimate_cases = [
            case for case in self.cases
            if case["label"] == "legitimate"
        ]

        for case in legitimate_cases:
            with self.subTest(url=case["url"]):
                result = scan_static_url(case["url"])

                self.assertNotEqual(
                    result["decision"]["decision"],
                    "BLOCK",
                    msg=f"Legitimate URL was blocked: {case['url']}"
                )

    def test_brand_impersonation_is_detected(self):
        urls = [
            "https://paypal.com.evil-site.com/login",
            "https://paypa1.com/verify",
            "https://g00gle.com/account"
        ]

        for url in urls:
            with self.subTest(url=url):
                result = scan_static_url(url)

                detected_rules = {
                    item["rule"]
                    for item in result["findings"]
                }

                self.assertTrue(
                    detected_rules.intersection({
                        "BRAND_IMPERSONATION",
                        "DOMAIN_SIMILARITY"
                    }),
                    msg=f"No brand impersonation finding for {url}"
                )

    def test_ip_address_is_detected(self):
        result = scan_static_url("http://192.0.2.1/login")

        detected_rules = {
            item["rule"] for item in result["findings"]
        }

        self.assertIn("IP_ADDRESS", detected_rules)

    def test_at_symbol_is_detected(self):
        result = scan_static_url(
            "https://example.com@evil-site.com/login"
        )

        detected_rules = {
            item["rule"] for item in result["findings"]
        }

        self.assertIn("AT_SYMBOL", detected_rules)

    def test_nested_encoding_is_detected(self):
        result = scan_static_url(
            "https://example.com/%256c%256f%2567%2569%256e"
        )

        encoding = result["features"].get(
            "encoding_analysis", {}
        )

        self.assertTrue(encoding.get("nested_encoding"))

    def test_malformed_encoding_is_detected(self):
        result = scan_static_url("https://example.com/%ZZ")

        encoding = result["features"].get(
            "encoding_analysis", {}
        )

        self.assertTrue(encoding.get("malformed_encoding"))

    def test_idn_homograph_is_detected(self):
        result = scan_static_url(
            "https://xn--ypal-43d9g.com/"
        )

        idn = result["features"].get("idn_analysis", {})

        self.assertTrue(
            idn.get("has_suspicious_confusables")
            or idn.get("mixed_script_labels")
            or idn.get("invalid_idn")
            or idn.get("requires_idn_review")
        )

    def test_exact_brand_domain_is_not_impersonation(self):
        result = scan_static_url("https://paypal.com/")

        detected_rules = {
            item["rule"] for item in result["findings"]
        }

        self.assertNotIn(
            "BRAND_IMPERSONATION",
            detected_rules
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
