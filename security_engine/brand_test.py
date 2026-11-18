import unittest

if __package__:
    from .url_analyzer import analyze_url
    from .rule_engine import check_brand_impersonation
else:
    from url_analyzer import analyze_url
    from rule_engine import check_brand_impersonation


class BrandImpersonationTests(unittest.TestCase):
    def test_brand_cases(self):
        cases = [
            ("https://paypal.com", False),
            ("https://paypal.com.evil-site.com", True),
            ("https://paypa1.com", True),
            ("https://paypal-login.com", True),
            ("https://paypal.com.example.test/login", True),
            ("https://google.com", False),
            ("https://g00gle.com", True),
        ]
        for url, expected_detected in cases:
            with self.subTest(url=url):
                features = analyze_url(url)
                result = check_brand_impersonation(features)
                self.assertEqual(result["detected"], expected_detected, msg=f"Failed for {url}")


    def test_paypal_subdomain_impersonation_on_test_tld(self):
        url = "https://paypal.com.example.test/login"
        features = analyze_url(url)
        self.assertEqual(features["registered_domain"], "example.test")
        self.assertEqual(features["subdomain"], "paypal.com")
        self.assertEqual(features["subdomain_count"], 2)

        result = check_brand_impersonation(features)
        self.assertTrue(result["detected"])
        self.assertIn("paypal", result["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
