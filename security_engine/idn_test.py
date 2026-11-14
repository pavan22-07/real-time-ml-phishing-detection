import unittest

if __package__:
    from .url_analyzer import analyze_url
    from .rule_engine import check_idn_homograph, run_security_rules
else:
    from url_analyzer import analyze_url
    from rule_engine import check_idn_homograph, run_security_rules


class IDNHomographTests(unittest.TestCase):
    def test_idn_homograph_cases(self):
        # Lookalike domains should be detected
        cyrillic_paypal = analyze_url("https://раypal.com")
        self.assertTrue(check_idn_homograph(cyrillic_paypal)["detected"])

        cyrillic_google = analyze_url("https://gооgle.com")
        self.assertTrue(check_idn_homograph(cyrillic_google)["detected"])

        punycode_paypal = analyze_url("https://xn--ypal-43d9g.com")
        self.assertTrue(check_idn_homograph(punycode_paypal)["detected"])

        # Legitimate ASCII domains should not trigger IDN homograph finding
        legit_paypal = analyze_url("https://paypal.com")
        self.assertFalse(check_idn_homograph(legit_paypal)["detected"])

        legit_google = analyze_url("https://google.com")
        self.assertFalse(check_idn_homograph(legit_google)["detected"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
