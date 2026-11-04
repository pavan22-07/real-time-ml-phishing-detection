
import unittest
from url_analyzer import analyze_url


class URLCredentialTests(unittest.TestCase):

    def test_at_symbol_in_credentials(self):
        result = analyze_url(
            "https://example.com@evil-site.com/login"
        )
        self.assertTrue(result["has_url_credentials"])

    def test_at_symbol_in_path(self):
        result = analyze_url(
            "https://example.com/path@home"
        )
        self.assertFalse(result["has_url_credentials"])

    def test_at_symbol_in_query(self):
        result = analyze_url(
            "https://example.com/search?q=user@home"
        )
        self.assertFalse(result["has_url_credentials"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
