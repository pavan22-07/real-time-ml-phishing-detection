"""
Unit tests for URL Feature Extraction.
"""

import unittest
from ml_engine.feature_extraction import (
    extract_features_from_url,
    calculate_entropy,
    FEATURE_NAMES,
    get_default_feature_vector
)


class FeatureExtractionTests(unittest.TestCase):

    def test_feature_names_count_and_completeness(self):
        """Verify feature count matches default schema."""
        default_vector = get_default_feature_vector()
        self.assertEqual(len(FEATURE_NAMES), len(default_vector))
        self.assertEqual(len(FEATURE_NAMES), 33)

    def test_normal_https_url(self):
        """Test standard HTTPS URL feature extraction."""
        feats = extract_features_from_url("https://www.google.com/search?q=cybersecurity")
        self.assertEqual(feats["is_https"], 1)
        self.assertEqual(feats["is_ip"], 0)
        self.assertEqual(feats["subdom_cnt"], 1)  # 'www'
        self.assertEqual(feats["dom_len"], 6)     # 'google'
        self.assertEqual(feats["query_param_cnt"], 1)
        self.assertGreater(feats["url_len"], 20)

    def test_http_url(self):
        """Test standard HTTP URL feature extraction."""
        feats = extract_features_from_url("http://example.com/index.html")
        self.assertEqual(feats["is_https"], 0)
        self.assertEqual(feats["is_ip"], 0)
        self.assertEqual(feats["dom_len"], 7)  # 'example'

    def test_ip_based_url(self):
        """Test IP address detection in URL."""
        feats_v4 = extract_features_from_url("http://192.168.1.100/admin/login")
        self.assertEqual(feats_v4["is_ip"], 1)
        feats_v6 = extract_features_from_url("http://[2001:db8::1]:8080/path")
        self.assertEqual(feats_v6["is_ip"], 1)

    def test_unicode_and_punycode_hostname(self):
        """Test Punycode and IDN hostname indicators."""
        puny_feats = extract_features_from_url("http://xn--pple-43d.com/login")
        self.assertEqual(puny_feats["has_punycode"], 1)
        normal_feats = extract_features_from_url("https://apple.com/login")
        self.assertEqual(normal_feats["has_punycode"], 0)

    def test_url_containing_at_symbol(self):
        """Test detection of @ symbol in URL credentials or path."""
        feats = extract_features_from_url("http://admin:secret@malicious-site.com/login")
        self.assertEqual(feats["has_at"], 1)
        self.assertEqual(feats["has_credentials"], 1)

    def test_url_encoding(self):
        """Test URL encoding count and valid percent detection."""
        feats = extract_features_from_url("https://example.com/path%20with%20spaces%21")
        self.assertEqual(feats["url_encoding_cnt"], 3)
        self.assertEqual(feats["has_malformed_encoding"], 0)

    def test_nested_encoding(self):
        """Test nested %25 encoding detection."""
        feats = extract_features_from_url("http://example.com/%2520nested%252Fpath")
        self.assertEqual(feats["has_nested_encoding"], 1)

    def test_malformed_encoding(self):
        """Test malformed percent encoding detection."""
        feats = extract_features_from_url("http://example.com/bad%zz%2")
        self.assertEqual(feats["has_malformed_encoding"], 1)

    def test_long_url_and_many_query_params(self):
        """Test long URL and query parameter counting."""
        long_url = "https://example.com/path?" + "&".join(f"param{i}=val{i}" for i in range(25))
        feats = extract_features_from_url(long_url)
        self.assertGreater(feats["url_len"], 200)
        self.assertEqual(feats["query_param_cnt"], 25)

    def test_empty_and_invalid_input(self):
        """Test empty string and None handling."""
        empty_feats = extract_features_from_url("")
        self.assertEqual(empty_feats["url_len"], 0)
        self.assertEqual(empty_feats["overall_entropy"], 0.0)

        none_feats = extract_features_from_url(None)
        self.assertEqual(none_feats["url_len"], 0)

    def test_localhost(self):
        """Test localhost URL parsing."""
        feats = extract_features_from_url("http://localhost:8000/dashboard")
        self.assertEqual(feats["hostname_len"], 9)
        self.assertEqual(feats["is_ip"], 0)

    def test_entropy_calculation(self):
        """Test Shannon entropy calculation consistency."""
        entropy_low = calculate_entropy("aaaaaaa")
        self.assertEqual(entropy_low, 0.0)
        entropy_high = calculate_entropy("abcdefghijklmnopqrstuvwxyz0123456789")
        self.assertGreater(entropy_high, 4.0)


if __name__ == "__main__":
    unittest.main()
