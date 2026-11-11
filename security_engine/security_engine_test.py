import unittest
from unittest.mock import patch

if __package__:
    from . import security_engine
else:
    import security_engine


FRESH_CLEAN_THREAT_INTEL = {
    "available": True,
    "feed_status": "FRESH",
    "matched": False,
    "match_type": None,
    "matched_indicator": None,
    "source": "OpenPhish Community",
    "reason": "No matching indicator found in local feed",
}


class SecurityEngineWrapperTests(unittest.TestCase):
    """Deterministic unit tests for security_engine.analyze_url_security."""

    def test_benign_url_allows_and_initializes_empty_redirect_analysis(self):
        with (
            patch.object(
                security_engine,
                "check_threat_intelligence",
                return_value=dict(FRESH_CLEAN_THREAT_INTEL),
            ) as mock_intel,
            patch.object(security_engine, "analyze_redirects") as mock_redirects,
        ):
            result = security_engine.analyze_url_security(
                "https://www.wikipedia.org/",
                inspect_redirects=False,
            )

        mock_intel.assert_called_once_with("https://www.wikipedia.org/")
        mock_redirects.assert_not_called()

        self.assertEqual(
            set(result.keys()),
            {
                "url",
                "features",
                "findings",
                "risk_assessment",
                "final_decision",
                "engine_status",
            },
        )
        self.assertEqual(result["url"], "https://www.wikipedia.org/")
        self.assertEqual(result["features"]["redirect_analysis"], {})
        self.assertEqual(result["final_decision"]["decision"], "ALLOW")
        self.assertEqual(result["engine_status"], "COMPLETED")

    def test_fresh_threat_intel_match_blocks_url(self):
        matched_intel = {
            "available": True,
            "feed_status": "FRESH",
            "matched": True,
            "match_type": "EXACT_URL",
            "matched_indicator": "https://login-check.example.invalid/auth",
            "source": "OpenPhish Community",
            "reason": "Exact URL match found in phishing feed",
        }

        with (
            patch.object(
                security_engine,
                "check_threat_intelligence",
                return_value=matched_intel,
            ),
            patch.object(security_engine, "analyze_redirects") as mock_redirects,
        ):
            result = security_engine.analyze_url_security(
                "https://login-check.example.invalid/auth"
            )

        mock_redirects.assert_not_called()
        self.assertEqual(result["features"]["redirect_analysis"], {})
        self.assertTrue(result["risk_assessment"]["confirmed_threat"])
        self.assertEqual(result["final_decision"]["decision"], "BLOCK")
        self.assertEqual(result["engine_status"], "COMPLETED")

    def test_unavailable_threat_intel_marks_engine_incomplete(self):
        unavailable_intel = {
            "available": False,
            "feed_status": "UNAVAILABLE",
            "matched": False,
            "match_type": None,
            "matched_indicator": None,
            "source": "OpenPhish Community",
            "reason": "Local threat intelligence feed unavailable",
        }

        with patch.object(
            security_engine,
            "check_threat_intelligence",
            return_value=unavailable_intel,
        ):
            result = security_engine.analyze_url_security(
                "https://www.wikipedia.org/",
                inspect_redirects=False,
            )

        self.assertEqual(result["final_decision"]["decision"], "WARN")
        self.assertEqual(result["engine_status"], "INCOMPLETE")
        self.assertEqual(result["final_decision"]["inspection_status"], "INCOMPLETE")

    def test_brand_impersonation_runs_full_assessment_pipeline(self):
        with patch.object(
            security_engine,
            "check_threat_intelligence",
            return_value=dict(FRESH_CLEAN_THREAT_INTEL),
        ):
            result = security_engine.analyze_url_security(
                "https://paypal.com.evil-site.com/login",
                inspect_redirects=False,
            )

        detected_rules = {
            finding["rule"]
            for finding in result["findings"]
            if finding.get("detected")
        }
        self.assertIn("BRAND_IMPERSONATION", detected_rules)
        self.assertGreater(result["risk_assessment"]["risk_score"], 0)
        self.assertIn(result["final_decision"]["decision"], {"WARN", "BLOCK"})
        self.assertEqual(result["engine_status"], "COMPLETED")

    def test_redirect_inspection_enabled_detects_https_downgrade(self):
        redirect_payload = {
            "original_url": "https://example.com/",
            "final_url": "http://example.com/landing",
            "redirect_count": 1,
            "has_redirects": True,
            "redirect_chain": [],
            "loop_detected": False,
            "https_downgrade": True,
            "external_redirects": [],
            "final_status_code": 200,
            "error": None,
            "stop_reason": "Final destination reached",
        }

        with (
            patch.object(
                security_engine,
                "check_threat_intelligence",
                return_value=dict(FRESH_CLEAN_THREAT_INTEL),
            ),
            patch.object(
                security_engine,
                "analyze_redirects",
                return_value=redirect_payload,
            ) as mock_redirects,
        ):
            result = security_engine.analyze_url_security(
                "https://example.com/",
                inspect_redirects=True,
            )

        mock_redirects.assert_called_once_with("https://example.com/")
        self.assertEqual(result["features"]["redirect_analysis"], redirect_payload)
        detected_rules = {
            finding["rule"]
            for finding in result["findings"]
            if finding.get("detected")
        }
        self.assertIn("REDIRECT_ANALYSIS", detected_rules)
        self.assertEqual(result["final_decision"]["decision"], "WARN")
        self.assertEqual(result["engine_status"], "COMPLETED")

    def test_redirect_inspection_error_marks_engine_incomplete(self):
        redirect_error_payload = {
            "original_url": "https://example.com/",
            "final_url": None,
            "redirect_count": 0,
            "has_redirects": False,
            "redirect_chain": [],
            "loop_detected": False,
            "https_downgrade": False,
            "external_redirects": [],
            "final_status_code": None,
            "error": "DNS resolution failed",
            "stop_reason": "Destination rejected",
        }

        with (
            patch.object(
                security_engine,
                "check_threat_intelligence",
                return_value=dict(FRESH_CLEAN_THREAT_INTEL),
            ),
            patch.object(
                security_engine,
                "analyze_redirects",
                return_value=redirect_error_payload,
            ) as mock_redirects,
        ):
            result = security_engine.analyze_url_security(
                "https://example.com/",
                inspect_redirects=True,
            )

        mock_redirects.assert_called_once_with("https://example.com/")
        self.assertEqual(result["final_decision"]["decision"], "WARN")
        self.assertEqual(result["engine_status"], "INCOMPLETE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
