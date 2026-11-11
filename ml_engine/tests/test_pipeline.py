"""
Unit tests for Pipeline Integration Interface.
"""

import unittest
from ml_engine.pipeline import MLInferencePipeline, ml_pipeline


class PipelineIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.pipeline = MLInferencePipeline(preload=True)

    def test_pipeline_single_prediction(self):
        """Verify pipeline.predict returns expected structure."""
        result = self.pipeline.predict("https://example.com")
        self.assertEqual(result["status"], "SUCCESS")
        self.assertIn("phishing_probability", result)
        self.assertIn("legitimate_probability", result)

    def test_pipeline_batch_prediction(self):
        """Verify batch prediction returns list of structured responses."""
        urls = ["https://google.com", "https://github.com", "http://suspicious-verify.xyz"]
        results = self.pipeline.predict_batch(urls)
        self.assertEqual(len(results), 3)
        for r in results:
            self.assertEqual(r["status"], "SUCCESS")

    def test_pipeline_batch_invalid_input(self):
        """Verify batch prediction gracefully handles non-list or empty input."""
        self.assertEqual(self.pipeline.predict_batch([]), [])
        self.assertEqual(self.pipeline.predict_batch(None), [])

    def test_pipeline_metadata(self):
        """Verify get_metadata returns model and feature info."""
        meta = self.pipeline.get_metadata()
        self.assertIn("model_name", meta)
        self.assertIn("feature_count", meta)
        self.assertEqual(meta["feature_count"], 33)

    def test_combined_response_formatting(self):
        """Verify combined response helper produces clean composite contract."""
        ml_resp = {
            "url": "https://example.com",
            "prediction": "LEGITIMATE",
            "label": 0,
            "phishing_probability": 0.05,
            "legitimate_probability": 0.95,
            "model_name": "Random Forest",
            "model_version": "1.0.0",
            "status": "SUCCESS"
        }
        sec_resp = {
            "risk_score": 5,
            "risk_level": "LOW",
            "decision": "ALLOW"
        }
        combined = self.pipeline.format_combined_response(
            cybersecurity_output=sec_resp,
            ml_output=ml_resp,
            proposed_action="ALLOW"
        )
        self.assertEqual(combined["url"], "https://example.com")
        self.assertEqual(combined["ml_engine"]["prediction"], "LEGITIMATE")
        self.assertEqual(combined["cybersecurity_engine"]["decision"], "ALLOW")
        self.assertEqual(combined["combined_layer"]["decision"], "ALLOW")

    def test_error_isolation_no_fabricated_output(self):
        """Verify errors in one module do not silently fabricate results."""
        invalid_res = self.pipeline.predict("")
        self.assertEqual(invalid_res["status"], "ERROR")
        self.assertIsNone(invalid_res["phishing_probability"])
        self.assertIsNone(invalid_res["legitimate_probability"])


if __name__ == "__main__":
    unittest.main()
