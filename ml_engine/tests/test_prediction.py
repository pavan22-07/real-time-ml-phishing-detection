"""
Unit tests for Real-Time URL Prediction.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import ml_engine.predict as predict_module
from ml_engine.predict import predict_url
from ml_engine.config import BEST_MODEL_PATH


class PredictionTests(unittest.TestCase):

    def test_response_structure_keys(self):
        """Verify response contains all contract keys."""
        res = predict_url("https://www.google.com")
        expected_keys = {
            "url", "prediction", "label",
            "phishing_probability", "legitimate_probability",
            "model_name", "model_version", "status"
        }
        self.assertTrue(expected_keys.issubset(res.keys()))
        self.assertEqual(res["status"], "SUCCESS")

    def test_probability_ranges_and_sum(self):
        """Verify probability values are within [0.0, 1.0] and sum to 1.0."""
        res = predict_url("https://www.github.com")
        p_phish = res["phishing_probability"]
        p_legit = res["legitimate_probability"]

        self.assertGreaterEqual(p_phish, 0.0)
        self.assertLessEqual(p_phish, 1.0)
        self.assertGreaterEqual(p_legit, 0.0)
        self.assertLessEqual(p_legit, 1.0)
        self.assertAlmostEqual(p_phish + p_legit, 1.0, places=3)

    def test_legitimate_url_prediction(self):
        """Verify typical high-reputation domain predicts LEGITIMATE."""
        res = predict_url("https://www.wikipedia.org/")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["prediction"], "LEGITIMATE")
        self.assertEqual(res["label"], 0)
        self.assertGreater(res["legitimate_probability"], 0.70)

    def test_phishing_url_prediction(self):
        """Verify known phishing-style URL predicts PHISHING (label=1)."""
        res = predict_url("https://pay.pagcorefeiraosetembro.site/2wq7Gr7zmL8gBAN?utm_source=organic&amp;utm_campaign=")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["prediction"], "PHISHING")
        self.assertEqual(res["label"], 1)
        self.assertGreater(res["phishing_probability"], 0.50)

    def test_empty_string_input(self):
        """Verify empty string returns clean ERROR status."""
        res = predict_url("")
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["prediction"], "ERROR")
        self.assertIn("error_message", res)

    def test_none_input(self):
        """Verify None returns clean ERROR status."""
        res = predict_url(None)
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["prediction"], "ERROR")
        self.assertIn("error_message", res)

    def test_whitespace_input(self):
        """Verify whitespace returns clean ERROR status."""
        res = predict_url("    \n\t  ")
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["prediction"], "ERROR")

    def test_missing_model_artifact_returns_error(self):
        """Verify missing model artifact returns structured ERROR and never classifies as LEGITIMATE."""
        orig_cache = (
            predict_module._CACHED_PIPELINE,
            predict_module._CACHED_METADATA,
            predict_module._CACHED_SCHEMA,
        )
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                missing_model_path = Path(tmp_dir) / "nonexistent_best_model.joblib"
                predict_module._CACHED_PIPELINE = None
                predict_module._CACHED_METADATA = None
                predict_module._CACHED_SCHEMA = None

                with patch.object(predict_module, "BEST_MODEL_PATH", missing_model_path):
                    res = predict_url("https://www.google.com")

                self.assertEqual(res["status"], "ERROR")
                self.assertEqual(res["prediction"], "ERROR")
                self.assertNotEqual(res["prediction"], "LEGITIMATE")
                self.assertIsNone(res["label"])
                self.assertIsNone(res["phishing_probability"])
                self.assertIsNone(res["legitimate_probability"])
                self.assertIn("unavailable", res["error_message"].lower())
        finally:
            (
                predict_module._CACHED_PIPELINE,
                predict_module._CACHED_METADATA,
                predict_module._CACHED_SCHEMA,
            ) = orig_cache

    def test_unexpected_prediction_error_returns_error(self):
        """Verify inference runtime exceptions return structured ERROR with no fabricated output."""
        broken_pipeline = MagicMock()
        broken_pipeline.classes_ = [0, 1]
        broken_pipeline.predict_proba.side_effect = RuntimeError("Simulated inference crash")
        mock_meta = {"model_name": "Random Forest", "model_version": "1.0.0"}

        with patch.object(predict_module, "get_model", return_value=(broken_pipeline, mock_meta, [])):
            res = predict_url("https://example.com")

        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["prediction"], "ERROR")
        self.assertIsNone(res["label"])
        self.assertIsNone(res["phishing_probability"])
        self.assertIn("simulated inference crash", res["error_message"].lower())

    def test_reversed_class_ordering(self):
        """Verify that when classes_ is [1, 0], columns are correctly mapped."""
        mock_pipeline = MagicMock()
        mock_pipeline.classes_ = [1, 0]
        # P(1)=0.85, P(0)=0.15
        mock_pipeline.predict_proba.return_value = [[0.85, 0.15]]
        mock_pipeline.predict.return_value = [1]
        mock_meta = {"model_name": "Random Forest", "model_version": "1.0.0"}

        with patch.object(predict_module, "get_model", return_value=(mock_pipeline, mock_meta, [])):
            res = predict_url("https://example.com")

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["prediction"], "PHISHING")
        self.assertEqual(res["phishing_probability"], 0.85)
        self.assertEqual(res["legitimate_probability"], 0.15)
        self.assertFalse(res["is_calibrated"])

    def test_missing_class_in_classes_attribute(self):
        """Verify that missing binary classes raises structured error."""
        mock_pipeline = MagicMock()
        mock_pipeline.classes_ = [0]
        mock_pipeline.predict_proba.return_value = [[1.0]]
        mock_meta = {"model_name": "Random Forest", "model_version": "1.0.0"}

        with patch.object(predict_module, "get_model", return_value=(mock_pipeline, mock_meta, [])):
            res = predict_url("https://example.com")

        self.assertEqual(res["status"], "ERROR")
        self.assertIn("classes_", res["error_message"].lower())

    def test_invalid_probability_sum_error(self):
        """Verify that probabilities not summing to ~1.0 returns ERROR."""
        mock_pipeline = MagicMock()
        mock_pipeline.classes_ = [0, 1]
        mock_pipeline.predict_proba.return_value = [[0.2, 0.2]]
        mock_pipeline.predict.return_value = [0]
        mock_meta = {"model_name": "Random Forest", "model_version": "1.0.0"}

        with patch.object(predict_module, "get_model", return_value=(mock_pipeline, mock_meta, [])):
            res = predict_url("https://example.com")

        self.assertEqual(res["status"], "ERROR")
        self.assertIn("sum", res["error_message"].lower())


if __name__ == "__main__":
    unittest.main()
