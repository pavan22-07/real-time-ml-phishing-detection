"""Unit and fault-isolation tests for unified_engine contracts and adapters."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ml_engine.predict as ml_predict
import unified_engine.adapters as adapters
from unified_engine import (
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
    run_cybersecurity_adapter,
    run_engine_adapters,
    run_ml_adapter,
)


def _make_security_payload(
    *,
    url: str = "https://www.wikipedia.org/",
    decision: str = "ALLOW",
    risk_score: int = 0,
    risk_level: str = "LOW",
    inspection_status: str = "COMPLETED",
    warnings: list | None = None,
    findings: list | None = None,
) -> dict:
    return {
        "url": url,
        "features": {"redirect_analysis": {}},
        "findings": findings or [],
        "risk_assessment": {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "action": decision,
            "confirmed_threat": decision == "BLOCK",
            "findings_count": len(findings or []),
            "findings": findings or [],
            "score_breakdown": [],
            "group_scores": {},
        },
        "final_decision": {
            "decision": decision,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "confirmed_threat": decision == "BLOCK",
            "reasons": ["Test reason"],
            "findings_count": len(findings or []),
            "explanations": [],
            "inspection_warnings": warnings or [],
            "inspection_status": inspection_status,
        },
        "engine_status": inspection_status,
    }


class CybersecurityAdapterTests(unittest.TestCase):
    """Tests normalizing security_engine outputs and handling failures."""

    def test_successful_allow_result_preserves_raw_and_scale(self):
        payload = _make_security_payload(decision="ALLOW", risk_score=0)

        with patch.object(
            adapters,
            "analyze_url_security",
            return_value=payload,
        ) as mock_sec:
            result = run_cybersecurity_adapter("  https://www.wikipedia.org/  ")

        mock_sec.assert_called_once_with(
            "https://www.wikipedia.org/",
            inspect_redirects=False,
        )
        self.assertEqual(result["engine"], ENGINE_SECURITY)
        self.assertEqual(result["status"], ENGINE_STATUS_OK)
        self.assertEqual(result["verdict"], VERDICT_BENIGN)
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["risk_score"], 0.0)
        self.assertIsNone(result["raw_phishing_probability"])
        self.assertEqual(result["score_type"], SCORE_TYPE_RISK)
        self.assertEqual(result["score_scale"], SCORE_SCALE_RISK)
        self.assertFalse(result["is_calibrated"])
        self.assertEqual(result["warnings"], [])
        self.assertIsNone(result["error"])
        self.assertIs(result["raw_result"], payload)
        json.dumps(result)

    def test_successful_block_result_maps_to_malicious_and_keeps_signals(self):
        findings = [
            {
                "rule": "THREAT_INTELLIGENCE",
                "detected": True,
                "reason": "Exact URL match found in phishing feed",
                "severity": "CRITICAL",
                "confidence": 0.98,
                "evidence_group": "threat_reputation",
            }
        ]
        payload = _make_security_payload(
            url="https://phish.example.invalid/login",
            decision="BLOCK",
            risk_score=75,
            risk_level="CRITICAL",
            findings=findings,
        )

        with patch.object(adapters, "analyze_url_security", return_value=payload):
            result = run_cybersecurity_adapter("https://phish.example.invalid/login")

        self.assertEqual(result["status"], ENGINE_STATUS_OK)
        self.assertEqual(result["verdict"], VERDICT_MALICIOUS)
        self.assertEqual(result["risk_score"], 75.0)
        self.assertEqual(len(result["signals"]), 1)
        self.assertEqual(result["signals"][0]["code"], "THREAT_INTELLIGENCE")
        self.assertEqual(result["signals"][0]["severity"], "CRITICAL")

    def test_incomplete_inspection_maps_to_degraded_with_warnings(self):
        payload = _make_security_payload(
            decision="WARN",
            risk_score=4,
            inspection_status="INCOMPLETE",
            warnings=["Threat intelligence verification is incomplete"],
        )

        with patch.object(adapters, "analyze_url_security", return_value=payload):
            result = run_cybersecurity_adapter("https://www.wikipedia.org/")

        self.assertEqual(result["status"], ENGINE_STATUS_DEGRADED)
        self.assertEqual(result["verdict"], VERDICT_SUSPICIOUS)
        self.assertEqual(
            result["warnings"],
            ["Threat intelligence verification is incomplete"],
        )
        self.assertIsNone(result["error"])

    def test_cybersecurity_exception_returns_isolated_error(self):
        with patch.object(
            adapters,
            "analyze_url_security",
            side_effect=RuntimeError("Feed parser failure"),
        ):
            result = run_cybersecurity_adapter("https://www.wikipedia.org/")

        self.assertEqual(result["engine"], ENGINE_SECURITY)
        self.assertEqual(result["status"], ENGINE_STATUS_ERROR)
        self.assertEqual(result["verdict"], VERDICT_UNKNOWN)
        self.assertIsNone(result["score"])
        self.assertIsNone(result["risk_score"])
        self.assertIn("Feed parser failure", result["error"])
        self.assertTrue(result["warnings"])

    def test_tldextract_cache_env_configured_before_security_call(self):
        observed_cache = {}

        def fake_analyze(url, inspect_redirects=False):
            observed_cache["value"] = os.environ.get("TLDEXTRACT_CACHE")
            return _make_security_payload(url=url)

        with (
            patch.dict(os.environ, {}, clear=False),
            patch.object(adapters, "analyze_url_security", side_effect=fake_analyze),
        ):
            os.environ.pop("TLDEXTRACT_CACHE", None)
            run_cybersecurity_adapter("https://www.wikipedia.org/")

        self.assertTrue(observed_cache.get("value"))


class MLAdapterTests(unittest.TestCase):
    """Tests normalizing ml_engine outputs and handling errors."""

    def test_successful_legitimate_result_and_uncalibrated_contract(self):
        ml_payload = {
            "url": "https://www.wikipedia.org/",
            "prediction": "LEGITIMATE",
            "label": 0,
            "phishing_probability": 0.0467,
            "legitimate_probability": 0.9533,
            "model_name": "Random Forest",
            "model_version": "1.0.0",
            "status": "SUCCESS",
        }

        with patch.object(adapters, "predict_url", return_value=ml_payload):
            result = run_ml_adapter("https://www.wikipedia.org/")

        self.assertEqual(result["engine"], ENGINE_ML)
        self.assertEqual(result["status"], ENGINE_STATUS_OK)
        self.assertEqual(result["verdict"], VERDICT_BENIGN)
        self.assertAlmostEqual(result["score"], 0.0467, places=4)
        self.assertAlmostEqual(result["raw_phishing_probability"], 0.0467, places=4)
        self.assertIsNone(result["risk_score"])
        self.assertEqual(result["score_type"], SCORE_TYPE_ML_PROB)
        self.assertEqual(result["score_scale"], SCORE_SCALE_PROB)
        self.assertFalse(result["is_calibrated"])
        self.assertNotIn("confidence", result)
        for signal in result["signals"]:
            self.assertNotIn("confidence", signal)
        self.assertIs(result["raw_result"], ml_payload)
        json.dumps(result)

    def test_successful_phishing_result(self):
        ml_payload = {
            "url": "http://192.168.1.100/verify/paypal/login.php",
            "prediction": "PHISHING",
            "label": 1,
            "phishing_probability": 0.8123,
            "legitimate_probability": 0.1877,
            "model_name": "Random Forest",
            "model_version": "1.0.0",
            "status": "SUCCESS",
        }

        with patch.object(adapters, "predict_url", return_value=ml_payload):
            result = run_ml_adapter("http://192.168.1.100/verify/paypal/login.php")

        self.assertEqual(result["status"], ENGINE_STATUS_OK)
        self.assertEqual(result["verdict"], VERDICT_SUSPICIOUS)
        self.assertAlmostEqual(result["raw_phishing_probability"], 0.8123, places=4)
        self.assertFalse(result["is_calibrated"])
        self.assertEqual(result["signals"][0]["code"], "ML_PHISHING_PREDICTION")

    def test_ml_inference_error_payload_and_exception(self):
        error_payload = {
            "url": "https://example.com",
            "prediction": "ERROR",
            "label": None,
            "phishing_probability": None,
            "legitimate_probability": None,
            "model_name": "Random Forest",
            "model_version": "1.0.0",
            "status": "ERROR",
            "error_message": "Inference execution failed: corrupted input",
        }

        with patch.object(adapters, "predict_url", return_value=error_payload):
            res_err = run_ml_adapter("https://example.com")

        self.assertEqual(res_err["status"], ENGINE_STATUS_ERROR)
        self.assertEqual(res_err["verdict"], VERDICT_UNKNOWN)
        self.assertIsNone(res_err["raw_phishing_probability"])
        self.assertIn("corrupted input", res_err["error"])
        self.assertIs(res_err["raw_result"], error_payload)

        with patch.object(
            adapters,
            "predict_url",
            side_effect=RuntimeError("Unexpected model failure"),
        ):
            res_exc = run_ml_adapter("https://example.com")

        self.assertEqual(res_exc["status"], ENGINE_STATUS_ERROR)
        self.assertEqual(res_exc["verdict"], VERDICT_UNKNOWN)
        self.assertIn("Unexpected model failure", res_exc["error"])

    def test_missing_model_artifact_returns_error_never_benign(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            missing_path = Path(tmp_dir) / "missing_best_model.joblib"
            with (
                patch.object(ml_predict, "BEST_MODEL_PATH", missing_path),
                patch.object(ml_predict, "_CACHED_PIPELINE", None),
                patch.object(ml_predict, "_CACHED_METADATA", None),
                patch.object(ml_predict, "_CACHED_SCHEMA", None),
            ):
                result = run_ml_adapter("https://www.wikipedia.org/")

        self.assertEqual(result["status"], ENGINE_STATUS_ERROR)
        self.assertEqual(result["verdict"], VERDICT_UNKNOWN)
        self.assertNotEqual(result["verdict"], VERDICT_BENIGN)
        self.assertIsNone(result["raw_phishing_probability"])
        self.assertIn("unavailable", result["error"].lower())


class BoundaryValidationAndFaultIsolationTests(unittest.TestCase):
    """Tests invalid inputs and mutual fault isolation across both adapters."""

    def test_invalid_inputs_rejected_at_adapter_boundary(self):
        invalid_inputs = [None, "", "   ", 12345, "http://[invalid"]

        for bad_input in invalid_inputs:
            with self.subTest(bad_input=bad_input):
                with (
                    patch.object(adapters, "analyze_url_security") as mock_sec,
                    patch.object(adapters, "predict_url") as mock_ml,
                ):
                    results = run_engine_adapters(bad_input)

                mock_sec.assert_not_called()
                mock_ml.assert_not_called()

                for engine_name in (ENGINE_SECURITY, ENGINE_ML):
                    res = results[engine_name]
                    self.assertEqual(res["status"], ENGINE_STATUS_ERROR)
                    self.assertEqual(res["verdict"], VERDICT_UNKNOWN)
                    self.assertIsNone(res["score"])
                    self.assertTrue(res["error"])

    def test_cybersecurity_failure_does_not_prevent_ml_adapter(self):
        with patch.object(
            adapters,
            "analyze_url_security",
            side_effect=RuntimeError("Security engine crashed"),
        ):
            results = run_engine_adapters("https://www.wikipedia.org/")

        sec_res = results[ENGINE_SECURITY]
        ml_res = results[ENGINE_ML]

        self.assertEqual(sec_res["status"], ENGINE_STATUS_ERROR)
        self.assertEqual(sec_res["verdict"], VERDICT_UNKNOWN)

        self.assertEqual(ml_res["status"], ENGINE_STATUS_OK)
        self.assertEqual(ml_res["verdict"], VERDICT_BENIGN)
        self.assertIsNotNone(ml_res["raw_phishing_probability"])
        self.assertFalse(ml_res["is_calibrated"])

    def test_ml_failure_does_not_prevent_cybersecurity_adapter(self):
        sec_payload = _make_security_payload(
            url="https://www.wikipedia.org/",
            decision="ALLOW",
            risk_score=0,
        )

        with (
            patch.object(adapters, "analyze_url_security", return_value=sec_payload),
            patch.object(
                adapters,
                "predict_url",
                side_effect=FileNotFoundError("best_model.joblib missing"),
            ),
        ):
            results = run_engine_adapters("https://www.wikipedia.org/")

        sec_res = results[ENGINE_SECURITY]
        ml_res = results[ENGINE_ML]

        self.assertEqual(ml_res["status"], ENGINE_STATUS_ERROR)
        self.assertEqual(ml_res["verdict"], VERDICT_UNKNOWN)

        self.assertEqual(sec_res["status"], ENGINE_STATUS_OK)
        self.assertEqual(sec_res["verdict"], VERDICT_BENIGN)
        self.assertEqual(sec_res["risk_score"], 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
