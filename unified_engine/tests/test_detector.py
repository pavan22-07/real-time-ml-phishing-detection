"""Integration tests for unified_engine.detector.scan_url."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import ml_engine.predict as ml_predict
import unified_engine.adapters as adapters
from unified_engine.contracts import ENGINE_ML, ENGINE_SECURITY
from unified_engine.detector import scan_url


def _raw_sec(
    *,
    url="https://www.wikipedia.org/",
    decision="ALLOW",
    risk_score=0,
    risk_level="LOW",
    inspection_status="COMPLETED",
    warnings=None,
    findings=None,
):
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
            "reasons": [f"Decision={decision}"],
            "findings_count": len(findings or []),
            "explanations": [],
            "inspection_warnings": warnings or [],
            "inspection_status": inspection_status,
        },
        "engine_status": inspection_status,
    }


def _raw_ml(
    *,
    url="https://www.wikipedia.org/",
    prediction="LEGITIMATE",
    label=0,
    phishing_probability=0.04,
    status="SUCCESS",
    error_message=None,
):
    payload = {
        "url": url,
        "prediction": prediction,
        "label": label,
        "phishing_probability": phishing_probability,
        "legitimate_probability": (
            round(1.0 - phishing_probability, 4)
            if phishing_probability is not None
            else None
        ),
        "model_name": "Random Forest",
        "model_version": "1.0.0",
        "status": status,
    }
    if error_message is not None:
        payload["error_message"] = error_message
    return payload


class UnifiedDetectorTests(unittest.TestCase):
    """End-to-end tests for scan_url(url, inspect_redirects=False)."""

    def test_both_benign_returns_allow_raw_outputs_and_utc_timestamp(self):
        sec_raw = _raw_sec(decision="ALLOW", risk_score=0)
        ml_raw = _raw_ml(prediction="LEGITIMATE", label=0, phishing_probability=0.04)

        with (
            patch.object(adapters, "analyze_url_security", return_value=sec_raw) as mock_sec,
            patch.object(adapters, "predict_url", return_value=ml_raw) as mock_ml,
        ):
            result = scan_url("  https://www.wikipedia.org/  ")

        mock_sec.assert_called_once_with(
            "https://www.wikipedia.org/",
            inspect_redirects=False,
        )
        mock_ml.assert_called_once_with("https://www.wikipedia.org/")

        self.assertEqual(result["url"], "https://www.wikipedia.org/")
        self.assertEqual(result["final_decision"], "ALLOW")
        self.assertFalse(result["degraded_mode"])
        self.assertFalse(result["inspect_redirects"])
        self.assertEqual(
            result["engine_statuses"],
            {ENGINE_SECURITY: "OK", ENGINE_ML: "OK"},
        )
        self.assertIs(result["engines"][ENGINE_SECURITY]["raw_result"], sec_raw)
        self.assertIs(result["engines"][ENGINE_ML]["raw_result"], ml_raw)
        self.assertFalse(result["engines"][ENGINE_ML]["is_calibrated"])

        parsed_ts = datetime.fromisoformat(result["timestamp"])
        self.assertEqual(parsed_ts.tzinfo, timezone.utc)
        json.dumps(result)

    def test_both_suspicious_returns_warn(self):
        sec_raw = _raw_sec(decision="WARN", risk_score=25, risk_level="MEDIUM")
        ml_raw = _raw_ml(prediction="PHISHING", label=1, phishing_probability=0.88)

        with (
            patch.object(adapters, "analyze_url_security", return_value=sec_raw),
            patch.object(adapters, "predict_url", return_value=ml_raw),
        ):
            result = scan_url("https://paypal-login-check.example/auth")

        self.assertEqual(result["final_decision"], "WARN")
        self.assertFalse(result["degraded_mode"])

    def test_cybersecurity_block_with_ml_benign_returns_block(self):
        sec_raw = _raw_sec(decision="BLOCK", risk_score=75, risk_level="CRITICAL")
        ml_raw = _raw_ml(prediction="LEGITIMATE", label=0, phishing_probability=0.05)

        with (
            patch.object(adapters, "analyze_url_security", return_value=sec_raw),
            patch.object(adapters, "predict_url", return_value=ml_raw),
        ):
            result = scan_url("https://known-phish.example/login")

        self.assertEqual(result["final_decision"], "BLOCK")
        self.assertFalse(result["degraded_mode"])

    def test_cybersecurity_block_with_ml_error_returns_block_and_degraded(self):
        sec_raw = _raw_sec(decision="BLOCK", risk_score=80, risk_level="CRITICAL")
        ml_raw = _raw_ml(
            prediction="ERROR",
            label=None,
            phishing_probability=None,
            status="ERROR",
            error_message="Model artifact missing",
        )

        with (
            patch.object(adapters, "analyze_url_security", return_value=sec_raw),
            patch.object(adapters, "predict_url", return_value=ml_raw),
        ):
            result = scan_url("https://known-phish.example/login")

        self.assertEqual(result["final_decision"], "BLOCK")
        self.assertTrue(result["degraded_mode"])
        self.assertEqual(result["engine_statuses"][ENGINE_ML], "ERROR")
        self.assertEqual(result["errors"][ENGINE_ML], "Model artifact missing")

    def test_cybersecurity_warn_with_ml_benign_returns_warn(self):
        sec_raw = _raw_sec(decision="WARN", risk_score=4)
        ml_raw = _raw_ml(prediction="LEGITIMATE", label=0, phishing_probability=0.4285)

        with (
            patch.object(adapters, "analyze_url_security", return_value=sec_raw),
            patch.object(adapters, "predict_url", return_value=ml_raw),
        ):
            result = scan_url(
                "http://secure-login.bank-update.account-verification.xyz/login.php?user=admin&token=123"
            )

        self.assertEqual(result["final_decision"], "WARN")
        self.assertFalse(result["degraded_mode"])

    def test_cybersecurity_allow_with_ml_phishing_returns_warn(self):
        sec_raw = _raw_sec(decision="ALLOW", risk_score=0)
        ml_raw = _raw_ml(prediction="PHISHING", label=1, phishing_probability=0.96)

        with (
            patch.object(adapters, "analyze_url_security", return_value=sec_raw),
            patch.object(adapters, "predict_url", return_value=ml_raw),
        ):
            result = scan_url("https://novel-phish.example/step1")

        self.assertEqual(result["final_decision"], "WARN")
        self.assertFalse(result["degraded_mode"])

    def test_cybersecurity_incomplete_with_ml_benign_returns_warn_degraded(self):
        sec_raw = _raw_sec(
            decision="WARN",
            risk_score=0,
            inspection_status="INCOMPLETE",
            warnings=["Threat intelligence verification is incomplete"],
        )
        ml_raw = _raw_ml(prediction="LEGITIMATE", label=0, phishing_probability=0.03)

        with (
            patch.object(adapters, "analyze_url_security", return_value=sec_raw),
            patch.object(adapters, "predict_url", return_value=ml_raw),
        ):
            result = scan_url("https://www.wikipedia.org/")

        self.assertEqual(result["final_decision"], "WARN")
        self.assertTrue(result["degraded_mode"])
        self.assertEqual(result["engine_statuses"][ENGINE_SECURITY], "DEGRADED")
        self.assertIn("Threat intelligence verification is incomplete", result["warnings"])

    def test_cybersecurity_exception_still_runs_ml_and_returns_warn(self):
        ml_raw = _raw_ml(prediction="LEGITIMATE", label=0, phishing_probability=0.03)

        with (
            patch.object(
                adapters,
                "analyze_url_security",
                side_effect=RuntimeError("Security failure"),
            ),
            patch.object(adapters, "predict_url", return_value=ml_raw) as mock_ml,
        ):
            result = scan_url("https://www.wikipedia.org/")

        mock_ml.assert_called_once_with("https://www.wikipedia.org/")
        self.assertEqual(result["final_decision"], "WARN")
        self.assertTrue(result["degraded_mode"])
        self.assertEqual(result["engine_statuses"][ENGINE_SECURITY], "ERROR")
        self.assertEqual(result["engine_statuses"][ENGINE_ML], "OK")
        self.assertIn("Security failure", result["errors"][ENGINE_SECURITY])

    def test_ml_missing_model_with_cybersecurity_allow_returns_warn(self):
        sec_raw = _raw_sec(decision="ALLOW", risk_score=0)

        with tempfile.TemporaryDirectory() as tmp_dir:
            missing_path = Path(tmp_dir) / "missing_model.joblib"
            with (
                patch.object(adapters, "analyze_url_security", return_value=sec_raw),
                patch.object(ml_predict, "BEST_MODEL_PATH", missing_path),
                patch.object(ml_predict, "_CACHED_PIPELINE", None),
                patch.object(ml_predict, "_CACHED_METADATA", None),
                patch.object(ml_predict, "_CACHED_SCHEMA", None),
            ):
                result = scan_url("https://www.wikipedia.org/")

        self.assertEqual(result["final_decision"], "WARN")
        self.assertTrue(result["degraded_mode"])
        self.assertEqual(result["engine_statuses"][ENGINE_SECURITY], "OK")
        self.assertEqual(result["engine_statuses"][ENGINE_ML], "ERROR")

    def test_both_engines_unavailable_returns_error(self):
        with (
            patch.object(
                adapters,
                "analyze_url_security",
                side_effect=RuntimeError("Security down"),
            ),
            patch.object(
                adapters,
                "predict_url",
                side_effect=RuntimeError("ML down"),
            ),
        ):
            result = scan_url("https://www.wikipedia.org/")

        self.assertEqual(result["final_decision"], "ERROR")
        self.assertTrue(result["degraded_mode"])
        self.assertEqual(
            result["engine_statuses"],
            {ENGINE_SECURITY: "ERROR", ENGINE_ML: "ERROR"},
        )
        self.assertIn("Security down", result["errors"][ENGINE_SECURITY])
        self.assertIn("ML down", result["errors"][ENGINE_ML])

    def test_invalid_inputs_return_error_without_invoking_engines(self):
        for bad_url in (None, "", "   ", 42, "http://[invalid"):
            with self.subTest(bad_url=bad_url):
                with (
                    patch.object(adapters, "analyze_url_security") as mock_sec,
                    patch.object(adapters, "predict_url") as mock_ml,
                ):
                    result = scan_url(bad_url)

                mock_sec.assert_not_called()
                mock_ml.assert_not_called()
                self.assertEqual(result["final_decision"], "ERROR")
                self.assertTrue(result["degraded_mode"])
                self.assertEqual(
                    result["engine_statuses"],
                    {ENGINE_SECURITY: "ERROR", ENGINE_ML: "ERROR"},
                )

    def test_inspect_redirects_true_is_forwarded_when_requested(self):
        sec_raw = _raw_sec(decision="ALLOW", risk_score=0)
        ml_raw = _raw_ml(prediction="LEGITIMATE", label=0, phishing_probability=0.04)

        with (
            patch.object(adapters, "analyze_url_security", return_value=sec_raw) as mock_sec,
            patch.object(adapters, "predict_url", return_value=ml_raw),
        ):
            result = scan_url("https://www.wikipedia.org/", inspect_redirects=True)

        mock_sec.assert_called_once_with(
            "https://www.wikipedia.org/",
            inspect_redirects=True,
        )
        self.assertTrue(result["inspect_redirects"])
        self.assertEqual(result["final_decision"], "ALLOW")


if __name__ == "__main__":
    unittest.main(verbosity=2)
