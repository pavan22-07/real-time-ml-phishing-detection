"""Unit tests for unified_engine.policy.evaluate_combined_policy."""

import unittest

from unified_engine.contracts import (
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
    build_engine_result,
)
from unified_engine.policy import evaluate_combined_policy


def _sec_result(
    *,
    status=ENGINE_STATUS_OK,
    verdict=VERDICT_BENIGN,
    risk_score=0.0,
    warnings=None,
    error=None,
    signals=None,
    raw_decision=None,
):
    raw_result = None
    if raw_decision is not None:
        raw_result = {
            "final_decision": {
                "decision": raw_decision,
                "reasons": [f"Cybersecurity decision: {raw_decision}"],
                "inspection_warnings": list(warnings or []),
            }
        }
    return build_engine_result(
        engine=ENGINE_SECURITY,
        url="https://example.com",
        status=status,
        verdict=verdict,
        score=risk_score if status != ENGINE_STATUS_ERROR else None,
        score_type=SCORE_TYPE_RISK,
        score_scale=SCORE_SCALE_RISK,
        is_calibrated=False,
        risk_score=risk_score if status != ENGINE_STATUS_ERROR else None,
        raw_phishing_probability=None,
        signals=signals or [],
        warnings=warnings or [],
        error=error,
        raw_result=raw_result,
    )


def _ml_result(
    *,
    status=ENGINE_STATUS_OK,
    verdict=VERDICT_BENIGN,
    prob=0.05,
    warnings=None,
    error=None,
    signals=None,
):
    return build_engine_result(
        engine=ENGINE_ML,
        url="https://example.com",
        status=status,
        verdict=verdict,
        score=prob if status != ENGINE_STATUS_ERROR else None,
        score_type=SCORE_TYPE_ML_PROB,
        score_scale=SCORE_SCALE_PROB,
        is_calibrated=False,
        risk_score=None,
        raw_phishing_probability=prob if status != ENGINE_STATUS_ERROR else None,
        signals=signals or [],
        warnings=warnings or [],
        error=error,
        raw_result=None,
    )


class CombinedPolicyTests(unittest.TestCase):
    """Verify all decision table branches and fail-safe invariants."""

    def test_both_benign_healthy_allows(self):
        outcome = evaluate_combined_policy(
            _sec_result(status=ENGINE_STATUS_OK, verdict=VERDICT_BENIGN, risk_score=0.0, raw_decision="ALLOW"),
            _ml_result(status=ENGINE_STATUS_OK, verdict=VERDICT_BENIGN, prob=0.02),
        )
        self.assertEqual(outcome["final_decision"], "ALLOW")
        self.assertFalse(outcome["degraded_mode"])
        self.assertEqual(outcome["warnings"], [])
        self.assertEqual(outcome["errors"], {ENGINE_SECURITY: None, ENGINE_ML: None})
        self.assertTrue(outcome["reasons"])

    def test_both_suspicious_warns_without_inventing_block(self):
        outcome = evaluate_combined_policy(
            _sec_result(
                status=ENGINE_STATUS_OK,
                verdict=VERDICT_SUSPICIOUS,
                risk_score=25.0,
                raw_decision="WARN",
                signals=[{"code": "BRAND_IMPERSONATION", "severity": "HIGH", "reason": "Brand match"}],
            ),
            _ml_result(status=ENGINE_STATUS_OK, verdict=VERDICT_SUSPICIOUS, prob=0.95),
        )
        self.assertEqual(outcome["final_decision"], "WARN")
        self.assertFalse(outcome["degraded_mode"])
        self.assertIn("Brand match", outcome["reasons"])

    def test_cybersecurity_block_with_ml_benign_blocks(self):
        outcome = evaluate_combined_policy(
            _sec_result(status=ENGINE_STATUS_OK, verdict=VERDICT_MALICIOUS, risk_score=80.0, raw_decision="BLOCK"),
            _ml_result(status=ENGINE_STATUS_OK, verdict=VERDICT_BENIGN, prob=0.01),
        )
        self.assertEqual(outcome["final_decision"], "BLOCK")
        self.assertFalse(outcome["degraded_mode"])

    def test_cybersecurity_block_with_ml_error_blocks_in_degraded_mode(self):
        outcome = evaluate_combined_policy(
            _sec_result(status=ENGINE_STATUS_OK, verdict=VERDICT_MALICIOUS, risk_score=75.0, raw_decision="BLOCK"),
            _ml_result(
                status=ENGINE_STATUS_ERROR,
                verdict=VERDICT_UNKNOWN,
                error="Model missing",
                warnings=["ML prediction unavailable."],
            ),
        )
        self.assertEqual(outcome["final_decision"], "BLOCK")
        self.assertTrue(outcome["degraded_mode"])
        self.assertEqual(outcome["errors"][ENGINE_ML], "Model missing")
        self.assertIn("ML prediction unavailable.", outcome["warnings"])

    def test_cybersecurity_warn_with_ml_benign_warns(self):
        outcome = evaluate_combined_policy(
            _sec_result(status=ENGINE_STATUS_OK, verdict=VERDICT_SUSPICIOUS, risk_score=4.0, raw_decision="WARN"),
            _ml_result(status=ENGINE_STATUS_OK, verdict=VERDICT_BENIGN, prob=0.4285),
        )
        self.assertEqual(outcome["final_decision"], "WARN")
        self.assertFalse(outcome["degraded_mode"])

    def test_cybersecurity_allow_with_ml_phishing_warns_never_blocks(self):
        outcome = evaluate_combined_policy(
            _sec_result(status=ENGINE_STATUS_OK, verdict=VERDICT_BENIGN, risk_score=0.0, raw_decision="ALLOW"),
            _ml_result(status=ENGINE_STATUS_OK, verdict=VERDICT_SUSPICIOUS, prob=0.9999),
        )
        self.assertEqual(outcome["final_decision"], "WARN")
        self.assertFalse(outcome["degraded_mode"])

    def test_incomplete_cybersecurity_with_ml_benign_warns_in_degraded_mode(self):
        outcome = evaluate_combined_policy(
            _sec_result(
                status=ENGINE_STATUS_DEGRADED,
                verdict=VERDICT_BENIGN,
                risk_score=0.0,
                warnings=["Threat intelligence verification is incomplete"],
            ),
            _ml_result(status=ENGINE_STATUS_OK, verdict=VERDICT_BENIGN, prob=0.03),
        )
        self.assertEqual(outcome["final_decision"], "WARN")
        self.assertTrue(outcome["degraded_mode"])
        self.assertIn("Threat intelligence verification is incomplete", outcome["warnings"])

    def test_incomplete_cybersecurity_block_still_blocks(self):
        outcome = evaluate_combined_policy(
            _sec_result(
                status=ENGINE_STATUS_DEGRADED,
                verdict=VERDICT_MALICIOUS,
                risk_score=75.0,
                raw_decision="BLOCK",
                warnings=["Redirect inspection could not be completed"],
            ),
            _ml_result(status=ENGINE_STATUS_OK, verdict=VERDICT_BENIGN, prob=0.05),
        )
        self.assertEqual(outcome["final_decision"], "BLOCK")
        self.assertTrue(outcome["degraded_mode"])

    def test_cybersecurity_error_with_ml_benign_never_allows(self):
        outcome = evaluate_combined_policy(
            _sec_result(
                status=ENGINE_STATUS_ERROR,
                verdict=VERDICT_UNKNOWN,
                error="URL analyzer crashed",
                warnings=["Cybersecurity engine raised an unexpected exception."],
            ),
            _ml_result(status=ENGINE_STATUS_OK, verdict=VERDICT_BENIGN, prob=0.02),
        )
        self.assertEqual(outcome["final_decision"], "WARN")
        self.assertTrue(outcome["degraded_mode"])
        self.assertEqual(outcome["errors"][ENGINE_SECURITY], "URL analyzer crashed")

    def test_ml_error_with_cybersecurity_allow_warns_in_degraded_mode(self):
        outcome = evaluate_combined_policy(
            _sec_result(status=ENGINE_STATUS_OK, verdict=VERDICT_BENIGN, risk_score=0.0, raw_decision="ALLOW"),
            _ml_result(
                status=ENGINE_STATUS_ERROR,
                verdict=VERDICT_UNKNOWN,
                error="best_model.joblib unavailable",
                warnings=["ML prediction unavailable."],
            ),
        )
        self.assertEqual(outcome["final_decision"], "WARN")
        self.assertTrue(outcome["degraded_mode"])
        self.assertEqual(outcome["errors"][ENGINE_ML], "best_model.joblib unavailable")

    def test_both_engines_error_returns_structured_error(self):
        outcome = evaluate_combined_policy(
            _sec_result(status=ENGINE_STATUS_ERROR, verdict=VERDICT_UNKNOWN, error="Security unavailable"),
            _ml_result(status=ENGINE_STATUS_ERROR, verdict=VERDICT_UNKNOWN, error="ML unavailable"),
        )
        self.assertEqual(outcome["final_decision"], "ERROR")
        self.assertTrue(outcome["degraded_mode"])
        self.assertEqual(
            outcome["errors"],
            {ENGINE_SECURITY: "Security unavailable", ENGINE_ML: "ML unavailable"},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
