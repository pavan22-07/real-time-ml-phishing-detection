"""
Engine Adapters for the Unified Phishing Detection Pipeline.

Wraps `security_engine.analyze_url_security` and `ml_engine.predict.predict_url`
with input validation, offline TLD cache configuration, fault isolation, and
normalization into the shared `EngineResult` contract.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TLD_CACHE_DIR = PROJECT_ROOT / "data" / ".tld_cache"


def ensure_tldextract_cache() -> Path:
    """
    Configure TLDEXTRACT_CACHE prior to importing or calling security_engine.

    `security_engine.url_analyzer` calls `tldextract.extract()`, whose global
    extractor binds `TLDEXTRACT_CACHE` when `tldextract` is first imported.
    Calling this helper before importing `security_engine` or `ml_engine`
    prevents offline lock errors inside read-only site-packages directories.
    """
    configured = os.environ.get("TLDEXTRACT_CACHE")
    cache_path = Path(configured) if configured else DEFAULT_TLD_CACHE_DIR
    if not configured:
        os.environ["TLDEXTRACT_CACHE"] = str(cache_path)
    cache_path.mkdir(parents=True, exist_ok=True)
    return cache_path


# Configure cache before importing engines that import `tldextract`.
ensure_tldextract_cache()

from ml_engine.predict import predict_url
from security_engine import analyze_url_security

from .contracts import (
    ENGINE_ML,
    ENGINE_SECURITY,
    ENGINE_STATUS_DEGRADED,
    ENGINE_STATUS_OK,
    SCORE_SCALE_PROB,
    SCORE_SCALE_RISK,
    SCORE_TYPE_ML_PROB,
    SCORE_TYPE_RISK,
    VERDICT_BENIGN,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    EngineResult,
    EngineSignal,
    EngineVerdict,
    build_engine_result,
    build_error_result,
)

_SECURITY_DECISION_TO_VERDICT: Dict[str, EngineVerdict] = {
    "ALLOW": VERDICT_BENIGN,
    "WARN": VERDICT_SUSPICIOUS,
    "BLOCK": VERDICT_MALICIOUS,
}


def validate_url_input(url: Any) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate raw URL input at the adapter boundary without modifying engines.

    Returns:
        (is_valid, normalized_or_original_url, error_message)
    """
    if url is None:
        return False, None, "Input URL cannot be None."

    if not isinstance(url, str):
        return False, str(url), "Input URL must be a string."

    clean_url = url.strip()
    if not clean_url:
        return False, clean_url, "Input URL cannot be empty or whitespace."

    try:
        parsed = urlsplit(clean_url)
        _ = parsed.port
    except ValueError as exc:
        return False, clean_url, f"Malformed URL input: {exc}"

    return True, clean_url, None


def run_cybersecurity_adapter(
    url: Any,
    inspect_redirects: bool = False,
) -> EngineResult:
    """
    Invoke `security_engine.analyze_url_security` and normalize its output.

    Redirect inspection remains disabled (`inspect_redirects=False`) by default.
    """
    is_valid, normalized_url, validation_error = validate_url_input(url)
    if not is_valid:
        return build_error_result(
            engine=ENGINE_SECURITY,
            url=normalized_url,
            score_type=SCORE_TYPE_RISK,
            score_scale=SCORE_SCALE_RISK,
            error=validation_error or "Invalid URL input.",
        )

    assert normalized_url is not None

    try:
        ensure_tldextract_cache()
        raw = analyze_url_security(
            normalized_url,
            inspect_redirects=inspect_redirects,
        )
    except Exception as exc:
        return build_error_result(
            engine=ENGINE_SECURITY,
            url=normalized_url,
            score_type=SCORE_TYPE_RISK,
            score_scale=SCORE_SCALE_RISK,
            error=f"Cybersecurity engine execution failed: {exc}",
            warnings=["Cybersecurity engine raised an unexpected exception."],
        )

    if not isinstance(raw, dict):
        return build_error_result(
            engine=ENGINE_SECURITY,
            url=normalized_url,
            score_type=SCORE_TYPE_RISK,
            score_scale=SCORE_SCALE_RISK,
            error="Cybersecurity engine returned a non-dict response.",
        )

    final_decision = raw.get("final_decision")
    risk_assessment = raw.get("risk_assessment")
    if not isinstance(final_decision, dict) or not isinstance(risk_assessment, dict):
        return build_error_result(
            engine=ENGINE_SECURITY,
            url=normalized_url,
            score_type=SCORE_TYPE_RISK,
            score_scale=SCORE_SCALE_RISK,
            error="Cybersecurity engine returned an incomplete response structure.",
            raw_result=raw,
        )

    raw_decision = final_decision.get("decision")
    verdict = _SECURITY_DECISION_TO_VERDICT.get(raw_decision, VERDICT_UNKNOWN)
    if verdict == VERDICT_UNKNOWN:
        return build_error_result(
            engine=ENGINE_SECURITY,
            url=normalized_url,
            score_type=SCORE_TYPE_RISK,
            score_scale=SCORE_SCALE_RISK,
            error=f"Unrecognized cybersecurity decision: {raw_decision!r}",
            warnings=list(final_decision.get("inspection_warnings") or []),
            raw_result=raw,
        )

    raw_score = risk_assessment.get("risk_score")
    try:
        risk_score = float(raw_score) if raw_score is not None else None
    except (TypeError, ValueError):
        risk_score = None

    if risk_score is None or not (0.0 <= risk_score <= 100.0):
        return build_error_result(
            engine=ENGINE_SECURITY,
            url=normalized_url,
            score_type=SCORE_TYPE_RISK,
            score_scale=SCORE_SCALE_RISK,
            error=f"Invalid cybersecurity risk_score: {raw_score!r}",
            warnings=list(final_decision.get("inspection_warnings") or []),
            raw_result=raw,
        )

    engine_status_str = raw.get("engine_status") or final_decision.get("inspection_status")
    status = ENGINE_STATUS_OK if engine_status_str == "COMPLETED" else ENGINE_STATUS_DEGRADED

    warnings = list(final_decision.get("inspection_warnings") or [])
    if status == ENGINE_STATUS_DEGRADED and not warnings:
        warnings.append(f"Cybersecurity engine inspection status: {engine_status_str}")

    signals: list[EngineSignal] = []
    for finding in raw.get("findings") or []:
        if isinstance(finding, dict) and finding.get("detected"):
            signals.append(
                {
                    "code": str(finding.get("rule", "UNKNOWN")),
                    "severity": str(finding.get("severity", "INFO")),
                    "reason": str(finding.get("reason", "")),
                    "evidence_group": str(finding.get("evidence_group", "general")),
                }
            )

    return build_engine_result(
        engine=ENGINE_SECURITY,
        url=normalized_url,
        status=status,
        verdict=verdict,
        score=risk_score,
        score_type=SCORE_TYPE_RISK,
        score_scale=SCORE_SCALE_RISK,
        is_calibrated=False,
        risk_score=risk_score,
        raw_phishing_probability=None,
        signals=signals,
        warnings=warnings,
        error=None,
        raw_result=raw,
    )


def run_ml_adapter(url: Any) -> EngineResult:
    """
    Invoke `ml_engine.predict.predict_url` and normalize its output.

    Preserves `raw_phishing_probability` in [0.0, 1.0] with `is_calibrated=False`
    and never labels raw ML probability as calibrated confidence.
    """
    is_valid, normalized_url, validation_error = validate_url_input(url)
    if not is_valid:
        return build_error_result(
            engine=ENGINE_ML,
            url=normalized_url,
            score_type=SCORE_TYPE_ML_PROB,
            score_scale=SCORE_SCALE_PROB,
            error=validation_error or "Invalid URL input.",
        )

    assert normalized_url is not None

    try:
        raw = predict_url(normalized_url)
    except Exception as exc:
        return build_error_result(
            engine=ENGINE_ML,
            url=normalized_url,
            score_type=SCORE_TYPE_ML_PROB,
            score_scale=SCORE_SCALE_PROB,
            error=f"ML engine execution failed: {exc}",
            warnings=["ML engine raised an unexpected exception."],
        )

    if not isinstance(raw, dict):
        return build_error_result(
            engine=ENGINE_ML,
            url=normalized_url,
            score_type=SCORE_TYPE_ML_PROB,
            score_scale=SCORE_SCALE_PROB,
            error="ML engine returned a non-dict response.",
        )

    ml_status = raw.get("status")
    prediction = raw.get("prediction")
    if ml_status != "SUCCESS" or prediction == "ERROR":
        error_msg = raw.get("error_message") or f"ML inference failed with status={ml_status!r}"
        return build_error_result(
            engine=ENGINE_ML,
            url=normalized_url,
            score_type=SCORE_TYPE_ML_PROB,
            score_scale=SCORE_SCALE_PROB,
            error=str(error_msg),
            warnings=["ML prediction unavailable."],
            raw_result=raw,
        )

    raw_prob = raw.get("phishing_probability")
    try:
        phishing_prob = float(raw_prob) if raw_prob is not None else None
    except (TypeError, ValueError):
        phishing_prob = None

    if phishing_prob is None or not (0.0 <= phishing_prob <= 1.0):
        return build_error_result(
            engine=ENGINE_ML,
            url=normalized_url,
            score_type=SCORE_TYPE_ML_PROB,
            score_scale=SCORE_SCALE_PROB,
            error=f"Invalid ML phishing_probability value: {raw_prob!r}",
            warnings=["ML returned invalid probability value."],
            raw_result=raw,
        )

    if prediction == "PHISHING" or raw.get("label") == 1:
        verdict = VERDICT_SUSPICIOUS
        signal_code = "ML_PHISHING_PREDICTION"
        severity = "MEDIUM"
    elif prediction == "LEGITIMATE" or raw.get("label") == 0:
        verdict = VERDICT_BENIGN
        signal_code = "ML_LEGITIMATE_PREDICTION"
        severity = "INFO"
    else:
        return build_error_result(
            engine=ENGINE_ML,
            url=normalized_url,
            score_type=SCORE_TYPE_ML_PROB,
            score_scale=SCORE_SCALE_PROB,
            error=f"Unrecognized ML prediction label: {prediction!r}",
            raw_result=raw,
        )

    model_name = raw.get("model_name", "Unknown")
    model_version = raw.get("model_version", "unknown")
    signals: list[EngineSignal] = [
        {
            "code": signal_code,
            "severity": severity,
            "reason": (
                f"ML model '{model_name}' (v{model_version}) predicted {prediction} "
                f"with uncalibrated phishing probability {phishing_prob:.4f}"
            ),
            "evidence_group": "ml_statistical",
        }
    ]

    return build_engine_result(
        engine=ENGINE_ML,
        url=normalized_url,
        status=ENGINE_STATUS_OK,
        verdict=verdict,
        score=phishing_prob,
        score_type=SCORE_TYPE_ML_PROB,
        score_scale=SCORE_SCALE_PROB,
        is_calibrated=False,
        risk_score=None,
        raw_phishing_probability=phishing_prob,
        signals=signals,
        warnings=[],
        error=None,
        raw_result=raw,
    )


def run_engine_adapters(
    url: Any,
    inspect_redirects: bool = False,
) -> Dict[str, EngineResult]:
    """
    Execute both adapters independently and return their normalized EngineResults.

    Failure in either adapter is isolated and never prevents the other adapter
    from executing. Combined policy decisions belong to Phase 2 (`policy.py`).
    """
    return {
        ENGINE_SECURITY: run_cybersecurity_adapter(
            url,
            inspect_redirects=inspect_redirects,
        ),
        ENGINE_ML: run_ml_adapter(url),
    }
