"""
Service layer orchestrating URL scans via the Unified Engine.
Preserves architectural separation: Django does not call cybersecurity or ML engines directly.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from django.contrib.auth.models import User
from .models import ScanHistory

logger = logging.getLogger(__name__)


def execute_url_scan(
    url: str,
    user: User,
    inspect_redirects: bool = False
) -> Tuple[ScanHistory, Dict[str, Any]]:
    """
    Execute a URL scan by delegating to the Unified Engine and persisting the result.

    Args:
        url: Raw URL string submitted by the user.
        user: Authenticated User initiating the scan.
        inspect_redirects: Kept False by default for static analysis / SSRF safety.

    Returns:
        Tuple of (saved_scan_history_model, unified_engine_result_dict)
    """
    # Enforce static analysis by default and avoid enabling redirect inspection in public API
    safe_inspect_redirects = False

    try:
        from unified_engine.detector import scan_url
        result = scan_url(url, inspect_redirects=safe_inspect_redirects)
    except Exception as exc:
        logger.exception("Unified Engine execution encountered unexpected error: %s", exc)
        result = {
            "url": str(url) if url else None,
            "final_decision": "ERROR",
            "degraded_mode": True,
            "reasons": [f"Detection engine error: {type(exc).__name__}"],
            "warnings": ["Unified detection could not be completed safely."],
            "errors": {"unified_engine": str(exc)},
            "engine_statuses": {"cybersecurity": "ERROR", "machine_learning": "ERROR"},
            "engines": {
                "cybersecurity": {
                    "status": "ERROR",
                    "verdict": None,
                    "confidence": None,
                    "raw_result": None
                },
                "machine_learning": {
                    "status": "ERROR",
                    "prediction": None,
                    "confidence": None,
                    "is_calibrated": False,
                    "raw_result": None
                }
            },
            "inspect_redirects": safe_inspect_redirects,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    # Extract cybersecurity specifics (supports both 'security_engine' and 'cybersecurity' keys)
    security_data = (
        result.get("engines", {}).get("security_engine")
        or result.get("engines", {}).get("cybersecurity", {})
    )
    sec_verdict = security_data.get("verdict")
    sec_risk_score = None
    raw_sec = security_data.get("raw_result")
    if isinstance(raw_sec, dict):
        fin_dec = raw_sec.get("final_decision")
        if isinstance(fin_dec, dict) and "risk_score" in fin_dec:
            sec_risk_score = fin_dec.get("risk_score")
    if sec_risk_score is None and security_data.get("risk_score") is not None:
        sec_risk_score = int(security_data.get("risk_score"))

    # Extract machine learning specifics (supports both 'ml_engine' and 'machine_learning' keys)
    ml_data = (
        result.get("engines", {}).get("ml_engine")
        or result.get("engines", {}).get("machine_learning", {})
    )
    raw_ml = ml_data.get("raw_result")
    ml_prediction = None
    if isinstance(raw_ml, dict):
        ml_prediction = raw_ml.get("prediction")
    if not ml_prediction:
        ml_prediction = ml_data.get("prediction") or ml_data.get("verdict")

    ml_raw_prob = None
    if isinstance(raw_ml, dict):
        prob_dict = raw_ml.get("probability")
        if isinstance(prob_dict, dict) and "phishing" in prob_dict:
            ml_raw_prob = prob_dict.get("phishing")
        elif "phishing_probability" in raw_ml:
            ml_raw_prob = raw_ml.get("phishing_probability")

    if ml_raw_prob is None and ml_data.get("raw_phishing_probability") is not None:
        ml_raw_prob = ml_data.get("raw_phishing_probability")
    if ml_raw_prob is None and ml_data.get("confidence") is not None:
        ml_raw_prob = ml_data.get("confidence")

    # Persist the complete audit record to PostgreSQL
    scan_record = ScanHistory.objects.create(
        user=user,
        url=result.get("url") or (url.strip() if isinstance(url, str) else str(url)),
        final_decision=result.get("final_decision", "ERROR"),
        cybersecurity_verdict=sec_verdict,
        cybersecurity_risk_score=sec_risk_score,
        ml_prediction=ml_prediction,
        raw_phishing_probability=ml_raw_prob,
        degraded_mode=result.get("degraded_mode", False),
        engine_statuses=result.get("engine_statuses", {}),
        scan_reasons=result.get("reasons", []),
        warnings=result.get("warnings", []),
        errors=result.get("errors", {}),
        complete_result=result
    )

    return scan_record, result
