"""
Shared EngineResult Contract for Unified Phishing Detection.

Defines normalized, JSON-serializable output structures and factory helpers
shared by both cybersecurity and machine learning engine adapters without
altering either engine's internal behavior or outputs.
"""

from typing import Any, Dict, List, Literal, Optional, TypedDict

EngineName = Literal["security_engine", "ml_engine"]
EngineStatus = Literal["OK", "DEGRADED", "ERROR"]
EngineVerdict = Literal["BENIGN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]

ENGINE_SECURITY: EngineName = "security_engine"
ENGINE_ML: EngineName = "ml_engine"

ENGINE_STATUS_OK: EngineStatus = "OK"
ENGINE_STATUS_DEGRADED: EngineStatus = "DEGRADED"
ENGINE_STATUS_ERROR: EngineStatus = "ERROR"
ENGINE_STATUSES = (ENGINE_STATUS_OK, ENGINE_STATUS_DEGRADED, ENGINE_STATUS_ERROR)

VERDICT_BENIGN: EngineVerdict = "BENIGN"
VERDICT_SUSPICIOUS: EngineVerdict = "SUSPICIOUS"
VERDICT_MALICIOUS: EngineVerdict = "MALICIOUS"
VERDICT_UNKNOWN: EngineVerdict = "UNKNOWN"
ENGINE_VERDICTS = (
    VERDICT_BENIGN,
    VERDICT_SUSPICIOUS,
    VERDICT_MALICIOUS,
    VERDICT_UNKNOWN,
)

SCORE_TYPE_RISK = "cybersecurity_risk_score"
SCORE_SCALE_RISK = "0-100"

SCORE_TYPE_ML_PROB = "ml_raw_phishing_probability"
SCORE_SCALE_PROB = "0.0-1.0"


class EngineSignal(TypedDict, total=False):
    """Normalized signal emitted by an individual detection engine."""

    code: str
    severity: str
    reason: str
    evidence_group: str


class EngineResult(TypedDict):
    """
    Normalized per-engine contract consumed by downstream policy evaluation.

    Scale separation guarantees:
    - Cybersecurity engine reports `score_type="cybersecurity_risk_score"`,
      `score_scale="0-100"`, `risk_score` in [0, 100], and
      `raw_phishing_probability=None`.
    - ML engine reports `score_type="ml_raw_phishing_probability"`,
      `score_scale="0.0-1.0"`, `raw_phishing_probability` in [0.0, 1.0],
      `risk_score=None`, and `is_calibrated=False`.
    - ML probabilities are raw uncalibrated model scores and are never
      represented as calibrated confidence.
    """

    engine: EngineName
    url: Optional[str]
    status: EngineStatus
    verdict: EngineVerdict
    score: Optional[float]
    score_type: str
    score_scale: str
    is_calibrated: bool
    risk_score: Optional[float]
    raw_phishing_probability: Optional[float]
    signals: List[EngineSignal]
    warnings: List[str]
    error: Optional[str]
    raw_result: Optional[Dict[str, Any]]


def build_engine_result(
    *,
    engine: EngineName,
    url: Optional[str],
    status: EngineStatus,
    verdict: EngineVerdict,
    score: Optional[float],
    score_type: str,
    score_scale: str,
    is_calibrated: bool = False,
    risk_score: Optional[float] = None,
    raw_phishing_probability: Optional[float] = None,
    signals: Optional[List[EngineSignal]] = None,
    warnings: Optional[List[str]] = None,
    error: Optional[str] = None,
    raw_result: Optional[Dict[str, Any]] = None,
) -> EngineResult:
    """Construct and validate a normalized EngineResult dictionary."""
    if status not in ENGINE_STATUSES:
        raise ValueError(f"Unsupported engine status: {status!r}")
    if verdict not in ENGINE_VERDICTS:
        raise ValueError(f"Unsupported engine verdict: {verdict!r}")

    return {
        "engine": engine,
        "url": url,
        "status": status,
        "verdict": verdict,
        "score": score,
        "score_type": score_type,
        "score_scale": score_scale,
        "is_calibrated": is_calibrated,
        "risk_score": risk_score,
        "raw_phishing_probability": raw_phishing_probability,
        "signals": list(signals) if signals is not None else [],
        "warnings": list(warnings) if warnings is not None else [],
        "error": error,
        "raw_result": raw_result,
    }


def build_error_result(
    *,
    engine: EngineName,
    url: Optional[str],
    score_type: str,
    score_scale: str,
    error: str,
    warnings: Optional[List[str]] = None,
    raw_result: Optional[Dict[str, Any]] = None,
) -> EngineResult:
    """Build a fail-safe ERROR / UNKNOWN EngineResult with no fabricated score."""
    return build_engine_result(
        engine=engine,
        url=url,
        status=ENGINE_STATUS_ERROR,
        verdict=VERDICT_UNKNOWN,
        score=None,
        score_type=score_type,
        score_scale=score_scale,
        is_calibrated=False,
        risk_score=None,
        raw_phishing_probability=None,
        signals=[],
        warnings=warnings or [],
        error=error,
        raw_result=raw_result,
    )
