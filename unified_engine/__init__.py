"""
Unified Phishing Detection Engine — Phase 1: Contracts and Engine Adapters.

Exposes the normalized EngineResult contract and fault-isolated adapters for
the deterministic cybersecurity engine and the statistical ML engine.
"""

from .contracts import (
    ENGINE_ML,
    ENGINE_SECURITY,
    ENGINE_STATUS_DEGRADED,
    ENGINE_STATUS_ERROR,
    ENGINE_STATUS_OK,
    ENGINE_STATUSES,
    ENGINE_VERDICTS,
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
    EngineStatus,
    EngineVerdict,
)
from .adapters import (
    run_cybersecurity_adapter,
    run_engine_adapters,
    run_ml_adapter,
    validate_url_input,
)

__all__ = [
    "ENGINE_ML",
    "ENGINE_SECURITY",
    "ENGINE_STATUS_DEGRADED",
    "ENGINE_STATUS_ERROR",
    "ENGINE_STATUS_OK",
    "ENGINE_STATUSES",
    "ENGINE_VERDICTS",
    "SCORE_SCALE_PROB",
    "SCORE_SCALE_RISK",
    "SCORE_TYPE_ML_PROB",
    "SCORE_TYPE_RISK",
    "VERDICT_BENIGN",
    "VERDICT_MALICIOUS",
    "VERDICT_SUSPICIOUS",
    "VERDICT_UNKNOWN",
    "EngineResult",
    "EngineSignal",
    "EngineStatus",
    "EngineVerdict",
    "run_cybersecurity_adapter",
    "run_engine_adapters",
    "run_ml_adapter",
    "validate_url_input",
]
