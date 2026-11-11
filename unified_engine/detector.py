"""
Unified Phishing Detector Orchestrator.

Exposes `scan_url(url, inspect_redirects=False)` as the single entry point for
the Django backend and downstream services, combining deterministic cybersecurity
analysis and ML inference via `adapters.py` and `policy.py`.
"""

from datetime import datetime, timezone
from typing import Any, Dict

from .adapters import run_engine_adapters, validate_url_input
from .contracts import ENGINE_ML, ENGINE_SECURITY
from .policy import evaluate_combined_policy


def scan_url(
    url: Any,
    inspect_redirects: bool = False,
) -> Dict[str, Any]:
    """
    Scan a URL using both cybersecurity and ML engines and return a combined decision.

    Args:
        url: Target URL string to inspect. Invalid inputs return a structured
            `"ERROR"` response without raising exceptions.
        inspect_redirects: Whether to perform live HTTP redirect inspection inside
            `security_engine`. Disabled (`False`) by default for low-latency scans.

    Returns:
        Dictionary containing:
            - url (Optional[str]): Normalized input URL (or None if None passed).
            - final_decision (str): `"ALLOW"`, `"WARN"`, `"BLOCK"`, or `"ERROR"`.
            - degraded_mode (bool): True if either engine returned `DEGRADED` or `ERROR`.
            - reasons (List[str]): Policy and engine reasoning strings.
            - warnings (List[str]): Aggregated inspection warnings and error notices.
            - errors (Dict[str, Optional[str]]): Per-engine error messages.
            - engine_statuses (Dict[str, str]): Per-engine `OK`/`DEGRADED`/`ERROR` statuses.
            - engines (Dict[str, EngineResult]): Normalized results including `raw_result`.
            - inspect_redirects (bool): Redirect inspection flag used for this scan.
            - timestamp (str): UTC ISO-8601 scan timestamp.
    """
    _, normalized_url, _ = validate_url_input(url)

    engine_results = run_engine_adapters(
        url,
        inspect_redirects=inspect_redirects,
    )
    security_result = engine_results[ENGINE_SECURITY]
    ml_result = engine_results[ENGINE_ML]

    policy_outcome = evaluate_combined_policy(security_result, ml_result)

    return {
        "url": normalized_url,
        "final_decision": policy_outcome["final_decision"],
        "degraded_mode": policy_outcome["degraded_mode"],
        "reasons": policy_outcome["reasons"],
        "warnings": policy_outcome["warnings"],
        "errors": policy_outcome["errors"],
        "engine_statuses": {
            ENGINE_SECURITY: security_result["status"],
            ENGINE_ML: ml_result["status"],
        },
        "engines": {
            ENGINE_SECURITY: security_result,
            ENGINE_ML: ml_result,
        },
        "inspect_redirects": bool(inspect_redirects),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
