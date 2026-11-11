"""
Combined Decision Policy for the Unified Phishing Detection Pipeline.

Evaluates normalized `EngineResult` objects from `security_engine` and
`ml_engine` to produce an authoritative `ALLOW`, `WARN`, `BLOCK`, or `ERROR`
decision without modifying engine rules or inventing numeric ML thresholds.
"""

from typing import Any, Dict, Iterable, List, Literal, Optional

from .contracts import (
    ENGINE_ML,
    ENGINE_SECURITY,
    ENGINE_STATUS_ERROR,
    ENGINE_STATUS_OK,
    VERDICT_BENIGN,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    EngineResult,
)

CombinedDecision = Literal["ALLOW", "WARN", "BLOCK", "ERROR"]


def _dedupe_non_empty(items: Iterable[Optional[str]]) -> List[str]:
    """Return unique non-empty strings while preserving original order."""
    seen = set()
    ordered: List[str] = []
    for item in items:
        if isinstance(item, str):
            text = item.strip()
            if text and text not in seen:
                seen.add(text)
                ordered.append(text)
    return ordered


def _is_cybersecurity_block(security_result: EngineResult) -> bool:
    """
    Confirm deterministic cybersecurity MALICIOUS verdict corresponds to BLOCK.

    When raw_result is attached, verifies `final_decision.decision == "BLOCK"`.
    """
    if security_result.get("verdict") != VERDICT_MALICIOUS:
        return False

    raw = security_result.get("raw_result")
    if isinstance(raw, dict):
        raw_final = raw.get("final_decision")
        if isinstance(raw_final, dict):
            raw_decision = raw_final.get("decision")
            if raw_decision is not None and raw_decision != "BLOCK":
                return False

    return True


def _collect_signal_reasons(result: EngineResult) -> List[str]:
    """Extract human-readable finding/prediction reasons from an EngineResult."""
    reasons: List[str] = []
    for signal in result.get("signals") or []:
        if isinstance(signal, dict):
            reason = signal.get("reason")
            if reason:
                reasons.append(str(reason))
    return reasons


def evaluate_combined_policy(
    security_result: EngineResult,
    ml_result: EngineResult,
) -> Dict[str, Any]:
    """
    Pure policy function combining cybersecurity and ML `EngineResult` objects.

    Policy precedence:
    1. Authoritative cybersecurity BLOCK (`MALICIOUS`) -> `BLOCK`
       (never downgraded by ML benign prediction or ML unavailability).
    2. Both engines in `ERROR` state -> `ERROR` (fail-closed, never `ALLOW`).
    3. Either engine `SUSPICIOUS` (or ML `MALICIOUS`) -> `WARN`
       (ML alone never triggers `BLOCK`).
    4. Either engine `DEGRADED`/`ERROR` or `UNKNOWN` verdict -> `WARN`
       (incomplete verification or missing engine never silently `ALLOW`s).
    5. Both engines `OK` and `BENIGN` -> `ALLOW`.
    """
    sec_status = security_result.get("status", ENGINE_STATUS_ERROR)
    sec_verdict = security_result.get("verdict", VERDICT_UNKNOWN)
    ml_status = ml_result.get("status", ENGINE_STATUS_ERROR)
    ml_verdict = ml_result.get("verdict", VERDICT_UNKNOWN)

    sec_error = security_result.get("error")
    ml_error = ml_result.get("error")

    degraded_mode = (
        sec_status != ENGINE_STATUS_OK
        or ml_status != ENGINE_STATUS_OK
    )

    warnings_list: List[str] = list(security_result.get("warnings") or [])
    warnings_list.extend(ml_result.get("warnings") or [])
    if sec_error:
        warnings_list.append(f"cybersecurity error: {sec_error}")
    if ml_error:
        warnings_list.append(f"ml error: {ml_error}")
    warnings = _dedupe_non_empty(warnings_list)

    errors: Dict[str, Optional[str]] = {
        ENGINE_SECURITY: sec_error,
        ENGINE_ML: ml_error,
    }

    policy_reasons: List[str] = []

    if _is_cybersecurity_block(security_result):
        final_decision: CombinedDecision = "BLOCK"
        policy_reasons.append(
            "Cybersecurity engine issued an authoritative BLOCK verdict."
        )
        if ml_verdict == VERDICT_BENIGN:
            policy_reasons.append(
                "ML benign prediction did not downgrade the cybersecurity BLOCK."
            )
        elif ml_status != ENGINE_STATUS_OK:
            policy_reasons.append(
                "ML engine was unavailable during cybersecurity BLOCK."
            )
    elif sec_status == ENGINE_STATUS_ERROR and ml_status == ENGINE_STATUS_ERROR:
        final_decision = "ERROR"
        policy_reasons.append(
            "Both cybersecurity and ML engines returned errors; URL cannot be allowed."
        )
    elif (
        sec_verdict == VERDICT_SUSPICIOUS
        or ml_verdict in (VERDICT_SUSPICIOUS, VERDICT_MALICIOUS)
    ):
        final_decision = "WARN"
        if sec_verdict == VERDICT_SUSPICIOUS and ml_verdict in (
            VERDICT_SUSPICIOUS,
            VERDICT_MALICIOUS,
        ):
            policy_reasons.append(
                "Both cybersecurity and ML engines flagged suspicious indicators."
            )
        elif sec_verdict == VERDICT_SUSPICIOUS:
            policy_reasons.append(
                "Cybersecurity engine flagged suspicious or incomplete indicators."
            )
        else:
            policy_reasons.append(
                "ML engine flagged suspicious URL characteristics; escalated to WARN without auto-BLOCK."
            )
    elif (
        degraded_mode
        or sec_verdict == VERDICT_UNKNOWN
        or ml_verdict == VERDICT_UNKNOWN
    ):
        final_decision = "WARN"
        if sec_status == ENGINE_STATUS_ERROR:
            policy_reasons.append(
                "Cybersecurity engine encountered an error; fail-safe WARN applied."
            )
        elif sec_status != ENGINE_STATUS_OK:
            policy_reasons.append(
                "Cybersecurity inspection is incomplete; fail-safe WARN applied."
            )
        if ml_status != ENGINE_STATUS_OK:
            policy_reasons.append(
                "ML inference is unavailable or degraded; fail-safe WARN applied."
            )
    else:
        final_decision = "ALLOW"
        policy_reasons.append(
            "Both cybersecurity and ML engines verified the URL as benign with healthy inspection status."
        )

    raw_sec_reasons: List[str] = []
    raw_sec = security_result.get("raw_result")
    if isinstance(raw_sec, dict):
        raw_final = raw_sec.get("final_decision")
        if isinstance(raw_final, dict):
            raw_sec_reasons = list(raw_final.get("reasons") or [])

    combined_reasons = _dedupe_non_empty(
        policy_reasons
        + raw_sec_reasons
        + _collect_signal_reasons(security_result)
        + _collect_signal_reasons(ml_result)
    )

    return {
        "final_decision": final_decision,
        "degraded_mode": degraded_mode,
        "reasons": combined_reasons,
        "warnings": warnings,
        "errors": errors,
    }
