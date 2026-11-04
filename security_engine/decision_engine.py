
def determine_decision(risk_assessment, features):

    score = risk_assessment["risk_score"]
    findings = risk_assessment.get("findings", [])

    threat_intel = features.get("threat_intelligence", {})
    redirect = features.get("redirect_analysis", {})

    detected_findings = [
        finding for finding in findings
        if finding.get("detected")
    ]

    detected_rules = {
        finding.get("rule")
        for finding in detected_findings
    }

    reasons = []

    # Priority 1: Fresh threat intelligence match
    if (
        threat_intel.get("matched")
        and threat_intel.get("feed_status") == "FRESH"
    ):
        decision = "BLOCK"
        reasons.append(
            "URL matches a current phishing threat-intelligence indicator"
        )

    # Priority 2: Numerical risk score
    elif score >= 70:
        decision = "BLOCK"
        reasons.append("Critical cybersecurity risk score")

    elif score >= 20:
        decision = "WARN"
        reasons.append(
            "Suspicious URL characteristics detected"
        )

    else:
        decision = "ALLOW"
        reasons.append(
            "No significant suspicious indicators detected"
        )

    # Priority 3: High-severity findings
    # A high-severity finding must never silently result in ALLOW.
    high_severity_findings = [
        finding for finding in detected_findings
        if finding.get("severity") == "HIGH"
    ]

    if high_severity_findings and decision == "ALLOW":
        decision = "WARN"

        for finding in high_severity_findings:
            reasons.append(
                f"High-severity indicator detected: "
                f"{finding.get('rule')}"
            )

    # IP addresses and URL credentials require at least a warning.
    if decision == "ALLOW":

        if "IP_ADDRESS" in detected_rules:
            decision = "WARN"
            reasons.append(
                "URL uses an IP address as its hostname"
            )

        if "AT_SYMBOL" in detected_rules:
            decision = "WARN"
            reasons.append(
                "URL contains user information before its actual hostname"
            )

    # Inspection coverage
    inspection_warnings = []

    if redirect.get("error"):
        inspection_warnings.append(
            "Redirect inspection could not be completed"
        )

    if (
        threat_intel.get("available") is False
        or threat_intel.get("feed_status") in {
            "STALE", "UNKNOWN", "UNAVAILABLE"
        }
    ):
        inspection_warnings.append(
            "Threat intelligence verification is incomplete"
        )

    if decision == "ALLOW" and inspection_warnings:
        decision = "WARN"
        reasons.append(
            "Security verification is incomplete"
        )

    explanations = [
        {
            "rule": finding.get("rule"),
            "severity": finding.get("severity"),
            "reason": finding.get("reason")
        }
        for finding in detected_findings
    ]

    return {
        "decision": decision,
        "risk_score": score,
        "risk_level": risk_assessment["risk_level"],
        "confirmed_threat": risk_assessment.get(
            "confirmed_threat", False
        ),
        "reasons": reasons,
        "findings_count": len(explanations),
        "explanations": explanations,
        "inspection_warnings": inspection_warnings,
        "inspection_status": (
            "INCOMPLETE" if inspection_warnings else "COMPLETED"
        )
    }
