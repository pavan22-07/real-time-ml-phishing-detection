
RULE_SCORES = {
    "IP_ADDRESS": 15,
    "AT_SYMBOL": 15,
    "SUSPICIOUS_KEYWORDS": 5,
    "URL_ENCODING": 5,
    "EXCESSIVE_SUBDOMAINS": 5,
    "LONG_URL": 5,
    "DOMAIN_SIMILARITY": 20,
    "BRAND_IMPERSONATION": 25,
    "IDN_HOMOGRAPH": 25,
    "REDIRECT_ANALYSIS": 20,
    "THREAT_INTELLIGENCE": 60
}


GROUP_CAPS = {
    "url_structure": 30,
    "brand_identity": 35,
    "redirect_behavior": 20,
    "threat_reputation": 60,
    "general": 20
}


def calculate_risk_score(findings):
    """
    Calculate a confidence-adjusted score.

    Duplicate rules are ignored.
    Correlated findings are grouped and capped.
    Final score is limited to 0-100.
    """

    seen_rules = set()
    group_scores = {}
    score_breakdown = []

    for finding in findings:

        if not finding.get("detected", False):
            continue

        rule = finding.get("rule")

        if not rule or rule in seen_rules:
            continue

        seen_rules.add(rule)

        weight = RULE_SCORES.get(rule, 0)

        confidence = finding.get("confidence", 0.5)

        # Validate confidence.
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.5

        confidence = max(0.0, min(confidence, 1.0))

        raw_score = round(weight * confidence)

        group = finding.get("evidence_group", "general")

        group_scores[group] = (
            group_scores.get(group, 0) + raw_score
        )

        score_breakdown.append({
            "rule": rule,
            "weight": weight,
            "confidence": confidence,
            "raw_score": raw_score,
            "evidence_group": group
        })

    total_score = 0

    for group, group_score in group_scores.items():

        cap = GROUP_CAPS.get(group, 20)

        total_score += min(group_score, cap)

    total_score = min(total_score, 100)

    return {
        "risk_score": total_score,
        "group_scores": group_scores,
        "score_breakdown": score_breakdown
    }


def get_risk_level(score):

    if score >= 70:
        return "CRITICAL"

    elif score >= 45:
        return "HIGH"

    elif score >= 20:
        return "MEDIUM"

    else:
        return "LOW"


def get_security_action(risk_level, confirmed_threat=False):

    if confirmed_threat:
        return "BLOCK"

    if risk_level == "CRITICAL":
        return "BLOCK"

    elif risk_level == "HIGH":
        return "BLOCK"

    elif risk_level == "MEDIUM":
        return "WARN"

    return "ALLOW"


def assess_risk(findings):

    scoring = calculate_risk_score(findings)

    score = scoring["risk_score"]

    level = get_risk_level(score)

    confirmed_threat = any(
        finding.get("rule") == "THREAT_INTELLIGENCE"
        and finding.get("detected")
        and finding.get("confidence", 0) >= 0.75
        for finding in findings
    )

    action = get_security_action(
        level,
        confirmed_threat=confirmed_threat
    )

    detected_findings = [
        finding
        for finding in findings
        if finding.get("detected")
    ]

    return {
        "risk_score": score,
        "risk_level": level,
        "action": action,
        "confirmed_threat": confirmed_threat,
        "findings_count": len(detected_findings),
        "findings": detected_findings,
        "score_breakdown": scoring["score_breakdown"],
        "group_scores": scoring["group_scores"]
    }


if __name__ == "__main__":

    test_findings = [
        {
            "rule": "IP_ADDRESS",
            "detected": True,
            "reason": "URL uses an IP address",
            "confidence": 0.75,
            "evidence_group": "url_structure"
        },
        {
            "rule": "AT_SYMBOL",
            "detected": True,
            "reason": "URL contains @ symbol",
            "confidence": 0.75,
            "evidence_group": "url_structure"
        },
        {
            "rule": "BRAND_IMPERSONATION",
            "detected": True,
            "reason": "Possible brand impersonation",
            "confidence": 0.85,
            "evidence_group": "brand_identity"
        }
    ]

    result = assess_risk(test_findings)

    print("\nRISK ASSESSMENT")
    print(result)
