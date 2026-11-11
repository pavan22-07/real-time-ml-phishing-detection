
if __package__:
    from .url_analyzer import analyze_url
    from .rule_engine import run_security_rules
    from .risk_scoring import assess_risk
    from .redirect_analyzer import analyze_redirects
    from .threat_intel import check_threat_intelligence
    from .decision_engine import determine_decision
else:
    from url_analyzer import analyze_url
    from rule_engine import run_security_rules
    from risk_scoring import assess_risk
    from redirect_analyzer import analyze_redirects
    from threat_intel import check_threat_intelligence
    from decision_engine import determine_decision



def analyze_url_security(url, inspect_redirects=False):
    """
    Run the end-to-end cybersecurity detection pipeline for a URL.

    Args:
        url (str): Target URL string to inspect.
        inspect_redirects (bool): Whether to perform network-based redirect
            inspection. When False, features["redirect_analysis"] defaults to {}.

    Returns:
        dict: Structured security analysis report with keys:
            - url (str): Submitted URL.
            - features (dict): Extracted URL, threat-intel, and redirect features.
            - findings (list): Security rule evaluation results.
            - risk_assessment (dict): Output of assess_risk(findings).
            - final_decision (dict): Output of determine_decision(risk_assessment, features).
            - engine_status (str): Inspection status ("COMPLETED" or "INCOMPLETE").
    """

    features = analyze_url(url)

    # Local threat-intelligence lookup
    features["threat_intelligence"] = (
        check_threat_intelligence(url)
    )

    # Optional network-based redirect inspection
    if inspect_redirects:
        features["redirect_analysis"] = analyze_redirects(url)
    else:
        features["redirect_analysis"] = {}

    # Run all cybersecurity rules
    findings = run_security_rules(features)

    # Assess risk and determine final cybersecurity decision
    risk_assessment = assess_risk(findings)
    final_decision = determine_decision(risk_assessment, features)

    return {
        "url": url,
        "features": features,
        "findings": findings,
        "risk_assessment": risk_assessment,
        "final_decision": final_decision,
        "engine_status": final_decision["inspection_status"]
    }
