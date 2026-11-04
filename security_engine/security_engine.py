
from url_analyzer import analyze_url
from rule_engine import run_security_rules
from risk_scoring import assess_risk
from redirect_analyzer import analyze_redirects
from threat_intel import check_threat_intelligence
from decision_engine import generate_security_report



def analyze_url_security(url, inspect_redirects=False):

    features = analyze_url(url)

    # Local threat-intelligence lookup
    features["threat_intelligence"] = (
        check_threat_intelligence(url)
    )

    # Optional network-based redirect inspection
    if inspect_redirects:
        features["redirect_analysis"] = analyze_redirects(url)

    # Run all cybersecurity rules
    findings = run_security_rules(features)

    # Generate final cybersecurity report
    report = generate_security_report(
        url,
        features,
        findings
    )

    return {
        "url": url,
        "features": features,
        "findings": findings,
        "risk_assessment": report["security_analysis"],
        "final_decision": report["final_decision"],
        "engine_status": report["engine_status"]
    }
