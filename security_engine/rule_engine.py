
from difflib import SequenceMatcher

if __package__:
    from .url_analyzer import analyze_url
else:
    from url_analyzer import analyze_url


PROTECTED_DOMAINS = [
    "paypal.com",
    "google.com",
    "microsoft.com",
    "amazon.com",
    "apple.com"
]


def make_finding(
    rule,
    detected,
    reason,
    severity="INFO",
    confidence=0.0,
    evidence_group="general"
):
    return {
        "rule": rule,
        "detected": detected,
        "reason": reason,
        "severity": severity,
        "confidence": confidence,
        "evidence_group": evidence_group
    }

def normalize_brand_candidate(value):
    """
    Normalize common numeric lookalikes in a domain label.
    This is a heuristic, not a complete homoglyph detector.
    """

    substitutions = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t"
    }

    return "".join(
        substitutions.get(char, char)
        for char in value.lower()
    )


def get_brand_similarity(candidate, brand):
    """
    Compare only the registered domain label with a brand label.
    Never compare the complete URL or arbitrary hostname substring.
    """

    normalized_candidate = normalize_brand_candidate(candidate)
    normalized_brand = normalize_brand_candidate(brand)

    return SequenceMatcher(
        None,
        normalized_candidate,
        normalized_brand
    ).ratio()


def check_ip_address(features):

    if features.get("has_ip", False):
        return make_finding(
            "IP_ADDRESS", True,
            "URL uses an IP address instead of a domain",
            "MEDIUM", 0.75, "url_structure"
        )

    return make_finding(
        "IP_ADDRESS", False,
        "URL does not use an IP address"
    )



def check_at_symbol(features):

    has_credentials = features.get(
        "has_url_credentials",
        features.get("has_at_symbol", False)
    )

    return make_finding(
        rule="AT_SYMBOL",
        detected=has_credentials,
        reason=(
            "URL contains user information before the actual hostname"
            if has_credentials
            else "No URL credentials detected"
        ),
        severity="MEDIUM",
        confidence=0.75,
        evidence_group="url_structure"
    )




def check_suspicious_keywords(features):

    keywords = features.get("suspicious_keywords", [])
    hostname = (features.get("hostname") or "").lower()

    suspicious_host_keywords = [
        word for word in keywords
        if word in hostname
    ]

    if len(suspicious_host_keywords) >= 2:
        return make_finding(
            "SUSPICIOUS_KEYWORDS",
            True,
            (
                "Multiple suspicious keywords detected in hostname: "
                f"{suspicious_host_keywords}"
            ),
            "HIGH",
            0.80,
            "url_structure"
        )

    if suspicious_host_keywords:
        return make_finding(
            "SUSPICIOUS_KEYWORDS",
            True,
            (
                "Suspicious keyword detected in hostname: "
                f"{suspicious_host_keywords}"
            ),
            "MEDIUM",
            0.60,
            "url_structure"
        )

    if keywords:
        return make_finding(
            "SUSPICIOUS_KEYWORDS",
            True,
            f"Suspicious keywords found outside hostname: {keywords}",
            "LOW",
            0.35,
            "url_structure"
        )

    return make_finding(
        "SUSPICIOUS_KEYWORDS",
        False,
        "No suspicious keywords detected"
    )



def check_url_encoding(features):

    encoding = features.get("encoding_analysis", {})

    has_encoding = (
        encoding.get("has_encoding", False)
        or features.get("has_encoding", False)
    )

    nested = encoding.get("nested_encoding", False)
    malformed = encoding.get("malformed_encoding", False)

    if nested or malformed:
        return make_finding(
            "URL_ENCODING", True,
            "Nested or malformed URL encoding detected",
            "HIGH", 0.85, "url_structure"
        )

    if has_encoding:
        return make_finding(
            "URL_ENCODING", True,
            "Percent-encoded characters detected",
            "LOW", 0.35, "url_structure"
        )

    return make_finding(
        "URL_ENCODING", False,
        "No suspicious URL encoding detected"
    )


def check_subdomains(features):

    count = features.get("subdomain_count", 0)

    if count >= 3:
        return make_finding(
            "EXCESSIVE_SUBDOMAINS", True,
            f"URL contains {count} subdomain labels",
            "MEDIUM", 0.65, "url_structure"
        )

    return make_finding(
        "EXCESSIVE_SUBDOMAINS", False,
        f"URL contains {count} subdomain labels"
    )


def check_url_length(features):

    length = features.get("url_length", 0)

    if length > 100:
        return make_finding(
            "LONG_URL", True,
            f"URL length is {length} characters",
            "LOW", 0.40, "url_structure"
        )

    return make_finding(
        "LONG_URL", False,
        f"URL length is {length} characters"
    )



def check_domain_similarity(features):

    registered_domain = (
        features.get("registered_domain") or ""
    ).lower()

    if not registered_domain:
        return make_finding(
            "DOMAIN_SIMILARITY",
            False,
            "Registered domain is unavailable"
        )

    # Compare the registrable domain label only.
    # For example: example.co.uk -> example
    candidate = registered_domain.split(".")[0]

    for protected in PROTECTED_DOMAINS:

        brand = protected.split(".")[0]

        if candidate == brand:
            continue

        similarity = get_brand_similarity(
            candidate,
            brand
        )

        if similarity >= 0.80:
            return make_finding(
                "DOMAIN_SIMILARITY",
                True,
                (
                    f"Registered domain label '{candidate}' "
                    f"resembles protected brand '{brand}'"
                ),
                "HIGH",
                0.80,
                "brand_identity"
            )

    return make_finding(
        "DOMAIN_SIMILARITY",
        False,
        "No suspicious registered-domain similarity detected"
    )



def check_brand_impersonation(features):

    hostname = (
        features.get("hostname") or ""
    ).lower().rstrip(".")

    registered_domain = (
        features.get("registered_domain") or ""
    ).lower()

    if not hostname or not registered_domain:
        return make_finding(
            "BRAND_IMPERSONATION",
            False,
            "Insufficient domain information for brand analysis"
        )

    # A legitimate brand's registered domain and its subdomains
    # must not be treated as impersonation.
    if registered_domain in PROTECTED_DOMAINS:
        return make_finding(
            "BRAND_IMPERSONATION",
            False,
            "Registered domain matches a protected brand domain"
        )

    hostname_labels = hostname.split(".")

    # Remove the registered domain and public suffix.
    # Inspect only the labels preceding the registered domain.
    subdomain_labels = hostname_labels[
        :len(hostname_labels) - len(registered_domain.split("."))
    ]

    # Inspect individual registered-domain labels and subdomains.
    candidate_labels = [
        registered_domain.split(".")[0]
    ] + subdomain_labels

    detected_brands = []

    for protected in PROTECTED_DOMAINS:

        brand = protected.split(".")[0]

        # Exact brand token in a subdomain, e.g.
        # paypal.com.evil-site.com
        if any(
            brand in label.split("-")
            for label in subdomain_labels
        ):
            detected_brands.append(brand)
            continue

        # Similarity is evaluated only against the actual
        # registered-domain label, never arbitrary URL text.
        domain_label = registered_domain.split(".")[0]

        if domain_label == brand:
            continue
        if brand in domain_label.split("-"):
            detected_brands.append(brand)
            continue

        similarity = get_brand_similarity(
            domain_label,
            brand
        )

        if similarity >= 0.80:
            detected_brands.append(brand)

    detected_brands = sorted(set(detected_brands))

    if detected_brands:
        return make_finding(
            "BRAND_IMPERSONATION",
            True,
            f"Possible brand impersonation: {detected_brands}",
            "HIGH",
            0.85,
            "brand_identity"
        )

    return make_finding(
        "BRAND_IMPERSONATION",
        False,
        "No known brand impersonation detected"
    )



def check_idn_homograph(features):

    idn = features.get("idn_analysis", {})

    suspicious = any([
        bool(idn.get("mixed_script_labels")),
        idn.get("has_suspicious_confusables", False),
        idn.get("invalid_idn", False)
    ])

    if idn.get("invalid_idn"):
        reason = "Invalid IDN encoding detected"

    elif idn.get("mixed_script_labels"):
        reason = "Mixed writing systems detected in hostname"

    elif idn.get("has_suspicious_confusables"):
        reason = (
            "Potential Unicode lookalike characters detected: "
            f"{idn.get('confusable_characters', [])}"
        )

    elif idn.get("requires_idn_review"):
        return make_finding(
            "IDN_HOMOGRAPH", False,
            "Internationalized domain requires review"
        )

    else:
        reason = "No suspicious IDN characteristics detected"

    if suspicious:
        return make_finding(
            "IDN_HOMOGRAPH", True,
            reason,
            "HIGH", 0.90, "brand_identity"
        )

    return make_finding(
        "IDN_HOMOGRAPH", False,
        reason
    )


def check_redirect_behavior(features):

    redirect = features.get("redirect_analysis")

    if not redirect:
        return make_finding(
            "REDIRECT_ANALYSIS", False,
            "Redirect inspection was not performed"
        )

    findings = []

    if redirect.get("loop_detected"):
        findings.append("Redirect loop detected")

    if redirect.get("https_downgrade"):
        findings.append("HTTPS-to-HTTP downgrade detected")

    if findings:
        return make_finding(
            "REDIRECT_ANALYSIS", True,
            "; ".join(findings),
            "HIGH", 0.90, "redirect_behavior"
        )

    if redirect.get("error"):
        return make_finding(
            "REDIRECT_ANALYSIS", False,
            f"Inspection failed: {redirect['error']}"
        )

    if redirect.get("external_redirects"):
        return make_finding(
            "REDIRECT_ANALYSIS", False,
            "Cross-domain redirects observed; contextual review recommended"
        )

    return make_finding(
        "REDIRECT_ANALYSIS", False,
        "No suspicious redirect behavior detected"
    )


def check_threat_intelligence_rule(features):

    intelligence = features.get("threat_intelligence", {})

    if not intelligence.get("available"):
        return make_finding(
            "THREAT_INTELLIGENCE", False,
            intelligence.get(
                "reason",
                "Threat intelligence unavailable"
            )
        )

    if intelligence.get("matched"):

        feed_status = intelligence.get("feed_status")

        confidence = (
            0.98 if feed_status == "FRESH"
            else 0.65
        )

        return make_finding(
            "THREAT_INTELLIGENCE", True,
            intelligence.get("reason", "Threat intelligence match"),
            "CRITICAL", confidence, "threat_reputation"
        )

    return make_finding(
        "THREAT_INTELLIGENCE", False,
        intelligence.get(
            "reason",
            "No threat intelligence match"
        )
    )


def evaluate_security_rules(features):
    """
    Evaluate every rule, including rules that did not detect anything.
    """

    return [
        check_ip_address(features),
        check_at_symbol(features),
        check_suspicious_keywords(features),
        check_url_encoding(features),
        check_subdomains(features),
        check_url_length(features),
        check_domain_similarity(features),
        check_brand_impersonation(features),
        check_idn_homograph(features),
        check_redirect_behavior(features),
        check_threat_intelligence_rule(features)
    ]


def run_security_rules(features):
    """
    Backward-compatible function returning detected findings only.
    """

    all_results = evaluate_security_rules(features)

    return [
        result
        for result in all_results
        if result["detected"]
    ]


def summarize_findings(findings):

    unique_findings = {
        finding["rule"]: finding
        for finding in findings
        if finding.get("detected")
    }

    result = list(unique_findings.values())

    return {
        "total_findings": len(result),
        "findings": result
    }


if __name__ == "__main__":

    url = input("Enter URL: ")

    features = analyze_url(url)

    all_results = evaluate_security_rules(features)
    findings = run_security_rules(features)

    print("\nALL RULE RESULTS")
    for item in all_results:
        print(item)

    print("\nDETECTED FINDINGS")
    print(summarize_findings(findings))
