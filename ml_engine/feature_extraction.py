"""
URL Feature Extraction Module for Phishing Detection.

Extracts comprehensive structural, domain, security, and statistical features
from URL strings using static analysis only (no network requests, no webpage fetching).
"""

import math
import re
import ipaddress
import unicodedata
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import Dict, Any, Tuple
import tldextract

from ml_engine.config import TLD_CACHE_DIR

# Initialize offline-capable TLDExtract
TLD_CACHE_DIR.mkdir(parents=True, exist_ok=True)
_extractor = tldextract.TLDExtract(
    cache_dir=str(TLD_CACHE_DIR),
    fallback_to_snapshot=True,
    suffix_list_urls=None
)

# Known URL shorteners
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "t.co", "rebrand.ly", "tiny.cc", "cutt.ly",
    "shorte.st", "bl.ink", "lnkd.in", "s.id", "soo.gd", "q.gs"
}

# Known high-risk or commonly abused TLDs in phishing datasets
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "club", "tk", "ml", "ga", "cf", "gq",
    "work", "loan", "men", "click", "rest", "fit", "surf", "casa",
    "stream", "download", "link", "bid", "racing", "date", "faith"
}

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "security", "account",
    "update", "banking", "signin", "sign-in", "password", "authenticate",
    "wallet", "confirm", "validation", "support", "service", "billing",
    "invoice", "recover", "unlock", "alert", "notification", "suspend",
    "ebayisapi", "webscr", "auth", "token"
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def is_ip_address_string(host: str) -> int:
    """Check if host string is a valid IPv4 or IPv6 address."""
    if not host:
        return 0
    clean_host = host.strip("[]")
    # If IPv4 with port (e.g. 192.168.1.1:8080)
    if ":" in clean_host and clean_host.count(":") == 1:
        clean_host = clean_host.split(":")[0]
    try:
        ipaddress.ip_address(clean_host)
        return 1
    except ValueError:
        return 0


def extract_features_from_url(url: str) -> Dict[str, Any]:
    """
    Extract all features from a single URL string for machine learning.
    Returns a dictionary of numerical features suitable for ML models.
    """
    if not isinstance(url, str) or not url.strip():
        # Return zeroed default schema for invalid/empty URL
        return get_default_feature_vector()

    url_str = url.strip()

    # Pre-parse URL
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_str):
        # Default scheme for parsing if missing
        parse_target = "http://" + url_str
    else:
        parse_target = url_str

    try:
        parsed = urlparse(parse_target)
    except Exception:
        return get_default_feature_vector()

    hostname = (parsed.hostname or "").lower()
    netloc = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme.lower() if parsed.scheme else ""

    # Extract domain info with offline tldextract
    try:
        ext = _extractor(hostname)
        subdomain = ext.subdomain
        domain = ext.domain
        suffix = ext.suffix
        if hasattr(ext, "top_domain_under_public_suffix"):
            registered_domain = ext.top_domain_under_public_suffix or ""
        else:
            registered_domain = getattr(ext, "registered_domain", "")
    except Exception:
        subdomain, domain, suffix, registered_domain = "", "", "", ""

    url_len = len(url_str)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    # 1. Structural Counts
    dot_cnt = url_str.count(".")
    hyphen_cnt = url_str.count("-")
    digit_cnt = sum(c.isdigit() for c in url_str)
    alpha_cnt = sum(c.isalpha() for c in url_str)
    upper_cnt = sum(c.isupper() for c in url_str)

    # Special characters: non-alphanumeric, non-slash, non-colon
    special_cnt = sum(not c.isalnum() and c not in "/:" for c in url_str)
    separator_cnt = sum(url_str.count(sep) for sep in ["/", "?", "=", "&", "#"])

    # Query parameters
    try:
        query_params = parse_qs(query)
        query_param_cnt = len(query_params)
    except Exception:
        query_param_cnt = query.count("=")

    # Path segments & components
    path_segments = [seg for seg in path.split("/") if seg]
    url_component_cnt = (1 if scheme else 0) + (1 if hostname else 0) + len(path_segments) + (1 if query else 0)

    # Ratios
    digit_ratio = round(digit_cnt / url_len, 4) if url_len > 0 else 0.0
    alpha_ratio = round(alpha_cnt / url_len, 4) if url_len > 0 else 0.0
    special_ratio = round(special_cnt / url_len, 4) if url_len > 0 else 0.0
    upper_ratio = round(upper_cnt / url_len, 4) if url_len > 0 else 0.0

    # 2. Domain features
    subdomain_labels = [s for s in subdomain.split(".") if s]
    subdom_cnt = len(subdomain_labels)
    dom_len = len(domain)
    is_ip = is_ip_address_string(hostname)
    is_https = 1 if scheme == "https" else 0
    is_suspicious_tld = 1 if suffix.lower() in SUSPICIOUS_TLDS else 0
    has_hyphen_in_dom = 1 if "-" in domain else 0
    digit_cnt_dom = sum(c.isdigit() for c in domain)
    digit_ratio_dom = round(digit_cnt_dom / dom_len, 4) if dom_len > 0 else 0.0
    entropy_dom = calculate_entropy(domain)

    # 3. Security Indicators
    has_credentials = 1 if (parsed.username or parsed.password) else 0
    has_at = 1 if "@" in url_str else 0

    # Encoding features
    percent_occurrences = url_str.count("%")
    valid_encodings = len(re.findall(r"%[0-9a-fA-F]{2}", url_str))
    nested_encodings = len(re.findall(r"%25[0-9a-fA-F]{2}", url_str, re.IGNORECASE))
    malformed_encodings = 1 if (percent_occurrences > valid_encodings) else 0

    # Suspicious keywords count in URL
    url_lower = url_str.lower()
    keyword_cnt = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Shortener check
    is_shortened = 1 if registered_domain.lower() in SHORTENER_DOMAINS or hostname.lower() in SHORTENER_DOMAINS else 0
    excessive_subdoms = 1 if subdom_cnt >= 3 else 0

    # Punycode / IDN
    has_punycode = 1 if "xn--" in hostname else 0

    # 4. Statistical features
    overall_entropy = calculate_entropy(url_str)

    features = {
        "url_len": url_len,
        "hostname_len": host_len,
        "path_len": path_len,
        "query_len": query_len,
        "dot_cnt": dot_cnt,
        "hyphen_cnt": hyphen_cnt,
        "digit_cnt": digit_cnt,
        "special_cnt": special_cnt,
        "digit_ratio": digit_ratio,
        "alpha_ratio": alpha_ratio,
        "special_ratio": special_ratio,
        "uppercase_ratio": upper_ratio,
        "query_param_cnt": query_param_cnt,
        "separator_cnt": separator_cnt,
        "url_component_cnt": url_component_cnt,
        "subdom_cnt": subdom_cnt,
        "dom_len": dom_len,
        "is_ip": is_ip,
        "is_https": is_https,
        "is_suspicious_tld": is_suspicious_tld,
        "has_hyphen_in_dom": has_hyphen_in_dom,
        "digit_ratio_dom": digit_ratio_dom,
        "entropy_dom": entropy_dom,
        "has_credentials": has_credentials,
        "has_at": has_at,
        "url_encoding_cnt": valid_encodings,
        "has_nested_encoding": 1 if nested_encodings > 0 else 0,
        "has_malformed_encoding": malformed_encodings,
        "suspicious_keyword_cnt": keyword_cnt,
        "is_shortened": is_shortened,
        "excessive_subdoms": excessive_subdoms,
        "has_punycode": has_punycode,
        "overall_entropy": overall_entropy
    }

    return features


def extract_features_with_metadata(url: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Extract features alongside registered domain and hostname metadata.
    Used during dataset preparation for domain-aware grouped splitting.
    """
    features = extract_features_from_url(url)

    url_str = url.strip() if isinstance(url, str) else ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_str):
        parse_target = "http://" + url_str
    else:
        parse_target = url_str

    try:
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").lower()
        ext = _extractor(hostname)
        if hasattr(ext, "top_domain_under_public_suffix"):
            registered_domain = ext.top_domain_under_public_suffix or ""
        else:
            registered_domain = getattr(ext, "registered_domain", "") or hostname or "unknown_domain"
    except Exception:
        hostname = "unknown_host"
        registered_domain = "unknown_domain"

    metadata = {
        "url": url_str,
        "hostname": hostname,
        "registered_domain": registered_domain
    }
    return features, metadata


def get_default_feature_vector() -> Dict[str, Any]:
    """Return a zeroed feature dictionary with the complete schema."""
    return {
        "url_len": 0,
        "hostname_len": 0,
        "path_len": 0,
        "query_len": 0,
        "dot_cnt": 0,
        "hyphen_cnt": 0,
        "digit_cnt": 0,
        "special_cnt": 0,
        "digit_ratio": 0.0,
        "alpha_ratio": 0.0,
        "special_ratio": 0.0,
        "uppercase_ratio": 0.0,
        "query_param_cnt": 0,
        "separator_cnt": 0,
        "url_component_cnt": 0,
        "subdom_cnt": 0,
        "dom_len": 0,
        "is_ip": 0,
        "is_https": 0,
        "is_suspicious_tld": 0,
        "has_hyphen_in_dom": 0,
        "digit_ratio_dom": 0.0,
        "entropy_dom": 0.0,
        "has_credentials": 0,
        "has_at": 0,
        "url_encoding_cnt": 0,
        "has_nested_encoding": 0,
        "has_malformed_encoding": 0,
        "suspicious_keyword_cnt": 0,
        "is_shortened": 0,
        "excessive_subdoms": 0,
        "has_punycode": 0,
        "overall_entropy": 0.0
    }


FEATURE_NAMES = list(get_default_feature_vector().keys())
