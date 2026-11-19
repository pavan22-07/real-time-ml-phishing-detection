from pathlib import Path
from urllib.parse import urlparse, unquote
import ipaddress
import re
import tldextract
import unicodedata

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TLD_CACHE_DIR = PROJECT_ROOT / "data" / ".tld_cache"
TLD_CACHE_DIR.mkdir(parents=True, exist_ok=True)

_extractor = tldextract.TLDExtract(
    cache_dir=str(TLD_CACHE_DIR),
    fallback_to_snapshot=True,
    suffix_list_urls=None
)


def analyze_idn(hostname):

    if not hostname:
        return {
            "has_unicode": False,
            "is_punycode": False,
            "ascii_hostname": None,
            "unicode_hostname": None,
            "mixed_script_labels": [],
            "confusable_characters": [],
            "has_suspicious_confusables": False,
            "invalid_idn": False,
            "requires_idn_review": False
        }

    hostname = unicodedata.normalize("NFC", hostname.lower()).rstrip(".")

    labels = hostname.split(".")
    has_unicode = any(ord(char) > 127 for char in hostname)

    is_punycode = any(
        label.startswith("xn--")
        for label in labels
    )

    invalid_idn = False
    decoded_labels = []

    # Decode Punycode labels into Unicode
    for label in labels:
        try:
            if label.startswith("xn--"):
                decoded = label.encode("ascii").decode("idna")
            else:
                decoded = label

            decoded_labels.append(decoded)

        except (UnicodeError, ValueError):
            decoded_labels.append(label)
            invalid_idn = True

    unicode_hostname = ".".join(decoded_labels)

    # Convert the complete hostname into ASCII IDNA form
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        ascii_hostname = None
        invalid_idn = True

    # Detect scripts used within individual labels
    mixed_script_labels = []

    for label in decoded_labels:
        scripts = set()

        for char in label:
            if not char.isalpha():
                continue

            char_name = unicodedata.name(char, "")

            if "LATIN" in char_name:
                scripts.add("LATIN")
            elif "CYRILLIC" in char_name:
                scripts.add("CYRILLIC")
            elif "GREEK" in char_name:
                scripts.add("GREEK")
            else:
                scripts.add("OTHER")

        if len(scripts) > 1:
            mixed_script_labels.append({
                "label": label,
                "scripts": sorted(scripts)
            })

    # Common Cyrillic and Greek lookalikes
    confusable_map = {
        "а": "a", "е": "e", "о": "o",
        "р": "p", "с": "c", "у": "y",
        "х": "x", "і": "i", "ј": "j",
        "ѕ": "s", "ӏ": "l",
        "Α": "A", "Β": "B", "Ε": "E",
        "Ζ": "Z", "Η": "H", "Ι": "I",
        "Κ": "K", "Μ": "M", "Ν": "N",
        "Ο": "O", "Ρ": "P", "Τ": "T",
        "Χ": "X", "ο": "o", "ρ": "p",
        "ν": "v", "ι": "i"
    }

    confusable_characters = sorted({
        char
        for char in unicode_hostname
        if char in confusable_map
    })

    has_suspicious_confusables = bool(confusable_characters)

    requires_idn_review = any([
        has_unicode,
        is_punycode,
        bool(mixed_script_labels),
        has_suspicious_confusables,
        invalid_idn
    ])

    return {
        "has_unicode": has_unicode,
        "is_punycode": is_punycode,
        "ascii_hostname": ascii_hostname,
        "unicode_hostname": unicode_hostname,
        "mixed_script_labels": mixed_script_labels,
        "confusable_characters": confusable_characters,
        "has_suspicious_confusables": has_suspicious_confusables,
        "invalid_idn": invalid_idn,
        "requires_idn_review": requires_idn_review
    }

def analyze_encoding(url):

    encoded_patterns = re.findall(
        r"%[0-9a-fA-F]{2}",
        url
    )

    decoded_url = unquote(url)

    nested_encoding = bool(
        re.search(r"%[0-9a-fA-F]{2}", decoded_url)
    )

    malformed_encoding = bool(
        re.search(r"%(?![0-9a-fA-F]{2})", url)
    )

    return {
        "has_encoding": len(encoded_patterns) > 0,
        "encoded_count": len(encoded_patterns),
        "nested_encoding": nested_encoding,
        "malformed_encoding": malformed_encoding,
        "decoded_url": decoded_url
    }


def analyze_url(url):
    if url is None or not isinstance(url, str):
        raise ValueError("URL must be a string")
    clean_url = url.strip()
    if not clean_url:
        raise ValueError("URL cannot be empty or whitespace")

    encoding_features = analyze_encoding(clean_url)
    parse_target = clean_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url) and not clean_url.startswith("//"):
        parse_target = "//" + clean_url

    try:
        parsed = urlparse(parse_target)
    except Exception as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc

    raw_hostname = parsed.hostname
    has_trailing_dot = bool(raw_hostname and raw_hostname.endswith("."))
    hostname = raw_hostname.rstrip(".").lower() if raw_hostname else None

    has_url_credentials = (
        parsed.username is not None
        or parsed.password is not None
        or (parsed.netloc and "@" in parsed.netloc)
    )

    port = parsed.port
    scheme_lower = (parsed.scheme or "").lower()
    has_unusual_port = bool(
        port is not None
        and not (
            (scheme_lower == "http" and port == 80)
            or (scheme_lower == "https" and port == 443)
        )
    )

    SUSPICIOUS_EXTENSIONS = (
        ".exe", ".scr", ".bat", ".cmd", ".msi", ".apk",
        ".vbs", ".ps1", ".hta", ".iso", ".jar", ".zip", ".rar", ".7z"
    )
    path_lower = parsed.path.lower() if parsed.path else ""
    has_suspicious_extension = any(
        path_lower.endswith(ext) or f"{ext}?" in clean_url.lower()
        for ext in SUSPICIOUS_EXTENSIONS
    )

    try:
        parsed_ip = ipaddress.ip_address(hostname) if hostname else None
        has_ip = parsed_ip is not None
        has_private_ip = bool(
            has_ip and (
                parsed_ip.is_private
                or parsed_ip.is_loopback
                or parsed_ip.is_link_local
                or parsed_ip.is_reserved
                or not parsed_ip.is_global
            )
        )
    except (ValueError, TypeError):
        has_ip = False
        has_private_ip = False

    if hostname and not has_ip:
        domain_info = _extractor(hostname)

        if domain_info.suffix:
            subdomain = domain_info.subdomain
            registered_domain = f"{domain_info.domain}.{domain_info.suffix}"
        else:
            # Fallback for reserved/private TLDs not in PSL snapshot (e.g. .test, .example, .local)
            parts = hostname.split(".")
            if len(parts) >= 2:
                registered_domain = f"{parts[-2]}.{parts[-1]}"
                subdomain = ".".join(parts[:-2])
            else:
                registered_domain = parts[0]
                subdomain = ""

        idn_features = analyze_idn(hostname)

        subdomain_count = (
            len(subdomain.split("."))
            if subdomain
            else 0
        )

    else:
        subdomain = ""
        registered_domain = None
        subdomain_count = 0
        idn_features = analyze_idn(hostname if hostname else None)

    # Credential/payment context is evaluated only in the path and query,
    # never in the hostname. This is used together with brand impersonation
    # evidence; by itself it is not sufficient to classify a URL as malicious.
    path_query_text = unquote(f"{parsed.path}?{parsed.query}").lower()
    path_words = set(re.findall(r"[a-z0-9]+", path_query_text))
    path_hyphenated = set(re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)+", path_query_text))
    all_path_tokens = path_words | path_hyphenated

    STRONG_CREDENTIAL_TERMS = {
        "password", "passcode", "checkout", "payment", "billing",
        "wallet", "authentication", "credential", "credentials",
    }
    GENERIC_CREDENTIAL_TERMS = {
        "login", "signin", "verify", "verification", "account",
        "secure", "update", "confirm", "portal", "profile", "access", "reset"
    }

    detected_strong = sorted(
        t for t in all_path_tokens
        if t in STRONG_CREDENTIAL_TERMS
        or any(k in t for k in ("password-reset", "reset-password", "credential", "payment", "checkout", "billing", "authentication"))
    )

    detected_generic = sorted(
        t for t in all_path_tokens
        if t in GENERIC_CREDENTIAL_TERMS
    )

    detected_credential_context = sorted(set(detected_strong) | set(detected_generic))

    special_chars = "@-_%?=&"
    special_count = sum(clean_url.count(char) for char in special_chars)

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "bank"
    ]

    found_keywords = []

    for word in suspicious_keywords:
        if word in clean_url.lower():
            found_keywords.append(word)

    return {
        "hostname": hostname,
        "raw_hostname": raw_hostname,
        "has_trailing_dot": has_trailing_dot,
        "subdomain": subdomain,
        "registered_domain": registered_domain,
        "subdomain_count": subdomain_count,
        "url_length": len(clean_url),
        "dot_count": parsed.netloc.count("."),
        "has_ip": has_ip,
        "has_private_ip": has_private_ip,
        "port": port,
        "has_unusual_port": has_unusual_port,
        "has_suspicious_extension": has_suspicious_extension,
        "special_char_count": special_count,
        "uses_https": parsed.scheme == "https",
        "suspicious_keywords": found_keywords,
        "has_at_symbol": "@" in clean_url,
        "has_encoding": "%" in clean_url,
        "has_hyphen": "-" in parsed.netloc,
        "encoding_analysis": encoding_features,
        "idn_analysis": idn_features,
        "has_url_credentials": has_url_credentials,
        "credential_context_terms": detected_credential_context,
        "strong_credential_terms": detected_strong,
        "generic_credential_terms": detected_generic,
        "has_strong_credential_context": bool(detected_strong),
        "has_credential_context": bool(detected_credential_context),
    }

