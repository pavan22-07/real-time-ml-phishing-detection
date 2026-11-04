from urllib.parse import urlparse,unquote
import ipaddress
import re
import tldextract
import unicodedata


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
    encoding_features = analyze_encoding(url)
    parsed = urlparse(url)
    hostname = parsed.hostname
    has_url_credentials = (
    parsed.username is not None
    or parsed.password is not None
)

    if hostname:
        domain_info = tldextract.extract(hostname)

        subdomain = domain_info.subdomain

        registered_domain = (
            f"{domain_info.domain}.{domain_info.suffix}"
            if domain_info.suffix
            else None
        )
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
        idn_features = analyze_idn(None)
    

    try:
        ipaddress.ip_address(hostname)
        has_ip = True
    except (ValueError, TypeError):
        has_ip = False

    special_chars = "@-_%?=&"
    special_count = sum(url.count(char) for char in special_chars)

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
        if word in url.lower():
            found_keywords.append(word)

    return {
        "hostname": hostname,
        "subdomain": subdomain,
        "registered_domain": registered_domain,
        "subdomain_count": subdomain_count,
        "url_length": len(url),
        "dot_count": parsed.netloc.count("."),
        "has_ip": has_ip,
        "special_char_count": special_count,
        "uses_https": parsed.scheme == "https",
        "suspicious_keywords": found_keywords,
        "has_at_symbol": "@" in url,
        "has_encoding": "%" in url,
        "has_hyphen": "-" in parsed.netloc,
        "encoding_analysis": encoding_features,
        "idn_analysis": idn_features,
        "has_url_credentials": has_url_credentials,
        "has_at_symbol": "@" in url,
    }

