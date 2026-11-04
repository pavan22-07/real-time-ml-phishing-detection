
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
import tldextract


MAX_REDIRECTS = 10
TIMEOUT = (3, 5)

REDIRECT_CODES = {301, 302, 303, 307, 308}


def validate_public_url(url):
    """
    Validate a URL before making an outbound request.

    Reject non-HTTP schemes, credentials, local hosts,
    private IPs and non-public DNS destinations.
    """

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in {"http", "https"}:
            return False, "Only HTTP and HTTPS are supported"

        if not parsed.hostname:
            return False, "Missing hostname"

        if parsed.username is not None or parsed.password is not None:
            return False, "URLs containing credentials are rejected"

        hostname = parsed.hostname.rstrip(".").lower()

        if hostname == "localhost" or hostname.endswith(".localhost"):
            return False, "Localhost destinations are rejected"

        try:
            addresses = {
                ipaddress.ip_address(hostname)
            }
        except ValueError:
            try:
                records = socket.getaddrinfo(
                    hostname,
                    parsed.port or (443 if parsed.scheme == "https" else 80),
                    type=socket.SOCK_STREAM
                )

                addresses = {
                    ipaddress.ip_address(record[4][0])
                    for record in records
                }

            except socket.gaierror:
                return False, "DNS resolution failed"

        if not addresses:
            return False, "No IP addresses found"

        for address in addresses:
            if not address.is_global:
                return False, f"Non-public IP destination rejected: {address}"

        return True, "URL passed preliminary destination validation"

    except (ValueError, UnicodeError):
        return False, "Invalid URL"


def get_registered_domain(hostname):
    if not hostname:
        return None

    extracted = tldextract.extract(hostname)

    if not extracted.suffix:
        return None

    return f"{extracted.domain}.{extracted.suffix}"


def normalize_url(url):
    parsed = urlsplit(url)

    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path or "/",
        parsed.query,
        ""  # Fragments are not sent in HTTP requests
    ))


def analyze_redirects(url, max_redirects=MAX_REDIRECTS):

    if not isinstance(max_redirects, int) or not 0 <= max_redirects <= 10:
        raise ValueError("max_redirects must be between 0 and 10")

    chain = []
    visited = set()

    current_url = url
    redirect_count = 0
    loop_detected = False
    downgrade_detected = False
    external_redirects = []
    error = None
    final_status = None
    stop_reason = None

    session = requests.Session()

    # Do not inherit proxy settings from the environment.
    session.trust_env = False

    try:
        while True:

            normalized = normalize_url(current_url)

            if normalized in visited:
                loop_detected = True
                stop_reason = "Redirect loop detected"
                break

            visited.add(normalized)

            valid, validation_message = validate_public_url(current_url)

            if not valid:
                error = validation_message
                stop_reason = "Destination rejected"
                break

            parsed_current = urlsplit(current_url)
            current_host = parsed_current.hostname

            try:
                response = session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=TIMEOUT,
                    stream=True,
                    verify=True,
                    headers={
                        "User-Agent": "PhishingSecurityAnalyzer/1.0",
                        "Accept": "*/*"
                    }
                )

            except requests.RequestException as exc:
                error = f"HTTP request failed: {type(exc).__name__}"
                stop_reason = "Request failed"
                break

            try:
                status = response.status_code
                final_status = status

                entry = {
                    "url": current_url,
                    "hostname": current_host,
                    "status_code": status,
                    "registered_domain": get_registered_domain(
                        current_host
                    )
                }

                chain.append(entry)

                if status not in REDIRECT_CODES:
                    stop_reason = "Final response reached"
                    break

                location = response.headers.get("Location")

                if not location:
                    stop_reason = "Redirect response without Location header"
                    break

                next_url = urljoin(current_url, location)

                old_scheme = parsed_current.scheme.lower()
                new_scheme = urlsplit(next_url).scheme.lower()

                if old_scheme == "https" and new_scheme == "http":
                    downgrade_detected = True

                next_valid, next_message = validate_public_url(next_url)

                if not next_valid:
                    error = next_message
                    stop_reason = "Redirect destination rejected"
                    break

                next_host = urlsplit(next_url).hostname

                old_domain = get_registered_domain(current_host)
                new_domain = get_registered_domain(next_host)

                if old_domain != new_domain:
                    external_redirects.append({
                        "from": current_host,
                        "to": next_host
                    })

                if normalize_url(next_url) in visited:
                    loop_detected = True
                    stop_reason = "Redirect loop detected"
                    break

                if redirect_count >= max_redirects:
                    stop_reason = "Maximum redirect limit reached"
                    break

                redirect_count += 1
                current_url = next_url

            finally:
                response.close()

    finally:
        session.close()

    final_url = chain[-1]["url"] if chain else None

    if redirect_count > 0:
        has_redirects = True
    else:
        has_redirects = False

    return {
        "original_url": url,
        "final_url": final_url,
        "redirect_count": redirect_count,
        "has_redirects": has_redirects,
        "redirect_chain": chain,
        "loop_detected": loop_detected,
        "https_downgrade": downgrade_detected,
        "external_redirects": external_redirects,
        "final_status_code": final_status,
        "error": error,
        "stop_reason": stop_reason
    }
