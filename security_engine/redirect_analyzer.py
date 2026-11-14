"""
Redirect Analyzer and SSRF Protection Module.
Inspects HTTP/HTTPS redirect chains safely with full SSRF mitigation,
IP pinning to prevent DNS rebinding/TOCTOU, and offline TLD extraction.
"""

from pathlib import Path
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit, urlunsplit
from typing import Dict, Any, List, Optional, Tuple, Set

import requests
from requests.adapters import HTTPAdapter
import urllib3
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.util import connection
import tldextract

# Local offline tldextract configuration
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TLD_CACHE_DIR = PROJECT_ROOT / "data" / ".tld_cache"
TLD_CACHE_DIR.mkdir(parents=True, exist_ok=True)

_extractor = tldextract.TLDExtract(
    cache_dir=str(TLD_CACHE_DIR),
    fallback_to_snapshot=True,
    suffix_list_urls=None
)

MAX_REDIRECTS = 10
TIMEOUT = (3, 5)
REDIRECT_CODES = {301, 302, 303, 307, 308}

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

BLOCKED_IP_STRINGS = {
    "169.254.169.254",   # AWS / GCP / Azure link-local metadata
    "fd00:ec2::254",      # AWS IPv6 metadata
    "100.100.100.200",    # Alibaba Cloud metadata
}


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """
    Check if an IP address is safe and publicly routable.
    Rejects loopback, private, link-local, multicast, reserved,
    unspecified, IPv4-mapped private/link-local IPv6, and cloud metadata.
    """
    ip_str = str(ip).lower()
    if ip_str in BLOCKED_IP_STRINGS:
        return False, f"Cloud metadata IP rejected: {ip_str}"

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_public_ip(ip.ipv4_mapped)

    if ip.is_loopback:
        return False, f"Loopback IP rejected: {ip_str}"
    if ip.is_link_local:
        return False, f"Link-local IP rejected: {ip_str}"
    if ip.is_private:
        return False, f"Private IP rejected: {ip_str}"
    if ip.is_multicast:
        return False, f"Multicast IP rejected: {ip_str}"
    if ip.is_reserved:
        return False, f"Reserved IP rejected: {ip_str}"
    if ip.is_unspecified:
        return False, f"Unspecified IP rejected: {ip_str}"
    if not ip.is_global:
        return False, f"Non-global IP rejected: {ip_str}"

    return True, "IP is public"


def validate_and_resolve_destination(
    url: str,
    resolver=socket.getaddrinfo
) -> Tuple[bool, Optional[str], Optional[str], List[str]]:
    """
    Validate a destination URL and resolve all IP addresses.
    Rejects non-HTTP schemes, URL credentials, localhost/metadata hostnames,
    and non-public/private/reserved IP addresses.

    Returns:
        (is_valid, validated_ip, error_message, all_resolved_ips)
    """
    if not url or not isinstance(url, str):
        return False, None, "Invalid or empty URL", []

    try:
        parsed = urlsplit(url.strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            return False, None, "Only HTTP and HTTPS are supported", []

        if not parsed.hostname:
            return False, None, "Missing hostname in URL", []

        if parsed.username is not None or parsed.password is not None:
            return False, None, "URLs containing credentials are rejected", []

        hostname = parsed.hostname.rstrip(".").lower()

        if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".localhost"):
            return False, None, f"Blocked hostname rejected: {hostname}", []

        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

        # Check if hostname is already a raw literal IP
        try:
            literal_ip = ipaddress.ip_address(hostname)
            is_pub, msg = is_public_ip(literal_ip)
            if not is_pub:
                return False, None, msg, [str(literal_ip)]
            return True, str(literal_ip), None, [str(literal_ip)]
        except ValueError:
            pass

        # Resolve all DNS A/AAAA records
        try:
            records = resolver(
                hostname,
                port,
                type=socket.SOCK_STREAM
            )
        except (socket.gaierror, socket.herror) as exc:
            return False, None, f"DNS resolution failed: {exc}", []
        except Exception as exc:
            return False, None, f"DNS resolution error: {exc}", []

        if not records:
            return False, None, "No DNS records returned for hostname", []

        resolved_ips: List[str] = []
        for record in records:
            ip_str = record[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                return False, None, f"Invalid resolved IP format: {ip_str}", []

            is_pub, msg = is_public_ip(ip_obj)
            if not is_pub:
                return False, None, f"Destination resolved to non-public IP ({msg})", resolved_ips
            resolved_ips.append(str(ip_obj))

        if not resolved_ips:
            return False, None, "No valid IP addresses found for hostname", []

        # Return first validated IP to pin TCP connection
        return True, resolved_ips[0], None, resolved_ips

    except (ValueError, UnicodeError) as exc:
        return False, None, f"Invalid URL: {exc}", []


def validate_public_url(url: str, resolver=socket.getaddrinfo) -> Tuple[bool, str]:
    """
    Validate a URL before making an outbound request.
    Maintains backward compatibility with security_engine callers.
    """
    valid, _, err_msg, _ = validate_and_resolve_destination(url, resolver=resolver)
    if valid:
        return True, "URL passed destination validation"
    return False, err_msg or "URL validation failed"


def get_registered_domain(hostname: Optional[str]) -> Optional[str]:
    """Extract registered domain label using offline tldextract."""
    if not hostname:
        return None
    extracted = _extractor(hostname)
    if not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}"


def normalize_url(url: str) -> str:
    """Normalize URL by stripping fragments and lowercasing scheme/netloc."""
    parsed = urlsplit(url)
    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path or "/",
        parsed.query,
        ""
    ))


class PinnedHTTPConnection(HTTPConnection):
    """HTTPConnection that connects directly to pinned_ip, bypassing DNS."""
    pinned_ip: Optional[str] = None

    def _new_conn(self) -> socket.socket:
        target_ip = self.pinned_ip or self._dns_host
        try:
            return connection.create_connection(
                (target_ip, self.port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except socket.gaierror as e:
            raise urllib3.exceptions.NameResolutionError(self.host, self, e) from e
        except socket.timeout as e:
            raise urllib3.exceptions.ConnectTimeoutError(
                self, f"Connection to {self.host} ({target_ip}) timed out."
            ) from e
        except OSError as e:
            raise urllib3.exceptions.NewConnectionError(
                self, f"Failed to establish connection to {self.host} ({target_ip}): {e}"
            ) from e


class PinnedHTTPSConnection(HTTPSConnection):
    """HTTPSConnection that connects directly to pinned_ip with SNI & cert verification for host."""
    pinned_ip: Optional[str] = None

    def _new_conn(self) -> socket.socket:
        target_ip = self.pinned_ip or self._dns_host
        try:
            return connection.create_connection(
                (target_ip, self.port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except socket.gaierror as e:
            raise urllib3.exceptions.NameResolutionError(self.host, self, e) from e
        except socket.timeout as e:
            raise urllib3.exceptions.ConnectTimeoutError(
                self, f"Connection to {self.host} ({target_ip}) timed out."
            ) from e
        except OSError as e:
            raise urllib3.exceptions.NewConnectionError(
                self, f"Failed to establish connection to {self.host} ({target_ip}): {e}"
            ) from e


class PinnedHTTPPool(HTTPConnectionPool):
    ConnectionCls = PinnedHTTPConnection


class PinnedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = PinnedHTTPSConnection


class SSRFPinnedAdapter(HTTPAdapter):
    """
    Adapter that forces HTTP/HTTPS connections to connect directly to a
    pre-validated IP address, eliminating DNS-rebinding / TOCTOU.
    Preserves the original hostname for SNI, certificate matching, and HTTP Host header.
    """
    def __init__(self, pinned_ip: str, *args, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
        http_conn = type("SSRFHTTPConn", (PinnedHTTPConnection,), {"pinned_ip": self.pinned_ip})
        https_conn = type("SSRFHTTPSConn", (PinnedHTTPSConnection,), {"pinned_ip": self.pinned_ip})
        http_pool = type("SSRFHTTPPool", (PinnedHTTPPool,), {"ConnectionCls": http_conn})
        https_pool = type("SSRFHTTPSPool", (PinnedHTTPSPool,), {"ConnectionCls": https_conn})
        self.poolmanager.pool_classes_by_scheme = {
            "http": http_pool,
            "https": https_pool
        }


def analyze_redirects(
    url: str,
    max_redirects: int = MAX_REDIRECTS,
    session: Optional[requests.Session] = None,
    resolver=socket.getaddrinfo
) -> Dict[str, Any]:
    """
    Safely inspect HTTP redirect chain with strict SSRF validation and IP pinning.

    Args:
        url: Starting URL.
        max_redirects: Maximum redirects allowed (0-10).
        session: Optional custom requests.Session (for test injection).
        resolver: Optional DNS resolver function (for test injection).

    Returns:
        Structured redirect analysis report.
    """
    if not isinstance(max_redirects, int) or not 0 <= max_redirects <= 10:
        raise ValueError("max_redirects must be an integer between 0 and 10")

    chain: List[Dict[str, Any]] = []
    visited: Set[str] = set()

    current_url = url
    redirect_count = 0
    loop_detected = False
    downgrade_detected = False
    external_redirects: List[Dict[str, str]] = []
    error = None
    final_status = None
    stop_reason = None

    own_session = session is None
    req_session = session or requests.Session()
    # Explicitly disable proxy environment inheritance
    req_session.trust_env = False

    try:
        while True:
            normalized = normalize_url(current_url)

            if normalized in visited:
                loop_detected = True
                stop_reason = "Redirect loop detected"
                break

            visited.add(normalized)

            # Validate destination and resolve all IPs
            valid, pinned_ip, validation_error, _ = validate_and_resolve_destination(
                current_url,
                resolver=resolver
            )

            if not valid:
                error = validation_error
                stop_reason = "Destination rejected"
                break

            parsed_current = urlsplit(current_url)
            current_host = parsed_current.hostname

            # Mount SSRF-pinned adapter to guarantee the connection uses the validated IP
            if pinned_ip:
                pinned_adapter = SSRFPinnedAdapter(pinned_ip)
                req_session.mount("http://", pinned_adapter)
                req_session.mount("https://", pinned_adapter)

            response = None
            try:
                response = req_session.get(
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

                status = response.status_code
                final_status = status

                entry = {
                    "url": current_url,
                    "hostname": current_host,
                    "status_code": status,
                    "registered_domain": get_registered_domain(current_host)
                }
                chain.append(entry)

                if status not in REDIRECT_CODES:
                    stop_reason = "Final response reached"
                    break

                location = response.headers.get("Location")
                if not location or not location.strip():
                    stop_reason = "Redirect response without Location header"
                    break

                try:
                    next_url = urljoin(current_url, location.strip())
                except (ValueError, UnicodeError) as exc:
                    error = f"Malformed redirect Location header: {exc}"
                    stop_reason = "Redirect destination rejected"
                    break

                old_scheme = parsed_current.scheme.lower()
                new_scheme = urlsplit(next_url).scheme.lower()

                if old_scheme == "https" and new_scheme == "http":
                    downgrade_detected = True

                # Pre-validate redirect destination independently before continuing
                next_valid, _, next_msg, _ = validate_and_resolve_destination(
                    next_url,
                    resolver=resolver
                )
                if not next_valid:
                    error = next_msg
                    stop_reason = "Redirect destination rejected"
                    break

                next_host = urlsplit(next_url).hostname
                old_domain = get_registered_domain(current_host)
                new_domain = get_registered_domain(next_host)

                if old_domain and new_domain and old_domain != new_domain:
                    external_redirects.append({
                        "from": current_host or "",
                        "to": next_host or ""
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

            except requests.RequestException as exc:
                error = f"HTTP request failed: {type(exc).__name__}: {exc}"
                stop_reason = "Request failed"
                break

            finally:
                if response is not None:
                    response.close()

    finally:
        if own_session:
            req_session.close()

    final_url = chain[-1]["url"] if chain else None
    has_redirects = redirect_count > 0

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
