
import hashlib
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


BASE_DIR = Path(__file__).resolve().parent.parent

FEED_DIR = BASE_DIR / "data" / "threat_feeds"

OPENPHISH_FILE = FEED_DIR / "openphish.txt"

METADATA_FILE = FEED_DIR / "openphish_metadata.json"

FEED_STALE_AFTER_HOURS = 24


def utc_now():
    return datetime.now(timezone.utc)


def normalize_url(url):

    try:
        parsed = urlsplit(url.strip())

        if parsed.scheme.lower() not in {"http", "https"}:
            return None

        if not parsed.hostname:
            return None

        if parsed.username is not None or parsed.password is not None:
            return None

        hostname = (
            parsed.hostname.rstrip(".")
            .encode("idna")
            .decode("ascii")
            .lower()
        )

        port = parsed.port

        if port and not (
            (parsed.scheme.lower() == "http" and port == 80)
            or (parsed.scheme.lower() == "https" and port == 443)
        ):
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        return urlunsplit((
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.query,
            ""
        ))

    except (ValueError, UnicodeError, AttributeError):
        return None


def load_metadata():

    if not METADATA_FILE.exists():
        return None

    try:
        return json.loads(
            METADATA_FILE.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return None


def load_feed():
    if not OPENPHISH_FILE.exists():
        return {
            "available": False,
            "malformed": False,
            "urls": set(),
            "hostnames": set(),
            "metadata": None,
            "reason": "Threat feed file does not exist"
        }

    try:
        raw_bytes = OPENPHISH_FILE.read_bytes()
        text = raw_bytes.decode("utf-8")
        lines = text.splitlines()
    except (OSError, UnicodeDecodeError):
        return {
            "available": False,
            "malformed": True,
            "urls": set(),
            "hostnames": set(),
            "metadata": None,
            "reason": "Threat feed file could not be read or decoded"
        }

    metadata = load_metadata()
    if metadata is None or not isinstance(metadata, dict):
        return {
            "available": False,
            "malformed": True,
            "urls": set(),
            "hostnames": set(),
            "metadata": None,
            "reason": "Threat feed metadata is missing, unreadable, or not a JSON object"
        }

    # Validate required metadata fields
    source = metadata.get("source")
    if not isinstance(source, str) or not source.strip():
        return {
            "available": False,
            "malformed": True,
            "urls": set(),
            "hostnames": set(),
            "metadata": metadata,
            "reason": "Threat feed metadata missing or invalid 'source' field"
        }

    updated_at_str = metadata.get("updated_at")
    if not isinstance(updated_at_str, str) or not updated_at_str.strip():
        return {
            "available": False,
            "malformed": True,
            "urls": set(),
            "hostnames": set(),
            "metadata": metadata,
            "reason": "Threat feed metadata missing or empty 'updated_at' field"
        }
    try:
        datetime.fromisoformat(updated_at_str)
    except (ValueError, TypeError):
        return {
            "available": False,
            "malformed": True,
            "urls": set(),
            "hostnames": set(),
            "metadata": metadata,
            "reason": "Threat feed metadata 'updated_at' is not a valid ISO timestamp"
        }

    entry_count = metadata.get("entry_count")
    if not isinstance(entry_count, int) or isinstance(entry_count, bool) or entry_count < 0:
        return {
            "available": False,
            "malformed": True,
            "urls": set(),
            "hostnames": set(),
            "metadata": metadata,
            "reason": "Threat feed metadata missing or invalid 'entry_count' field"
        }

    sha256_val = metadata.get("sha256")
    if not isinstance(sha256_val, str) or not sha256_val.strip():
        return {
            "available": False,
            "malformed": True,
            "urls": set(),
            "hostnames": set(),
            "metadata": metadata,
            "reason": "Threat feed metadata missing or empty 'sha256' field"
        }

    # Verify checksum consistency against metadata
    actual_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    if actual_sha256.lower() != sha256_val.strip().lower():
        return {
            "available": False,
            "malformed": True,
            "urls": set(),
            "hostnames": set(),
            "metadata": metadata,
            "reason": "Threat feed checksum does not match metadata"
        }

    urls = set()
    hostnames = set()

    for line in lines:
        normalized = normalize_url(line)
        if normalized:
            urls.add(normalized)
            hostname = urlsplit(normalized).hostname
            if hostname:
                hostnames.add(hostname)

    # Validate actual unique valid entry count against metadata entry_count
    if len(urls) != entry_count:
        return {
            "available": False,
            "malformed": True,
            "urls": set(),
            "hostnames": set(),
            "metadata": metadata,
            "reason": f"Threat feed actual valid entry count ({len(urls)}) does not match metadata entry_count ({entry_count})"
        }

    return {
        "available": True,
        "urls": urls,
        "hostnames": hostnames,
        "metadata": metadata
    }


def feed_status(feed):
    if feed.get("malformed"):
        return "MALFORMED"

    if not feed.get("available", False):
        return "UNAVAILABLE"

    metadata = feed.get("metadata")
    if not metadata or not isinstance(metadata, dict):
        return "MALFORMED"

    try:
        updated_at_str = metadata.get("updated_at")
        if not updated_at_str or not isinstance(updated_at_str, str):
            return "MALFORMED"

        updated_at = datetime.fromisoformat(updated_at_str)

        if updated_at.tzinfo is None:
            updated_at = updated_at.replace(
                tzinfo=timezone.utc
            )

        age = utc_now() - updated_at

        if age > timedelta(hours=FEED_STALE_AFTER_HOURS):
            return "STALE"

        return "FRESH"

    except (ValueError, KeyError, TypeError):
        return "MALFORMED"


def check_threat_intelligence(url):
    normalized = normalize_url(url)

    if not normalized:
        return {
            "available": False,
            "feed_status": "UNAVAILABLE",
            "matched": False,
            "match_type": None,
            "matched_indicator": None,
            "source": "OpenPhish Community",
            "reason": "Invalid URL supplied"
        }

    feed = load_feed()

    status = feed_status(feed)

    if not feed["available"]:
        return {
            "available": False,
            "feed_status": status,
            "matched": False,
            "match_type": None,
            "matched_indicator": None,
            "source": "OpenPhish Community",
            "reason": feed.get("reason", "Local threat intelligence feed unavailable")
        }

    hostname = urlsplit(normalized).hostname

    # Exact URL match
    if normalized in feed["urls"]:

        return {
            "available": True,
            "feed_status": status,
            "matched": True,
            "match_type": "EXACT_URL",
            "matched_indicator": normalized,
            "source": "OpenPhish Community",
            "reason": "Exact URL match found in phishing feed"
        }

    # Hostname or subdomain match
    matched_host = next(
        (
            indicator
            for indicator in feed["hostnames"]
            if hostname == indicator
            or hostname.endswith("." + indicator)
        ),
        None
    )

    if matched_host:

        return {
            "available": True,
            "feed_status": status,
            "matched": True,
            "match_type": "HOSTNAME",
            "matched_indicator": matched_host,
            "source": "OpenPhish Community",
            "reason": "Hostname matches a phishing intelligence indicator"
        }

    return {
        "available": True,
        "feed_status": status,
        "matched": False,
        "match_type": None,
        "matched_indicator": None,
        "source": "OpenPhish Community",
        "reason": "No matching indicator found in local feed"
    }
