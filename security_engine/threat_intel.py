
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
            "urls": set(),
            "hostnames": set(),
            "metadata": None
        }

    try:
        lines = OPENPHISH_FILE.read_text(
            encoding="utf-8"
        ).splitlines()

    except OSError:
        return {
            "available": False,
            "urls": set(),
            "hostnames": set(),
            "metadata": None
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

    return {
        "available": True,
        "urls": urls,
        "hostnames": hostnames,
        "metadata": load_metadata()
    }


def feed_status(feed):

    metadata = feed.get("metadata")

    if not feed["available"] or not metadata:
        return "UNAVAILABLE"

    try:
        updated_at = datetime.fromisoformat(
            metadata["updated_at"]
        )

        if updated_at.tzinfo is None:
            updated_at = updated_at.replace(
                tzinfo=timezone.utc
            )

        age = utc_now() - updated_at

        if age > timedelta(hours=FEED_STALE_AFTER_HOURS):
            return "STALE"

        return "FRESH"

    except (ValueError, KeyError, TypeError):
        return "UNKNOWN"


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
            "reason": "Local threat intelligence feed unavailable"
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
