
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

if __package__:
    from .threat_intel import (
        FEED_DIR,
        OPENPHISH_FILE,
        METADATA_FILE
    )
else:
    from threat_intel import (
        FEED_DIR,
        OPENPHISH_FILE,
        METADATA_FILE
    )


OPENPHISH_URL = "https://openphish.com/feed.txt"

MAX_FEED_SIZE = 20 * 1024 * 1024
TIMEOUT = (5, 30)


def update_openphish_feed():

    FEED_DIR.mkdir(parents=True, exist_ok=True)

    try:
        response = requests.get(
            OPENPHISH_URL,
            timeout=TIMEOUT,
            verify=True,
            stream=True,
            headers={
                "User-Agent": "PhishingDetectionMiniProject/1.0"
            }
        )

        response.raise_for_status()

        content = bytearray()

        for chunk in response.iter_content(chunk_size=65536):

            if not chunk:
                continue

            content.extend(chunk)

            if len(content) > MAX_FEED_SIZE:
                raise ValueError("Feed exceeds maximum permitted size")

        response.close()

        text = content.decode("utf-8-sig")

        valid_urls = []

        for line in text.splitlines():

            line = line.strip()

            if not line:
                continue

            if not line.startswith(("http://", "https://")):
                continue

            valid_urls.append(line)

        # Avoid replacing a previously working feed with empty or
        # obviously invalid data.
        if not valid_urls:
            raise ValueError("Downloaded feed contains no valid URLs")

        unique_urls = sorted(set(valid_urls))

        feed_content = "\n".join(unique_urls) + "\n"
        feed_bytes = feed_content.encode("utf-8")

        checksum = hashlib.sha256(feed_bytes).hexdigest()

        updated_at = datetime.now(timezone.utc).isoformat()

        metadata = {
            "source": "OpenPhish Community",
            "updated_at": updated_at,
            "entry_count": len(unique_urls),
            "sha256": checksum,
            "feed_url": OPENPHISH_URL
        }

        # Write temporary files first.
        temporary_feed = OPENPHISH_FILE.with_suffix(".tmp")
        temporary_metadata = METADATA_FILE.with_suffix(".tmp")

        temporary_feed.write_bytes(feed_bytes)

        temporary_metadata.write_text(
            json.dumps(metadata, indent=4),
            encoding="utf-8"
        )

        # Replace existing files only after successful validation.
        os.replace(temporary_feed, OPENPHISH_FILE)
        os.replace(temporary_metadata, METADATA_FILE)

        print("OpenPhish feed updated successfully")
        print("Entries:", len(unique_urls))
        print("SHA-256:", checksum)
        print("Updated:", updated_at)

        return metadata

    except (
        requests.RequestException,
        UnicodeError,
        OSError,
        ValueError
    ) as exc:

        print("Threat feed update failed:", type(exc).__name__, str(exc))
        print("Previous feed, if present, has been retained.")

        return None


if __name__ == "__main__":
    update_openphish_feed()
