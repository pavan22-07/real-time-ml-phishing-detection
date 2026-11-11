
import json
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

if __package__:
    from . import threat_intel
else:
    import threat_intel


class ThreatIntelligenceTests(unittest.TestCase):

    def setUp(self):

        self.temp_dir = tempfile.TemporaryDirectory()

        self.feed_file = Path(self.temp_dir.name) / "feed.txt"
        self.metadata_file = Path(self.temp_dir.name) / "metadata.json"

        self.feed_file.write_text(
            "\n".join([
                "https://malicious.example.invalid/login",
                "http://bad-site.example.invalid/account"
            ]),
            encoding="utf-8"
        )

        from datetime import datetime, timezone

        self.metadata_file.write_text(
            json.dumps({
                "source": "Test Feed",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "entry_count": 2
            }),
            encoding="utf-8"
        )

        self.feed_patch = patch.object(
            threat_intel,
            "OPENPHISH_FILE",
            self.feed_file
        )

        self.metadata_patch = patch.object(
            threat_intel,
            "METADATA_FILE",
            self.metadata_file
        )

        self.feed_patch.start()
        self.metadata_patch.start()

    def tearDown(self):

        self.feed_patch.stop()
        self.metadata_patch.stop()

        self.temp_dir.cleanup()

    def test_exact_url_match(self):

        result = threat_intel.check_threat_intelligence(
            "https://malicious.example.invalid/login"
        )

        self.assertTrue(result["matched"])
        self.assertEqual(result["match_type"], "EXACT_URL")

    def test_hostname_match(self):

        result = threat_intel.check_threat_intelligence(
            "https://malicious.example.invalid/other-path"
        )

        self.assertTrue(result["matched"])
        self.assertEqual(result["match_type"], "HOSTNAME")

    def test_subdomain_match(self):

        result = threat_intel.check_threat_intelligence(
            "https://sub.malicious.example.invalid/login"
        )

        self.assertTrue(result["matched"])

    def test_legitimate_url_not_matched(self):

        result = threat_intel.check_threat_intelligence(
            "https://google.com"
        )

        self.assertFalse(result["matched"])

    def test_feed_unavailable(self):

        self.feed_file.unlink()

        result = threat_intel.check_threat_intelligence(
            "https://google.com"
        )

        self.assertFalse(result["available"])
        self.assertEqual(result["feed_status"], "UNAVAILABLE")

    def test_invalid_url(self):

        result = threat_intel.check_threat_intelligence(
            "not-a-valid-url"
        )

        self.assertFalse(result["available"])
        self.assertFalse(result["matched"])

    def test_feed_stale(self):

        from datetime import datetime, timezone, timedelta

        old_time = (
            datetime.now(timezone.utc) - timedelta(hours=48)
        ).isoformat()

        self.metadata_file.write_text(
            json.dumps({
                "source": "Test Feed",
                "updated_at": old_time,
                "entry_count": 2
            }),
            encoding="utf-8"
        )

        result = threat_intel.check_threat_intelligence(
            "https://google.com"
        )

        self.assertEqual(result["feed_status"], "STALE")
        self.assertFalse(result["matched"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
