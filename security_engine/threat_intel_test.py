
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
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

        feed_bytes = self.feed_file.read_bytes()
        self.valid_hash = hashlib.sha256(feed_bytes).hexdigest()

        self.metadata_file.write_text(
            json.dumps({
                "source": "Test Feed",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "entry_count": 2,
                "sha256": self.valid_hash
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

        old_time = (
            datetime.now(timezone.utc) - timedelta(hours=48)
        ).isoformat()

        self.metadata_file.write_text(
            json.dumps({
                "source": "Test Feed",
                "updated_at": old_time,
                "entry_count": 2,
                "sha256": self.valid_hash
            }),
            encoding="utf-8"
        )

        result = threat_intel.check_threat_intelligence(
            "https://google.com"
        )

        self.assertEqual(result["feed_status"], "STALE")
        self.assertFalse(result["matched"])

    def test_missing_threat_feed_checksum(self):
        # Metadata without sha256 checksum field
        self.metadata_file.write_text(
            json.dumps({
                "source": "Test Feed",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "entry_count": 2
            }),
            encoding="utf-8"
        )

        result = threat_intel.check_threat_intelligence("https://malicious.example.invalid/login")
        self.assertFalse(result["available"])
        self.assertEqual(result["feed_status"], "MALFORMED")
        self.assertIn("sha256", result["reason"].lower())

    def test_missing_entry_count(self):
        # Metadata without entry_count field
        self.metadata_file.write_text(
            json.dumps({
                "source": "Test Feed",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "sha256": self.valid_hash
            }),
            encoding="utf-8"
        )

        result = threat_intel.check_threat_intelligence("https://malicious.example.invalid/login")
        self.assertFalse(result["available"])
        self.assertEqual(result["feed_status"], "MALFORMED")
        self.assertIn("entry_count", result["reason"].lower())

    def test_incorrect_entry_count(self):
        # Metadata entry_count says 50, but feed has only 2 unique valid URLs
        self.metadata_file.write_text(
            json.dumps({
                "source": "Test Feed",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "entry_count": 50,
                "sha256": self.valid_hash
            }),
            encoding="utf-8"
        )

        result = threat_intel.check_threat_intelligence("https://malicious.example.invalid/login")
        self.assertFalse(result["available"])
        self.assertEqual(result["feed_status"], "MALFORMED")
        self.assertIn("entry count", result["reason"].lower())

    def test_missing_timestamp(self):
        # Metadata without updated_at timestamp field
        self.metadata_file.write_text(
            json.dumps({
                "source": "Test Feed",
                "entry_count": 2,
                "sha256": self.valid_hash
            }),
            encoding="utf-8"
        )

        result = threat_intel.check_threat_intelligence("https://malicious.example.invalid/login")
        self.assertFalse(result["available"])
        self.assertEqual(result["feed_status"], "MALFORMED")
        self.assertIn("updated_at", result["reason"].lower())

    def test_malformed_metadata_json(self):
        # Metadata file contains corrupted JSON
        self.metadata_file.write_text(
            "{ invalid json broken content",
            encoding="utf-8"
        )

        result = threat_intel.check_threat_intelligence("https://malicious.example.invalid/login")
        self.assertFalse(result["available"])
        self.assertEqual(result["feed_status"], "MALFORMED")
        self.assertIn("metadata", result["reason"].lower())

    def test_missing_metadata_file(self):
        # Metadata file removed entirely
        self.metadata_file.unlink()

        result = threat_intel.check_threat_intelligence("https://malicious.example.invalid/login")
        self.assertFalse(result["available"])
        self.assertEqual(result["feed_status"], "MALFORMED")
        self.assertIn("metadata", result["reason"].lower())

    def test_feed_checksum_mismatch_detected(self):
        self.metadata_file.write_text(
            json.dumps({
                "source": "Test Feed",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "entry_count": 2,
                "sha256": "badbeef000000000000000000000000000000000000000000000000000000000"
            }),
            encoding="utf-8"
        )

        result = threat_intel.check_threat_intelligence("https://google.com")
        self.assertFalse(result["available"])
        self.assertEqual(result["feed_status"], "MALFORMED")
        self.assertIn("checksum", result["reason"].lower())

    def test_feed_checksum_valid(self):
        feed_bytes = self.feed_file.read_bytes()
        valid_hash = hashlib.sha256(feed_bytes).hexdigest()
        self.metadata_file.write_text(
            json.dumps({
                "source": "Test Feed",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "entry_count": 2,
                "sha256": valid_hash
            }),
            encoding="utf-8"
        )

        result = threat_intel.check_threat_intelligence("https://malicious.example.invalid/login")
        self.assertTrue(result["available"])
        self.assertEqual(result["feed_status"], "FRESH")
        self.assertTrue(result["matched"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
