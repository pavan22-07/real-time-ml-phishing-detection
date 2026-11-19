"""
Automated test suite for scans module and dashboard metrics.
Includes unit tests with mocked engine boundary and integration tests with real Unified Engine.
"""

import uuid
from datetime import timedelta
from unittest.mock import patch
from django.contrib.auth.models import User
from django.utils import timezone
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from .models import ScanHistory


class ScanAPITests(APITestCase):
    """Unit and functional tests for the URL scan endpoints and dashboard stats."""

    def setUp(self):
        self.user1 = User.objects.create_user(
            username="user_one",
            email="user_one@example.com",
            password="Password123!"
        )
        self.user2 = User.objects.create_user(
            username="user_two",
            email="user_two@example.com",
            password="Password123!"
        )
        self.scan_url_endpoint = reverse("scan-list-create")
        self.dashboard_stats_endpoint = reverse("dashboard-stats")

        # Mock standard ALLOW response from Unified Engine
        self.mock_allow_result = {
            "url": "https://example.com/",
            "final_decision": "ALLOW",
            "degraded_mode": False,
            "reasons": ["All security checks passed"],
            "warnings": [],
            "errors": {"cybersecurity": None, "machine_learning": None},
            "engine_statuses": {"cybersecurity": "OK", "machine_learning": "OK"},
            "engines": {
                "cybersecurity": {
                    "status": "OK",
                    "verdict": "BENIGN",
                    "confidence": 0.0,
                    "raw_result": {
                        "final_decision": {"decision": "ALLOW", "risk_score": 0}
                    }
                },
                "machine_learning": {
                    "status": "OK",
                    "prediction": "LEGITIMATE",
                    "confidence": 0.04,
                    "is_calibrated": False,
                    "raw_result": {
                        "probability": {"phishing": 0.04, "legitimate": 0.96}
                    }
                }
            },
            "inspect_redirects": False,
            "timestamp": "2026-11-17T12:00:00+00:00"
        }

    def test_unauthenticated_scan_rejected(self):
        """Unauthenticated scan request returns HTTP 401."""
        response = self.client.post(self.scan_url_endpoint, {"url": "https://example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_authenticated_successful_scan(self):
        """Authenticated scan delegates to Unified Engine and returns standard response."""
        self.client.force_authenticate(user=self.user1)

        with patch("unified_engine.detector.scan_url", return_value=self.mock_allow_result) as mock_scan:
            response = self.client.post(
                self.scan_url_endpoint,
                {"url": "https://example.com"},
                format="json"
            )
            mock_scan.assert_called_once_with("https://example.com", inspect_redirects=False)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["final_decision"], "ALLOW")
        self.assertFalse(response.data["degraded_mode"])
        self.assertEqual(response.data["cybersecurity"]["status"], "OK")
        self.assertEqual(response.data["cybersecurity"]["verdict"], "BENIGN")
        self.assertEqual(response.data["cybersecurity"]["risk_score"], 0)
        self.assertEqual(response.data["machine_learning"]["status"], "OK")
        self.assertEqual(response.data["machine_learning"]["prediction"], "LEGITIMATE")
        self.assertEqual(response.data["machine_learning"]["raw_phishing_probability"], 0.04)
        self.assertFalse(response.data["machine_learning"]["is_calibrated"])
        self.assertIn("id", response.data)

        # Verify database persistence
        scan_id = response.data["id"]
        saved_scan = ScanHistory.objects.get(id=scan_id)
        self.assertEqual(saved_scan.user, self.user1)
        self.assertEqual(saved_scan.final_decision, "ALLOW")

    def test_missing_url(self):
        """Scan request missing 'url' key returns HTTP 400."""
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(self.scan_url_endpoint, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("url", response.data)

    def test_empty_url(self):
        """Scan request with empty string URL returns HTTP 400."""
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(self.scan_url_endpoint, {"url": ""}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("url", response.data)

    def test_whitespace_url(self):
        """Scan request with whitespace-only URL returns HTTP 400."""
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(self.scan_url_endpoint, {"url": "    "}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_engine_returns_warn(self):
        """Unified Engine WARN verdict is properly saved and returned."""
        self.client.force_authenticate(user=self.user1)
        mock_warn = dict(self.mock_allow_result)
        mock_warn["final_decision"] = "WARN"
        mock_warn["reasons"] = ["Heuristic warning triggered"]
        mock_warn["engines"]["cybersecurity"]["verdict"] = "SUSPICIOUS"
        mock_warn["engines"]["cybersecurity"]["raw_result"]["final_decision"]["risk_score"] = 55

        with patch("unified_engine.detector.scan_url", return_value=mock_warn):
            response = self.client.post(
                self.scan_url_endpoint,
                {"url": "https://suspicious-site.example"},
                format="json"
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["final_decision"], "WARN")
        self.assertEqual(response.data["cybersecurity"]["verdict"], "SUSPICIOUS")
        self.assertEqual(response.data["cybersecurity"]["risk_score"], 55)

    def test_engine_returns_block(self):
        """Unified Engine BLOCK verdict is properly saved and returned."""
        self.client.force_authenticate(user=self.user1)
        mock_block = dict(self.mock_allow_result)
        mock_block["final_decision"] = "BLOCK"
        mock_block["reasons"] = ["Threat intelligence match"]
        mock_block["engines"]["cybersecurity"]["verdict"] = "MALICIOUS"
        mock_block["engines"]["cybersecurity"]["raw_result"]["final_decision"]["risk_score"] = 95
        mock_block["engines"]["machine_learning"]["prediction"] = "PHISHING"
        mock_block["engines"]["machine_learning"]["raw_result"]["probability"]["phishing"] = 0.98

        with patch("unified_engine.detector.scan_url", return_value=mock_block):
            response = self.client.post(
                self.scan_url_endpoint,
                {"url": "https://malicious-phish.invalid"},
                format="json"
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["final_decision"], "BLOCK")
        self.assertEqual(response.data["cybersecurity"]["verdict"], "MALICIOUS")
        self.assertEqual(response.data["machine_learning"]["prediction"], "PHISHING")

    def test_engine_returns_error(self):
        """Unified Engine ERROR verdict is persisted with degraded_mode."""
        self.client.force_authenticate(user=self.user1)
        mock_error = dict(self.mock_allow_result)
        mock_error["final_decision"] = "ERROR"
        mock_error["degraded_mode"] = True
        mock_error["reasons"] = ["Both engines failed"]

        with patch("unified_engine.detector.scan_url", return_value=mock_error):
            response = self.client.post(
                self.scan_url_endpoint,
                {"url": "https://unparseable-input.test"},
                format="json"
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["final_decision"], "ERROR")
        self.assertTrue(response.data["degraded_mode"])

    def test_degraded_mode_when_one_engine_fails(self):
        """If one engine fails, degraded mode is True and decision is safe (never unverified ALLOW)."""
        self.client.force_authenticate(user=self.user1)
        mock_degraded = dict(self.mock_allow_result)
        mock_degraded["final_decision"] = "WARN"
        mock_degraded["degraded_mode"] = True
        mock_degraded["engine_statuses"]["machine_learning"] = "ERROR"
        mock_degraded["warnings"] = ["Machine learning engine inference failed."]

        with patch("unified_engine.detector.scan_url", return_value=mock_degraded):
            response = self.client.post(
                self.scan_url_endpoint,
                {"url": "https://example.com/ml-fail"},
                format="json"
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data["degraded_mode"])
        self.assertEqual(response.data["final_decision"], "WARN")

    def test_scan_history_retrieval_and_user_isolation(self):
        """Users can only view their own scan history records."""
        # Create scans for user1
        ScanHistory.objects.create(
            user=self.user1,
            url="https://user1-scan.com",
            final_decision="ALLOW",
            engine_statuses={"cybersecurity": "OK", "machine_learning": "OK"},
            scan_reasons=["Passed"],
            warnings=[]
        )
        # Create scans for user2
        user2_scan = ScanHistory.objects.create(
            user=self.user2,
            url="https://user2-private-scan.com",
            final_decision="BLOCK",
            engine_statuses={"cybersecurity": "OK", "machine_learning": "OK"},
            scan_reasons=["Blocked"],
            warnings=[]
        )

        # User 1 requests history
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(self.scan_url_endpoint)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        urls_in_history = [item["url"] for item in response.data["results"]]
        self.assertIn("https://user1-scan.com", urls_in_history)
        self.assertNotIn("https://user2-private-scan.com", urls_in_history)

        # User 1 attempts to access user 2's specific scan detail
        detail_url = reverse("scan-detail", kwargs={"id": user2_scan.id})
        detail_resp = self.client.get(detail_url)
        self.assertEqual(detail_resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_scan_detail_404_for_unknown_uuid(self):
        """Requesting a non-existent scan UUID returns HTTP 404."""
        self.client.force_authenticate(user=self.user1)
        random_uuid = uuid.uuid4()
        detail_url = reverse("scan-detail", kwargs={"id": random_uuid})
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_scan_pagination(self):
        """Scan list endpoint paginates results with page_size=20."""
        self.client.force_authenticate(user=self.user1)
        # Create 25 scan records
        for i in range(25):
            ScanHistory.objects.create(
                user=self.user1,
                url=f"https://example{i}.com",
                final_decision="ALLOW",
                engine_statuses={"cybersecurity": "OK", "machine_learning": "OK"},
                scan_reasons=[],
                warnings=[]
            )

        response = self.client.get(self.scan_url_endpoint)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 25)
        self.assertEqual(len(response.data["results"]), 20)
        self.assertIsNotNone(response.data["next"])

    def test_dashboard_stats_correct_counts_and_isolation(self):
        """Dashboard statistics calculate correct per-user counts."""
        # Setup scans for user1
        ScanHistory.objects.create(
            user=self.user1,
            url="https://site1.com",
            final_decision="ALLOW",
            engine_statuses={},
            scan_reasons=[],
            warnings=[]
        )
        ScanHistory.objects.create(
            user=self.user1,
            url="https://site2.com",
            final_decision="ALLOW",
            engine_statuses={},
            scan_reasons=[],
            warnings=[]
        )
        ScanHistory.objects.create(
            user=self.user1,
            url="https://site3.com",
            final_decision="WARN",
            engine_statuses={},
            scan_reasons=[],
            warnings=[]
        )
        ScanHistory.objects.create(
            user=self.user1,
            url="https://site4.com",
            final_decision="BLOCK",
            engine_statuses={},
            scan_reasons=[],
            warnings=[]
        )
        # Scan for user2 that should NOT affect user1 stats
        ScanHistory.objects.create(
            user=self.user2,
            url="https://user2-block.com",
            final_decision="BLOCK",
            engine_statuses={},
            scan_reasons=[],
            warnings=[]
        )

        self.client.force_authenticate(user=self.user1)
        response = self.client.get(self.dashboard_stats_endpoint)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data["total_scans"], 4)
        self.assertEqual(response.data["total_allow"], 2)
        self.assertEqual(response.data["total_warn"], 1)
        self.assertEqual(response.data["total_block"], 1)
        self.assertEqual(response.data["total_error"], 0)
        self.assertEqual(response.data["recent_scans_count"], 4)
        self.assertIsNotNone(response.data["latest_scan_timestamp"])

    def test_dashboard_stats_empty(self):
        """User with no scans receives all zero statistics and null timestamp."""
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(self.dashboard_stats_endpoint)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["total_scans"], 0)
        self.assertEqual(response.data["total_allow"], 0)
        self.assertEqual(response.data["total_warn"], 0)
        self.assertEqual(response.data["total_block"], 0)
        self.assertEqual(response.data["total_error"], 0)
        self.assertEqual(response.data["recent_scans_count"], 0)
        self.assertIsNone(response.data["latest_scan_timestamp"])

    def test_actual_unified_engine_integration_scan(self):
        """
        Integration test invoking the real Unified Engine with a safe, legitimate URL.
        Verifies end-to-end flow from Django API to actual detection modules.
        Note: When offline threat intelligence feed age > 24h, policy mandates WARN
        (preserving the invariant that stale threat intelligence cannot produce an unverified ALLOW).
        """
        self.client.force_authenticate(user=self.user1)

        safe_url = "https://example.com"
        response = self.client.post(self.scan_url_endpoint, {"url": safe_url}, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("id", response.data)
        # Unified Engine returns WARN when threat intelligence is stale (>24h), preserving security policy
        self.assertIn(response.data["final_decision"], ["ALLOW", "WARN"])
        self.assertIn(response.data["cybersecurity"]["status"], ["OK", "DEGRADED"])
        self.assertEqual(response.data["machine_learning"]["status"], "OK")
        self.assertEqual(response.data["machine_learning"]["prediction"], "LEGITIMATE")
        self.assertFalse(response.data["machine_learning"]["is_calibrated"])

        # Check database record created by real engine execution
        record = ScanHistory.objects.get(id=response.data["id"])
        self.assertEqual(record.user, self.user1)
        self.assertIn("complete_result", record.__dict__)
        engines_dict = record.complete_result.get("engines", {})
        self.assertTrue("security_engine" in engines_dict or "cybersecurity" in engines_dict)
        self.assertTrue("ml_engine" in engines_dict or "machine_learning" in engines_dict)

    def test_paypal_brand_credential_compound_blocks_in_live_pipeline(self):
        """
        Regression test: https://paypal.com.example.test/login/password-reset
        must trigger BRAND_IMPERSONATION + BRAND_CREDENTIAL_CONTEXT compound BLOCK
        through the live Django scan API and persist correctly.
        """
        self.client.force_authenticate(user=self.user1)

        failing_url = "https://paypal.com.example.test/login/password-reset"
        response = self.client.post(self.scan_url_endpoint, {"url": failing_url}, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["final_decision"], "BLOCK")
        self.assertEqual(response.data["cybersecurity"]["verdict"], "MALICIOUS")
        self.assertEqual(response.data["cybersecurity"]["risk_score"], 37)
        self.assertIn(
            "Cybersecurity engine issued an authoritative BLOCK verdict.",
            response.data["reasons"]
        )
        self.assertIn(
            "High-confidence protected-brand impersonation is combined with credential or payment context",
            response.data["reasons"]
        )

        # Verify DB persistence
        record = ScanHistory.objects.get(id=response.data["id"])
        self.assertEqual(record.user, self.user1)
        self.assertEqual(record.final_decision, "BLOCK")
        self.assertEqual(record.cybersecurity_verdict, "MALICIOUS")
        self.assertEqual(record.cybersecurity_risk_score, 37)

    def test_paypal_brand_credential_compound_schemeless_url_blocks_in_live_pipeline(self):
        """
        Regression test: schemeless 'paypal.com.example.test/login/password-reset'
        must also trigger compound BLOCK rather than degrading to BENIGN/WARN.
        """
        self.client.force_authenticate(user=self.user1)

        schemeless_url = "paypal.com.example.test/login/password-reset"
        response = self.client.post(self.scan_url_endpoint, {"url": schemeless_url}, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["final_decision"], "BLOCK")
        self.assertEqual(response.data["cybersecurity"]["verdict"], "MALICIOUS")
        self.assertEqual(response.data["cybersecurity"]["risk_score"], 37)

        record = ScanHistory.objects.get(id=response.data["id"])
        self.assertEqual(record.final_decision, "BLOCK")
        self.assertEqual(record.cybersecurity_verdict, "MALICIOUS")
        self.assertEqual(record.cybersecurity_risk_score, 37)

    def test_paypal_subdomain_account_warns_not_block(self):
        """
        Regression test: https://paypal.com.example.test/account
        Brand impersonation without strong credential context must return WARN, not BLOCK.
        """
        self.client.force_authenticate(user=self.user1)

        url = "https://paypal.com.example.test/account"
        response = self.client.post(self.scan_url_endpoint, {"url": url}, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["final_decision"], "WARN")
        self.assertNotEqual(response.data["final_decision"], "BLOCK")
        self.assertEqual(response.data["cybersecurity"]["verdict"], "SUSPICIOUS")

    def test_legitimate_paypal_login_never_blocks(self):
        """
        Regression test: https://www.paypal.com/login
        Legitimate brand domain must never trigger brand impersonation or BLOCK.
        """
        self.client.force_authenticate(user=self.user1)

        url = "https://www.paypal.com/login"
        response = self.client.post(self.scan_url_endpoint, {"url": url}, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data["final_decision"], "BLOCK")
        self.assertNotEqual(response.data["cybersecurity"]["verdict"], "MALICIOUS")

    def test_unrelated_domain_login_password_reset_not_block(self):
        """
        Regression test: example.test/login/password-reset
        Credential words on an unrelated domain without brand impersonation must not compound BLOCK.
        """
        self.client.force_authenticate(user=self.user1)

        url = "example.test/login/password-reset"
        response = self.client.post(self.scan_url_endpoint, {"url": url}, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data["final_decision"], "BLOCK")
        self.assertNotEqual(response.data["cybersecurity"]["verdict"], "MALICIOUS")
