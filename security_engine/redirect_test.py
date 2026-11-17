"""
Comprehensive Unit Tests for Redirect Analyzer and SSRF Mitigation.
Deterministic, isolated tests for IP validation, DNS rebinding prevention,
cloud metadata blocking, redirect loops, and error handling.
"""

import socket
import unittest
from unittest.mock import MagicMock, patch

if __package__:
    from .redirect_analyzer import (
        analyze_redirects,
        validate_public_url,
        validate_and_resolve_destination,
        is_public_ip,
        get_registered_domain,
        MAX_REDIRECTS,
        SSRFPinnedAdapter,
        PinnedHTTPSConnection,
        PinnedHTTPConnection,
    )
else:
    from redirect_analyzer import (
        analyze_redirects,
        validate_public_url,
        validate_and_resolve_destination,
        is_public_ip,
        get_registered_domain,
        MAX_REDIRECTS,
        SSRFPinnedAdapter,
        PinnedHTTPSConnection,
        PinnedHTTPConnection,
    )
import ipaddress


class RedirectAnalyzerSSRFTests(unittest.TestCase):
    """Unit tests validating SSRF protection and safe redirect inspection."""

    # 1. Localhost destinations
    def test_localhost_hostname_rejected(self):
        valid, msg = validate_public_url("http://localhost/admin")
        self.assertFalse(valid)
        self.assertIn("blocked", msg.lower())

    def test_subdomain_localhost_rejected(self):
        valid, msg = validate_public_url("http://service.localhost:8080/api")
        self.assertFalse(valid)
        self.assertIn("blocked", msg.lower())

    # 2. Private IPv4 addresses
    def test_private_ipv4_loopback_rejected(self):
        valid, msg = validate_public_url("http://127.0.0.1:8000/")
        self.assertFalse(valid)
        self.assertIn("loopback", msg.lower())

    def test_private_ipv4_class_a_rejected(self):
        valid, msg = validate_public_url("http://10.1.2.3/secret")
        self.assertFalse(valid)
        self.assertIn("private", msg.lower())

    def test_private_ipv4_class_b_rejected(self):
        valid, msg = validate_public_url("http://172.16.5.10/")
        self.assertFalse(valid)
        self.assertIn("private", msg.lower())

    def test_private_ipv4_class_c_rejected(self):
        valid, msg = validate_public_url("http://192.168.1.1/router")
        self.assertFalse(valid)
        self.assertIn("private", msg.lower())

    # 3. Private and link-local IPv6 addresses
    def test_private_ipv6_loopback_rejected(self):
        valid, msg = validate_public_url("http://[::1]:8080/")
        self.assertFalse(valid)
        self.assertIn("loopback", msg.lower())

    def test_private_ipv6_unique_local_rejected(self):
        valid, msg = validate_public_url("http://[fc00::1]/")
        self.assertFalse(valid)
        self.assertIn("private", msg.lower())

    def test_private_ipv6_link_local_rejected(self):
        valid, msg = validate_public_url("http://[fe80::1]/")
        self.assertFalse(valid)
        self.assertIn("link-local", msg.lower())

    # 4. IPv4-mapped IPv6 addresses
    def test_ipv4_mapped_ipv6_loopback_rejected(self):
        valid, msg = validate_public_url("http://[::ffff:127.0.0.1]/")
        self.assertFalse(valid)
        self.assertIn("loopback", msg.lower())

    def test_ipv4_mapped_ipv6_metadata_rejected(self):
        valid, msg = validate_public_url("http://[::ffff:169.254.169.254]/")
        self.assertFalse(valid)
        self.assertIn("metadata", msg.lower())

    # 5. Cloud metadata endpoints
    def test_cloud_metadata_ip_rejected(self):
        valid, msg = validate_public_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(valid)
        self.assertIn("metadata", msg.lower())

    def test_gcp_metadata_hostname_rejected(self):
        valid, msg = validate_public_url("http://metadata.google.internal/computeMetadata/v1/")
        self.assertFalse(valid)
        self.assertIn("blocked", msg.lower())

    def test_aws_ipv6_metadata_rejected(self):
        valid, msg = validate_public_url("http://[fd00:ec2::254]/latest/meta-data/")
        self.assertFalse(valid)
        self.assertIn("metadata", msg.lower())

    # 6. Invalid schemes and credentials
    def test_ftp_scheme_rejected(self):
        valid, msg = validate_public_url("ftp://example.com/file.txt")
        self.assertFalse(valid)
        self.assertIn("http", msg.lower())

    def test_credentials_in_url_rejected(self):
        valid, msg = validate_public_url("http://user:password@example.com/")
        self.assertFalse(valid)
        self.assertIn("credentials", msg.lower())

    # 7. DNS resolving to multiple IPs (one is private -> reject)
    def test_multi_ip_with_private_address_rejected(self):
        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port)),
            ]

        valid, _, err, resolved = validate_and_resolve_destination(
            "https://rebinding.test/",
            resolver=fake_resolver
        )
        self.assertFalse(valid)
        self.assertIn("non-public", err.lower())

    # 8. DNS rebinding scenario: connection pins the pre-validated IP
    def test_dns_rebinding_connection_uses_pinned_ip(self):
        call_count = 0

        def alternating_resolver(host, port, type=socket.SOCK_STREAM):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
            # Attacker changes DNS to loopback on second lookup
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

        # Initial validation sees public IP
        valid, pinned_ip, _, _ = validate_and_resolve_destination(
            "https://rebinding.example.com/",
            resolver=alternating_resolver
        )
        self.assertTrue(valid)
        self.assertEqual(pinned_ip, "93.184.216.34")

        # Second validation (e.g. if re-checked independently) catches rebinding
        valid2, _, err2, _ = validate_and_resolve_destination(
            "https://rebinding.example.com/",
            resolver=alternating_resolver
        )
        self.assertFalse(valid2)
        self.assertIn("loopback", err2.lower())

    # 9. Mocked redirect inspection tests
    def test_single_benign_response_no_redirect(self):
        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_session.get.return_value = mock_response

        result = analyze_redirects(
            "https://example.com/landing",
            session=mock_session,
            resolver=fake_resolver
        )

        self.assertEqual(result["redirect_count"], 0)
        self.assertFalse(result["has_redirects"])
        self.assertEqual(result["final_status_code"], 200)
        self.assertEqual(result["stop_reason"], "Final response reached")
        self.assertIsNone(result["error"])

    def test_redirect_to_private_ip_is_blocked(self):
        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"Location": "http://192.168.1.1/secret"}
        mock_session.get.return_value = mock_response

        result = analyze_redirects(
            "https://example.com/redirect",
            session=mock_session,
            resolver=fake_resolver
        )

        self.assertEqual(result["redirect_count"], 0)
        self.assertEqual(result["stop_reason"], "Redirect destination rejected")
        self.assertIn("private ip", result["error"].lower())

    def test_redirect_to_metadata_endpoint_is_blocked(self):
        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}
        mock_session.get.return_value = mock_response

        result = analyze_redirects(
            "https://example.com/redirect",
            session=mock_session,
            resolver=fake_resolver
        )

        self.assertEqual(result["redirect_count"], 0)
        self.assertEqual(result["stop_reason"], "Redirect destination rejected")
        self.assertIn("metadata", result["error"].lower())

    def test_redirect_loop_detected(self):
        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_session = MagicMock()
        resp_a = MagicMock()
        resp_a.status_code = 302
        resp_a.headers = {"Location": "https://example.com/b"}

        resp_b = MagicMock()
        resp_b.status_code = 302
        resp_b.headers = {"Location": "https://example.com/a"}

        mock_session.get.side_effect = [resp_a, resp_b]

        result = analyze_redirects(
            "https://example.com/a",
            session=mock_session,
            resolver=fake_resolver
        )

        self.assertTrue(result["loop_detected"])
        self.assertEqual(result["stop_reason"], "Redirect loop detected")

    def test_https_downgrade_detected(self):
        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_session = MagicMock()
        resp_a = MagicMock()
        resp_a.status_code = 301
        resp_a.headers = {"Location": "http://example.com/insecure"}

        resp_b = MagicMock()
        resp_b.status_code = 200
        resp_b.headers = {}

        mock_session.get.side_effect = [resp_a, resp_b]

        result = analyze_redirects(
            "https://example.com/secure",
            session=mock_session,
            resolver=fake_resolver
        )

        self.assertTrue(result["https_downgrade"])
        self.assertEqual(result["redirect_count"], 1)
        self.assertEqual(result["final_status_code"], 200)

    def test_excessive_redirects_stopped(self):
        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_session = MagicMock()
        # Generates chain of 15 redirects
        mock_responses = []
        for i in range(15):
            r = MagicMock()
            r.status_code = 302
            r.headers = {"Location": f"https://example.com/step_{i+1}"}
            mock_responses.append(r)

        mock_session.get.side_effect = mock_responses

        result = analyze_redirects(
            "https://example.com/step_0",
            max_redirects=3,
            session=mock_session,
            resolver=fake_resolver
        )

        self.assertEqual(result["redirect_count"], 3)
        self.assertEqual(result["stop_reason"], "Maximum redirect limit reached")

    def test_malformed_redirect_location_stops_gracefully(self):
        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_session = MagicMock()
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"Location": "http://[invalid-ipv6/"}
        mock_session.get.return_value = resp

        result = analyze_redirects(
            "https://example.com/start",
            session=mock_session,
            resolver=fake_resolver
        )

        self.assertEqual(result["stop_reason"], "Redirect destination rejected")
        self.assertIsNotNone(result["error"])

    def test_http_request_connection_failure_handled(self):
        import requests

        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.ConnectTimeout("Connection timed out")

        result = analyze_redirects(
            "https://example.com/unreachable",
            session=mock_session,
            resolver=fake_resolver
        )

        self.assertEqual(result["stop_reason"], "Request failed")
        self.assertIn("ConnectTimeout", result["error"])

    def test_explicit_session_proxy_disabled_and_rejected(self):
        """Test that explicit session proxies are cleared and adapter rejects proxy managers."""
        import requests
        session = requests.Session()
        session.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080"
        }

        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}

        with patch.object(requests.Session, "get", return_value=mock_response) as mock_get:
            result = analyze_redirects(
                "http://example.com/test",
                session=session,
                resolver=fake_resolver
            )
            # Verify session proxies were securely disabled/cleared
            self.assertEqual(session.proxies, {})
            self.assertFalse(session.trust_env)
            # Verify get was called with proxies={}
            mock_get.assert_called_once()
            _, kwargs = mock_get.call_args
            self.assertEqual(kwargs.get("proxies"), {})

        # Verify SSRFPinnedAdapter rejects proxy manager instantiation
        adapter = SSRFPinnedAdapter("93.184.216.34")
        with self.assertRaises(ValueError) as cm:
            adapter.proxy_manager_for("http://127.0.0.1:8080")
        self.assertIn("Proxy configuration is disabled", str(cm.exception))

    def test_environment_proxy_ignored(self):
        """Test that environment variables (HTTP_PROXY, HTTPS_PROXY) are ignored."""
        import os
        import requests

        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}

        with patch.dict(os.environ, {
            "HTTP_PROXY": "http://evil-proxy:8080",
            "HTTPS_PROXY": "http://evil-proxy:8443",
            "http_proxy": "http://evil-proxy:8080",
            "https_proxy": "http://evil-proxy:8443"
        }):
            with patch.object(requests.Session, "get", return_value=mock_response) as mock_get:
                result = analyze_redirects(
                    "http://example.com/env-test",
                    resolver=fake_resolver
                )
                self.assertEqual(result["final_status_code"], 200)
                mock_get.assert_called_once()
                _, kwargs = mock_get.call_args
                self.assertEqual(kwargs.get("proxies"), {})

    def test_pinned_destination_connection_behavior(self):
        """Test that the underlying socket connection directly targets the pinned public IP."""
        conn = PinnedHTTPSConnection(host="example.com", port=443)
        conn.pinned_ip = "93.184.216.34"

        with patch("urllib3.util.connection.create_connection") as mock_create_conn:
            fake_sock = MagicMock()
            mock_create_conn.return_value = fake_sock

            sock = conn._new_conn()
            self.assertEqual(sock, fake_sock)
            mock_create_conn.assert_called_once()
            args, _ = mock_create_conn.call_args
            dest_address = args[0]
            self.assertEqual(dest_address, ("93.184.216.34", 443))

    def test_tls_sni_and_hostname_verification_preserved(self):
        """Test that TLS SNI and hostname certificate verification preserve original hostname."""
        conn = PinnedHTTPSConnection(host="example.com", port=443)
        conn.pinned_ip = "93.184.216.34"

        self.assertEqual(conn.host, "example.com")

        with patch("urllib3.util.connection.create_connection") as mock_create_conn, \
             patch("urllib3.connection._ssl_wrap_socket_and_match_hostname") as mock_ssl_wrap:
            fake_sock = MagicMock()
            mock_create_conn.return_value = fake_sock
            mock_ssl_wrap.return_value = MagicMock(socket=fake_sock, is_verified=True)

            conn.connect()

            mock_ssl_wrap.assert_called_once()
            _, kwargs = mock_ssl_wrap.call_args
            self.assertEqual(kwargs["server_hostname"], "example.com")
            self.assertEqual(conn.host, "example.com")

        import requests
        def fake_resolver(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.SSLError("Hostname mismatch on certificate")

        result = analyze_redirects(
            "https://example.com/bad-cert",
            session=mock_session,
            resolver=fake_resolver
        )
        self.assertEqual(result["stop_reason"], "Request failed")
        self.assertIn("SSLError", result["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
