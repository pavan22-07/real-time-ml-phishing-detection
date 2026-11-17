"""
Automated test suite for accounts authentication module.
"""

from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken


class AuthenticationAPITests(APITestCase):
    """Unit tests for user registration, login, token refresh, and profile retrieval."""

    def setUp(self):
        self.register_url = reverse("auth-register")
        self.login_url = reverse("auth-login")
        self.refresh_url = reverse("auth-token-refresh")
        self.profile_url = reverse("auth-profile")

        self.valid_user_data = {
            "username": "alice",
            "email": "alice@example.com",
            "password": "SecurePassword123!",
            "password_confirm": "SecurePassword123!",
        }

        # Create pre-existing user for login and duplicate tests
        self.existing_user = User.objects.create_user(
            username="bob",
            email="bob@example.com",
            password="BobPassword123!"
        )

    def test_successful_registration(self):
        """Valid registration creates user and returns JWT token pair."""
        response = self.client.post(self.register_url, self.valid_user_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("tokens", response.data)
        self.assertIn("access", response.data["tokens"])
        self.assertIn("refresh", response.data["tokens"])
        self.assertIn("user", response.data)
        self.assertEqual(response.data["user"]["username"], "alice")
        self.assertEqual(response.data["user"]["email"], "alice@example.com")
        self.assertNotIn("password", response.data["user"])

        # Verify password is encrypted in database
        user = User.objects.get(username="alice")
        self.assertTrue(user.check_password("SecurePassword123!"))

    def test_registration_duplicate_username(self):
        """Registration with existing username returns HTTP 400."""
        data = dict(self.valid_user_data)
        data["username"] = "bob"  # Already taken
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("username", response.data)

    def test_registration_duplicate_email(self):
        """Registration with existing email returns HTTP 400."""
        data = dict(self.valid_user_data)
        data["email"] = "bob@example.com"  # Already taken
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    def test_registration_invalid_email(self):
        """Registration with malformed email format returns HTTP 400."""
        data = dict(self.valid_user_data)
        data["email"] = "not-an-email"
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    def test_registration_password_mismatch(self):
        """Registration with mismatched password confirmation returns HTTP 400."""
        data = dict(self.valid_user_data)
        data["password_confirm"] = "DifferentPassword123!"
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password_confirm", response.data)

    def test_registration_weak_password(self):
        """Registration with weak password (< 8 chars) returns HTTP 400."""
        data = dict(self.valid_user_data)
        data["password"] = "short"
        data["password_confirm"] = "short"
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)

    def test_successful_login(self):
        """Valid credentials return HTTP 200 with JWT tokens."""
        login_data = {
            "username": "bob",
            "password": "BobPassword123!"
        }
        response = self.client.post(self.login_url, login_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("tokens", response.data)
        self.assertIn("access", response.data["tokens"])
        self.assertIn("refresh", response.data["tokens"])
        self.assertEqual(response.data["user"]["username"], "bob")

    def test_login_with_email(self):
        """User can log in using their email address as username."""
        login_data = {
            "username": "bob@example.com",
            "password": "BobPassword123!"
        }
        response = self.client.post(self.login_url, login_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("tokens", response.data)
        self.assertEqual(response.data["user"]["username"], "bob")

    def test_invalid_login_wrong_password(self):
        """Login with incorrect password returns HTTP 400."""
        login_data = {
            "username": "bob",
            "password": "WrongPassword999!"
        }
        response = self.client.post(self.login_url, login_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn("tokens", response.data)

    def test_invalid_login_nonexistent_user(self):
        """Login with non-existent username returns HTTP 400."""
        login_data = {
            "username": "nonexistent_user",
            "password": "SomePassword123!"
        }
        response = self.client.post(self.login_url, login_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_token_refresh(self):
        """Valid refresh token returns a new access token."""
        refresh = RefreshToken.for_user(self.existing_user)
        refresh_data = {"refresh": str(refresh)}
        response = self.client.post(self.refresh_url, refresh_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    def test_unauthorized_profile_access(self):
        """Profile request without JWT header returns HTTP 401."""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_authorized_profile_access(self):
        """Authenticated profile request returns user details without sensitive fields."""
        self.client.force_authenticate(user=self.existing_user)
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["username"], "bob")
        self.assertEqual(response.data["email"], "bob@example.com")
        self.assertNotIn("password", response.data)
