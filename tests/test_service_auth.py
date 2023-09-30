# python -m unittest tests/test_service_auth.py
import unittest
from unittest import mock
from datetime import timedelta
from service_auth import (
    authenticate_user,
    create_access_token,
    generate_verification_token,
    verify_reset_token,
    get_user_by_email,
    get_current_user_from_cache,
    generate_reset_password_token,
)


class TestAuthService(unittest.TestCase):
    # Authentication tests
    @mock.patch("service_auth.get_user_by_email")
    @mock.patch("service_auth.verify_password")
    def test_authenticate_user(self, mock_verify, mock_get_user):
        mock_db = mock.Mock()
        mock_get_user.return_value = mock.Mock(hashed_password="hashed_password")
        mock_verify.return_value = True

        user = authenticate_user(mock_db, "test@example.com", "password")
        self.assertIsNotNone(user)

        mock_verify.return_value = False
        user = authenticate_user(mock_db, "test@example.com", "wrong_password")
        self.assertIsNone(user)

    # Token generation and verification tests
    def test_generate_verification_token(self):
        email = "test@example.com"
        token = generate_verification_token(email)
        self.assertIsNotNone(token)

    def test_verify_reset_token(self):
        email = "test@example.com"
        token = generate_reset_password_token(email)
        verified_email = verify_reset_token(token)
        self.assertEqual(verified_email, email)

        # Test with an invalid token
        invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.invalid_signature"
        self.assertIsNone(verify_reset_token(invalid_token))

    # Test token creation
    def test_create_access_token(self):
        data = {"sub": "test@example.com"}
        token = create_access_token(data, timedelta(minutes=15))
        self.assertIsNotNone(token)

    # Test retrieval of user by email
    @mock.patch("service_auth.models.User")
    def test_get_user_by_email(self, mock_user_model):
        mock_db = mock.Mock()
        get_user_by_email(mock_db, "test@example.com")
        mock_db.query.assert_called_once()

    # Test retrieval of current user from cache
    @mock.patch("service_auth.redis_client.get")
    def test_get_current_user_from_cache(self, mock_redis_get):
        mock_redis_get.return_value = '{"id": 1, "email": "test@example.com"}'
        user_info = get_current_user_from_cache("1")
        self.assertEqual(user_info["id"], 1)
        self.assertEqual(user_info["email"], "test@example.com")

    # Test reset password token generation
    def test_generate_reset_password_token(self):
        email = "test@example.com"
        token = generate_reset_password_token(email)
        self.assertIsNotNone(token)


if __name__ == "__main__":
    unittest.main()
