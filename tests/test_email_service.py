# python -m unittest tests/test_email_service.py
import unittest
from unittest.mock import patch, MagicMock
from fastapi_mail import FastMail, MessageSchema
import email_service


class TestEmailService(unittest.IsolatedAsyncioTestCase):
    @patch.object(email_service, "FastMail", return_value=MagicMock(spec=FastMail))
    async def test_send_verification_email(self, MockedFastMail):
        fm_instance = MockedFastMail.return_value

        await email_service.send_verification_email("test@example.com", "test_token")

        # Перевірка, що send_message було викликано
        fm_instance.send_message.assert_called_once()

        # Перевірка аргументів
        expected_message = MessageSchema(
            subtype="plain",
            subject="Email Verification",
            recipients=["test@example.com"],
            body="Your token: test_token",
        )
        fm_instance.send_message.assert_called_with(expected_message)

    @patch.object(email_service, "FastMail", return_value=MagicMock(spec=FastMail))
    async def test_send_reset_password_email(self, MockedFastMail):
        fm_instance = MockedFastMail.return_value

        await email_service.send_reset_password_email("test@example.com", "test_token")

        # Перевірка, що send_message було викликано
        fm_instance.send_message.assert_called_once()

        # Перевірка аргументів
        expected_message = MessageSchema(
            subtype="plain",
            subject="Reset Password",
            recipients=["test@example.com"],
            body="Your token: test_token",
        )
        fm_instance.send_message.assert_called_with(expected_message)


if __name__ == "__main__":
    unittest.main()
