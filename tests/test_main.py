# python -m unittest tests/test_main.py
import unittest
from fastapi.testclient import TestClient
from main import app, get_db
from unittest.mock import patch, MagicMock
from contacts import models, schemas

client = TestClient(app)


class TestMain(unittest.TestCase):
    # Мок для бази даних
    def mock_get_db(self):
        return MagicMock()

    def login_and_get_token(self):
        response = client.post(
            "/token",
            data={"username": "demo@example.com", "password": "strongpassword"},
        )
        token_data = response.json()
        return token_data["access_token"]

    def test_create_user(self):
        user_data = {"email": "demo@example.com", "password": "strongpassword"}

        with patch("main.get_db", self.mock_get_db):
            response = client.post("/users/", json=user_data)
            self.assertEqual(response.status_code, 201)

    def test_verify_email_with_invalid_token(self):
        with patch("main.get_db", self.mock_get_db):
            response = client.get("/verify-email/?token=invalidtoken")
            self.assertEqual(response.status_code, 400)

    def test_search_contacts(self):
        # Логінимося та отримуємо токен
        access_token = self.login_and_get_token()

        headers = {"Authorization": f"Bearer {access_token}"}

        # Тут ми мокуємо get_current_user, щоб повернути мокованого користувача
        mocked_current_user = models.User(
            id=1, email="demo@example.com", hashed_password="hashed_password"
        )
        with patch("main.get_current_user", return_value=mocked_current_user), patch(
            "main.get_db", self.mock_get_db
        ):
            response = client.get("/contacts/search?name=John", headers=headers)
            self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
