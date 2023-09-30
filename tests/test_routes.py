# pytest tests/test_routes.py
import pytest
from fastapi.testclient import TestClient
from main import app
from unittest.mock import patch, MagicMock

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    return MagicMock()


def test_create_user(mock_db_session):
    test_email = "demo@example.com"
    test_password = "strongpassword"

    user_data = {"email": test_email, "password": test_password}

    with patch("main.get_db", return_value=mock_db_session):
        response = client.post("/users/", json=user_data)
        assert response.status_code == 201
