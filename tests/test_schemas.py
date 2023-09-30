# python -m unittest tests/test_schemas.py
import unittest
from datetime import date
from pydantic import ValidationError
from contacts import schemas


class TestContactSchema(unittest.TestCase):
    def test_valid_contact_creation(self):
        data = {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe@example.com",
            "phone_number": "+1234567890",
            "birth_date": date(1990, 1, 1),
            "additional_info": "Some info",
        }
        contact = schemas.ContactBase(**data)
        self.assertEqual(contact.first_name, "John")

    def test_invalid_contact_creation(self):
        # email without domain
        data = {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe",
            "phone_number": "+1234567890",
            "birth_date": date(1990, 1, 1),
            "additional_info": "Some info",
        }
        with self.assertRaises(ValidationError):
            contact = schemas.ContactBase(**data)


if __name__ == "__main__":
    unittest.main()
