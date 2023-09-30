from pydantic import BaseModel, EmailStr
from datetime import date


class ContactBase(BaseModel):
    """
    Базова схема контакту, що містить основні атрибути контакту.
    """

    first_name: str
    last_name: str
    email: EmailStr
    phone_number: str
    birth_date: date
    additional_info: str


class ContactCreate(ContactBase):
    """
    Схема для створення контакту, наслідує атрибути з ContactBase.
    """

    pass


class ContactUpdate(ContactBase):
    """
    Схема для оновлення контакту, наслідує атрибути з ContactBase.
    """

    pass


class Contact(ContactBase):
    """
    Схема контакту, що розширює ContactBase додаванням ідентифікатора контакту.
    """

    id: int

    class Config:
        from_attributes = True


class Token(BaseModel):
    """
    Схема токена, використовується для представлення інформації про токен доступу.
    """

    access_token: str
    token_type: str


class UserResponse(BaseModel):
    """
    Схема відповіді користувача, яка містить основні атрибути користувача.
    """

    id: int
    email: EmailStr


class LoginSchema(BaseModel):
    """
    Схема для входу користувача, що містить атрибути, необхідні для аутентифікації.
    """

    email: EmailStr
    password: str
