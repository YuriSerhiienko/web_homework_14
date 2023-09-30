import jwt
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from contacts import models, database
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from decouple import config
import redis
import json

REDIS_URL = config("REDIS_URL")
redis_client = redis.StrictRedis.from_url(REDIS_URL)
SECRET_KEY = config("SECRET_KEY")
ALGORITHM = "HS256"


def get_db():
    """
    Повертає сесію бази даних та закриває її після завершення запиту.
    """
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(data: dict, expires_delta: timedelta):
    """
    Створює токен доступу з вказаними даними та терміном дії.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict):
    """
    Створює токен оновлення на основі вказаних даних.
    """
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def get_user_by_email(db: Session, email: str):
    """
    Повертає користувача за електронною поштою.
    """
    return db.query(models.User).filter(models.User.email == email).first()


def get_user(db: Session, user_id: int):
    """
    Повертає користувача за ідентифікатором.
    """
    return db.query(models.User).filter(models.User.id == user_id).first()


def authenticate_user(db: Session, email: str, password: str):
    """
    Аутентифікує користувача за його електронною поштою та паролем.
    """
    user = get_user_by_email(db, email)

    if user is None or not verify_password(password, user.hashed_password):
        return None
    return user


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    """
    Перевіряє, чи відповідає звичайний пароль зашифрованому паролю.
    """
    return pwd_context.verify(plain_password, hashed_password)


hashed_password = pwd_context.hash("password")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
):
    """
    Отримує поточного користувача на основі токена.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.DecodeError:
        raise credentials_exception

    # Спроба отримати користувача з Redis
    user_info = get_current_user_from_cache(str(user_id))
    if user_info:
        return user_info

    user = get_user(db, user_id)
    if user is None:
        raise credentials_exception

    # Зберігаємо інформацію про користувача в Redis на 1 годину
    redis_client.set(
        f"user:{user_id}", json.dumps({"id": user.id, "email": user.email}), ex=3600
    )

    return user


def generate_verification_token(email: str):
    """
    Генерує токен підтвердження для електронної пошти.
    """
    data = {"email": email, "exp": datetime.utcnow() + timedelta(hours=1)}
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user_from_cache(user_id: str) -> dict:
    """
    Отримує інформацію про поточного користувача з кешу Redis.
    """
    user_info = redis_client.get(f"user:{user_id}")
    if user_info:
        return json.loads(user_info)
    return None


def generate_reset_password_token(email: str):
    """
    Генерує токен для скидання пароля.
    """
    expiration = datetime.utcnow() + timedelta(hours=1)
    token = jwt.encode(
        {"sub": email, "exp": expiration}, SECRET_KEY, algorithm=ALGORITHM
    )
    return token


def verify_reset_token(token: str):
    """
    Перевіряє токен для скидання пароля та повертає електронну адресу користувача.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.DecodeError:
        return None
