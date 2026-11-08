import hashlib
import os
import hmac

from datetime import datetime


class User:
    def __init__(
            self,
            user_id: int,
            username: str,
            hashed_password: str,
            salt: str,
            registration_date: datetime
    ):
        self._user_id = user_id
        self._username = username
        self._hashed_password = hashed_password
        self._salt = salt
        self._registration_date = registration_date

    @property
    def username(self):
        return self._username

    @property
    def user_id(self) -> int:
        return self._user_id

    @property
    def registration_date(self) -> datetime:
        return self._registration_date

    @username.setter
    def username(self, name: str):
        """Изменяет имя пользователя"""
        if not isinstance(name, str):
            raise TypeError('Имя должно быть строкой')

        name = name.strip()
        if not name:
            raise ValueError('Имя не может быть пустым')
        self._username = name

    def get_user_info(self):
        """Печатает данные о пользователе"""
        print(
            f"ID: {self._user_id}\n",
            f"Имя пользователя: {self._username}\n",
            f"Дата регистрации: {self._registration_date}\n"
        )

    @staticmethod
    def _validate_password(password):
        if not isinstance(password, str):
            raise ValueError('Пароль должен быть строкой')
        if len(password) < 4:
            raise ValueError('Пароль не может быть короче 4 символов')

    @staticmethod
    def _hash_password(password, salt: bytes):
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations=600_000
        ).hex()

    def change_password(self, new_password: str, old_password: str):
        """Изменяет пароль и хэширует его"""
        if not self.verify_password(old_password):
            raise ValueError('Неверный пароль')
        self._validate_password(new_password)

        salt = os.urandom(16)
        self._hashed_password = self._hash_password(new_password, salt)
        self._salt = salt.hex()

    def verify_password(self, password: str):
        """Возвращает True, если пароль верный"""
        if not isinstance(password, str):
            return False
        salt = bytes.fromhex(self._salt)
        computed = self._hash_password(password, salt)
        return hmac.compare_digest(computed, self._hashed_password)
