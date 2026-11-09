import hashlib
import os
import hmac

from datetime import datetime

from valutatrade_hub.core.utils import convert_currency


class User:
    '''Класс пользователя системы'''

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
    def username(self) -> str:
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


class Wallet:
    '''Класс кошелька для одной валюты'''

    def __init__(
            self,
            currency_code: str,
            balance: float = 0.0
    ):
        if not isinstance(currency_code, str):
            raise TypeError("Код валюты должен быть строкой")
        code = currency_code.strip().upper()
        if len(code) != 3 or not code.isalpha():
            raise ValueError("Код валюты должен состоять из 3 букв (ISO 4217)")
        if isinstance(balance, bool) or not isinstance(balance, (int, float)):
            raise TypeError('Баланс должен быть числом')
        if balance != balance or balance in (float('inf'), float('-inf')):
            raise ValueError('Баланс должен быть конечным числом')
        if balance < 0:
            raise ValueError('Начальный баланс не может быть отрицательным')
        self._currency_code = code
        self._balance = float(balance)

    @property
    def currency_code(self) -> str:
        return self._currency_code

    @property
    def balance(self) -> float:
        return self._balance

    @balance.setter
    def balance(self, amount: float) -> None:
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise TypeError('Баланс должен быть числом')
        if amount != amount or amount in (float('inf'), float('-inf')):
            raise ValueError('Баланс должен быть конечным числом')
        if amount < 0:
            raise ValueError('Баланс не может быть отрицательным')
        self._balance = float(amount)

    @staticmethod
    def _validate_amount(amount: float) -> None:
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise TypeError('Сумма должна быть числом')
        if amount != amount or amount in (float('inf'), float('-inf')):
            raise ValueError('Сумма должна быть конечным числом')
        if amount <= 0:
            raise ValueError('Сумма должна быть положительной')

    def deposit(self, amount: float) -> None:
        """Пополняет баланс на указанную сумму"""
        self._validate_amount(amount)
        self.balance = self._balance + amount

    def withdraw(self, amount: float) -> None:
        """Снимает указанную сумму с баланса"""
        self._validate_amount(amount)
        if amount > self._balance:
            raise ValueError('На балансе недостаточно средств')
        self.balance = self._balance - amount

    def get_balance_info(self) -> None:
        print(f"На балансе {self._balance} {self.currency_code}")


class Portfolio:
    def __init__(
            self,
            user: User,
            wallets: dict[str, Wallet]
    ):
        if not isinstance(user, User):
            raise TypeError(
                f'Ожидается класс User, получено: {type(user).__name__}')
        self._user = user
        self._wallets: dict[str, Wallet] = dict(wallets) if wallets else {}

    @property
    def user(self) -> User:
        """Возвращает объект пользователя"""
        return self._user

    @property
    def wallets(self) -> dict[str, Wallet]:
        return dict(self._wallets)

    @staticmethod
    def _normalize_code(currency_code: str) -> str:
        if not isinstance(currency_code, str):
            raise TypeError("Код валюты должен быть строкой")
        code = currency_code.strip().upper()
        if len(code) != 3 or not code.isalpha():
            raise ValueError("Код валюты должен состоять из 3 букв (ISO 4217)")
        return code

    def add_currency(self, currency_code: str) -> None:
        """Добавляет в портфолио новый кошелек"""
        code = self._normalize_code(currency_code)
        if code in self._wallets:
            raise ValueError(f'В портфолио уже есть кошелек {code}')
        new_wallet = Wallet(code)

        self._wallets[code] = new_wallet

    def get_wallet(self, currency_code: str) -> Wallet:
        """Возвращает объект кошелька с указанной валютой"""
        code = self._normalize_code(currency_code)
        if code not in self._wallets:
            raise ValueError(f'В кошельке нет активов в {code}')
        wallet = self._wallets[code]
        return wallet

    def get_total_value(self, base_currency='USD') -> float:
        """Возвращает общую стоимость всех валют в базовой валюте"""
        base = self._normalize_code(base_currency)
        total_value = 0.0
        for currency, wallet in self._wallets.items():
            if currency == base:
                total_value += wallet.balance
            else:
                total_value += convert_currency(wallet.balance, currency, base)
        return total_value
