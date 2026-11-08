class User:
    def __init__(
            self,
            _user_id: int,
            _username: str,
            _hashed_password: str,
            _salt: str,
            _registration_date
    ):
        self._user_id = _user_id
        self._username = _username
        self._hashed_password = _hashed_password
        self._salt = _salt
        self._registration_date = _registration_date

    def get_user_info(self):
        pass

    def change_password(self, new_password: str):
        pass

    def verify_password(self, password: str):
        pass
