from unittest import TestCase
from iam.validation import Authorize, get_user
from iam.exceptions import UnauthorizeException
import os


alter_token = None

class TestAuthoriziation(TestCase):
    def setUp(self) -> None:
        self.token = os.getenv("token", alter_token)
        self.invalid_token = self.token[:-2] + "x"

        self.user = get_user(self.token)

        return super().setUp()

    def test_get_user_valid_token(self):
        authorize = Authorize()
        authorize(self.user)

    def test_get_user_invalid_token(self):
        with self.assertRaises(UnauthorizeException):
            get_user(self.invalid_token)

    def test_user_payload(self):
        user = self.user
        self.assertIsNotNone(user.sub)
        self.assertIsInstance(user.scopes, list)
        self.assertGreater(len(user.scopes), 0)

    def test_user_group_payload(self):
        # Consider the user has below scopes
        scopes = [":profile:get", ":profile:update"]

        # Consider the user is in below groups
        groups = ["user"]

        # Authorize only scopes
        authorize = Authorize(scopes=scopes)
        authorize(self.user)


        # Authorize only roles
        authorize = Authorize(roles=groups)
        authorize(self.user)


        # Authorize scopes and roles
        authorize = Authorize(scopes=scopes, roles=groups)
        authorize(self.user)
