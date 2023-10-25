from unittest import TestCase
from iam.validation import Authorize, get_user
from iam.exceptions import UnauthorizeException
import os


alter_token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJsbWRXYzVzNjhMMkhSbUlGV25CQ29KSEExNnJFR0Fod3ZSbFVUOWdTY1ZvIn0.eyJleHAiOjE2OTgyMzgwMDEsImlhdCI6MTY5ODIzNjIwMSwianRpIjoiYzMzNjRhZWEtY2UxOC00OThhLTgyNTYtMWQ5ZGYzNTVlY2MzIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnZpc2FwaWNrLmNvbS9yZWFsbXMvbWFzdGVyIiwic3ViIjoiOTM3ZmQ4NzAtODQ3NS00ZmJiLTk0NjUtNDc2ZmRhZmNhZTlkIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2ViYXBwIiwic2Vzc2lvbl9zdGF0ZSI6IjQzN2RiMzVhLTJkYTktNGNhMC05ZDVlLWI3ZjI1NGViZWE1YyIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cHM6Ly9zbWFydGFwcGx5bGVnYWwuY29tIiwiaHR0cHM6Ly9hcHBseS12aXNhcGljay52ZXJjZWwuYXBwIiwiaHR0cHM6Ly9hcHBseS52aXNhcGljay5jb20iLCJodHRwOi8vbG9jYWxob3N0OjMwMDAiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIjpwcm9maWxlOmdldCIsIm9mZmxpbmVfYWNjZXNzIiwidXNlciIsInRlc3QtcmVhbG0tcm9sZSIsIjpwcm9maWxlOnVwZGF0ZSJdfSwic2NvcGUiOiJyZWFkIHdlYmFwcC1kZWZhdWx0LXVzZXIgZW1haWwgd2ViLW9yaWdpbnMgb2ZmbGluZV9hY2Nlc3MgcHJvZmlsZSIsInNpZCI6IjQzN2RiMzVhLTJkYTktNGNhMC05ZDVlLWI3ZjI1NGViZWE1YyIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiVXNlciBEZXZlbG9wZXIiLCJncm91cHMiOlsidXNlciJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1c2VyQGRldi52aXNhcGljay5jb20iLCJnaXZlbl9uYW1lIjoiVXNlciIsImZhbWlseV9uYW1lIjoiRGV2ZWxvcGVyIiwiZW1haWwiOiJ1c2VyQGRldi52aXNhcGljay5jb20ifQ.DknlL0FIr_VQPU0EY5eHM_XDgCTbp-UEZBmpel4K18CWz2t1rQ3Hnm5L0tCLl6B8HTI9ad1D5oyN_StcExlZSUSgP0wiOzkxsWveHxHPJspVlaeWBZDcKQBeJANIDy2LLfaTHcVrU8MyBt3SPxxnqyC_6MCKFD2mpbcDrYVuGM8B8cMT4MFY8-wpKA9MsSjBnquJ9iEuBkuBX0fX79ULk_jCeGX4ajirgB2UA_zHCRtT1L47bgy9emk1n0SegPMSQRHfjNU0M4XG_rWFJBbjcAv_IvNyqhr6_-eUphTcBRy1by7_nrnq6I55Tl8Pbkk878vSVU0JwTbLkwFe27Gw1A"

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
