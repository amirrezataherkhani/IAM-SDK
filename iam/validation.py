from typing import Annotated
from jose import jwt, JWTError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError

from iam.exceptions import UnauthorizeException, TokenException, AccessDeniedException
from iam.schema import TokenPayload
from logging import Logger

log = Logger(__name__)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
)


class JWTVerify:
    """
    JWT signature verification using RS256
    """

    __audience = None
    __public_key = None
    __alghorithm = "RS256"

    def __init__(
            self,
            public_key_file_address: str,
            audience: str,
    ) -> None:
        self.set_audience(audience)
        self.set_public_key(public_key_file_address)

    def set_audience(self, audience: str) -> None:
        if not audience:
            raise Exception("audience is invalid.")
        self.__audience = audience

    def set_public_key(self, file: str) -> None:
        self.__public_key = self.__get_public_key_file(file)

    def __get_public_key_file(self, file: str):
        with open(file, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(), backend=default_backend()
            )
        return public_key

    def get_body(self, token: str) -> TokenPayload:
        return TokenPayload(
            **jwt.decode(
                token,
                self.__public_key,
                algorithms=[self.__alghorithm],
                audience=self.__audience,
            )
        )

    def verify(self, token: str) -> bool:
        try:
            self.get_body(token)
        except Exception as e:
            log.critical(e)
            return False
        return True


authenticate_value = f"Bearer "

credentials_exception = UnauthorizeException(
    headers={"WWW-Authenticate": authenticate_value},
)


def get_user(token: Annotated[str, Depends(oauth2_scheme)]) -> TokenPayload:
    """
    Retrieves the user information from the provided token.

    Args:
        token (Annotated[str, Depends(oauth2_scheme)]): The token without 'bearer' used to authenticate the user.

    Returns:
        TokenPayload: The payload containing the user information.

    Raises:
        TokenException: If the token is missing or does not start with "bearer".
        UnauthorizeException: If there is an error during token verification or validation.
    """
    if not token or token.lower().startswith("bearer"):
        raise TokenException

    try:
        payload = jwt.get_unverified_claims(token)
        username: str = payload.get("sub")
        token_scopes: list[str] = payload.get("scope", "").split(" ")
        token_data: TokenPayload = TokenPayload(
            **payload, scopes=token_scopes, id=username
        )
    except (JWTError, ValidationError) as e:
        log.critical(e)
        raise UnauthorizeException

    return token_data


class Authorize:
    def __init__(self, roles: list[str] = [], scopes: list[str] = []) -> None:
        self.roles = roles
        self.scopes = scopes

    def authorize(self, user: TokenPayload) -> TokenPayload:
        """
        Authorizes the user by checking if the user has the required scopes and roles.

        Args:
            user (TokenPayload): The token payload of the user.

        Returns:
            TokenPayload: The authorized token payload of the user.

        Raises:
            AccessDeniedException: If the user does not have the required scopes or roles.
        """

        if any(scope not in user.realm_access.roles for scope in self.scopes):
            raise AccessDeniedException

        if any(group not in user.groups for group in self.roles):
            raise AccessDeniedException

        return user

    def __call__(self, user: TokenPayload = Depends(get_user)) -> TokenPayload:
        return self.authorize(user)
