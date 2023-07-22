from typing import Annotated, Union, List, Optional
from jose import jwt, JWTError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError
from iam.exceptions import UnauthorizeException
from iam.schema import TokenPayload

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
        except:
            return False
        return True


def get_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    scopes: list[str] = [],
    roles: list[str] = [],
) -> TokenPayload:
    """
    Authorize scopes and returns token payload

    Parameters
    ----------
    token : str
        The incoming token without 'bearer'.

    security_scopes : Union[SecurityScopes, list[str], None]
        The list of scopes

    Returns
    -------
    TokenPayload
        include all data in the token body.
    """
    authenticate_value = f"Bearer "

    if scopes:
        authenticate_value += f'scope="{"".join(scopes)}"'

    if roles:
        authenticate_value += f'roles="{"".join(roles)}"'

    credentials_exception = UnauthorizeException(
        headers={"WWW-Authenticate": authenticate_value},
    )

    try:
        payload = jwt.get_unverified_claims(token)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes: list[str] = payload.get("scope", "").split(" ")
        token_data: TokenPayload = TokenPayload(
            **payload, scopes=token_scopes, id=username
        )
    except (JWTError, ValidationError):
        raise credentials_exception

    for role in roles:
        if role not in token_data.realm_access.roles:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )

    for scope in scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return token_data