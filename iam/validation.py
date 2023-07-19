from typing import Annotated, Union, List, Optional
from jose import jwt, JWTError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError
from iam.exceptions import UnauthorizeException
from iam.schema import TokenPayload, Security

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
    security: Union[Security, None] = None,
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

    if isinstance(security, Security):
        authenticate_value = f'Bearer scope="{security.scope_str}"'

    elif not security:
        security = Security()
        authenticate_value = "Bearer"
    else:
        raise Exception("invalid 'security' type.")
    
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

    for role in security.roles:
        if role not in token_data.realm_access.roles:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )

    for scope in security.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return token_data



# token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0cC03cFJfSVp2Z1VEZDdqam1SVjhOVV9wVUpGeW43c3BWRXpSaEl3OXk4In0.eyJleHAiOjE2ODk3ODYwNzIsImlhdCI6MTY4OTc1MDA3MiwianRpIjoiMTY3ZTc0NzEtYTZiZC00MmI4LTljZDktODc3YjJjODdkNmE1IiwiaXNzIjoiaHR0cHM6Ly92aXNhcGljay1rZXljbG9jay5kYXJrdWJlLmFwcC9yZWFsbXMvcGlja21hcC1wbHVzIiwic3ViIjoiY2ZlYWE5NjktNTkxMi00YjFmLThlZDItM2NhNjBlZmE3ZWMzIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiY291cnNlIiwic2Vzc2lvbl9zdGF0ZSI6ImVmOGU0MTU2LWVmZTYtNDBlMi05MzdjLWNjNzc4YzA5MWE1MyIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cHM6Ly93d3cua2V5Y2xvYWsub3JnIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJhZG1pbiIsInVzZXJzX21hbmFnZSJdfSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwic2lkIjoiZWY4ZTQxNTYtZWZlNi00MGUyLTkzN2MtY2M3NzhjMDkxYTUzIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJKb2huIERvZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImpvaG5Ac2l0ZS5jb20iLCJnaXZlbl9uYW1lIjoiSm9obiIsImZhbWlseV9uYW1lIjoiRG9lIiwiZW1haWwiOiJqb2huQHNpdGUuY29tIn0.UGj6iynV2kfPqoOKSIpphErGAaELleK9vjCaEo-VWtic7B95NebE5MMp7aKtKpDAupeQ1lHJdRKMesRTIkRK_THhQVxhKdRcRZk9gJBnR7tebQOB9IgL__No83bCL05N66WBTQhrzQVeUUuhBMj_RzQHJUDbpRxHOW3jjObDfXyxc8vGtinM-_C1yncZ6aDUIgURcIN06aA_UIPrpq1A0shWkdbNMRf9dzhNijp4pLNYVHWU2tLLko0yHY5N8kycCv3A51-FzspD5PBNU26iYCrThdKh7R4HqhB69sbyhgil_gg0nILtxraK719n4_m65XP-hybd8FkS16fox_9XoA"

# print(
#     get_user(
#         token
#     )
# )