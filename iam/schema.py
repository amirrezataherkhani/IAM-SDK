from pydantic import BaseModel, Field
from uuid import UUID
from typing import Optional


class RealmAccess(BaseModel):
    roles: Optional[list[str]] = []


class TokenBasePayload(BaseModel):
    iat: int
    exp: int
    sub: str
    azp: str

    allowed_origins: Optional[list[str]] = Field(..., alias="allowed-origins")
    realm_access: RealmAccess = RealmAccess(roles=[])
    scope: Optional[str] = None
    groups: Optional[list[str]] = []
    preferred_username: Optional[str] = None

    @property
    def scopes(self) -> list[str]:
        return self.scope.split(" ")
    
    # @field_validator("scopes")
    # @classmethod
    # def str_scopes_to_list(cls, v: str) -> list[str]:
    #     if not v:
    #         raise ValueError("must contain a space")
    #     return v.split(" ")


class UserAttributes(TokenBasePayload):
    id: Optional[UUID] = None
    given_name: Optional[str] = None
    email_verified: Optional[bool] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None


class CleintAttributes(TokenBasePayload):
    clientId: Optional[str] = None


class TokenPayload(UserAttributes):
    ...
