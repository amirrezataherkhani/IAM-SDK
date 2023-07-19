from pydantic import BaseModel, Field
from uuid import UUID
from typing import Optional


class RealmAccess(BaseModel):
    roles: Optional[list[str]]


class TokenBasePayload(BaseModel):
    iat: int
    exp: int
    sub: str
    azp: str

    allowed_origins: Optional[list[str]] = Field(..., alias="allowed-origins")
    realm_access: Optional[RealmAccess]


class UserAttributes(TokenBasePayload):
    id: Optional[UUID]
    given_name: Optional[str]
    email_verified: Optional[bool]
    preferred_username: Optional[str]
    given_name: Optional[str]
    family_name: Optional[str]
    email: Optional[str]
    name: Optional[str]
    scopes: list[str]


class TokenPayload(UserAttributes):
    ...
