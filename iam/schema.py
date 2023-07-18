from pydantic import BaseModel
from uuid import UUID


class User(BaseModel):
    id: UUID
    given_name: str
    email_verified: bool
    preferred_username: str
    given_name: str
    family_name: str
    email: str
    name: str


class JWTBody(User):
    scopes: list[str]
