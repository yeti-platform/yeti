import secrets

from passlib.context import CryptContext
from pydantic import BaseModel, Field

from core import database_arango

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def generate_api_key():
    return secrets.token_hex(32)

class User(BaseModel, database_arango.ArangoYetiConnector):

    _collection_name = "users"

    id: str | None
    username: str
    enabled: bool = True
    api_key: str = Field(default_factory=generate_api_key)

    @classmethod
    def load(cls, object: dict) -> "User":
        return cls(**object)


class UserSensitive(User):
    password: str = ''

    @classmethod
    def load(cls, object: dict) -> "UserSensitive":
        return cls(**object)

    def set_password(self, plain_password: str):
        self.password = pwd_context.hash(plain_password)

    def verify_password(self, plain_password: str) -> bool:
        return pwd_context.verify(plain_password, self.password)
