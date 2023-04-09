from pydantic import BaseModel
from core import database_arango

from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(BaseModel, database_arango.ArangoYetiConnector):

    _collection_name = "users"

    id: str | None
    username: str
    enabled: bool = True

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
