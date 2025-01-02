import re
import secrets
from typing import ClassVar, Literal

from passlib.context import CryptContext
from pydantic import ConfigDict, Field, computed_field

from core import database_arango
from core.config.config import yeti_config
from core.schemas import graph
from core.schemas.model import YetiModel

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

RBAC_DEFAULT_ROLES = {
    "none": graph.Role.NONE,
    "reader": graph.Role.READER,
    "writer": graph.Role.WRITER,
    "owner": graph.Role.OWNER,
}


def generate_api_key():
    return secrets.token_hex(32)


class User(YetiModel, database_arango.ArangoYetiConnector):
    model_config = ConfigDict(str_strip_whitespace=True)
    _collection_name: ClassVar[str] = "users"
    _root_type: Literal["user"] = "user"
    _type_filter: ClassVar[None] = None

    username: str
    enabled: bool = True
    admin: bool = False
    api_key: str = Field(default_factory=generate_api_key)

    global_role: graph.Permission = RBAC_DEFAULT_ROLES[
        str(yeti_config.get("rbac", "default_role", default="none"))
    ]

    @computed_field(return_type=Literal["user"])
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict) -> "User":
        return cls(**object)

    def reset_api_key(self, api_key=None) -> None:
        if api_key:
            if not re.match(r"^[a-f0-9]{64}$", api_key):
                raise ValueError("Invalid API key: must match ^[a-f0-9]{64}$")
            self.api_key = api_key
        else:
            self.api_key = secrets.token_hex(32)

    def has_role(self, target: str, role: graph.Permission) -> bool:
        if self.global_role & role:
            return True
        return graph.RoleRelationship.has_role(self, target, role)


class UserSensitive(User):
    password: str = ""

    @classmethod
    def load(cls, object: dict) -> "UserSensitive":
        return cls(**object)

    def set_password(self, plain_password: str) -> None:
        self.password = pwd_context.hash(plain_password)

    def verify_password(self, plain_password: str) -> bool:
        return pwd_context.verify(plain_password, self.password)
