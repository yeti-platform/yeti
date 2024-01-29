import datetime
from typing import ClassVar, Literal

from core import database_arango
from core.schemas.model import YetiModel
from pydantic import computed_field


class AuditLog(YetiModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "auditlog"
    _type_filter: ClassVar[str | None] = None
    _root_type: Literal["auditlog"] = "auditlog"

    timestamp: datetime.datetime
    username: str
    action: str
    status: str
    target: str
    content: dict = {}
    ip: str
    status_code: int

    @computed_field(return_type=Literal["auditlog"])
    @property
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict) -> "AuditLog":
        return cls(**object)
