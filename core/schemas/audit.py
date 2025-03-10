import datetime
from typing import TYPE_CHECKING, ClassVar, Literal

from pydantic import ConfigDict, computed_field

from core import database_arango
from core.schemas.model import YetiBaseModel, YetiModel

if TYPE_CHECKING:
    from core.schemas.dfiq import DFIQTypes
    from core.schemas.entity import EntityTypes
    from core.schemas.indicator import IndicatorTypes
    from core.schemas.observable import ObservableTypes

    AllObjectTypes = EntityTypes | ObservableTypes | IndicatorTypes | DFIQTypes


class AuditLog(YetiModel, database_arango.ArangoYetiConnector):
    model_config = ConfigDict(str_strip_whitespace=True)

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


class TimelineLog(YetiBaseModel, database_arango.ArangoYetiConnector):
    model_config = ConfigDict(str_strip_whitespace=True)
    _exclude_overwrite: list[str] = []

    _collection_name: ClassVar[str] = "timeline"
    _type_filter: ClassVar[str | None] = None
    _root_type: Literal["timeline"] = "timeline"

    timestamp: datetime.datetime
    actor: str
    target_id: str
    action: str
    details: dict

    @classmethod
    def load(cls, object: dict) -> "TimelineLog":
        return cls(**object)


def log_timeline(
    username: str,
    new: "AllObjectTypes",
    old: "AllObjectTypes" = None,
    action: str | None = None,
    details: dict | None = None,
):
    if details is None:
        if not action:
            action = "update" if old else "create"
        if old:
            old_dump = old.model_dump(exclude=new._TIMELINE_IGNORE_FIELDS)
            new_dump = new.model_dump(exclude=new._TIMELINE_IGNORE_FIELDS)
            # only retain fields that are different
            for key in old_dump:
                if old_dump[key] == new_dump[key]:
                    del new_dump[key]
            details = new_dump
        else:
            details = new.model_dump()
    if details:
        TimelineLog(
            timestamp=datetime.datetime.now(),
            actor=username,
            target_id=new.extended_id,
            action=action,
            details=details,
        ).save()


def log_timeline_tags(actor: str, obj: "AllObjectTypes", old_tags: list[str]):
    new_tags = obj.tags
    details = {
        "removed": set(old_tags) - set(new_tags),
        "added": set(new_tags) - set(old_tags),
    }
    TimelineLog(
        timestamp=datetime.datetime.now(),
        actor=actor,
        target_id=obj.extended_id,
        action="tag",
        details=details,
    ).save()
