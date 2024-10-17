from __future__ import annotations

from enum import Enum, IntEnum, auto
from typing import TYPE_CHECKING, Annotated, Any, Literal, Type, Union

from pydantic import BaseModel, Discriminator, Field
from pydantic import Tag as PydanticTag

if TYPE_CHECKING:
    from core.schemas import (
        dfiq,
        entity,
        graph,
        indicator,
        observable,
        tag,
        task,
        template,
        user,
    )


class MessageType(str, Enum):
    event = "event"
    log = "log"


class EventMessage(str, Enum):
    new = "new"
    update = "update"
    delete = "delete"


ObservableObjectTypes = Annotated[
    "observable.ObservableTypes", Field(discriminator="type")
]
TaskObjectTypes = Annotated["task.TaskTypes", Field(discriminator="type")]
EntityObjectTypes = Annotated["entity.EntityTypes", Field(discriminator="type")]
IndicatorObjectTypes = Annotated[
    "indicator.IndicatorTypes", Field(discriminator="type")
]
UserTypes = Union["user.UserSensitive", "user.User"]


def yeti_object_discriminator(v):
    if isinstance(v, dict):
        return v.get("root_type", None)
    elif isinstance(v, BaseModel):
        return getattr(v, "root_type", None)
    return None


YetiObjectTypes = Annotated[
    Union[
        Annotated[ObservableObjectTypes, PydanticTag("observable")],
        Annotated["dfiq.DFIQTypes", PydanticTag("dfiq")],
        Annotated[TaskObjectTypes, PydanticTag("task")],
        Annotated[EntityObjectTypes, PydanticTag("entity")],
        Annotated[IndicatorObjectTypes, PydanticTag("indicator")],
        Annotated[UserTypes, PydanticTag("user")],
        Annotated["tag.Tag", PydanticTag("tag")],
        Annotated["template.Template", PydanticTag("template")],
        Annotated["graph.Relationship", PydanticTag("relationship")],
        Annotated["graph.TagRelationship", PydanticTag("tag_relationship")],
    ],
    Field(discriminator=Discriminator(yeti_object_discriminator)),
]


class ObjectEvent(BaseModel):
    type: EventMessage
    yeti_object: YetiObjectTypes


class LinkEvent(BaseModel):
    type: EventMessage
    source_object: YetiObjectTypes
    target_object: YetiObjectTypes
    relationship: "graph.Relationship"


class TagLinkEvent(BaseModel):
    type: EventMessage
    tagged_object: YetiObjectTypes
    tag_object: "tag.Tag"


class LogMessage(BaseModel):
    log: str | dict


EventMessageTypes = Union[ObjectEvent, LinkEvent, TagLinkEvent]


class Message(BaseModel):
    type: MessageType
    data: LogMessage | EventMessageTypes
