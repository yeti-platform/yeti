from __future__ import annotations

import abc
import datetime
from enum import Enum
from typing import TYPE_CHECKING, Annotated, Pattern, Union

from pydantic import BaseModel, Discriminator, Field
from pydantic import Tag as PydanticTag

from core.helpers import now

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
    log = "log"
    event = "event"


class EventType(str, Enum):
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


class AbstractEvent(BaseModel, abc.ABC):
    def match(self, acts_on: Pattern) -> bool:
        raise NotImplementedError


class ObjectEvent(AbstractEvent):
    type: EventType
    yeti_object: YetiObjectTypes

    def match(self, acts_on: Pattern) -> bool:
        return acts_on.match(self.event_message)

    @property
    def event_message(self) -> str:
        event_message = f"{self.type}:{self.yeti_object.root_type}"
        if hasattr(self.yeti_object, "type"):
            event_message += f":{self.yeti_object.type}"
        return event_message


class LinkEvent(AbstractEvent):
    type: EventType
    source_object: YetiObjectTypes
    target_object: YetiObjectTypes
    relationship: "graph.Relationship"

    def match(self, acts_on: Pattern) -> bool:
        return acts_on.match(self.link_source_event) or acts_on.match(
            self.link_target_event
        )

    @property
    def link_source_event(self) -> str:
        link_source_event = f"{self.type}:link:source:{self.source_object.root_type}"
        if hasattr(self.source_object, "type"):
            link_source_event += f":{self.source_object.type}"
        return link_source_event

    @property
    def link_target_event(self) -> str:
        link_target_event = f"{self.type}:link:target:{self.target_object.root_type}"
        if hasattr(self.target_object, "type"):
            link_target_event += f":{self.target_object.type}"
        return link_target_event


class TagEvent(AbstractEvent):
    type: EventType
    tagged_object: YetiObjectTypes
    tag_object: "tag.Tag"

    def match(self, acts_on: Pattern) -> bool:
        return acts_on.match(self.tag_message)

    @property
    def tag_message(self) -> str:
        return f"{self.type}:tagged:{self.tag_object.name}"


class AbstractMessage(BaseModel, abc.ABC):
    type: MessageType
    timestamp: datetime.datetime = Field(default_factory=now)


class LogMessage(AbstractMessage):
    type: MessageType = MessageType.log
    log: str | dict


EventTypes = Union[ObjectEvent, LinkEvent, TagEvent]


class EventMessage(AbstractMessage):
    type: MessageType = MessageType.event
    event: EventTypes
