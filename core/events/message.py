from enum import IntEnum, auto

from pydantic import BaseModel, Field


class MessageType(IntEnum):
    event = auto()
    log = auto()


event_pattern = r"^(new|update)\.(observables|entities|indicators|relationship)\.\w+|(new|update)\.(tags|tasks)$"


class EventData(BaseModel):
    event: str = Field(pattern=event_pattern)
    object_id: str


class LogData(BaseModel):
    log: str | dict


class Message(BaseModel):
    type: MessageType
    data: LogData | EventData
