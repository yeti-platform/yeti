from typing import ClassVar, Literal

from core.schemas import entity


class Note(entity.Entity):
    type: Literal["note"] = "note"
    _type_filter: ClassVar[str] = "note"
