from typing import ClassVar, Literal

from core.schemas import entity


class Note(entity.Entity):
    type: Literal[entity.EntityType.note] = entity.EntityType.note
    _type_filter: ClassVar[str] = entity.EntityType.note
