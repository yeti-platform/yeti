from typing import ClassVar

from core.schemas import entity


class Note(entity.Entity):
    type: entity.EntityType = entity.EntityType.note
    _type_filter: ClassVar[str] = entity.EntityType.note
