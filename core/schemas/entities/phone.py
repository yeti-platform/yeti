from typing import ClassVar, Literal

from core.schemas import entity


class Phone(entity.Entity):
    type: Literal[entity.EntityType.phone] = entity.EntityType.phone
    _type_filter: ClassVar[str] = entity.EntityType.phone
