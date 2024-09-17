from typing import ClassVar

from core.schemas import entity


class Phone(entity.Entity):
    type: entity.EntityType = entity.EntityType.phone
    _type_filter: ClassVar[str] = entity.EntityType.phone
