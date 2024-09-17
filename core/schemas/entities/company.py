from typing import ClassVar

from core.schemas import entity


class Company(entity.Entity):
    type: entity.EntityType = entity.EntityType.company
    _type_filter: ClassVar[str] = entity.EntityType.company
