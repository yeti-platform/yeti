from typing import ClassVar, Literal

from core.schemas import entity


class Company(entity.Entity):
    type: Literal[entity.EntityType.company] = entity.EntityType.company
    _type_filter: ClassVar[str] = entity.EntityType.company
