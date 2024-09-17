from typing import ClassVar

from core.schemas import entity


class Identity(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.identity
    type: entity.EntityType = entity.EntityType.identity

    identity_class: str = ""
    sectors: list[str] = []
    contact_information: str = ""
