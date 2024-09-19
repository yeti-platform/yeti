from typing import ClassVar, Literal

from core.schemas import entity


class Identity(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.identity
    type: Literal[entity.EntityType.identity] = entity.EntityType.identity

    identity_class: str = ""
    sectors: list[str] = []
    contact_information: str = ""
