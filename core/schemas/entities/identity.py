from typing import ClassVar, Literal

from core.schemas import entity


class Identity(entity.Entity):
    _type_filter: ClassVar[str] = "identity"
    type: Literal["identity"] = "identity"

    identity_class: str = ""
    sectors: list[str] = []
    contact_information: str = ""
