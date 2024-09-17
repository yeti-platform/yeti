from typing import ClassVar

from core.schemas import entity


class Investigation(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.investigation
    type: entity.EntityType = entity.EntityType.investigation

    reference: str = ""
