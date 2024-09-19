from typing import ClassVar, Literal

from core.schemas import entity


class Investigation(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.investigation
    type: Literal[entity.EntityType.investigation] = entity.EntityType.investigation

    reference: str = ""
