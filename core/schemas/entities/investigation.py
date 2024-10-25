from typing import ClassVar, Literal

from core.schemas import entity


class Investigation(entity.Entity):
    _type_filter: ClassVar[str] = "investigation"
    type: Literal["investigation"] = "investigation"

    reference: str = ""
