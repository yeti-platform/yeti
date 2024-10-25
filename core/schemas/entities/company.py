from typing import ClassVar, Literal

from core.schemas import entity


class Company(entity.Entity):
    type: Literal["company"] = "company"
    _type_filter: ClassVar[str] = "company"
