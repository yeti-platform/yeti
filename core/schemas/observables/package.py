from typing import Literal

from core.schemas import observable


class Package(observable.Observable):
    type: Literal["package"] = "package"
    version: str | None = None
    registry_type: str | None = None
