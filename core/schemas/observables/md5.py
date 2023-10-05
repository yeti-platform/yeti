from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal


class MD5(Observable):
    value: str
    type: Literal["md5"] = ObservableType.md5
