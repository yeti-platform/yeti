from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal


class Path(Observable):
    value: str
    type: Literal["path"] = ObservableType.path
