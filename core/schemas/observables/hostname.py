from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal


class Hostname(Observable):
    value: str
    type: Literal["hostname"] = ObservableType.hostname
