from core.schemas.observable import Observable, ObservableType
from typing import Literal


class SsdeepHash(Observable):
    value: str
    type: Literal["ssdeep"] = ObservableType.ssdeep
