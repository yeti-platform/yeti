from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal

class CIDR(Observable):
    value: str
    type: Literal['cidr'] = ObservableType.cidr
