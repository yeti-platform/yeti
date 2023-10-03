from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal

class SHA256(Observable):
    value: str
    type: Literal['sha256'] = ObservableType.sha256
