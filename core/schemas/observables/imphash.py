from core.schemas.observable import Observable, ObservableType
from typing import Literal

class Imphash(Observable):
    value: str
    type: Literal['imphash'] = ObservableType.imphash
