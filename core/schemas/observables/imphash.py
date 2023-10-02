from core.schemas.observable import Observable, ObservableType


class Imphash(Observable):
    value: str
    type: str = ObservableType.imphash
