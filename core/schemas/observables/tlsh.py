from core.schemas.observable import Observable, ObservableType

class TLSH(Observable):
    value: str
    type: str = ObservableType.tlsh
