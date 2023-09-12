from core.schemas.observable import Observable, ObservableType

class TlshObservable(Observable):
    value: str
    type: str = ObservableType.tlsh