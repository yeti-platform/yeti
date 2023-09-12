from core.schemas.observable import Observable, ObservableType


class ImphashObservable(Observable):
    value: str
    type: str = ObservableType.imphash