from core.schemas.observable import Observable
from core.schemas.observable import ObservableType

class Path(Observable):
    value: str
    type: ObservableType = ObservableType.path